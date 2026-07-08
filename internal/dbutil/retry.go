package dbutil

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/XSAM/otelsql"
	"github.com/cenkalti/backoff/v4"
	"github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
)

// ConnectWithRetry attempts to open and ping a database connection with exponential backoff.
// It retries transient connection errors but fails fast on permanent errors like authentication failures.
// Retries start at 100ms, cap at 3s, and give up after 5 minutes.
func ConnectWithRetry(ctx context.Context, driverName, dsn string, logger *slog.Logger) (*sql.DB, error) {
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 100 * time.Millisecond
	expBackoff.MaxInterval = 3 * time.Second
	expBackoff.MaxElapsedTime = 5 * time.Minute
	expBackoff.RandomizationFactor = 0 // No jitter for deterministic behavior

	backoffWithContext := backoff.WithContext(expBackoff, ctx)

	var db *sql.DB
	var lastErr error
	attemptNum := 0
	startTime := time.Now()

	operation := func() error {
		attemptNum++
		attemptStart := time.Now()

		// Open connection with OTEL instrumentation (does not actually connect yet)
		var err error
		db, err = otelsql.Open(driverName, dsn, TraceOptions(driverName)...)
		if err != nil {
			lastErr = errors.Wrap(err, "sql.Open failed")
			logAttemptFailure(logger, attemptNum, attemptStart, lastErr)
			return lastErr
		}

		// Register DB stats with OTEL metrics
		// Registration is intentionally not stored as db.Close() will clean up metrics
		if _, err := otelsql.RegisterDBStatsMetrics(db, otelsql.WithAttributes(
			DBSystemAttribute(driverName),
		)); err != nil {
			_ = db.Close()
			db = nil
			lastErr = errors.Wrap(err, "register DB stats metrics")
			logAttemptFailure(logger, attemptNum, attemptStart, lastErr)
			return lastErr
		}

		// Verify connection with ping (actual network round-trip)
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close() // Clean up failed connection
			db = nil
			lastErr = errors.Wrap(err, "db.Ping failed")
			logAttemptFailure(logger, attemptNum, attemptStart, lastErr)
			return lastErr
		}

		// Success
		elapsed := time.Since(startTime)
		logger.InfoContext(
			ctx, "Database connection established",
			slog.String("driver", driverName),
			slog.Int("attempts", attemptNum),
			slog.Duration("total_elapsed", elapsed),
		)
		return nil
	}

	if err := backoff.Retry(operation, backoffWithContext); err != nil {
		return nil, errors.Wrapf(lastErr, "database connection failed after %d attempts (timeout or context cancelled)", attemptNum)
	}

	return db, nil
}

// logAttemptFailure logs connection attempt failures with level based on attempt count.
// Attempts 1-3: DEBUG (expected transient failures during startup)
// Attempts 4+: WARN (sustained connectivity issues)
func logAttemptFailure(logger *slog.Logger, attemptNum int, attemptStart time.Time, err error) {
	elapsed := time.Since(attemptStart)
	attrs := []any{
		slog.Int("attempt", attemptNum),
		slog.Duration("attempt_duration", elapsed),
		slog.String("error", err.Error()),
	}

	if attemptNum <= 3 {
		logger.Debug("Database connection attempt failed (transient, will retry)", attrs...)
	} else {
		logger.Warn("Database connection attempt failed (sustained issue)", attrs...)
	}
}

// TraceOptions returns the otelsql instrumentation options shared by every
// Talos database connection: a db.system attribute derived from the driver
// name and span options that keep connection acquisition (connector connect)
// visible while omitting the noisy per-query connection reset spans. New
// connection dials emit a sql.connector.connect child span, making cold dials
// (TCP + TLS + auth) visible in traces. Pool wait time on a saturated pool is
// not spannable at the driver layer; otelsql.RegisterDBStatsMetrics exposes
// wait-duration metrics for that case.
func TraceOptions(driverName string) []otelsql.Option {
	return []otelsql.Option{
		otelsql.WithAttributes(DBSystemAttribute(driverName)),
		otelsql.WithSpanOptions(otelsql.SpanOptions{
			OmitConnResetSession: true,
		}),
	}
}

// DBSystemAttribute maps SQL driver names to OpenTelemetry semantic convention database system attributes.
// Used for consistent tracing and metrics labeling across database operations.
func DBSystemAttribute(driverName string) attribute.KeyValue {
	switch driverName {
	case "sqlite", "sqlite3":
		return semconv.DBSystemNameSQLite
	case DriverPgx, "postgres", "postgresql":
		return semconv.DBSystemNamePostgreSQL
	case "mysql":
		return semconv.DBSystemNameMySQL
	case "cockroachdb":
		// CockroachDB uses PostgreSQL wire protocol
		return semconv.DBSystemNamePostgreSQL
	default:
		return semconv.DBSystemNameOtherSQL
	}
}

// reviewed - @aeneasr - 2026-03-26
