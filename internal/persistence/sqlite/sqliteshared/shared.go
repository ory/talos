// Package sqliteshared contains SQLite helpers used by both the OSS and
// commercial drivers. Centralizing them here prevents silent behavioral
// drift between editions: the byte-identical helpers must stay byte-identical.
package sqliteshared

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"time"

	"github.com/XSAM/otelsql"
	"github.com/cockroachdb/errors"
	"github.com/jmoiron/sqlx"

	_ "modernc.org/sqlite" // Pure Go SQLite driver

	"github.com/ory/talos/internal/dbutil"
	"github.com/ory/talos/internal/persistence/persistmodel"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlutil"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// MaxBatchKeys is the maximum number of imported keys per batch insert.
// SQLite's SQLITE_MAX_VARIABLE_NUMBER is 32766; each key uses 15 bind parameters,
// so the hard limit is 32766 / 15 = 2184 keys per statement.
const MaxBatchKeys = 2184

// IsMemoryDSN reports whether the given (prefix-stripped) DSN targets an
// in-memory SQLite database. Drivers must pin the connection pool to one for
// memory DSNs because each connection would otherwise see an isolated database.
func IsMemoryDSN(dsn string) bool {
	return strings.Contains(dsn, ":memory:") ||
		strings.Contains(dsn, "mode=memory")
}

// withForeignKeysOn appends _pragma=foreign_keys(ON) to the DSN's query
// string. modernc.org/sqlite applies _pragma values in URL order, so any
// caller- or user-supplied foreign_keys value is overridden by ours appended
// last.
func withForeignKeysOn(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=" + url.QueryEscape("foreign_keys(ON)")
}

// OpenDB opens a SQLite database with OTEL instrumentation and DB stats metrics.
// Foreign keys are always enabled: every connection opened here has
// PRAGMA foreign_keys=ON regardless of caller. The caller owns the returned
// *sqlx.DB and is responsible for closing it and applying any pool
// configuration.
func OpenDB(dsn string) (*sqlx.DB, error) {
	dsn = withForeignKeysOn(dsn)

	sqlDB, err := otelsql.Open("sqlite", dsn, dbutil.TraceOptions("sqlite")...)
	if err != nil {
		return nil, errors.Wrap(err, "open database")
	}

	if _, err := otelsql.RegisterDBStatsMetrics(sqlDB, otelsql.WithAttributes(
		dbutil.DBSystemAttribute("sqlite"),
	)); err != nil {
		_ = sqlDB.Close()
		return nil, errors.Wrap(err, "register DB stats metrics")
	}

	return sqlx.NewDb(sqlDB, "sqlite"), nil
}

// WithTx executes fn inside a transaction. SQLite serializes writes
// internally, so no retry logic is needed.
func WithTx(ctx context.Context, conn *sqlx.DB, q *db.Queries, fn func(*db.Queries) error) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "begin transaction")
	}
	if err := fn(q.WithTx(tx)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return errors.Wrap(tx.Commit(), "commit transaction")
}

// Int32ToNullable converts an int32 to an any suitable for nullable SQL
// parameters. Zero value means no filter (NULL in SQL).
func Int32ToNullable(v int32) any {
	if v == 0 {
		return nil
	}
	return v
}

// ScanIssuedAPIKey scans one row from an issued_api_keys SELECT into a db.IssuedApiKey.
func ScanIssuedAPIKey(rows *sql.Rows) (db.IssuedApiKey, error) {
	var key db.IssuedApiKey
	err := rows.Scan(
		&key.NID, &key.KeyID, &key.Name, &key.TokenPrefix, &key.Version,
		&key.ActorID, &key.Scopes, &key.Status, &key.Metadata, &key.LastUsedAt,
		&key.ExpiresAt, &key.CreatedAt, &key.UpdatedAt, &key.RateLimitQuota,
		&key.RateLimitWindow, &key.RevocationReason, &key.RevocationReasonText,
		&key.AllowedCidrs, &key.RequestID, &key.Visibility,
	)
	return key, err
}

// ScanImportedAPIKey scans one row from an imported_api_keys SELECT into a db.ImportedApiKey.
func ScanImportedAPIKey(rows *sql.Rows) (db.ImportedApiKey, error) {
	var key db.ImportedApiKey
	err := rows.Scan(
		&key.NID, &key.KeyID, &key.Name, &key.ActorID,
		&key.Scopes, &key.Status, &key.Metadata, &key.LastUsedAt, &key.ExpiresAt,
		&key.CreatedAt, &key.UpdatedAt, &key.RateLimitQuota, &key.RateLimitWindow,
		&key.RevocationReason, &key.RevocationReasonText,
		&key.AllowedCidrs, &key.RequestID, &key.Visibility,
	)
	return key, err
}

// BuildBatchInsertImportedKeysQuery builds a single INSERT ... ON CONFLICT DO
// NOTHING RETURNING statement for imported keys. The RETURNING clause yields
// only actually-inserted rows so callers can derive the conflict set without a
// post-INSERT SELECT.
func BuildBatchInsertImportedKeysQuery(nid string, keys []persistmodel.BatchCreateImportedAPIKeyInput, now time.Time) (string, []any) {
	var builder strings.Builder
	builder.Grow(len(keys) * 70)
	builder.WriteString("INSERT INTO imported_api_keys (")
	builder.WriteString("nid, key_id, actor_id, name, scopes, metadata, status, expires_at, rate_limit_quota, rate_limit_window, allowed_cidrs, visibility, request_id, created_at, updated_at")
	builder.WriteString(") VALUES ")

	args := make([]any, 0, len(keys)*15)
	for i, key := range keys {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")

		scopes := sqlutil.NormalizeScopesJSON(key.Scopes)
		metadata := sqlutil.NormalizeMetadata(key.Metadata)
		args = append(
			args,
			nid,
			key.KeyID,
			sqlutil.PtrOrNil(key.ActorID),
			key.Name,
			scopes,
			metadata,
			int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			key.ExpiresAt,
			key.RateLimitQuota,
			key.RateLimitWindow,
			sqlutil.NormalizeScopesJSON(key.AllowedCIDRs),
			key.Visibility,
			sqlutil.PtrOrNil(key.RequestID),
			now,
			now,
		)
	}
	builder.WriteString(" ON CONFLICT (nid, key_id) DO NOTHING")
	builder.WriteString(" RETURNING nid, key_id, name, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility")

	return builder.String(), args
}

// QueryImportedKeysByIDs fetches imported_api_keys rows for the given (nid, keyIDs).
// Used by batch-insert paths to populate the conflict (existing) set.
func QueryImportedKeysByIDs(ctx context.Context, tx *sql.Tx, nid string, keyIDs []string) ([]db.ImportedApiKey, error) {
	if len(keyIDs) == 0 {
		return []db.ImportedApiKey{}, nil
	}

	query, args := sqlutil.BuildINQuery[db.ImportedApiKey](sqlutil.DialectQuestionMark, "imported_api_keys", nid, keyIDs)
	result, err := sqlutil.QueryRows(ctx, tx, query, args, len(keyIDs), ScanImportedAPIKey)
	if err != nil {
		return nil, errors.Wrap(err, "query imported keys by id")
	}

	return result, nil
}

// InitializeNetwork creates a network row with the given ID if it does not
// already exist.
func InitializeNetwork(ctx context.Context, conn *sqlx.DB, nid string) error {
	now := sqlutil.UTCNow()
	_, err := conn.ExecContext(
		ctx,
		"INSERT OR IGNORE INTO networks (id, created_at, updated_at) VALUES (?, ?, ?)",
		nid, now, now,
	)
	if err != nil {
		return errors.Wrap(err, "create network")
	}
	return nil
}
