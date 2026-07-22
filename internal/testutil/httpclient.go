package testutil

import (
	"net/http"
	"testing"
)

// NewTestTransport returns a transport dedicated to a single test client.
//
// httptest.Server.Close unconditionally calls
// http.DefaultTransport.CloseIdleConnections as a courtesy for users of the
// default transport. When parallel tests share http.DefaultTransport (the
// zero value of http.Client.Transport), one test closing its server tears
// down idle connections that another test's in-flight request is using,
// surfacing as "http: CloseIdleConnections called". A dedicated transport
// keeps that courtesy close away from live test clients.
func NewTestTransport(tb testing.TB) *http.Transport {
	tb.Helper()
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		tb.Fatalf("http.DefaultTransport is %T, not *http.Transport", http.DefaultTransport)
	}
	transport := base.Clone()
	tb.Cleanup(transport.CloseIdleConnections)
	return transport
}

// NewTestHTTPClient returns a jar-less client with a dedicated transport, see
// NewTestTransport.
func NewTestHTTPClient(tb testing.TB) *http.Client {
	tb.Helper()
	return &http.Client{Transport: NewTestTransport(tb)}
}
