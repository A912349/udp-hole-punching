package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"strings"

	_ "modernc.org/sqlite"
)

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// gzipAdmin compresses the larger read-only admin JSON responses. Topology
// snapshots contain repeated node IDs and fields, so compression cuts browser
// refresh traffic substantially while the small control-plane frames and the
// websocket upgrade remain untouched. The SSE stream is exempt too: it must
// flush frames as they happen instead of being buffered into one body.
func gzipAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/admin/") ||
			r.URL.Path == "/v1/admin/stream" ||
			!strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		buffer := &gzipResponseWriter{header: w.Header()}
		next.ServeHTTP(buffer, r)
		if buffer.status == 0 {
			buffer.status = http.StatusOK
		}
		if buffer.status >= 200 && buffer.status < 300 &&
			strings.HasPrefix(buffer.header.Get("Content-Type"), "application/json") && buffer.body.Len() >= 512 {
			buffer.header.Del("Content-Length")
			buffer.header.Set("Content-Encoding", "gzip")
			buffer.header.Add("Vary", "Accept-Encoding")
			w.WriteHeader(buffer.status)
			z := gzip.NewWriter(w)
			_, _ = z.Write(buffer.body.Bytes())
			_ = z.Close()
			return
		}
		w.WriteHeader(buffer.status)
		_, _ = w.Write(buffer.body.Bytes())
	})
}

type gzipResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *gzipResponseWriter) Header() http.Header { return w.header }
func (w *gzipResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *gzipResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

// controlFrame is deliberately small: after the upgrade all control-plane
// requests share one TCP/TLS connection, avoiding repeated HTTP handshakes.
type controlFrame struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
	Status int             `json:"status,omitempty"`
	Error  string          `json:"error,omitempty"`
	Event  string          `json:"event,omitempty"`
}

// controlResponseWriter is the small ResponseWriter implementation used by
// the in-process WebSocket control path. Going through httptest.NewRecorder
// here needlessly allocates an HTTP response and parses transfer metadata for
// every heartbeat/control frame.
type controlResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *controlResponseWriter) Header() http.Header { return w.header }

func (w *controlResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *controlResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}
