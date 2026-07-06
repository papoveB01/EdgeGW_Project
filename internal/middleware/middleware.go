package middleware

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// RequireAPIKey rejects requests that don't present the expected key as
// "Authorization: Bearer <key>" or "X-Gateway-API-Key: <key>". If key is
// empty, authentication is disabled (a startup warning is logged in main).
func RequireAPIKey(next http.Handler, key string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		presented := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if presented == "" || presented == r.Header.Get("Authorization") {
			presented = r.Header.Get("X-Gateway-API-Key")
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(key)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MaxBodySize limits request body size to prevent OOM.
func MaxBodySize(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}

// RequestLogger logs each request with structured fields.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}

		next.ServeHTTP(sw, r)

		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
