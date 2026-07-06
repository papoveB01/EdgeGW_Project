package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRequireAPIKey(t *testing.T) {
	h := RequireAPIKey(okHandler(), "secret123")

	cases := []struct {
		name       string
		header     string
		value      string
		wantStatus int
	}{
		{"no credentials", "", "", http.StatusUnauthorized},
		{"wrong bearer", "Authorization", "Bearer nope", http.StatusUnauthorized},
		{"correct bearer", "Authorization", "Bearer secret123", http.StatusOK},
		{"correct custom header", "X-Gateway-API-Key", "secret123", http.StatusOK},
		{"wrong custom header", "X-Gateway-API-Key", "nope", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("POST", "/process", nil)
		if tc.header != "" {
			req.Header.Set(tc.header, tc.value)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s: got %d, want %d", tc.name, rec.Code, tc.wantStatus)
		}
	}
}

func TestRequireAPIKey_DisabledWhenEmpty(t *testing.T) {
	h := RequireAPIKey(okHandler(), "")
	req := httptest.NewRequest("POST", "/process", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("empty key should disable auth: got %d", rec.Code)
	}
}
