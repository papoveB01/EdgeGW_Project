package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/papoveB01/EdgeGW_Project/internal/config"
)

func setupHubEnv(t *testing.T, hubURL string) {
	t.Helper()
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("HUB_API_URL", hubURL)
	t.Setenv("API_KEY", "test-api-key")
	t.Setenv("HMAC_SECRET", "test-hmac-secret")
	t.Setenv("INSTITUTION_ID", "TEST_INST")
	t.Setenv("BANK_SALT", "test_salt_32_characters_minimum_x")
	config.Reload()
	t.Cleanup(func() { config.Reload() })
}

func TestForwardToHub_SignsPayload(t *testing.T) {
	var gotAuth, gotSig string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotSig = r.Header.Get("X-Intel-Signature")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		gotBody = buf
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	setupHubEnv(t, srv.URL)

	if err := ForwardToHub(context.Background(), map[string]string{"k": "v"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer test-api-key" {
		t.Errorf("wrong Authorization header: %q", gotAuth)
	}
	if want := SignPayload(gotBody, "test-hmac-secret"); gotSig != want {
		t.Errorf("signature mismatch: got %q want %q", gotSig, want)
	}
}

func TestForwardPayload_NoDestinationIsPermanentError(t *testing.T) {
	// No hardcoded fallback destination: if nothing configured a Hub/vendor
	// URL, ForwardPayload must fail loudly and permanently rather than
	// silently posting to a placeholder host.
	setupHubEnv(t, "")

	err := ForwardPayload(context.Background(), []byte(`{}`))
	if err == nil {
		t.Fatal("expected an error when no destination is configured")
	}
	if !IsPermanent(err) {
		t.Errorf("expected a permanent (non-retryable) error, got: %v", err)
	}
}

func TestForwardToHubWithRetry_RetriesServerErrors(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setupHubEnv(t, srv.URL)

	if err := ForwardToHubWithRetry(context.Background(), map[string]string{"k": "v"}, 2); err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if n := atomic.LoadInt32(&attempts); n != 3 {
		t.Errorf("expected 3 attempts, got %d", n)
	}
}

func TestForwardToHubWithRetry_NoRetryOnClientError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		http.Error(w, "bad api key", http.StatusUnauthorized)
	}))
	defer srv.Close()
	setupHubEnv(t, srv.URL)

	err := ForwardToHubWithRetry(context.Background(), map[string]string{"k": "v"}, 2)
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status: %v", err)
	}
	if n := atomic.LoadInt32(&attempts); n != 1 {
		t.Errorf("4xx must not be retried: expected 1 attempt, got %d", n)
	}
}

func TestForwardToHubWithRetry_ContextCancelStopsRetries(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	setupHubEnv(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ForwardToHubWithRetry(ctx, map[string]string{"k": "v"}, 2)
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
	if n := atomic.LoadInt32(&attempts); n > 1 {
		t.Errorf("cancelled context should stop retries: got %d attempts", n)
	}
}

// TestForwardPayloadWithRetry_SendsIdenticalBytesOnEveryAttempt is
// ForwardPayloadWithRetry's key property over ForwardToHubWithRetry: since
// it never re-marshals, every attempt (including retries) must transmit
// byte-for-byte the same payload it was given, not merely a
// deterministic-so-far re-encoding of some other value.
func TestForwardPayloadWithRetry_SendsIdenticalBytesOnEveryAttempt(t *testing.T) {
	var attempts int32
	var mu sync.Mutex
	var gotBodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		mu.Lock()
		gotBodies = append(gotBodies, body)
		mu.Unlock()
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setupHubEnv(t, srv.URL)

	payload := []byte(`{"signal_id":"sig-retry-bytes","mosaic_version":2}`)
	if err := ForwardPayloadWithRetry(context.Background(), payload, 2); err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotBodies) != 3 {
		t.Fatalf("expected 3 attempts, got %d", len(gotBodies))
	}
	for i, body := range gotBodies {
		if string(body) != string(payload) {
			t.Errorf("attempt %d sent %q, want %q (bytes must be identical across every retry)", i, body, payload)
		}
	}
}

func TestForwardPayloadWithRetry_NoRetryOnClientError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		http.Error(w, "bad api key", http.StatusUnauthorized)
	}))
	defer srv.Close()
	setupHubEnv(t, srv.URL)

	err := ForwardPayloadWithRetry(context.Background(), []byte(`{}`), 2)
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if !IsPermanent(err) {
		t.Errorf("expected a permanent (non-retryable) error, got: %v", err)
	}
	if n := atomic.LoadInt32(&attempts); n != 1 {
		t.Errorf("4xx must not be retried: expected 1 attempt, got %d", n)
	}
}

func TestForwardPayloadWithRetry_ContextCancelStopsRetries(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	setupHubEnv(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ForwardPayloadWithRetry(ctx, []byte(`{}`), 2)
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
	if n := atomic.LoadInt32(&attempts); n > 1 {
		t.Errorf("cancelled context should stop retries: got %d attempts", n)
	}
}
