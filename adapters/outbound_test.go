package adapters

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"edge-gateway/config"
)

func TestSignPayload(t *testing.T) {
	// Known HMAC-SHA256
	payload := []byte("test-payload")
	secret := "test-secret"

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))

	got := SignPayload(payload, secret)
	if got != expected {
		t.Errorf("SignPayload = %s, want %s", got, expected)
	}

	// Deterministic
	got2 := SignPayload(payload, secret)
	if got != got2 {
		t.Error("SignPayload is not deterministic")
	}

	// Different secret produces different signature
	got3 := SignPayload(payload, "other-secret")
	if got == got3 {
		t.Error("Different secrets should produce different signatures")
	}

	// Empty payload works
	empty := SignPayload([]byte(""), secret)
	if empty == "" {
		t.Error("SignPayload returned empty for empty payload")
	}
	if empty == got {
		t.Error("Empty payload should differ from non-empty")
	}
}

func setupTestConfig(t *testing.T, hubURL string) {
	t.Helper()
	config.ResetForTest()
	os.Setenv("INSTITUTION_ID", "TEST_INST")
	os.Setenv("API_KEY", "test-api-key")
	os.Setenv("HUB_API_URL", hubURL)
	os.Setenv("BANK_SALT", "test-salt")
	os.Setenv("CONFIG_PATH", "/dev/null") // prevent loading any config file
	t.Cleanup(func() {
		os.Unsetenv("INSTITUTION_ID")
		os.Unsetenv("API_KEY")
		os.Unsetenv("HUB_API_URL")
		os.Unsetenv("BANK_SALT")
		os.Unsetenv("CONFIG_PATH")
		config.ResetForTest()
	})
}

func TestForwardToHub(t *testing.T) {
	t.Run("successful forward", func(t *testing.T) {
		var receivedHeaders http.Header
		var receivedBody []byte

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			receivedBody = buf[:n]
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		setupTestConfig(t, server.URL)
		os.Setenv("HMAC_SECRET", "test-hmac-secret")
		t.Cleanup(func() { os.Unsetenv("HMAC_SECRET") })

		signal := map[string]string{"test": "data"}
		err := ForwardToHub(signal)
		if err != nil {
			t.Fatalf("ForwardToHub returned error: %v", err)
		}

		// Verify headers
		if receivedHeaders.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", receivedHeaders.Get("Content-Type"))
		}
		if receivedHeaders.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("Authorization = %s, want Bearer test-api-key", receivedHeaders.Get("Authorization"))
		}
		if receivedHeaders.Get("X-Intel-Signature") == "" {
			t.Error("X-Intel-Signature header is missing")
		}

		// Verify signature is correct
		expectedSig := SignPayload(receivedBody, "test-hmac-secret")
		if receivedHeaders.Get("X-Intel-Signature") != expectedSig {
			t.Error("X-Intel-Signature does not match expected HMAC")
		}
	})

	t.Run("retry on 500", func(t *testing.T) {
		var attempts int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := atomic.AddInt32(&attempts, 1)
			if count <= 2 {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"temporary"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		setupTestConfig(t, server.URL)
		os.Setenv("HMAC_SECRET", "test-hmac-secret")
		t.Cleanup(func() { os.Unsetenv("HMAC_SECRET") })

		err := ForwardToHub(map[string]string{"retry": "test"})
		if err != nil {
			t.Fatalf("ForwardToHub should succeed after retries, got: %v", err)
		}
		if atomic.LoadInt32(&attempts) != 3 {
			t.Errorf("Expected 3 attempts, got %d", atomic.LoadInt32(&attempts))
		}
	})

	t.Run("fail after max retries", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"permanent"}`))
		}))
		defer server.Close()

		setupTestConfig(t, server.URL)
		os.Setenv("HMAC_SECRET", "test-hmac-secret")
		t.Cleanup(func() { os.Unsetenv("HMAC_SECRET") })

		err := ForwardToHub(map[string]string{"fail": "test"})
		if err == nil {
			t.Fatal("ForwardToHub should fail after max retries")
		}
	})

	t.Run("missing HMAC_SECRET", func(t *testing.T) {
		os.Unsetenv("HMAC_SECRET")
		setupTestConfig(t, "http://localhost:9999")

		err := ForwardToHub(map[string]string{"test": "data"})
		if err == nil {
			t.Fatal("ForwardToHub should fail without HMAC_SECRET")
		}
	})
}
