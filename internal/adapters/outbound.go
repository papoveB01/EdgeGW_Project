package adapters

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/config"
)

// hubClient is shared so connections to the Hub are pooled and reused.
// The per-attempt timeout is kept small so the full retry budget
// (attempts + backoff) fits inside the server's 10s WriteTimeout.
var hubClient = &http.Client{Timeout: 2500 * time.Millisecond}

// permanentError marks failures that will not succeed on retry (e.g. 4xx from the Hub).
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// SignPayload creates HMAC-SHA256 signature of the payload.
func SignPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// ForwardToHub sends anonymized signal to IntelFraud Hub. Single attempt.
func ForwardToHub(ctx context.Context, signal interface{}) error {
	cfg := config.Get()
	hubURL := cfg.Hub.HubEndpointURL
	if hubURL == "" {
		hubURL = os.Getenv("HUB_API_URL")
	}
	if hubURL == "" {
		hubURL = "http://intel-api:8000/api/v1/signals"
	}

	apiKey := cfg.Hub.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("API_KEY")
	}
	if apiKey == "" {
		return &permanentError{fmt.Errorf("hub.api_key / API_KEY not set")}
	}

	hmacSecret := os.Getenv("HMAC_SECRET")
	if hmacSecret == "" {
		return &permanentError{fmt.Errorf("HMAC_SECRET environment variable not set")}
	}

	payload, err := json.Marshal(signal)
	if err != nil {
		return &permanentError{fmt.Errorf("failed to marshal signal: %w", err)}
	}

	signature := SignPayload(payload, hmacSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hubURL, bytes.NewReader(payload))
	if err != nil {
		return &permanentError{fmt.Errorf("failed to create request: %w", err)}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Intel-Signature", signature)

	resp, err := hubClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	responseBody := string(bodyBytes)

	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests:
		// Client errors (bad key, bad payload) won't heal on retry.
		return &permanentError{fmt.Errorf("hub returned status %d: %s", resp.StatusCode, responseBody)}
	default:
		return fmt.Errorf("hub returned status %d: %s", resp.StatusCode, responseBody)
	}
}

// ForwardToHubWithRetry sends with exponential backoff retry. Permanent errors
// (4xx, config problems) fail immediately; retries stop if ctx is cancelled.
// Worst case with maxRetries=2: 3 x 2.5s attempts + 0.25s + 0.5s backoff = 8.25s,
// inside the server's 10s WriteTimeout.
func ForwardToHubWithRetry(ctx context.Context, signal interface{}, maxRetries int) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(250<<uint(attempt-1)) * time.Millisecond
			slog.Warn("Retrying hub forward", "attempt", attempt, "backoff", backoff.String())
			select {
			case <-ctx.Done():
				return fmt.Errorf("cancelled before retry %d: %w", attempt, ctx.Err())
			case <-time.After(backoff):
			}
		}
		lastErr = ForwardToHub(ctx, signal)
		if lastErr == nil {
			if attempt > 0 {
				slog.Info("Hub forward succeeded after retry", "attempt", attempt)
			}
			RecordMetric("signals_forwarded", 1)
			return nil
		}
		var perm *permanentError
		if errors.As(lastErr, &perm) {
			slog.Warn("Hub forward failed permanently, not retrying", "error", lastErr)
			return lastErr
		}
		slog.Warn("Hub forward failed", "attempt", attempt, "error", lastErr)
	}
	return fmt.Errorf("all %d attempts failed: %w", maxRetries+1, lastErr)
}
