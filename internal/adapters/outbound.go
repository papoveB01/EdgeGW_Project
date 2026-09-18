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

// IsPermanent reports whether a forward error will not succeed on retry
// (4xx from the Hub, config problems).
func IsPermanent(err error) bool {
	var perm *permanentError
	return errors.As(err, &perm)
}

// ForwardToHub sends an anonymized signal to the IntelFraud Hub. Single attempt.
func ForwardToHub(ctx context.Context, signal interface{}) error {
	payload, err := json.Marshal(signal)
	if err != nil {
		return &permanentError{fmt.Errorf("failed to marshal signal: %w", err)}
	}
	return ForwardPayload(ctx, payload)
}

// ForwardPayload sends a pre-marshaled signal payload to the Hub. Single attempt.
//
// No placeholder/fallback destination: config.Get already applies HUB_API_URL
// on top of the config file (env overrides file), so re-reading the env var
// here would be redundant, and a hardcoded host would silently resurrect the
// exact bug class this package's caller (main.go's validateStartup) exists to
// eliminate - a gateway with no real destination posting to a fake one
// instead of failing loudly. If nothing configured a destination, that is a
// caller bug (this mode should never have gotten this far), so it is a
// permanent, non-retryable error rather than a fallback URL.
func ForwardPayload(ctx context.Context, payload []byte) error {
	cfg := config.Get()
	hubURL := cfg.Hub.HubEndpointURL
	if hubURL == "" {
		return &permanentError{fmt.Errorf("no Hub/vendor destination configured (hub.hub_endpoint_url / HUB_API_URL not set)")}
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
	return forwardWithRetry(ctx, maxRetries, func(ctx context.Context) error {
		return ForwardToHub(ctx, signal)
	})
}

// ForwardPayloadWithRetry is ForwardToHubWithRetry's counterpart for an
// already-marshaled payload: the same bounded exponential-backoff retry,
// but without marshaling per attempt - every attempt sends the exact same
// bytes, guaranteed by construction rather than by signal being immutable
// between attempts. This matters for callers (cmd/gateway's synchronous
// egress-audit path) that need "the bytes we hash for a compliance record"
// and "the bytes we actually transmitted" to be the same bytes
// structurally, not just incidentally so long as nothing mutates signal in
// between marshals.
func ForwardPayloadWithRetry(ctx context.Context, payload []byte, maxRetries int) error {
	return forwardWithRetry(ctx, maxRetries, func(ctx context.Context) error {
		return ForwardPayload(ctx, payload)
	})
}

// forwardWithRetry runs attempt with the same bounded exponential backoff
// (250ms, 500ms, ...) ForwardToHubWithRetry has always used, stopping early
// on context cancellation or a permanent error, and recording
// signals_forwarded on eventual success. Shared by ForwardToHubWithRetry
// and ForwardPayloadWithRetry, which differ only in what "one attempt"
// means (marshal-then-send a signal, or send already-marshaled bytes).
func forwardWithRetry(ctx context.Context, maxRetries int, attempt func(ctx context.Context) error) error {
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			backoff := time.Duration(250<<uint(i-1)) * time.Millisecond
			slog.Warn("Retrying hub forward", "attempt", i, "backoff", backoff.String())
			select {
			case <-ctx.Done():
				return fmt.Errorf("cancelled before retry %d: %w", i, ctx.Err())
			case <-time.After(backoff):
			}
		}
		lastErr = attempt(ctx)
		if lastErr == nil {
			if i > 0 {
				slog.Info("Hub forward succeeded after retry", "attempt", i)
			}
			RecordMetric("signals_forwarded", 1)
			return nil
		}
		if IsPermanent(lastErr) {
			slog.Warn("Hub forward failed permanently, not retrying", "error", lastErr)
			return lastErr
		}
		slog.Warn("Hub forward failed", "attempt", i, "error", lastErr)
	}
	return fmt.Errorf("all %d attempts failed: %w", maxRetries+1, lastErr)
}
