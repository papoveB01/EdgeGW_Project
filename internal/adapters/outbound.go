package adapters

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/config"
)

// SignPayload creates HMAC-SHA256 signature of the payload.
func SignPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// ForwardToHub sends anonymized signal to IntelFraud Hub. Single attempt.
func ForwardToHub(signal interface{}) error {
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
		return fmt.Errorf("hub.api_key / API_KEY not set")
	}

	hmacSecret := os.Getenv("HMAC_SECRET")
	if hmacSecret == "" {
		return fmt.Errorf("HMAC_SECRET environment variable not set")
	}

	payload, err := json.Marshal(signal)
	if err != nil {
		return fmt.Errorf("failed to marshal signal: %w", err)
	}

	signature := SignPayload(payload, hmacSecret)

	req, err := http.NewRequest("POST", hubURL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Intel-Signature", signature)

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes := make([]byte, 1024)
	n, _ := resp.Body.Read(bodyBytes)
	responseBody := string(bodyBytes[:n])

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("hub returned status %d: %s", resp.StatusCode, responseBody)
	}

	return nil
}

// ForwardToHubWithRetry sends with exponential backoff retry.
func ForwardToHubWithRetry(signal interface{}, maxRetries int) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			slog.Warn("Retrying hub forward", "attempt", attempt, "backoff", backoff.String())
			time.Sleep(backoff)
		}
		lastErr = ForwardToHub(signal)
		if lastErr == nil {
			if attempt > 0 {
				slog.Info("Hub forward succeeded after retry", "attempt", attempt)
			}
			RecordMetric("signals_forwarded", 1)
			return nil
		}
		slog.Warn("Hub forward failed", "attempt", attempt, "error", lastErr)
	}
	return fmt.Errorf("all %d attempts failed: %w", maxRetries+1, lastErr)
}
