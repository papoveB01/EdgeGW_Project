package adapters

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"edge-gateway/config"
)

const (
	maxRetries     = 3
	initialBackoff = 500 * time.Millisecond
	maxBackoff     = 4 * time.Second
)

// hubClient is a shared HTTP client for connection pooling.
var hubClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// SignPayload creates HMAC-SHA256 signature of the payload
func SignPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// ForwardToHub sends anonymized signal to IntelFraud Hub using config (Hub params from Hub UI).
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
		return fmt.Errorf("HMAC_SECRET environment variable not set (set by bank from Hub onboarding)")
	}

	// Marshal signal to JSON
	payload, err := json.Marshal(signal)
	if err != nil {
		return fmt.Errorf("failed to marshal signal: %w", err)
	}

	// Sign the payload
	signature := SignPayload(payload, hmacSecret)

	// Create HTTP request
	req, err := http.NewRequest("POST", hubURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Intel-Signature", signature)

	log.Printf("Sending request to hub: %s", hubURL)
	log.Printf("Payload size: %d bytes", len(payload))

	// Send with retry
	resp, err := forwardWithRetry(req, payload, maxRetries)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	log.Printf("Hub responded with status: %d", resp.StatusCode)

	// Read response body for debugging
	bodyBytes := make([]byte, 1024)
	n, _ := resp.Body.Read(bodyBytes)
	responseBody := string(bodyBytes[:n])

	if responseBody != "" {
		truncLen := len(responseBody)
		if truncLen > 200 {
			truncLen = 200
		}
		log.Printf("Hub response: %s", responseBody[:truncLen])
	}

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("hub returned status %d: %s", resp.StatusCode, responseBody)
	}

	return nil
}

// forwardWithRetry sends the request with exponential backoff on transient failures.
func forwardWithRetry(req *http.Request, payload []byte, retries int) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			backoff := initialBackoff * (1 << uint(attempt-1))
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			log.Printf("Hub request retry %d/%d after %v...", attempt, retries, backoff)
			time.Sleep(backoff)

			// Reset the body for retry
			req.Body = io.NopCloser(bytes.NewReader(payload))
		}

		resp, err := hubClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			log.Printf("Hub request attempt %d/%d failed: %v", attempt+1, retries+1, err)
			continue
		}

		// Retry on 5xx server errors
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("hub returned status %d", resp.StatusCode)
			log.Printf("Hub request attempt %d/%d got %d, retrying...", attempt+1, retries+1, resp.StatusCode)
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("hub request failed after %d attempts: %w", retries+1, lastErr)
}
