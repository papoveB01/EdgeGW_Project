package adapters

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProcessInboundRequest_Valid(t *testing.T) {
	body := `{"id":"CUST-1","name":"Jane Doe","account":"ACC-1","amount":250.5,
		"latitude":6.4541,"longitude":3.3947,"timestamp":"2026-01-15T14:07:33Z"}`
	req := httptest.NewRequest("POST", "/process", strings.NewReader(body))

	raw, err := ProcessInboundRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw.ID != "CUST-1" || raw.Amount != 250.5 {
		t.Errorf("unexpected decode: %+v", raw)
	}
}

func TestProcessInboundRequest_Rejects(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"not json", `hello`},
		{"missing id", `{"name":"J","account":"A","amount":1,"timestamp":"2026-01-15T14:07:33Z"}`},
		{"null id", `{"id":null,"name":"J","account":"A","amount":1,"timestamp":"2026-01-15T14:07:33Z"}`},
		{"empty id", `{"id":"","name":"J","account":"A","amount":1,"timestamp":"2026-01-15T14:07:33Z"}`},
		{"null amount", `{"id":"C","name":"J","account":"A","amount":null,"timestamp":"2026-01-15T14:07:33Z"}`},
		{"string amount", `{"id":"C","name":"J","account":"A","amount":"lots","timestamp":"2026-01-15T14:07:33Z"}`},
		{"bad timestamp", `{"id":"C","name":"J","account":"A","amount":1,"timestamp":"01/15/2026"}`},
		{"lat without lon", `{"id":"C","name":"J","account":"A","amount":1,"latitude":6.4,"timestamp":"2026-01-15T14:07:33Z"}`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("POST", "/process", strings.NewReader(tc.body))
		if _, err := ProcessInboundRequest(req); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

// resetHealthState restores HealthCheckHandler's package-level state to its
// defaults so tests don't leak configuration into each other.
func resetHealthState(t *testing.T) {
	t.Helper()
	SetHealthSpoolStatus(nil)
	SetHealthThresholds(DefaultHealthMaxDepthRatio, DefaultHealthMaxStaleness)
}

func doHealthCheck(t *testing.T) (*http.Response, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	HealthCheckHandler(w, req)
	resp := w.Result()
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	return resp, body
}

func TestHealthCheckHandler_HealthyWithoutSpool(t *testing.T) {
	resetHealthState(t)
	defer resetHealthState(t)

	resp, body := doHealthCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
}

func TestHealthCheckHandler_HealthyWithSpoolWithinThresholds(t *testing.T) {
	resetHealthState(t)
	defer resetHealthState(t)

	SetHealthSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 5, MaxDepth: 1000, OldestPendingAge: 2 * time.Minute, HasPending: true}
	})

	resp, body := doHealthCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
	if body["spool_depth"].(float64) != 5 {
		t.Errorf("spool_depth = %v, want 5", body["spool_depth"])
	}
}

func TestHealthCheckHandler_UnhealthyWhenSpoolNearCapacity(t *testing.T) {
	resetHealthState(t)
	defer resetHealthState(t)

	SetHealthSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 960, MaxDepth: 1000, OldestPendingAge: time.Second, HasPending: true}
	})

	resp, body := doHealthCheck(t)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", resp.StatusCode)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("status = %v, want unhealthy", body["status"])
	}
	if body["reasons"] == nil {
		t.Error("expected reasons to explain why the gateway is unhealthy")
	}
}

func TestHealthCheckHandler_UnhealthyWhenStale(t *testing.T) {
	resetHealthState(t)
	defer resetHealthState(t)

	SetHealthSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 3, MaxDepth: 1000, OldestPendingAge: time.Hour, HasPending: true}
	})

	resp, body := doHealthCheck(t)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", resp.StatusCode)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("status = %v, want unhealthy", body["status"])
	}
}

func TestHealthCheckHandler_ThresholdsAreConfigurable(t *testing.T) {
	resetHealthState(t)
	defer resetHealthState(t)

	// A depth that would be fine under the default 95% ratio but breaches a
	// tighter, explicitly configured 50% ratio.
	SetHealthThresholds(0.5, DefaultHealthMaxStaleness)
	SetHealthSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 600, MaxDepth: 1000, OldestPendingAge: time.Second, HasPending: true}
	})

	resp, body := doHealthCheck(t)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", resp.StatusCode)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("status = %v, want unhealthy", body["status"])
	}
}

func TestHealthCheckHandler_NoPendingSkipsStalenessCheck(t *testing.T) {
	resetHealthState(t)
	defer resetHealthState(t)

	SetHealthSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 0, MaxDepth: 1000, HasPending: false}
	})

	resp, body := doHealthCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
	if _, present := body["oldest_pending_seconds"]; present {
		t.Error("oldest_pending_seconds should be omitted when there is nothing pending")
	}
}

// TestMetricsHandler_DeliveryFreshness exercises the metrics that let an
// operator tell a healthy feed from one that has gone quiet: RecordDelivery
// should make /metrics report a fresh (near-zero) seconds_since_last_delivery
// and a delivery latency average derived from the recorded queue times.
func TestMetricsHandler_DeliveryFreshness(t *testing.T) {
	RecordDelivery(200 * time.Millisecond)
	RecordDelivery(600 * time.Millisecond)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	MetricsHandler(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode metrics response: %v", err)
	}

	sinceRaw, ok := body["seconds_since_last_delivery"]
	if !ok || sinceRaw == nil {
		t.Fatal("expected seconds_since_last_delivery to be set after a delivery")
	}
	since := sinceRaw.(float64)
	if since < 0 || since > 5 {
		t.Errorf("seconds_since_last_delivery = %v, want a small non-negative value", since)
	}

	avgRaw, ok := body["delivery_latency_ms_avg"]
	if !ok {
		t.Fatal("expected delivery_latency_ms_avg to be present")
	}
	avg := avgRaw.(float64)
	if avg != 400 {
		t.Errorf("delivery_latency_ms_avg = %v, want 400 (avg of 200ms and 600ms)", avg)
	}
}
