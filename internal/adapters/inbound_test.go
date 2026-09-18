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

// resetReadinessState restores ReadinessCheckHandler's package-level state
// to its defaults so tests don't leak configuration into each other.
func resetReadinessState(t *testing.T) {
	t.Helper()
	SetReadinessSpoolStatus(nil)
	SetReadinessThresholds(DefaultReadinessMaxDepthRatio, DefaultReadinessMaxStaleness)
}

func doLivenessCheck(t *testing.T) (*http.Response, map[string]interface{}) {
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

func doReadinessCheck(t *testing.T) (*http.Response, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	ReadinessCheckHandler(w, req)
	resp := w.Result()
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode readiness response: %v", err)
	}
	return resp, body
}

// TestHealthCheckHandler_AlwaysHealthyRegardlessOfSpoolState pins /health as
// a pure liveness check: it must return 200 no matter how degraded a
// registered spool is, because restarting the process can't fix a backlog
// (it survives on the spool volume) or a downed vendor, and would only add
// a self-inflicted /process outage. This is a regression guard against
// re-coupling liveness and degradation on this handler.
func TestHealthCheckHandler_AlwaysHealthyRegardlessOfSpoolState(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	// Register a spool state that would make ReadinessCheckHandler report
	// unhealthy (near capacity AND stale) to prove HealthCheckHandler
	// ignores it entirely.
	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 999, MaxDepth: 1000, OldestPendingAge: 24 * time.Hour, HasPending: true}
	})

	resp, body := doLivenessCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200 (liveness must not 503 on spool state)", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
	if _, present := body["spool_depth"]; present {
		t.Error("liveness response should not carry spool details")
	}
}

func TestHealthCheckHandler_HealthyWithoutSpool(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	resp, body := doLivenessCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
}

func TestReadinessCheckHandler_HealthyWithoutSpool(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
}

func TestReadinessCheckHandler_HealthyWithSpoolWithinThresholds(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 5, MaxDepth: 1000, OldestPendingAge: 2 * time.Minute, HasPending: true}
	})

	resp, body := doReadinessCheck(t)
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

func TestReadinessCheckHandler_UnhealthyWhenSpoolNearCapacity(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 960, MaxDepth: 1000, OldestPendingAge: time.Second, HasPending: true}
	})

	resp, body := doReadinessCheck(t)
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

func TestReadinessCheckHandler_UnhealthyWhenStale(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 3, MaxDepth: 1000, OldestPendingAge: time.Hour, HasPending: true}
	})

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", resp.StatusCode)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("status = %v, want unhealthy", body["status"])
	}
}

func TestReadinessCheckHandler_ThresholdsAreConfigurable(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	// A depth that would be fine under the default 95% ratio but breaches a
	// tighter, explicitly configured 50% ratio.
	SetReadinessThresholds(0.5, DefaultReadinessMaxStaleness)
	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 600, MaxDepth: 1000, OldestPendingAge: time.Second, HasPending: true}
	})

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", resp.StatusCode)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("status = %v, want unhealthy", body["status"])
	}
}

func TestReadinessCheckHandler_NoPendingSkipsStalenessCheck(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 0, MaxDepth: 1000, HasPending: false}
	})

	resp, body := doReadinessCheck(t)
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

	avgRaw, ok := body["delivery_latency_ms_lifetime_avg"]
	if !ok {
		t.Fatal("expected delivery_latency_ms_lifetime_avg to be present")
	}
	if _, ok := body["delivery_latency_ms_ewma"]; !ok {
		t.Fatal("expected delivery_latency_ms_ewma to be present")
	}
	_ = avgRaw // exact value depends on other tests' cumulative deliveries; see the dedicated EWMA test below.
}

// TestMetricsHandler_DeliveryLatencyEWMAReactsFasterThanLifetimeAverage
// demonstrates why delivery_latency_ms_ewma exists: delivery_latency_ms_
// lifetime_avg is a cumulative average that a long history of fast
// deliveries can permanently dilute, so a fresh incident barely moves it —
// defeating early detection of degradation. The EWMA must react strongly to
// a recent spike instead.
func TestMetricsHandler_DeliveryLatencyEWMAReactsFasterThanLifetimeAverage(t *testing.T) {
	// A long run of fast deliveries, standing in for hours of healthy
	// operation that would otherwise swamp a cumulative average.
	for i := 0; i < 50; i++ {
		RecordDelivery(10 * time.Millisecond)
	}
	// A sudden incident: one much slower delivery.
	RecordDelivery(2000 * time.Millisecond)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	MetricsHandler(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode metrics response: %v", err)
	}

	ewma := body["delivery_latency_ms_ewma"].(float64)
	lifetimeAvg := body["delivery_latency_ms_lifetime_avg"].(float64)

	if ewma < 200 {
		t.Errorf("delivery_latency_ms_ewma = %v, want it to react strongly to the recent 2000ms spike", ewma)
	}
	if ewma <= lifetimeAvg {
		t.Errorf("expected the EWMA (%v) to sit well above the lifetime average (%v) right after a spike, "+
			"otherwise the EWMA isn't adding early-detection value over the cumulative average", ewma, lifetimeAvg)
	}
}
