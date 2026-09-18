package adapters

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	SetReadinessAuditStatus(nil)
	SetReadinessThresholds(DefaultReadinessMaxDepthRatio, DefaultReadinessMaxStaleness)
	SetReadinessMaxAuditFailures(DefaultReadinessMaxAuditFailures)
	SetReadinessMaxSpoolFsyncFailures(DefaultReadinessMaxSpoolFsyncFailures)
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

// TestHealthCheckHandler_AlwaysHealthyRegardlessOfAuditStatus mirrors
// TestHealthCheckHandler_AlwaysHealthyRegardlessOfSpoolState for the audit
// status: a stuck egress audit log is a DEGRADED condition (see
// AuditStatus's doc comment), never something a restart can fix, so
// liveness must ignore it just as it ignores spool state.
func TestHealthCheckHandler_AlwaysHealthyRegardlessOfAuditStatus(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	SetReadinessAuditStatus(func() AuditStatus {
		return AuditStatus{ConsecutiveFailures: 999}
	})

	resp, body := doLivenessCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200 (liveness must not 503 on audit status)", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
}

// TestReadinessCheckHandler_HealthyWithoutAuditStatus checks the default
// (no EGRESS_AUDIT_DIR configured, SetReadinessAuditStatus never called)
// doesn't make /readyz consider audit health at all.
func TestReadinessCheckHandler_HealthyWithoutAuditStatus(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
	if _, present := body["audit_consecutive_failures"]; present {
		t.Error("audit_consecutive_failures should be omitted when no audit status is registered")
	}
}

// TestReadinessCheckHandler_HealthyWithAuditFailuresBelowThreshold and
// TestReadinessCheckHandler_UnhealthyWhenAuditFailuresCrossThreshold pin the
// CHANGE 2 wiring: an egress-audit-log stuck for DefaultReadinessMaxAuditFailures
// consecutive writes must flip /readyz unhealthy with a distinct reason,
// the same way spool depth/staleness do - this is synchronous mode's only
// automatic degradation signal (see AuditStatus's doc comment).
func TestReadinessCheckHandler_HealthyWithAuditFailuresBelowThreshold(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	SetReadinessAuditStatus(func() AuditStatus {
		return AuditStatus{ConsecutiveFailures: DefaultReadinessMaxAuditFailures - 1}
	})

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
	if got := body["audit_consecutive_failures"].(float64); got != float64(DefaultReadinessMaxAuditFailures-1) {
		t.Errorf("audit_consecutive_failures = %v, want %d", got, DefaultReadinessMaxAuditFailures-1)
	}
}

func TestReadinessCheckHandler_UnhealthyWhenAuditFailuresCrossThreshold(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	SetReadinessAuditStatus(func() AuditStatus {
		return AuditStatus{ConsecutiveFailures: DefaultReadinessMaxAuditFailures}
	})

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", resp.StatusCode)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("status = %v, want unhealthy", body["status"])
	}
	reasons, ok := body["reasons"].([]interface{})
	if !ok || len(reasons) == 0 {
		t.Fatal("expected reasons to explain why the gateway is unhealthy")
	}
	found := false
	for _, r := range reasons {
		if s, _ := r.(string); s != "" && (s == "egress audit log has failed to write for too many consecutive deliveries") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a reason naming the stuck egress audit log, got %v", reasons)
	}
}

// TestReadinessCheckHandler_AuditThresholdIsConfigurable mirrors
// TestReadinessCheckHandler_ThresholdsAreConfigurable for the audit
// threshold.
func TestReadinessCheckHandler_AuditThresholdIsConfigurable(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	// 2 consecutive failures would be fine under the default threshold (3)
	// but breaches a tighter, explicitly configured threshold of 1.
	SetReadinessMaxAuditFailures(1)
	SetReadinessAuditStatus(func() AuditStatus {
		return AuditStatus{ConsecutiveFailures: 2}
	})

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", resp.StatusCode)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("status = %v, want unhealthy", body["status"])
	}
}

// TestReadinessCheckHandler_HealthyWithSpoolDirFsyncFailuresBelowThreshold
// and TestReadinessCheckHandler_UnhealthyWhenSpoolDirFsyncFailuresCrossThreshold
// pin the issue #15 wiring: a spool whose consecutive post-rename
// directory-fsync failures (spool.Spool.DirFsyncFailures(), surfaced via
// SpoolStatus.ConsecutiveDirFsyncFailures) cross
// DefaultReadinessMaxSpoolFsyncFailures must flip /readyz unhealthy with a
// distinct reason, the same way spool depth/staleness and the audit log's
// consecutive-failure count do - this is what turns a persistent
// directory-fsync failure into an alertable degraded state instead of a
// silent, unbounded stream of Enqueue/processTransaction 500s.
func TestReadinessCheckHandler_HealthyWithSpoolDirFsyncFailuresBelowThreshold(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{
			Depth: 1, MaxDepth: 1000, HasPending: false,
			ConsecutiveDirFsyncFailures: DefaultReadinessMaxSpoolFsyncFailures - 1,
		}
	})

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
	got, ok := body["spool_dir_fsync_consecutive_failures"].(float64)
	if !ok {
		t.Fatal("expected spool_dir_fsync_consecutive_failures to be reported when a spool status is registered")
	}
	if got != float64(DefaultReadinessMaxSpoolFsyncFailures-1) {
		t.Errorf("spool_dir_fsync_consecutive_failures = %v, want %d", got, DefaultReadinessMaxSpoolFsyncFailures-1)
	}
}

func TestReadinessCheckHandler_UnhealthyWhenSpoolDirFsyncFailuresCrossThreshold(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{
			Depth: 1, MaxDepth: 1000, HasPending: false,
			ConsecutiveDirFsyncFailures: DefaultReadinessMaxSpoolFsyncFailures,
		}
	})

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", resp.StatusCode)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("status = %v, want unhealthy", body["status"])
	}
	reasons, ok := body["reasons"].([]interface{})
	if !ok || len(reasons) == 0 {
		t.Fatal("expected reasons to explain why the gateway is unhealthy")
	}
	found := false
	for _, r := range reasons {
		if s, _ := r.(string); s == "spool directory fsync has failed for too many consecutive enqueues" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a reason naming the persistent spool directory-fsync failure, got %v", reasons)
	}
}

// TestReadinessCheckHandler_SpoolDirFsyncFailuresRecoverWhenCounterResets
// checks recovery: once the registered SpoolStatus reports the counter
// back at 0 (mirroring spool.Spool.DirFsyncFailures() resetting on the
// next successful directory fsync - see internal/spool's
// TestEnqueue_DirFsyncFailuresResetsOnSuccess), /readyz must go back to
// healthy, not stay latched unhealthy from a prior scrape.
func TestReadinessCheckHandler_SpoolDirFsyncFailuresRecoverWhenCounterResets(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	failures := DefaultReadinessMaxSpoolFsyncFailures
	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 1, MaxDepth: 1000, HasPending: false, ConsecutiveDirFsyncFailures: failures}
	})
	if resp, _ := doReadinessCheck(t); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want 503 before recovery", resp.StatusCode)
	}

	failures = 0
	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200 after the counter resets", resp.StatusCode)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy after the counter resets", body["status"])
	}
}

// TestReadinessCheckHandler_SpoolDirFsyncFailuresThresholdIsConfigurable
// mirrors TestReadinessCheckHandler_AuditThresholdIsConfigurable for
// READINESS_MAX_SPOOL_FSYNC_FAILURES.
func TestReadinessCheckHandler_SpoolDirFsyncFailuresThresholdIsConfigurable(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	// 2 consecutive failures would be fine under the default threshold (3)
	// but breaches a tighter, explicitly configured threshold of 1.
	SetReadinessMaxSpoolFsyncFailures(1)
	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 1, MaxDepth: 1000, HasPending: false, ConsecutiveDirFsyncFailures: 2}
	})

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", resp.StatusCode)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("status = %v, want unhealthy", body["status"])
	}
}

// TestReadinessCheckHandler_AuditAndSpoolStatusAreIndependent checks the two
// signals don't interfere: a perfectly healthy spool alongside a stuck
// audit log must still report unhealthy (for the audit reason), and vice
// versa.
func TestReadinessCheckHandler_AuditAndSpoolStatusAreIndependent(t *testing.T) {
	resetReadinessState(t)
	defer resetReadinessState(t)

	SetReadinessSpoolStatus(func() SpoolStatus {
		return SpoolStatus{Depth: 1, MaxDepth: 1000, OldestPendingAge: time.Second, HasPending: true}
	})
	SetReadinessAuditStatus(func() AuditStatus {
		return AuditStatus{ConsecutiveFailures: DefaultReadinessMaxAuditFailures}
	})

	resp, body := doReadinessCheck(t)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503 (audit alone should be enough to flip unhealthy)", resp.StatusCode)
	}
	if body["spool_depth"].(float64) != 1 {
		t.Errorf("expected healthy spool state to still be reported, got spool_depth=%v", body["spool_depth"])
	}
}

// TestMetricsHandler_SpoolDirFsyncFailuresCounter pins the issue #15
// /metrics wiring: main.go's spool.Hooks.OnDirFsyncFailure records a
// spool_dir_fsync_failures counter (via RecordMetric) on every consecutive
// directory-fsync failure, mirroring how audit_write_failures is recorded.
// RecordMetric/MetricsHandler are generic (any counter name registered is
// exposed), so this test exercises that path directly with this metric's
// specific name rather than re-testing spool.Spool's hook-firing logic,
// which internal/spool's TestEnqueue_OnDirFsyncFailureHookFiresOnlyOnFailure
// already covers.
func TestMetricsHandler_SpoolDirFsyncFailuresCounter(t *testing.T) {
	RecordMetric("spool_dir_fsync_failures", 1)
	RecordMetric("spool_dir_fsync_failures", 1)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	MetricsHandler(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode metrics response: %v", err)
	}

	got, ok := body["spool_dir_fsync_failures"].(float64)
	if !ok {
		t.Fatal("expected spool_dir_fsync_failures to be present on /metrics")
	}
	if got < 2 {
		t.Errorf("spool_dir_fsync_failures = %v, want at least 2 (tests share process-global metrics state)", got)
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

// resetDeliveryLatencyEWMAForTest clears the package-level EWMA state so a
// test can exercise "no sample recorded yet" (and "the very next sample is
// exactly 0.0") deterministically, regardless of what other tests in this
// package have already recorded — delivery latency metrics are
// process-global, like the rest of this package's metrics store.
func resetDeliveryLatencyEWMAForTest(t *testing.T) {
	t.Helper()
	ewmaMu.Lock()
	ewmaInitialized = false
	ewmaValueMs = 0
	ewmaMu.Unlock()
}

// TestMetricsHandler_SubMillisecondDeliveryLatencyStillReportsEWMA is a
// regression test for a confirmed bug: queueTime.Milliseconds() truncates
// toward zero, so any delivery faster than 1ms produced a latency sample of
// exactly 0.0. An earlier lock-free implementation encoded "no sample yet"
// as the float's zero bit pattern, which collided with that legitimate 0.0
// sample: the first fast delivery looked identical to "uninitialized", and
// delivery_latency_ms_ewma silently vanished from /metrics — the worst
// possible failure mode for a metric that exists to catch silent
// degradation. This pins the fix (a plain initialized bool, plus recording
// latency as a sub-millisecond float instead of a truncated integer).
func TestMetricsHandler_SubMillisecondDeliveryLatencyStillReportsEWMA(t *testing.T) {
	resetDeliveryLatencyEWMAForTest(t)

	RecordDelivery(500 * time.Microsecond) // 0.5ms: truncates to 0 under Milliseconds()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	MetricsHandler(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode metrics response: %v", err)
	}

	ewmaRaw, ok := body["delivery_latency_ms_ewma"]
	if !ok {
		t.Fatal("delivery_latency_ms_ewma is missing from /metrics after a sub-millisecond delivery " +
			"— this is the exact silent-disappearance bug this metric exists to prevent")
	}
	ewma := ewmaRaw.(float64)
	if ewma <= 0 || ewma > 1 {
		t.Errorf("delivery_latency_ms_ewma = %v, want a small positive value near 0.5 "+
			"(the real sub-ms sample, not truncated to exactly 0)", ewma)
	}
}

// TestUpdateDeliveryLatencyEWMA_ConcurrentUpdatesRaceClean hammers the EWMA
// updater from many goroutines under -race. Production has a single writer
// in practice (spool.Run's one forwarder goroutine drives OnDelivered ->
// RecordDelivery), but updateDeliveryLatencyEWMA is a package-level
// function a future caller could reach concurrently, and the mutex must
// hold up correctly if so.
func TestUpdateDeliveryLatencyEWMA_ConcurrentUpdatesRaceClean(t *testing.T) {
	resetDeliveryLatencyEWMAForTest(t)

	const goroutines = 50
	const samplesPerGoroutine = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < samplesPerGoroutine; i++ {
				updateDeliveryLatencyEWMA(float64((g + i) % 10))
			}
		}(g)
	}
	wg.Wait()

	ewma, ok := deliveryLatencyEWMA()
	if !ok {
		t.Fatal("expected the EWMA to be initialized after concurrent updates")
	}
	if ewma < 0 || ewma > 9 {
		t.Errorf("ewma = %v, want a value within the sampled range [0,9]", ewma)
	}
}
