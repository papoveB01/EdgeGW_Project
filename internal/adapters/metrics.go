package adapters

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Simple in-memory metrics for /metrics endpoint.
var (
	metricsStore = struct {
		mu       sync.RWMutex
		counters map[string]*int64
		gauges   map[string]*int64
	}{counters: make(map[string]*int64), gauges: make(map[string]*int64)}
	startTime = time.Now()

	// lastDeliveryUnixNano holds the UnixNano timestamp of the most recent
	// successful delivery (0 = never). It's a plain atomic rather than a
	// gauge so /metrics can compute "seconds since" at scrape time instead
	// of exposing a value that goes stale the instant it's set.
	lastDeliveryUnixNano atomic.Int64

	// deliveryLatencyEWMA holds an exponentially weighted moving average of
	// delivery latency, in milliseconds, guarded by ewmaMu. Unlike the
	// lifetime sum/count average below, this tracks *recent* deliveries so
	// a fresh incident (e.g. the vendor slowing down) moves it quickly
	// instead of being diluted by hours of prior fast deliveries.
	//
	// This is deliberately a plain mutex, not a lock-free CAS-over-bits
	// scheme: a sub-millisecond delivery is a legitimate sample of exactly
	// 0.0, which is indistinguishable from "no data yet" if "uninitialized"
	// is encoded as the float's zero bit pattern (a prior version of this
	// code did exactly that, and the collision made delivery_latency_ms_ewma
	// silently vanish from /metrics on the very first fast delivery — the
	// worst possible failure mode for a metric that exists to catch silent
	// failure). An explicit bool cannot collide with any float value. It's
	// also the simpler design for what is actually single-writer in this
	// binary (spool.Run's one forwarder goroutine calls OnDelivered ->
	// RecordDelivery), so lock-free bought nothing here; the mutex has
	// negligible cost and stays correct if a future caller adds a second
	// writer.
	ewmaMu          sync.Mutex
	ewmaInitialized bool
	ewmaValueMs     float64
)

// deliveryLatencyEWMAAlpha is the weight given to each new latency sample.
// Higher = more reactive to recent deliveries, lower = smoother. 0.2 means
// roughly the last ~5 deliveries dominate the average.
const deliveryLatencyEWMAAlpha = 0.2

// updateDeliveryLatencyEWMA folds one new latency sample (in milliseconds,
// may legitimately be 0 or fractional) into the running exponentially
// weighted moving average.
func updateDeliveryLatencyEWMA(sampleMs float64) {
	ewmaMu.Lock()
	defer ewmaMu.Unlock()
	if !ewmaInitialized {
		ewmaValueMs = sampleMs
		ewmaInitialized = true
		return
	}
	ewmaValueMs = deliveryLatencyEWMAAlpha*sampleMs + (1-deliveryLatencyEWMAAlpha)*ewmaValueMs
}

// deliveryLatencyEWMA returns the current EWMA and whether any sample has
// been recorded yet.
func deliveryLatencyEWMA() (ms float64, ok bool) {
	ewmaMu.Lock()
	defer ewmaMu.Unlock()
	return ewmaValueMs, ewmaInitialized
}

// RecordMetric increments a named counter.
func RecordMetric(name string, value int64) {
	metricsStore.mu.RLock()
	counter, ok := metricsStore.counters[name]
	metricsStore.mu.RUnlock()

	if !ok {
		metricsStore.mu.Lock()
		counter, ok = metricsStore.counters[name]
		if !ok {
			v := int64(0)
			counter = &v
			metricsStore.counters[name] = counter
		}
		metricsStore.mu.Unlock()
	}
	atomic.AddInt64(counter, value)
}

// SetGauge sets a named gauge to an absolute value (e.g. current spool depth).
func SetGauge(name string, value int64) {
	metricsStore.mu.RLock()
	gauge, ok := metricsStore.gauges[name]
	metricsStore.mu.RUnlock()

	if !ok {
		metricsStore.mu.Lock()
		gauge, ok = metricsStore.gauges[name]
		if !ok {
			v := int64(0)
			gauge = &v
			metricsStore.gauges[name] = gauge
		}
		metricsStore.mu.Unlock()
	}
	atomic.StoreInt64(gauge, value)
}

// RecordDelivery records a successful signal delivery for the freshness
// metrics: time-since-last-successful-delivery and delivery latency
// (queueTime is how long the signal waited between being accepted and being
// confirmed delivered; pass 0 when latency isn't known, e.g. synchronous
// forwarding with no queue). It updates both a lifetime cumulative latency
// average (for capacity planning) and a short-window EWMA (for spotting a
// fresh slowdown quickly) — see MetricsHandler for how each is exposed.
func RecordDelivery(queueTime time.Duration) {
	lastDeliveryUnixNano.Store(time.Now().UnixNano())
	RecordMetric("signals_forwarded", 1)
	if queueTime > 0 {
		// Microsecond precision converted to a float millisecond value:
		// queueTime.Milliseconds() truncates toward zero, so any delivery
		// under 1ms would otherwise record as exactly 0 and be
		// indistinguishable from "no sample" wherever that matters.
		msFloat := float64(queueTime.Microseconds()) / 1000.0
		RecordMetric("delivery_latency_ms_sum", queueTime.Milliseconds())
		RecordMetric("delivery_latency_count", 1)
		updateDeliveryLatencyEWMA(msFloat)
	}
}

// MetricsHandler returns current metrics as JSON.
func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	metricsStore.mu.RLock()
	defer metricsStore.mu.RUnlock()

	result := map[string]interface{}{
		"uptime_seconds": int(time.Since(startTime).Seconds()),
		"started_at":     startTime.UTC().Format(time.RFC3339),
	}
	var latencySum, latencyCount int64
	for name, counter := range metricsStore.counters {
		v := atomic.LoadInt64(counter)
		result[name] = v
		switch name {
		case "delivery_latency_ms_sum":
			latencySum = v
		case "delivery_latency_count":
			latencyCount = v
		}
	}
	for name, gauge := range metricsStore.gauges {
		result[name] = atomic.LoadInt64(gauge)
	}

	// Computed at scrape time so these never go stale between events: a
	// feed idle for hours still shows its true age, not the age recorded
	// at the last event.
	if last := lastDeliveryUnixNano.Load(); last != 0 {
		result["seconds_since_last_delivery"] = time.Since(time.Unix(0, last)).Seconds()
	} else {
		result["seconds_since_last_delivery"] = nil
	}
	if latencyCount > 0 {
		// Lifetime cumulative average: useful for capacity planning, but an
		// incident buried under hours of prior fast deliveries barely moves
		// it — see delivery_latency_ms_ewma for a metric that reacts to
		// current conditions.
		result["delivery_latency_ms_lifetime_avg"] = float64(latencySum) / float64(latencyCount)
		if ewma, ok := deliveryLatencyEWMA(); ok {
			result["delivery_latency_ms_ewma"] = ewma
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
