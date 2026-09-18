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
)

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
// forwarding with no queue).
func RecordDelivery(queueTime time.Duration) {
	lastDeliveryUnixNano.Store(time.Now().UnixNano())
	RecordMetric("signals_forwarded", 1)
	if queueTime > 0 {
		RecordMetric("delivery_latency_ms_sum", queueTime.Milliseconds())
		RecordMetric("delivery_latency_count", 1)
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
		result["delivery_latency_ms_avg"] = float64(latencySum) / float64(latencyCount)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
