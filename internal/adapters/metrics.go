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
		mu      sync.RWMutex
		counters map[string]*int64
	}{counters: make(map[string]*int64)}
	startTime = time.Now()
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

// MetricsHandler returns current metrics as JSON.
func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	metricsStore.mu.RLock()
	defer metricsStore.mu.RUnlock()

	result := map[string]interface{}{
		"uptime_seconds": int(time.Since(startTime).Seconds()),
		"started_at":     startTime.UTC().Format(time.RFC3339),
	}
	for name, counter := range metricsStore.counters {
		result[name] = atomic.LoadInt64(counter)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
