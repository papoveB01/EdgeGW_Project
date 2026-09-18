package adapters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/processor"
)

// ProcessInboundRequest handles incoming transaction data from Core Banking System.
// Decodes directly into RawData and validates field values (not just presence).
func ProcessInboundRequest(r *http.Request) (*processor.RawData, error) {
	defer r.Body.Close()

	var rawData processor.RawData
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&rawData); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if err := rawData.Validate(); err != nil {
		return nil, err
	}

	return &rawData, nil
}

// Default thresholds for HealthCheckHandler. Because egress is one-way and
// scores never come back through the gateway, the metrics endpoints (and
// this health check) are the only signal an operator has that the feed is
// current. Inference has a shelf life, so a queue that is technically still
// moving but running far behind is functionally down.
const (
	// DefaultHealthMaxDepthRatio is the fraction of spool capacity at or
	// above which the health check reports unhealthy.
	DefaultHealthMaxDepthRatio = 0.95
	// DefaultHealthMaxStaleness is how old the oldest pending spool item
	// may get before the health check reports unhealthy.
	DefaultHealthMaxStaleness = 15 * time.Minute
)

// SpoolStatus is a cheap, in-memory snapshot of spool state that
// HealthCheckHandler uses to decide whether the feed is falling behind. It
// deliberately carries no reference to *spool.Spool so this package doesn't
// need to import internal/spool; main.go supplies a closure instead.
type SpoolStatus struct {
	Depth            int
	MaxDepth         int
	OldestPendingAge time.Duration
	HasPending       bool
}

// SpoolStatusFunc returns a live SpoolStatus snapshot. Implementations must
// be cheap (no disk I/O, no blocking) since HealthCheckHandler is called by
// the container healthcheck every ~20s.
type SpoolStatusFunc func() SpoolStatus

var (
	healthMu            sync.RWMutex
	healthSpoolStatus   SpoolStatusFunc // nil in synchronous mode (no spool)
	healthMaxDepthRatio = DefaultHealthMaxDepthRatio
	healthMaxStaleness  = DefaultHealthMaxStaleness
)

// SetHealthSpoolStatus registers the callback HealthCheckHandler uses to
// read live spool state. Passing nil (the default) means there is no spool
// to check, so /health reports healthy based on HTTP serviceability alone.
func SetHealthSpoolStatus(fn SpoolStatusFunc) {
	healthMu.Lock()
	defer healthMu.Unlock()
	healthSpoolStatus = fn
}

// SetHealthThresholds configures when HealthCheckHandler reports unhealthy.
// A non-positive maxDepthRatio or maxStaleness is ignored, leaving the
// current value (default DefaultHealthMaxDepthRatio /
// DefaultHealthMaxStaleness) in place.
func SetHealthThresholds(maxDepthRatio float64, maxStaleness time.Duration) {
	healthMu.Lock()
	defer healthMu.Unlock()
	if maxDepthRatio > 0 {
		healthMaxDepthRatio = maxDepthRatio
	}
	if maxStaleness > 0 {
		healthMaxStaleness = maxStaleness
	}
}

// HealthCheckHandler returns gateway health status. Unlike a bare liveness
// probe, it degrades: if a spool is registered (async mode) and it is at or
// near capacity, or its oldest pending signal has aged past the staleness
// threshold, it reports "unhealthy" with 503 so an orchestrator (and the
// Docker healthcheck, which calls this same handler via the binary's
// -healthcheck self-probe) can actually detect a stuck feed instead of
// seeing a permanent "healthy". Reads only cached in-memory state, so it
// stays cheap for a ~20s polling interval.
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	healthMu.RLock()
	statusFn := healthSpoolStatus
	depthRatio := healthMaxDepthRatio
	staleness := healthMaxStaleness
	healthMu.RUnlock()

	body := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "edge-gateway",
		"version":   "2.0.0",
	}

	var reasons []string
	if statusFn != nil {
		st := statusFn()
		body["spool_depth"] = st.Depth
		body["spool_max_depth"] = st.MaxDepth
		if st.MaxDepth > 0 && float64(st.Depth)/float64(st.MaxDepth) >= depthRatio {
			reasons = append(reasons, "spool at or near capacity")
		}
		if st.HasPending {
			body["oldest_pending_seconds"] = st.OldestPendingAge.Seconds()
			if st.OldestPendingAge > staleness {
				reasons = append(reasons, "oldest pending signal exceeds staleness threshold")
			}
		}
	}

	httpStatus := http.StatusOK
	status := "healthy"
	if len(reasons) > 0 {
		status = "unhealthy"
		httpStatus = http.StatusServiceUnavailable
		body["reasons"] = reasons
	}
	body["status"] = status

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(body)
}
