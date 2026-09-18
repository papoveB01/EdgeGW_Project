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

// HealthCheckHandler is a LIVENESS check ONLY: it returns 200 whenever this
// process can serve HTTP, full stop. It never inspects the spool, and must
// never be extended to: a restart cannot fix a full or stale spool during a
// vendor outage (the backlog survives on the spool's volume; the vendor is
// still down), and a restart would only add a self-inflicted outage of its
// own by briefly dropping /process, which the bank's core system depends
// on.
//
// This is the handler the binary's own "-healthcheck" self-probe calls (see
// healthcheck() in cmd/gateway/main.go), which is what the Docker
// HEALTHCHECK in deployments/docker-compose.yml exercises, and what a
// Kubernetes livenessProbe or an autoheal sidecar would act on to restart
// the container. Precisely because failing this endpoint can trigger a
// restart, it is SAFE to wire only to conditions a restart actually
// remedies (a dead or wedged process) — which is exactly what it does.
//
// The degraded-but-alive signal (spool near capacity, backlog stale) lives
// on ReadinessCheckHandler (/readyz) instead. See that handler's doc
// comment for why it must never be wired to an auto-restart action.
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "edge-gateway",
		"version":   "2.0.0",
	})
}

// Default thresholds for ReadinessCheckHandler. Because egress is one-way
// and scores never come back through the gateway, /readyz and /metrics are
// the only signal an operator has that the feed is current. Inference has a
// shelf life, so a queue that is technically still moving but running far
// behind is functionally down, even though the process serving it is
// perfectly alive.
const (
	// DefaultReadinessMaxDepthRatio is the fraction of spool capacity at or
	// above which the readiness check reports unhealthy.
	DefaultReadinessMaxDepthRatio = 0.95
	// DefaultReadinessMaxStaleness is how old the oldest pending spool item
	// may get before the readiness check reports unhealthy.
	DefaultReadinessMaxStaleness = 15 * time.Minute
)

// SpoolStatus is a cheap, in-memory snapshot of spool state that
// ReadinessCheckHandler uses to decide whether the feed is falling behind.
// It deliberately carries no reference to *spool.Spool so this package
// doesn't need to import internal/spool; main.go supplies a closure
// instead.
type SpoolStatus struct {
	Depth            int
	MaxDepth         int
	OldestPendingAge time.Duration
	HasPending       bool
}

// SpoolStatusFunc returns a live SpoolStatus snapshot. Implementations must
// be cheap (no disk I/O, no blocking) since ReadinessCheckHandler may be
// polled frequently.
type SpoolStatusFunc func() SpoolStatus

var (
	readinessMu            sync.RWMutex
	readinessSpoolStatus   SpoolStatusFunc // nil in synchronous mode (no spool)
	readinessMaxDepthRatio = DefaultReadinessMaxDepthRatio
	readinessMaxStaleness  = DefaultReadinessMaxStaleness
)

// SetReadinessSpoolStatus registers the callback ReadinessCheckHandler uses
// to read live spool state. Passing nil (the default) means there is no
// spool to check, so /readyz reports healthy unconditionally.
func SetReadinessSpoolStatus(fn SpoolStatusFunc) {
	readinessMu.Lock()
	defer readinessMu.Unlock()
	readinessSpoolStatus = fn
}

// SetReadinessThresholds configures when ReadinessCheckHandler reports
// unhealthy. A non-positive maxDepthRatio or maxStaleness is ignored,
// leaving the current value (default DefaultReadinessMaxDepthRatio /
// DefaultReadinessMaxStaleness) in place.
func SetReadinessThresholds(maxDepthRatio float64, maxStaleness time.Duration) {
	readinessMu.Lock()
	defer readinessMu.Unlock()
	if maxDepthRatio > 0 {
		readinessMaxDepthRatio = maxDepthRatio
	}
	if maxStaleness > 0 {
		readinessMaxStaleness = maxStaleness
	}
}

// ReadinessCheckHandler reports whether the gateway is keeping up, not just
// alive: if a spool is registered (async mode) and it is at or near
// capacity, or its oldest pending signal has aged past the staleness
// threshold, it reports "unhealthy" with 503 and a "reasons" list.
//
// A full or stale spool during a vendor outage is the durable queue working
// exactly as designed — it is a DEGRADED condition, not a dead process.
//
//	DO NOT wire this endpoint to any auto-restart action (a Kubernetes
//	livenessProbe, Docker Swarm, an autoheal sidecar reusing this handler,
//	etc). Restarting fixes nothing here — the backlog survives on the
//	spool's volume and the vendor is still down — and each restart briefly
//	drops /process, turning an outage the spool exists to absorb into a
//	self-inflicted one. Wire it to alerting/paging, or, if used as a
//	Kubernetes readinessProbe, to traffic removal only. Use
//	HealthCheckHandler (/health) for anything that should trigger a
//	restart.
//
// Reads only cached in-memory state (no disk I/O), so it's cheap enough to
// poll frequently.
func ReadinessCheckHandler(w http.ResponseWriter, r *http.Request) {
	readinessMu.RLock()
	statusFn := readinessSpoolStatus
	depthRatio := readinessMaxDepthRatio
	staleness := readinessMaxStaleness
	readinessMu.RUnlock()

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
