// Package spool provides a durable, file-backed queue for anonymized signals.
// Signals are persisted before the gateway acknowledges them (202 Accepted),
// then delivered to the Hub by a background forwarder — so Hub outages don't
// lose signals and don't block the core banking system.
//
// Only anonymized payloads are ever written to disk; raw PII never touches
// the spool.
package spool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrFull is returned by Enqueue when the spool has reached its depth limit.
var ErrFull = errors.New("spool is full")

const deadDirName = "dead"

// ForwardFunc delivers one marshaled signal payload. It should return an
// error classified by isPermanent for dead-lettering decisions.
type ForwardFunc func(ctx context.Context, payload []byte) error

// Hooks let the spool report events without depending on a metrics package.
// The spool package must stay free of any dependency on internal/adapters,
// so callers (main.go) wire these to whatever metrics/health machinery they
// use.
type Hooks struct {
	// OnDelivered fires after a signal is successfully forwarded. queueTime
	// is how long the signal waited in the spool (enqueue to delivery) and
	// is the delivery-latency measure for freshness metrics.
	OnDelivered func(queueTime time.Duration)
	// OnDead fires when a signal is moved to the dead-letter directory.
	OnDead func()
	// OnFailed fires on every retryable delivery attempt that fails (not
	// just the final give-up), so failures are observable while the spool
	// is stuck retrying a head-of-line item under backoff.
	OnFailed func()
	// OnDepth fires whenever the pending count changes.
	OnDepth func(depth int)
	// OnOldestPendingAge fires whenever the age of the oldest pending item
	// is recomputed. ageSeconds is 0 when the queue is empty.
	OnOldestPendingAge func(ageSeconds float64)
}

// Spool is a durable oldest-first delivery queue.
type Spool struct {
	dir         string
	maxDepth    int
	forward     ForwardFunc
	isPermanent func(error) bool
	hooks       Hooks

	mu              sync.Mutex
	depth           int
	seq             uint64
	oldestPendingAt time.Time // zero value means no pending signal
	wake            chan struct{}
}

// New opens (or creates) a spool directory and counts any signals left over
// from a previous run; those are replayed by Run in order.
func New(dir string, maxDepth int, forward ForwardFunc, isPermanent func(error) bool, hooks Hooks) (*Spool, error) {
	if err := os.MkdirAll(filepath.Join(dir, deadDirName), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create spool dir: %w", err)
	}
	s := &Spool{
		dir:         dir,
		maxDepth:    maxDepth,
		forward:     forward,
		isPermanent: isPermanent,
		hooks:       hooks,
		wake:        make(chan struct{}, 1),
	}
	pending, err := s.listPending()
	if err != nil {
		return nil, err
	}
	s.depth = len(pending)
	s.reportDepth()
	s.updateOldestPending(pending)
	return s, nil
}

// Depth returns the number of signals waiting for delivery.
func (s *Spool) Depth() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.depth
}

// MaxDepth returns the spool's configured depth ceiling. It never changes
// after New, so it needs no locking.
func (s *Spool) MaxDepth() int {
	return s.maxDepth
}

// OldestPendingAge reports how long the oldest pending signal has been
// waiting, as of now. hasPending is false when the queue is empty. This
// reads a cached, in-memory value only (no disk I/O), so it is cheap enough
// to call from a health check on every request.
func (s *Spool) OldestPendingAge(now time.Time) (age time.Duration, hasPending bool) {
	s.mu.Lock()
	t := s.oldestPendingAt
	s.mu.Unlock()
	if t.IsZero() {
		return 0, false
	}
	return now.Sub(t), true
}

// Enqueue durably persists one marshaled signal (write temp + rename, so a
// crash mid-write never leaves a half-signal in the queue).
func (s *Spool) Enqueue(payload []byte) error {
	s.mu.Lock()
	if s.depth >= s.maxDepth {
		s.mu.Unlock()
		return ErrFull
	}
	s.depth++
	s.seq++
	name := fmt.Sprintf("%020d-%06d.json", time.Now().UnixNano(), s.seq)
	s.mu.Unlock()

	tmp := filepath.Join(s.dir, name+".tmp")
	final := filepath.Join(s.dir, name)
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		s.decDepth()
		return fmt.Errorf("failed to write spool file: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		s.decDepth()
		return fmt.Errorf("failed to commit spool file: %w", err)
	}
	s.reportDepth()

	// Nudge the forwarder without blocking if it's already awake.
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// Run delivers spooled signals oldest-first until ctx is cancelled. Retryable
// failures back off exponentially (1s..30s); permanent failures move the
// signal to the dead-letter directory so one poisoned signal can't block the
// queue. Pending signals persist across restarts.
func (s *Spool) Run(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		progressed, err := s.forwardOldest(ctx)
		switch {
		case progressed:
			backoff = time.Second
		case err == nil:
			// Queue empty: wait for new work.
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
			case <-time.After(2 * time.Second):
			}
		default:
			// Retryable failure: hold off, then retry the same signal.
			slog.Warn("Spool delivery failed, backing off", "backoff", backoff.String(), "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// forwardOldest attempts delivery of the oldest pending signal.
// progressed=true means the queue advanced (delivered or dead-lettered).
func (s *Spool) forwardOldest(ctx context.Context) (progressed bool, err error) {
	pending, err := s.listPending()
	if err != nil {
		return false, err
	}
	s.updateOldestPending(pending)
	if len(pending) == 0 {
		return false, nil
	}
	name := pending[0]
	path := filepath.Join(s.dir, name)
	enqueuedAt, _ := parseSpoolTime(name)

	payload, err := os.ReadFile(path)
	if err != nil {
		slog.Error("Unreadable spool file, dead-lettering", "file", name, "error", err)
		s.deadLetter(name)
		return true, nil
	}

	if err := s.forward(ctx, payload); err != nil {
		if s.isPermanent(err) {
			slog.Error("Hub permanently rejected signal, dead-lettering", "file", name, "error", err)
			s.deadLetter(name)
			return true, nil
		}
		if s.hooks.OnFailed != nil {
			s.hooks.OnFailed()
		}
		return false, err
	}

	os.Remove(path)
	s.decDepth()
	if s.hooks.OnDelivered != nil {
		var queueTime time.Duration
		if !enqueuedAt.IsZero() {
			queueTime = time.Since(enqueuedAt)
		}
		s.hooks.OnDelivered(queueTime)
	}
	return true, nil
}

func (s *Spool) deadLetter(name string) {
	if err := os.Rename(filepath.Join(s.dir, name), filepath.Join(s.dir, deadDirName, name)); err != nil {
		slog.Error("Failed to dead-letter spool file", "file", name, "error", err)
		return
	}
	s.decDepth()
	if s.hooks.OnDead != nil {
		s.hooks.OnDead()
	}
}

func (s *Spool) listPending() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read spool dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (s *Spool) decDepth() {
	s.mu.Lock()
	if s.depth > 0 {
		s.depth--
	}
	s.mu.Unlock()
	s.reportDepth()
}

func (s *Spool) reportDepth() {
	if s.hooks.OnDepth != nil {
		s.hooks.OnDepth(s.Depth())
	}
}

// updateOldestPending caches the enqueue time of the head of the pending
// list (pending must already be sorted oldest-first, as listPending
// returns) and reports it via OnOldestPendingAge. Callers must not hold s.mu.
//
// If the head's filename can't be parsed (it should always be one this
// package wrote, but disk state can surprise you), this deliberately fails
// toward "assume stale" rather than toward "no pending": a freshness signal
// that silently reports an item as not-pending because its timestamp was
// unreadable would hide a real backlog from staleness alerting, which is
// the wrong direction to fail in. So an unparseable name gets the Unix
// epoch as its enqueue time, guaranteeing a large, alarm-tripping age
// instead of a reassuring zero.
func (s *Spool) updateOldestPending(pending []string) {
	var t time.Time
	if len(pending) > 0 {
		if parsed, ok := parseSpoolTime(pending[0]); ok {
			t = parsed
		} else {
			slog.Warn("Unparseable spool filename, reporting oldest-pending age conservatively (assumed stale)",
				"file", pending[0])
			t = time.Unix(0, 0)
		}
	}
	s.mu.Lock()
	s.oldestPendingAt = t
	s.mu.Unlock()

	if s.hooks.OnOldestPendingAge != nil {
		if t.IsZero() {
			s.hooks.OnOldestPendingAge(0)
		} else {
			s.hooks.OnOldestPendingAge(time.Since(t).Seconds())
		}
	}
}

// parseSpoolTime recovers the enqueue timestamp encoded in a spool filename
// (the "<zero-padded unixnano>-<seq>.json" scheme documented on Enqueue).
func parseSpoolTime(name string) (time.Time, bool) {
	idx := strings.IndexByte(name, '-')
	if idx <= 0 {
		return time.Time{}, false
	}
	nanos, err := strconv.ParseInt(name[:idx], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, nanos), true
}
