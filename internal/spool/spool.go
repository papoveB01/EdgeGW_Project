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
type Hooks struct {
	OnDelivered func()
	OnDead      func()
	OnDepth     func(depth int)
}

// Spool is a durable oldest-first delivery queue.
type Spool struct {
	dir         string
	maxDepth    int
	forward     ForwardFunc
	isPermanent func(error) bool
	hooks       Hooks

	mu    sync.Mutex
	depth int
	seq   uint64
	wake  chan struct{}
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
	return s, nil
}

// Depth returns the number of signals waiting for delivery.
func (s *Spool) Depth() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.depth
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
	if len(pending) == 0 {
		return false, nil
	}
	name := pending[0]
	path := filepath.Join(s.dir, name)

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
		return false, err
	}

	os.Remove(path)
	s.decDepth()
	if s.hooks.OnDelivered != nil {
		s.hooks.OnDelivered()
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
