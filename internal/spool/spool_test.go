package spool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

var errPermanent = errors.New("permanent")

func isPerm(err error) bool { return errors.Is(err, errPermanent) }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}

func TestEnqueueAndDeliver(t *testing.T) {
	dir := t.TempDir()
	var delivered atomic.Int32
	var got atomic.Value
	s, err := New(dir, 100, func(ctx context.Context, payload []byte) error {
		got.Store(string(payload))
		delivered.Add(1)
		return nil
	}, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	if err := s.Enqueue([]byte(`{"sig":1}`)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return delivered.Load() == 1 })

	if got.Load().(string) != `{"sig":1}` {
		t.Errorf("payload mismatch: %v", got.Load())
	}
	waitFor(t, func() bool { return s.Depth() == 0 })
	if pending, _ := s.listPending(); len(pending) != 0 {
		t.Errorf("delivered file should be removed, found %v", pending)
	}
}

func TestRetryableFailureThenRecovery(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int32
	s, err := New(dir, 100, func(ctx context.Context, payload []byte) error {
		if calls.Add(1) < 3 {
			return errors.New("hub down")
		}
		return nil
	}, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Enqueue([]byte(`{"sig":1}`)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	// Retries at 1s then 2s backoff; delivery on 3rd call.
	deadline := time.Now().Add(10 * time.Second)
	for s.Depth() > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if s.Depth() != 0 {
		t.Fatalf("signal not delivered after retries: %d calls", calls.Load())
	}
	if calls.Load() != 3 {
		t.Errorf("expected 3 delivery attempts, got %d", calls.Load())
	}
}

func TestPermanentFailureDeadLetters(t *testing.T) {
	dir := t.TempDir()
	var dead atomic.Int32
	s, err := New(dir, 100, func(ctx context.Context, payload []byte) error {
		return errPermanent
	}, isPerm, Hooks{OnDead: func() { dead.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Enqueue([]byte(`{"bad":1}`)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	waitFor(t, func() bool { return dead.Load() == 1 })

	entries, _ := os.ReadDir(filepath.Join(dir, "dead"))
	if len(entries) != 1 {
		t.Errorf("expected 1 dead-lettered file, got %d", len(entries))
	}
	if s.Depth() != 0 {
		t.Errorf("dead-lettered signal should not count as pending: depth=%d", s.Depth())
	}
}

func TestReplayAfterRestart(t *testing.T) {
	dir := t.TempDir()
	block := func(ctx context.Context, payload []byte) error { return errors.New("down") }

	s1, err := New(dir, 100, block, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	s1.Enqueue([]byte(`{"sig":1}`))
	s1.Enqueue([]byte(`{"sig":2}`))
	// No Run: simulate crash with 2 pending signals on disk.

	var order []string
	var delivered atomic.Int32
	s2, err := New(dir, 100, func(ctx context.Context, payload []byte) error {
		order = append(order, string(payload))
		delivered.Add(1)
		return nil
	}, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if s2.Depth() != 2 {
		t.Fatalf("restart should see 2 pending signals, got %d", s2.Depth())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s2.Run(ctx)

	waitFor(t, func() bool { return delivered.Load() == 2 })
	if order[0] != `{"sig":1}` || order[1] != `{"sig":2}` {
		t.Errorf("expected oldest-first replay, got %v", order)
	}
}

func TestEnqueueFullReturnsErrFull(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 1, func(ctx context.Context, payload []byte) error { return nil }, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue([]byte(`{"sig":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue([]byte(`{"sig":2}`)); !errors.Is(err, ErrFull) {
		t.Errorf("expected ErrFull, got %v", err)
	}
}
