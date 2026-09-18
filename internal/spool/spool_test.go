package spool

import (
	"context"
	"errors"
	"fmt"
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
	var failed atomic.Int32
	var delivered atomic.Int32
	var lastQueueTime time.Duration
	s, err := New(dir, 100, func(ctx context.Context, payload []byte) error {
		if calls.Add(1) < 3 {
			return errors.New("hub down")
		}
		return nil
	}, isPerm, Hooks{
		OnFailed:    func() { failed.Add(1) },
		OnDelivered: func(qt time.Duration) { lastQueueTime = qt; delivered.Add(1) },
	})
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
	// Two of the three attempts failed; the third succeeded, so OnFailed
	// (which reports failed *attempts*, not final give-ups) should fire
	// exactly twice — this is what makes failures observable in spool mode,
	// where the synchronous path's forward_failures counter never fires.
	if failed.Load() != 2 {
		t.Errorf("expected 2 OnFailed calls, got %d", failed.Load())
	}
	if delivered.Load() != 1 {
		t.Errorf("expected 1 OnDelivered call, got %d", delivered.Load())
	}
	if lastQueueTime <= 0 {
		t.Errorf("expected positive queue time on delivery, got %v", lastQueueTime)
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

func TestMaxDepth(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 42, func(ctx context.Context, payload []byte) error { return nil }, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if s.MaxDepth() != 42 {
		t.Errorf("MaxDepth() = %d, want 42", s.MaxDepth())
	}
}

// TestOldestPendingAge exercises the freshness metric a stuck head-of-line
// item is supposed to surface: while a signal blocks in delivery,
// OldestPendingAge must report it as pending with a growing age, and once
// delivered, the queue must go back to reporting no pending signal.
func TestOldestPendingAge(t *testing.T) {
	dir := t.TempDir()
	release := make(chan struct{})
	var ageHookCalls atomic.Int32
	s, err := New(dir, 100, func(ctx context.Context, payload []byte) error {
		<-release
		return nil
	}, isPerm, Hooks{OnOldestPendingAge: func(ageSeconds float64) { ageHookCalls.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}

	if _, hasPending := s.OldestPendingAge(time.Now()); hasPending {
		t.Fatal("empty spool should report no pending signal")
	}

	if err := s.Enqueue([]byte(`{"sig":1}`)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	waitFor(t, func() bool {
		_, hasPending := s.OldestPendingAge(time.Now())
		return hasPending
	})
	age, hasPending := s.OldestPendingAge(time.Now())
	if !hasPending || age < 0 {
		t.Fatalf("expected a non-negative pending age, got age=%v hasPending=%v", age, hasPending)
	}
	if ageHookCalls.Load() == 0 {
		t.Error("expected OnOldestPendingAge to have fired at least once")
	}

	close(release)
	waitFor(t, func() bool {
		_, hasPending := s.OldestPendingAge(time.Now())
		return !hasPending
	})
}

// TestOldestPendingAgeSurvivesRestart pins the headline correctness claim of
// this package's freshness work: age-of-oldest-pending must be recovered
// from the filename-embedded enqueue timestamp on restart, not reset to
// zero just because the in-process Spool that did the enqueuing is gone.
// New() calling listPending() then updateOldestPending() is what makes that
// work; this test would fail if that wiring were ever dropped (e.g. by
// someone "simplifying" New()), even though every other test in this file
// would stay green.
//
// The file is backdated on disk (not slept for) so the test stays fast and
// deterministic.
func TestOldestPendingAgeSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	block := func(ctx context.Context, payload []byte) error { return errors.New("down") }

	s1, err := New(dir, 100, block, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Enqueue([]byte(`{"sig":1}`)); err != nil {
		t.Fatal(err)
	}
	// No Run: simulate a crash with the signal still sitting on disk.

	pending, err := s1.listPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending file before backdating, got %d: %v", len(pending), pending)
	}
	// Rewrite the filename's embedded unixnano timestamp to 2 hours in the
	// past, matching the "<zero-padded unixnano>-<seq>.json" scheme.
	backdated := time.Now().Add(-2 * time.Hour)
	newName := fmt.Sprintf("%020d-%06d.json", backdated.UnixNano(), 1)
	if err := os.Rename(filepath.Join(dir, pending[0]), filepath.Join(dir, newName)); err != nil {
		t.Fatal(err)
	}

	// Open a NEW Spool over the same directory, simulating a process
	// restart. The old Spool (s1) is abandoned, never delivered anything.
	s2, err := New(dir, 100, block, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}

	age, hasPending := s2.OldestPendingAge(time.Now())
	if !hasPending {
		t.Fatal("a fresh Spool over a directory with a pending file should report it as pending")
	}
	if age < 90*time.Minute || age > 150*time.Minute {
		t.Errorf("OldestPendingAge = %v, want ~2h recovered from the backdated filename; "+
			"a value near 0 means restart recovery is broken (age reset instead of recovered)", age)
	}
}

// TestOldestPendingAgeFailsConservativelyOnUnparseableFilename covers the
// fallback for a spool file whose name doesn't match the
// "<unixnano>-<seq>.json" scheme (shouldn't happen from this package's own
// writes, but disk state can surprise you). A freshness signal must fail
// toward "assume stale", not toward "no pending" — silently reporting no
// backlog because a timestamp was unreadable would hide a real one from
// staleness alerting.
func TestOldestPendingAgeFailsConservativelyOnUnparseableFilename(t *testing.T) {
	dir := t.TempDir()
	block := func(ctx context.Context, payload []byte) error { return errors.New("down") }

	if err := os.WriteFile(filepath.Join(dir, "not-a-valid-spool-name.json"), []byte(`{"sig":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New(dir, 100, block, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}

	age, hasPending := s.OldestPendingAge(time.Now())
	if !hasPending {
		t.Fatal("an unparseable pending file must still report hasPending=true, not disappear from the signal")
	}
	if age < 24*time.Hour {
		t.Errorf("age = %v, want a large conservative age (assumed stale), not something small enough to look fresh", age)
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

// --- Durability (fsync) tests: issue #13 -----------------------------------

func noopForward(ctx context.Context, payload []byte) error { return nil }

// TestEnqueue_FsyncsFileThenDirectory pins the headline durability claim of
// this change: by default, Enqueue must fsync the temp file's contents
// before the rename AND fsync the parent directory after it - in that
// order - so a 202 Accepted actually means the signal survives a host
// power loss, not just a process crash. It substitutes observing stubs for
// both sync points (following the pattern internal/auditlog and
// cmd/gateway/sink.go already use for their syncDir field) rather than
// trying to infer real fsync behavior from the filesystem, which isn't
// reliably observable from a test at all.
func TestEnqueue_FsyncsFileThenDirectory(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 100, noopForward, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}

	var events []string
	s.syncFile = func(f *os.File) error {
		events = append(events, "file:"+filepath.Base(f.Name()))
		return f.Sync()
	}
	s.syncDir = func(d string) error {
		events = append(events, "dir:"+d)
		return nil
	}

	if err := s.Enqueue([]byte(`{"sig":1}`)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected exactly 2 sync events, got %d: %v", len(events), events)
	}
	if events[0][:5] != "file:" {
		t.Errorf("expected the first sync event to be the temp file, got %q", events[0])
	}
	if events[1] != "dir:"+dir {
		t.Errorf("expected the second sync event to be the spool directory %q, got %q", dir, events[1])
	}
}

// TestEnqueue_FsyncDisabledSkipsBothSyncPoints verifies the SPOOL_FSYNC=false
// opt-out actually skips fsync entirely (both the file and the directory
// sync points), and that the signal is still enqueued and delivered
// normally without it.
func TestEnqueue_FsyncDisabledSkipsBothSyncPoints(t *testing.T) {
	t.Setenv("SPOOL_FSYNC", "false")

	dir := t.TempDir()
	s, err := New(dir, 100, noopForward, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if s.fsyncEnabled {
		t.Fatal("expected fsyncEnabled=false when SPOOL_FSYNC=false")
	}

	called := false
	s.syncFile = func(f *os.File) error { called = true; return f.Sync() }
	s.syncDir = func(d string) error { called = true; return nil }

	if err := s.Enqueue([]byte(`{"sig":1}`)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if called {
		t.Error("expected neither sync point to be invoked when SPOOL_FSYNC=false")
	}
	if s.Depth() != 1 {
		t.Errorf("expected the signal to still be enqueued, depth=%d", s.Depth())
	}
}

// TestFsyncEnabledFromEnv pins SPOOL_FSYNC's parsing rules: unset or
// unparseable values must fail safe toward fsync-ON (the whole point of
// making it the default), and recognized boolean spellings must be
// honored either way.
func TestFsyncEnabledFromEnv(t *testing.T) {
	tests := []struct {
		name string
		val  string
		want bool
	}{
		{"unset defaults to enabled", "", true},
		{"explicit false", "false", false},
		{"explicit true", "true", true},
		{"explicit 0", "0", false},
		{"explicit 1", "1", true},
		{"garbage fails safe to enabled", "not-a-bool", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SPOOL_FSYNC", tt.val)
			if got := fsyncEnabledFromEnv(); got != tt.want {
				t.Errorf("fsyncEnabledFromEnv() with SPOOL_FSYNC=%q = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

// TestEnqueue_FileFsyncFailureReturnsErrorAndCleansUp covers a failure
// BEFORE rename (the temp file's own fsync fails): Enqueue must return a
// non-nil error (so /process returns a failure status instead of a 202
// promising durability that isn't there), the depth counter must be
// decremented back down (this signal never actually entered the queue),
// and the temp file must be removed - nothing should be left on disk for
// a signal that was never durably committed, matching how the pre-existing
// write/rename failure paths already clean up.
func TestEnqueue_FileFsyncFailureReturnsErrorAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 100, noopForward, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("simulated file fsync failure")
	s.syncFile = func(f *os.File) error { return wantErr }

	err = s.Enqueue([]byte(`{"sig":1}`))
	if err == nil {
		t.Fatal("expected Enqueue to fail when the temp file fsync fails")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected returned error to wrap the fsync error, got: %v", err)
	}
	if s.Depth() != 0 {
		t.Errorf("depth should be decremented back to 0 after a failed enqueue, got %d", s.Depth())
	}

	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, e := range entries {
		if e.Name() != "dead" {
			t.Errorf("expected no leftover files in the spool dir after a file-fsync failure, found %q", e.Name())
		}
	}
}

// TestEnqueue_DirectoryFsyncFailureReturnsErrorButKeepsCommittedSignal
// covers a failure AFTER rename (the directory fsync fails): the signal's
// file already has its final name and its contents are already fsynced,
// so - unlike the pre-rename failure paths - there is nothing safe to roll
// back. Removing the file or decrementing depth here would silently lose
// a signal the queue has already committed to deliver. Enqueue must still
// return a non-nil error (the 202 promise - "this survives a power loss
// right now" - genuinely isn't true yet), but the committed file must
// remain on disk and depth must still count it as pending, so the
// background forwarder can and will still deliver it.
func TestEnqueue_DirectoryFsyncFailureReturnsErrorButKeepsCommittedSignal(t *testing.T) {
	dir := t.TempDir()
	var delivered atomic.Int32
	s, err := New(dir, 100, func(ctx context.Context, payload []byte) error {
		delivered.Add(1)
		return nil
	}, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("simulated directory fsync failure")
	s.syncDir = func(d string) error { return wantErr }

	err = s.Enqueue([]byte(`{"sig":1}`))
	if err == nil {
		t.Fatal("expected Enqueue to fail when the directory fsync fails")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected returned error to wrap the fsync error, got: %v", err)
	}
	if s.Depth() != 1 {
		t.Errorf("depth should still count the committed signal as pending, got %d", s.Depth())
	}

	pending, perr := s.listPending()
	if perr != nil {
		t.Fatal(perr)
	}
	if len(pending) != 1 {
		t.Fatalf("expected the committed signal's file to remain on disk, found %v", pending)
	}

	// The background forwarder must still be able to deliver it, despite
	// Enqueue having reported failure to its caller.
	s.syncDir = func(d string) error { return nil } // repair "disk" for the next new file, doesn't affect the already-renamed one
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, func() bool { return delivered.Load() == 1 })
}

// TestEnqueue_DoesNotHoldMutexAcrossFsync guards the concurrency contract
// CLAUDE.md documents explicitly: the spool's bookkeeping mutex must never
// be held across disk I/O. It substitutes a syncFile stub that blocks on a
// signal, then - WHILE that first Enqueue call is stuck inside the fsync -
// calls Depth() (which takes s.mu) from another goroutine and requires it
// to return promptly. If Enqueue held s.mu across the fsync, Depth() would
// block until the fsync unblocks, and this test would time out.
func TestEnqueue_DoesNotHoldMutexAcrossFsync(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 100, noopForward, isPerm, Hooks{})
	if err != nil {
		t.Fatal(err)
	}

	inFsync := make(chan struct{})
	release := make(chan struct{})
	s.syncFile = func(f *os.File) error {
		close(inFsync)
		<-release
		return f.Sync()
	}

	done := make(chan error, 1)
	go func() { done <- s.Enqueue([]byte(`{"sig":1}`)) }()

	select {
	case <-inFsync:
	case <-time.After(5 * time.Second):
		t.Fatal("Enqueue never reached the fsync stub")
	}

	depthDone := make(chan struct{})
	go func() {
		s.Depth()
		close(depthDone)
	}()
	select {
	case <-depthDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Depth() blocked while Enqueue was inside fsync - the mutex is held across disk I/O")
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
}
