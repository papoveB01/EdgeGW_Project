package auditlog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return lines
}

// TestRecord_DigestMatchesKnownBytes pins the digest algorithm against a
// hand-computed SHA-256 sum, so a future change to what's hashed (e.g.
// hashing something other than the exact delivered bytes) is caught even
// though the written record is opaque to a casual reader.
func TestRecord_DigestMatchesKnownBytes(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	payload := []byte(`{"signal_id":"abc-123","mosaic_scope":"local"}`)
	sum := sha256.Sum256(payload)
	wantDigest := hex.EncodeToString(sum[:])

	deliveredAt := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	if err := l.Record("https://vendor.example/signals", "abc-123", 2, 1, "local", "national_id", payload, deliveredAt); err != nil {
		t.Fatalf("Record: %v", err)
	}

	path := filepath.Join(dir, "audit-2026-03-15.ndjson")
	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d: %v", len(lines), lines)
	}

	var rec Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	if rec.PayloadSHA256 != wantDigest {
		t.Errorf("digest mismatch: got %s, want %s", rec.PayloadSHA256, wantDigest)
	}
	if rec.PayloadBytes != len(payload) {
		t.Errorf("payload bytes mismatch: got %d, want %d", rec.PayloadBytes, len(payload))
	}
	if rec.Timestamp != "2026-03-15T12:00:00Z" {
		t.Errorf("unexpected timestamp: %s", rec.Timestamp)
	}
	if rec.SignalID != "abc-123" || rec.MosaicVersion != 2 || rec.FeatureVersion != 1 || rec.MosaicScope != "local" || rec.MosaicBasis != "national_id" {
		t.Errorf("unexpected record fields: %+v", rec)
	}
	if len(rec.Payload) != 0 {
		t.Errorf("expected no payload stored (storePayload=false), got %s", rec.Payload)
	}
}

// TestRecord_PayloadOptIn verifies the default is digest-only and that the
// full payload appears only when explicitly requested.
func TestRecord_PayloadOptIn(t *testing.T) {
	tests := []struct {
		name         string
		storePayload bool
		wantPayload  bool
	}{
		{name: "default digest-only", storePayload: false, wantPayload: false},
		{name: "explicit opt-in stores payload", storePayload: true, wantPayload: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			l, err := New(dir, tt.storePayload)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { l.Close() })

			payload := []byte(`{"signal_id":"x","mosaic_scope":"local"}`)
			deliveredAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			if err := l.Record("dest", "x", 2, 1, "local", "national_id", payload, deliveredAt); err != nil {
				t.Fatalf("Record: %v", err)
			}

			path := filepath.Join(dir, "audit-2026-01-01.ndjson")
			lines := readLines(t, path)
			var rec Record
			if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			gotPayload := len(rec.Payload) != 0
			if gotPayload != tt.wantPayload {
				t.Errorf("payload present = %v, want %v (raw: %s)", gotPayload, tt.wantPayload, rec.Payload)
			}
			if tt.wantPayload {
				var got map[string]interface{}
				if err := json.Unmarshal(rec.Payload, &got); err != nil {
					t.Fatalf("stored payload not valid JSON: %v", err)
				}
				if got["signal_id"] != "x" {
					t.Errorf("stored payload mismatch: %v", got)
				}
			}
		})
	}
}

// TestRecord_SurvivesRestart simulates a process restart: records written
// by one Logger must be readable after that Logger is closed and a fresh
// Logger (as main() would construct on the next start) is opened against
// the same directory, and new records must append rather than clobber.
func TestRecord_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	deliveredAt := time.Date(2026, 6, 1, 9, 30, 0, 0, time.UTC)

	l1, err := New(dir, false)
	if err != nil {
		t.Fatalf("New (first process): %v", err)
	}
	if err := l1.Record("dest", "sig-1", 2, 1, "local", "national_id", []byte(`{"signal_id":"sig-1"}`), deliveredAt); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := l1.Close(); err != nil {
		t.Fatalf("Close (simulated crash/restart point): %v", err)
	}

	// Simulate restart: a brand-new Logger, same dir, no shared state.
	l2, err := New(dir, false)
	if err != nil {
		t.Fatalf("New (second process): %v", err)
	}
	t.Cleanup(func() { l2.Close() })
	if err := l2.Record("dest", "sig-2", 2, 1, "local", "national_id", []byte(`{"signal_id":"sig-2"}`), deliveredAt); err != nil {
		t.Fatalf("Record after restart: %v", err)
	}

	path := filepath.Join(dir, "audit-2026-06-01.ndjson")
	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("expected 2 surviving records after restart, got %d: %v", len(lines), lines)
	}
	var first, second Record
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal first: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("unmarshal second: %v", err)
	}
	if first.SignalID != "sig-1" || second.SignalID != "sig-2" {
		t.Errorf("unexpected signal IDs: %s, %s", first.SignalID, second.SignalID)
	}
}

// TestRecord_DayRollover exercises the per-UTC-day file convention shared
// with sink.go: a delivery on one UTC day and one on the next must land in
// two distinct files.
func TestRecord_DayRollover(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	day1 := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC)
	day2 := time.Date(2026, 3, 1, 0, 0, 1, 0, time.UTC)
	if err := l.Record("dest", "sig-day1", 2, 1, "local", "national_id", []byte(`{}`), day1); err != nil {
		t.Fatalf("Record day1: %v", err)
	}
	if err := l.Record("dest", "sig-day2", 2, 1, "local", "national_id", []byte(`{}`), day2); err != nil {
		t.Fatalf("Record day2: %v", err)
	}

	for _, name := range []string{"audit-2026-02-28.ndjson", "audit-2026-03-01.ndjson"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

// TestNew_CreatesDirWithRestrictivePermissions checks the directory is
// created 0o700, not sink.go's 0o755 — these records are personal data and
// (unlike the spool) are the permanent copy.
func TestNew_CreatesDirWithRestrictivePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "audit")
	l, err := New(dir, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("audit dir perm = %o, want 0700", perm)
	}
}

// TestRecord_FilePermissions checks the written file is 0o600.
func TestRecord_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	deliveredAt := time.Date(2026, 4, 4, 4, 4, 4, 0, time.UTC)
	if err := l.Record("dest", "sig", 2, 1, "local", "national_id", []byte(`{}`), deliveredAt); err != nil {
		t.Fatalf("Record: %v", err)
	}

	path := filepath.Join(dir, "audit-2026-04-04.ndjson")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("audit file perm = %o, want 0600", perm)
	}
}

// TestNew_FailsFastOnUnwritableDirectory pins the startup writability probe:
// os.MkdirAll alone would succeed silently against an already-existing but
// read-only directory (e.g. a misconfigured read-only bind mount), and the
// problem would otherwise only surface at the first CONFIRMED delivery -
// after the destination has already accepted the signal. New must instead
// fail immediately, the same way every other required-but-misconfigured
// setting fails at startup rather than at first use.
func TestNew_FailsFastOnUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits don't block root's writes, so this probe can't be exercised")
	}

	parent := t.TempDir()
	dir := filepath.Join(parent, "readonly-audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) }) // so t.TempDir() cleanup can remove it
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err := New(dir, false)
	if err == nil {
		t.Fatal("expected New to fail against a read-only directory, not silently succeed and fail later at first delivery")
	}
}

// TestRecord_SyncsParentDirOnlyOnNewFileCreation is the key durability
// test for this change (issue #8): a directory fsync must happen exactly
// once per newly created day file, and must NOT happen again on
// subsequent appends to that same file, since re-fsyncing the directory on
// every record would be pure write amplification on the hot path with no
// durability benefit (an append doesn't change the directory entry, only
// the file's own contents, which the existing data fsync already covers).
//
// It substitutes an observing stub for Logger.syncDir rather than trying
// to infer real fsync behavior from the filesystem (not reliably
// observable from a test at all), and covers both axes: repeated appends
// within one day, and a rollover to a new day file triggering exactly one
// more directory fsync.
func TestRecord_SyncsParentDirOnlyOnNewFileCreation(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	var syncedDirs []string
	l.syncDir = func(d string) error {
		syncedDirs = append(syncedDirs, d)
		return nil
	}

	day1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	payload := []byte(`{}`)

	// First record of the day: creates audit-2026-05-01.ndjson -> exactly
	// one directory fsync.
	if err := l.Record("dest", "sig-1", 2, 1, "local", "national_id", payload, day1); err != nil {
		t.Fatalf("Record 1: %v", err)
	}
	if got := len(syncedDirs); got != 1 {
		t.Fatalf("after creating the first day file: directory fsync count = %d, want 1", got)
	}

	// Three more appends to the SAME day file: must NOT add any more
	// directory fsyncs.
	for i := 0; i < 3; i++ {
		if err := l.Record("dest", "sig-append", 2, 1, "local", "national_id", payload, day1.Add(time.Duration(i+1)*time.Minute)); err != nil {
			t.Fatalf("Record append %d: %v", i, err)
		}
	}
	if got := len(syncedDirs); got != 1 {
		t.Fatalf("after 3 appends to the existing day file: directory fsync count = %d, want still 1 (no fsync on append)", got)
	}

	// Rolling over to a new UTC day creates a second file -> exactly one
	// more directory fsync (total 2).
	day2 := day1.Add(24 * time.Hour)
	if err := l.Record("dest", "sig-day2", 2, 1, "local", "national_id", payload, day2); err != nil {
		t.Fatalf("Record day2: %v", err)
	}
	if got := len(syncedDirs); got != 2 {
		t.Fatalf("after rolling over to a new day file: directory fsync count = %d, want 2", got)
	}
	for _, d := range syncedDirs {
		if d != dir {
			t.Errorf("syncDir called with %q, want %q", d, dir)
		}
	}
}

// TestRecord_ReopeningExistingDayFileDoesNotResync covers the "process
// restart on the same UTC day" case: a fresh Logger opening a day file
// that ALREADY EXISTS on disk (created by a previous Logger instance, as
// TestRecord_SurvivesRestart exercises for durability) must not fsync the
// directory again — that file's directory entry is already durable from
// when it was first created.
func TestRecord_ReopeningExistingDayFileDoesNotResync(t *testing.T) {
	dir := t.TempDir()
	deliveredAt := time.Date(2026, 5, 2, 8, 0, 0, 0, time.UTC)

	l1, err := New(dir, false)
	if err != nil {
		t.Fatalf("New (first process): %v", err)
	}
	if err := l1.Record("dest", "sig-1", 2, 1, "local", "national_id", []byte(`{}`), deliveredAt); err != nil {
		t.Fatalf("Record (first process): %v", err)
	}
	if err := l1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	l2, err := New(dir, false)
	if err != nil {
		t.Fatalf("New (second process): %v", err)
	}
	t.Cleanup(func() { l2.Close() })

	var syncedDirs []string
	l2.syncDir = func(d string) error {
		syncedDirs = append(syncedDirs, d)
		return nil
	}

	if err := l2.Record("dest", "sig-2", 2, 1, "local", "national_id", []byte(`{}`), deliveredAt.Add(time.Hour)); err != nil {
		t.Fatalf("Record (second process, same day file): %v", err)
	}
	if got := len(syncedDirs); got != 0 {
		t.Errorf("reopening an already-existing day file triggered %d directory fsync(s), want 0", got)
	}
}

// TestRecord_DirectoryFsyncFailureIsNotSwallowed pins the failure-semantics
// requirement from the PR: a directory-fsync failure on new-file creation
// must propagate as a non-nil error from Record, exactly like any other
// Record failure, so callers (cmd/gateway's auditingForward /
// auditingSyncForward) treat the record as NOT durable and retry — never
// silently treated as success.
func TestRecord_DirectoryFsyncFailureIsNotSwallowed(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	wantErr := fmt.Errorf("simulated directory fsync failure")
	l.syncDir = func(d string) error { return wantErr }

	deliveredAt := time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC)
	err = l.Record("dest", "sig-1", 2, 1, "local", "national_id", []byte(`{}`), deliveredAt)
	if err == nil {
		t.Fatal("expected Record to return an error when the directory fsync fails, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected returned error to wrap the directory fsync error, got: %v", err)
	}
}

// TestNew_SucceedsOnWritableDirectory is TestNew_FailsFastOnUnwritableDirectory's
// counterpart: the probe must not be a false positive against an ordinary,
// genuinely writable directory.
func TestNew_SucceedsOnWritableDirectory(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, false)
	if err != nil {
		t.Fatalf("expected New to succeed against a writable directory, got: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	// The probe file must not be left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		t.Errorf("expected no leftover files after New, found %s", e.Name())
	}
}
