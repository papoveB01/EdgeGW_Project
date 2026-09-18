package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalSink_WritesWhatItReceived(t *testing.T) {
	dir := t.TempDir()
	sink, err := newLocalSink(dir)
	if err != nil {
		t.Fatalf("newLocalSink: %v", err)
	}
	t.Cleanup(func() { sink.Close() })

	payloads := [][]byte{
		[]byte(`{"identity_mosaic":"abc","amount_tier":"TIER_1"}`),
		[]byte(`{"identity_mosaic":"def","amount_tier":"TIER_2"}`),
	}
	for _, p := range payloads {
		if err := sink.Forward(context.Background(), p); err != nil {
			t.Fatalf("Forward: %v", err)
		}
	}

	wantFile := filepath.Join(dir, "signals-"+time.Now().UTC().Format("2006-01-02")+".ndjson")
	f, err := os.Open(wantFile)
	if err != nil {
		t.Fatalf("expected sink file %s to exist: %v", wantFile, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanning sink file: %v", err)
	}

	if len(lines) != len(payloads) {
		t.Fatalf("expected %d lines, got %d: %v", len(payloads), len(lines), lines)
	}
	for i, line := range lines {
		var got, want map[string]interface{}
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i, err)
		}
		if err := json.Unmarshal(payloads[i], &want); err != nil {
			t.Fatalf("fixture %d not valid JSON: %v", i, err)
		}
		if got["identity_mosaic"] != want["identity_mosaic"] {
			t.Errorf("line %d: got mosaic %v, want %v", i, got["identity_mosaic"], want["identity_mosaic"])
		}
	}
}

func TestLocalSink_CreatesDirIfMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "sink")
	sink, err := newLocalSink(dir)
	if err != nil {
		t.Fatalf("newLocalSink: %v", err)
	}
	t.Cleanup(func() { sink.Close() })

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("expected sink dir to be created: %v", err)
	}
}

func TestLocalSink_MultipleForwardsAppendNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	sink, err := newLocalSink(dir)
	if err != nil {
		t.Fatalf("newLocalSink: %v", err)
	}
	t.Cleanup(func() { sink.Close() })

	const n = 50
	for i := 0; i < n; i++ {
		if err := sink.Forward(context.Background(), []byte(`{"n":`+string(rune('0'+i%10))+`}`)); err != nil {
			t.Fatalf("Forward %d: %v", i, err)
		}
	}

	wantFile := filepath.Join(dir, "signals-"+time.Now().UTC().Format("2006-01-02")+".ndjson")
	data, err := os.ReadFile(wantFile)
	if err != nil {
		t.Fatalf("reading sink file: %v", err)
	}
	f, err := os.Open(wantFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	lineCount := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineCount++
	}
	if lineCount != n {
		t.Errorf("expected %d lines, got %d (raw: %d bytes)", n, lineCount, len(data))
	}
}

// TestLocalSink_SyncsParentDirOnlyOnNewFileCreation is the key durability
// test for issue #8: Forward must fsync the parent directory exactly once
// per newly created day file, and must NOT fsync it again on subsequent
// appends to that same file (that would be pure write amplification on
// the hot path with no durability benefit — an append changes only the
// file's own contents, already covered by the existing data fsync).
//
// It substitutes an observing stub for localSink.syncDir rather than
// trying to infer real fsync behavior from the filesystem, which isn't
// reliably observable from a test at all.
func TestLocalSink_SyncsParentDirOnlyOnNewFileCreation(t *testing.T) {
	dir := t.TempDir()
	sink, err := newLocalSink(dir)
	if err != nil {
		t.Fatalf("newLocalSink: %v", err)
	}
	t.Cleanup(func() { sink.Close() })

	var syncedDirs []string
	sink.syncDir = func(d string) error {
		syncedDirs = append(syncedDirs, d)
		return nil
	}

	// First Forward call of the (test-run) day: creates the day file ->
	// exactly one directory fsync.
	if err := sink.Forward(context.Background(), []byte(`{"n":0}`)); err != nil {
		t.Fatalf("Forward 1: %v", err)
	}
	if got := len(syncedDirs); got != 1 {
		t.Fatalf("after creating the day file: directory fsync count = %d, want 1", got)
	}

	// Further appends to the same day file must NOT add any more
	// directory fsyncs.
	for i := 0; i < 5; i++ {
		if err := sink.Forward(context.Background(), []byte(`{"n":1}`)); err != nil {
			t.Fatalf("Forward append %d: %v", i, err)
		}
	}
	if got := len(syncedDirs); got != 1 {
		t.Fatalf("after 5 appends to the existing day file: directory fsync count = %d, want still 1", got)
	}
	if syncedDirs[0] != dir {
		t.Errorf("syncDir called with %q, want %q", syncedDirs[0], dir)
	}
}

// TestLocalSink_ReopeningExistingDayFileDoesNotResync covers the "process
// restart on the same UTC day" case: a fresh localSink opening a day file
// that ALREADY EXISTS on disk (created by a previous sink instance) must
// not fsync the directory again — that file's directory entry is already
// durable from when it was first created.
func TestLocalSink_ReopeningExistingDayFileDoesNotResync(t *testing.T) {
	dir := t.TempDir()

	sink1, err := newLocalSink(dir)
	if err != nil {
		t.Fatalf("newLocalSink (first process): %v", err)
	}
	if err := sink1.Forward(context.Background(), []byte(`{"n":0}`)); err != nil {
		t.Fatalf("Forward (first process): %v", err)
	}
	if err := sink1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sink2, err := newLocalSink(dir)
	if err != nil {
		t.Fatalf("newLocalSink (second process): %v", err)
	}
	t.Cleanup(func() { sink2.Close() })

	var syncedDirs []string
	sink2.syncDir = func(d string) error {
		syncedDirs = append(syncedDirs, d)
		return nil
	}

	if err := sink2.Forward(context.Background(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("Forward (second process, same day file): %v", err)
	}
	if got := len(syncedDirs); got != 0 {
		t.Errorf("reopening an already-existing day file triggered %d directory fsync(s), want 0", got)
	}
}

// TestLocalSink_DirectoryFsyncFailureIsNotSwallowed pins the
// failure-semantics requirement from the PR: a directory-fsync failure on
// new-file creation must propagate as a non-nil error from Forward,
// exactly like any other Forward failure, so callers (spool.forwardOldest
// in async mode, or auditingSyncForward / processTransaction directly in
// sync mode) treat the signal as NOT delivered and retry — never silently
// treated as success.
func TestLocalSink_DirectoryFsyncFailureIsNotSwallowed(t *testing.T) {
	dir := t.TempDir()
	sink, err := newLocalSink(dir)
	if err != nil {
		t.Fatalf("newLocalSink: %v", err)
	}
	t.Cleanup(func() { sink.Close() })

	wantErr := errors.New("simulated directory fsync failure")
	sink.syncDir = func(d string) error { return wantErr }

	err = sink.Forward(context.Background(), []byte(`{"n":0}`))
	if err == nil {
		t.Fatal("expected Forward to return an error when the directory fsync fails, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected returned error to wrap the directory fsync error, got: %v", err)
	}
}
