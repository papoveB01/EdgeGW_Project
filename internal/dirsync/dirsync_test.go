package dirsync

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSync_SucceedsOnOrdinaryDirectory is a smoke test: against a normal,
// writable directory (what this package actually runs against in
// production - see the package doc's platform scope), Sync must succeed
// and must not modify or remove anything in the directory.
func TestSync_SucceedsOnOrdinaryDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("setup write: %v", err)
	}

	if err := Sync(dir); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "file.txt" {
		t.Errorf("directory contents changed by Sync: %v", entries)
	}
}

// TestSync_ReturnsErrorForMissingDirectory pins the "propagate, never
// swallow" contract described in the package doc: a directory that
// doesn't exist (or any other os.Open failure) must come back as a
// non-nil error, not a silent success.
func TestSync_ReturnsErrorForMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	if err := Sync(dir); err == nil {
		t.Fatal("expected Sync against a missing directory to return an error")
	}
}

// TestOpenAppendFile_FirstCallCreates checks the straightforward case: a
// path that doesn't exist yet is created, and created=true is reported.
func TestOpenAppendFile_FirstCallCreates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.ndjson")

	f, created, err := OpenAppendFile(path, 0o600)
	if err != nil {
		t.Fatalf("OpenAppendFile: %v", err)
	}
	defer f.Close()

	if !created {
		t.Error("expected created=true for a path that did not previously exist")
	}
	if info, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("stat: %v", statErr)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file perm = %o, want 0600", perm)
	}
}

// TestOpenAppendFile_FallbackAppendsNotTruncates is the required test for
// the O_EXCL-first construction: a second call against a path that
// already has content must report created=false AND must append to the
// existing content, never truncate or recreate it. This is the exact
// property that matters for both auditlog.Logger.Record and
// localSink.Forward — losing prior records on a same-day reopen would be
// its own durability bug, arguably worse than the one this PR fixes.
func TestOpenAppendFile_FallbackAppendsNotTruncates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.ndjson")

	f1, created1, err := OpenAppendFile(path, 0o600)
	if err != nil {
		t.Fatalf("OpenAppendFile (first): %v", err)
	}
	if !created1 {
		t.Fatal("expected created=true on first call")
	}
	if _, err := f1.WriteString("line-one\n"); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := f1.Sync(); err != nil {
		t.Fatalf("sync first: %v", err)
	}
	if err := f1.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}

	f2, created2, err := OpenAppendFile(path, 0o600)
	if err != nil {
		t.Fatalf("OpenAppendFile (second, existing file): %v", err)
	}
	defer f2.Close()
	if created2 {
		t.Error("expected created=false when the file already existed")
	}
	if _, err := f2.WriteString("line-two\n"); err != nil {
		t.Fatalf("write second: %v", err)
	}
	if err := f2.Sync(); err != nil {
		t.Fatalf("sync second: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readfile: %v", err)
	}
	want := "line-one\nline-two\n"
	if string(got) != want {
		t.Errorf("file contents = %q, want %q (fallback must append, not truncate or recreate)", got, want)
	}
}

// TestOpenAppendFile_MissingParentDirReturnsError pins that a genuine
// open failure (parent directory doesn't exist) is returned as an error,
// not silently swallowed on either the create or fallback path.
func TestOpenAppendFile_MissingParentDirReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-subdir", "file.ndjson")
	if _, _, err := OpenAppendFile(path, 0o600); err == nil {
		t.Fatal("expected an error when the parent directory doesn't exist")
	}
}
