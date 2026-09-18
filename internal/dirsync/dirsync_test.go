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
