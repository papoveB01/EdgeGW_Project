package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/dirsync"
)

// localSink is the standalone-mode delivery destination: in a topology with
// no external vendor platform, "forward" means "durably persist for the
// bank's own later use" rather than POST somewhere. internal/spool has no
// knowledge that a destination is normally HTTP - it just calls the
// spool.ForwardFunc it was given - so this needs no change to that package
// at all; localSink.Forward is a drop-in ForwardFunc.
//
// Signals are appended as newline-delimited JSON, one file per UTC day, so a
// long-running deployment doesn't grow one unbounded file and operators can
// rotate/archive/delete old days independently.
type localSink struct {
	dir string

	mu  sync.Mutex
	day string
	f   *os.File

	// syncDir performs the parent-directory fsync described in Forward's
	// doc comment, run only when Forward is about to create a new day
	// file. It defaults to dirsync.Sync but is a field so tests can
	// substitute an observing stub and assert exactly when it fires,
	// rather than trying to infer fsync behavior via filesystem
	// introspection.
	syncDir func(dir string) error
}

// newLocalSink opens (creating if needed) the directory signals are written
// under.
func newLocalSink(dir string) (*localSink, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create sink dir: %w", err)
	}
	return &localSink{dir: dir, syncDir: dirsync.Sync}, nil
}

// Forward implements spool.ForwardFunc, and is also called directly for
// synchronous delivery when no spool is configured. It appends one
// newline-delimited JSON record and fsyncs before returning, so a signal is
// only ever reported "delivered" once it is actually durable on disk -
// signals must not silently disappear the way they did against an
// unreachable placeholder Hub URL.
//
// Beyond fsyncing the data file, Forward also fsyncs the parent directory —
// but ONLY at the moment a new day file is created, never on ordinary
// appends to a day file that already exists. A file's own fsync makes its
// contents durable but does not, by itself, guarantee the directory entry
// naming that file is durable too; under a host power loss (not a process
// crash) a brand-new file can vanish even though its bytes reached disk.
// See internal/dirsync's doc comment for the full explanation and the
// deliberate platform assumption (Linux and macOS, matching this project's
// build/dev targets — not Windows). A failed directory fsync is returned
// as an error rather than swallowed, exactly like the existing data-fsync
// failure just below: this func's caller (spool.forwardOldest, or
// auditingSyncForward / processTransaction directly in sync mode) treats a
// non-nil error as "not delivered", causing a retry — consistent with
// cmd/gateway/audit.go's documented "prefer a duplicate over a silent
// gap" choice for the sibling audit-log write path.
func (s *localSink) Forward(_ context.Context, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	day := time.Now().UTC().Format("2006-01-02")
	if s.f == nil || s.day != day {
		if s.f != nil {
			s.f.Close()
		}
		path := filepath.Join(s.dir, "signals-"+day+".ndjson")

		// dirsync.OpenAppendFile atomically determines, via O_EXCL, both
		// whether this call is about to create a new file AND creates it
		// in the same syscall — see its doc comment for why a separate
		// os.Stat-then-Open here would be racy across multiple writers
		// sharing this directory (not this project's deployment model
		// today, but not something this code should silently assume
		// either).
		f, creating, err := dirsync.OpenAppendFile(path, 0o600)
		if err != nil {
			s.f = nil
			return fmt.Errorf("failed to open sink file: %w", err)
		}
		s.f = f
		s.day = day

		if creating {
			if err := s.syncDir(s.dir); err != nil {
				return fmt.Errorf("failed to fsync sink directory after creating new day file: %w", err)
			}
		}
	}

	line := make([]byte, 0, len(payload)+1)
	line = append(line, payload...)
	line = append(line, '\n')
	if _, err := s.f.Write(line); err != nil {
		return fmt.Errorf("failed to write signal to sink: %w", err)
	}
	return s.f.Sync()
}

// Close releases the currently open sink file, if any.
func (s *localSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		err := s.f.Close()
		s.f = nil
		return err
	}
	return nil
}
