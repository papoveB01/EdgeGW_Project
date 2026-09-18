package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
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
}

// newLocalSink opens (creating if needed) the directory signals are written
// under.
func newLocalSink(dir string) (*localSink, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create sink dir: %w", err)
	}
	return &localSink{dir: dir}, nil
}

// Forward implements spool.ForwardFunc, and is also called directly for
// synchronous delivery when no spool is configured. It appends one
// newline-delimited JSON record and fsyncs before returning, so a signal is
// only ever reported "delivered" once it is actually durable on disk -
// signals must not silently disappear the way they did against an
// unreachable placeholder Hub URL.
func (s *localSink) Forward(_ context.Context, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	day := time.Now().UTC().Format("2006-01-02")
	if s.f == nil || s.day != day {
		if s.f != nil {
			s.f.Close()
		}
		path := filepath.Join(s.dir, "signals-"+day+".ndjson")
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			s.f = nil
			return fmt.Errorf("failed to open sink file: %w", err)
		}
		s.f = f
		s.day = day
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
