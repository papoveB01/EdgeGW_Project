// Package auditlog provides a durable, append-only, per-signal record of
// CONFIRMED egress deliveries — proof of what actually left the bank.
//
// This is deliberately a separate artifact from internal/spool's delivery
// queue. The spool is a queue, not a ledger: spool.forwardOldest calls
// os.Remove on a signal's file the instant delivery succeeds, so the
// spool's on-disk state is evidence of what has NOT yet been delivered (or
// permanently failed and was dead-lettered) — never evidence of what
// succeeded. Without this package, nothing durable records a successful
// delivery, and a question like "show me everything you sent this vendor
// last quarter" cannot be answered once a signal's spool file is gone.
//
// A Logger must only be written to AFTER a destination has confirmed
// delivery of the exact bytes recorded — never at enqueue or attempt time.
// See cmd/gateway's auditingForward and auditingSyncForward for the call
// sites, and their doc comments for the deliberate failure-semantics choice
// (prefer a duplicate delivery over a missing audit record).
//
// Records are newline-delimited JSON, one file per UTC day, fsynced before
// Record returns — the same convention cmd/gateway/sink.go already
// establishes for the standalone destination, kept consistent here rather
// than inventing a second one. This package does not rotate, compress or
// expire records; like the standalone sink, retention is the operator's
// responsibility (see README).
//
// Beyond fsyncing the data file, Record also fsyncs the parent directory —
// but ONLY at the moment a new day file is created, never on ordinary
// appends. A file's own fsync makes its contents durable but does not, by
// itself, guarantee the directory entry naming that file is durable too;
// under a host power loss (not a process crash) a brand-new file can
// vanish even though its bytes reached disk. See internal/dirsync's doc
// comment for the full explanation, the deliberate "creation only, not
// every append" scope, and the deliberate platform assumption (Linux and
// macOS, matching this project's build/dev targets — not Windows).
package auditlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/dirsync"
)

// Record is one durable audit entry: proof that a specific signal left the
// bank and was accepted by its destination.
type Record struct {
	// Timestamp is when delivery was CONFIRMED (ISO-8601 / RFC 3339, UTC,
	// nanosecond precision) — not when the signal was enqueued or first
	// attempted.
	Timestamp string `json:"timestamp"`
	// Destination identifies where the signal went: the vendor URL in
	// middleware mode, or a "local-sink:<dir>" identifier in standalone
	// mode. Callers pass a fixed, resolved-at-startup value.
	Destination string `json:"destination"`
	// SignalID is the per-event join key added in PR #1
	// (processor.AnonymizedSignal.SignalID) — not the person's identity
	// mosaic, which is deliberately NOT recorded here since it is not
	// needed to answer "what did we send" and duplicating it doubles the
	// re-identification surface of this file for no audit benefit.
	SignalID string `json:"signal_id"`
	// MosaicVersion / FeatureVersion / MosaicScope / MosaicBasis are
	// copied from the delivered signal so an auditor can tell which
	// derivation and feature contract produced it without
	// cross-referencing anything else. MosaicScope and MosaicBasis are
	// orthogonal (processor.ScopeBank/ScopeRegional and
	// processor.BasisNationalID/BasisInternalIDFallback as of mosaic
	// v3): scope is WHICH SECRET keyed the mosaic (so whether it's valid
	// to compare across institutions), basis is WHAT IDENTIFIER produced
	// it (so how stable/reliable it is). Recording scope but silently
	// omitting basis would leave exactly the kind of evidentiary gap
	// this audit log exists to prevent.
	MosaicVersion  int    `json:"mosaic_version"`
	FeatureVersion int    `json:"feature_version"`
	MosaicScope    string `json:"mosaic_scope"`
	MosaicBasis    string `json:"mosaic_basis"`
	// PayloadSHA256 is the hex-encoded SHA-256 digest of the EXACT bytes
	// delivered to the destination — durable proof of WHAT was sent
	// without necessarily storing a second copy of it.
	PayloadSHA256 string `json:"payload_sha256"`
	// PayloadBytes is the length of the delivered payload in bytes, useful
	// as a sanity check even when the payload itself isn't stored.
	PayloadBytes int `json:"payload_bytes"`
	// Payload is the full delivered payload, present only when the Logger
	// was configured to store it (see New's storePayload parameter). This
	// is opt-in and defaults to off: the payload is pseudonymized but is
	// still personal data, and a second copy of it is a second liability.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Logger appends audit records to per-UTC-day, newline-delimited-JSON files
// under dir, fsyncing every write. A Logger is safe for concurrent use.
type Logger struct {
	dir          string
	storePayload bool

	// mu guards the currently-open file handle. It is held across the
	// write+fsync below, the same way cmd/gateway/sink.go's per-file mutex
	// is: unlike internal/spool's bookkeeping mutex (which callers must
	// never hold across forward/disk calls), this lock exists specifically
	// to serialize concurrent writers onto one shared file descriptor, so
	// holding it across the write to that fd is the correct and only
	// option, not an oversight.
	mu  sync.Mutex
	day string
	f   *os.File

	// syncDir performs the parent-directory fsync described in the package
	// doc comment. It defaults to dirsync.Sync (the real implementation)
	// but is a field — rather than a direct dirsync.Sync call — so tests
	// in this package can substitute an observing stub and assert exactly
	// when it is (and is not) invoked, without trying to infer fsync
	// behavior from filesystem introspection, which isn't reliably
	// observable from a test at all.
	syncDir func(dir string) error
}

// New opens (creating if needed) the directory audit records are written
// under, and verifies it is actually writable before returning. storePayload
// controls whether Record embeds the full delivered payload (opt-in) or only
// its digest (the default) — see Record.Payload.
//
// The directory is created 0o700, not sink.go's 0o755: these records are
// personal data (pseudonymized, but still), this is the durable, retained
// copy (unlike the spool, which deletes on success), and nothing requires
// group/other to even list the directory. If sink.go's 0o755 is considered
// acceptable, that is worth revisiting too — see the PR description.
func New(dir string, storePayload bool) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create audit log dir: %w", err)
	}
	if err := probeWritable(dir); err != nil {
		return nil, fmt.Errorf("audit log directory %q is not writable: %w", dir, err)
	}
	return &Logger{dir: dir, storePayload: storePayload, syncDir: dirsync.Sync}, nil
}

// probeWritable verifies dir can actually be written to and fsynced.
// os.MkdirAll succeeding only proves the directory exists (or already did)
// — a read-only bind mount, wrong ownership, or a full filesystem all pass
// MkdirAll silently on an already-existing directory and would otherwise
// only be discovered at the first CONFIRMED delivery, by which point the
// destination has already accepted the signal: exactly the situation this
// package exists to prevent. Callers (cmd/gateway's main) already
// os.Exit(1) when New returns an error, so this makes a misconfigured
// EGRESS_AUDIT_DIR fail fast at startup, the same as every other required
// config, rather than at the first delivery.
func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".audit-writability-probe-*")
	if err != nil {
		return fmt.Errorf("failed to create probe file: %w", err)
	}
	name := f.Name()
	defer os.Remove(name)

	if _, err := f.Write([]byte("ok")); err != nil {
		f.Close()
		return fmt.Errorf("failed to write probe file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to fsync probe file: %w", err)
	}
	return f.Close()
}

// Record durably appends one audit entry for a CONFIRMED delivery. Callers
// must only call Record after the destination has accepted payload —
// never speculatively.
//
// deliveredAt is accepted as a parameter (rather than this function calling
// time.Now() itself) so tests can assert exact timestamps and exercise
// day-rollover deterministically.
//
// Record fsyncs before returning, so a record is only ever durable once
// this call returns nil — mirroring sink.go's Forward. A non-nil error
// means the record is NOT durably written; see cmd/gateway's
// auditingForward for how callers must react to that (retry, accepting a
// possible duplicate delivery, rather than silently treating the confirmed
// delivery as fully accounted for).
func (l *Logger) Record(destination, signalID string, mosaicVersion, featureVersion int, mosaicScope, mosaicBasis string, payload []byte, deliveredAt time.Time) error {
	digest := sha256.Sum256(payload)
	rec := Record{
		Timestamp:      deliveredAt.UTC().Format(time.RFC3339Nano),
		Destination:    destination,
		SignalID:       signalID,
		MosaicVersion:  mosaicVersion,
		FeatureVersion: featureVersion,
		MosaicScope:    mosaicScope,
		MosaicBasis:    mosaicBasis,
		PayloadSHA256:  hex.EncodeToString(digest[:]),
		PayloadBytes:   len(payload),
	}
	if l.storePayload {
		// payload is caller-owned bytes; json.RawMessage embeds it as-is
		// (it is already the valid JSON the destination received) rather
		// than re-encoding it as a quoted string.
		rec.Payload = json.RawMessage(payload)
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to encode audit record: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	day := deliveredAt.UTC().Format("2006-01-02")
	if l.f == nil || l.day != day {
		if l.f != nil {
			l.f.Close()
		}
		path := filepath.Join(l.dir, "audit-"+day+".ndjson")

		// Determine BEFORE opening whether this call is about to create a
		// new file, so the directory fsync below only fires on creation,
		// never on an ordinary re-open of a day file that already exists
		// (e.g. a process restart on the same UTC day). If Stat fails for
		// any reason other than "doesn't exist" (permission error, races,
		// etc.), fail safe toward treating it as a possible creation
		// rather than skipping a directory fsync that might be needed —
		// the extra fsync is cheap once per day file; a missed one is not.
		_, statErr := os.Stat(path)
		creating := statErr != nil

		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			l.f = nil
			return fmt.Errorf("failed to open audit log file: %w", err)
		}
		l.f = f
		l.day = day

		if creating {
			// A failed directory fsync here must NOT be swallowed: this
			// function has not yet written or synced the record, so
			// returning early with a non-nil error simply means the
			// caller (cmd/gateway's auditingForward /
			// auditingSyncForward) treats this exactly like any other
			// Record failure — "audit record failed to write" — which
			// per their documented failure semantics means "not durable
			// yet", triggering a retry (and possibly a duplicate
			// delivery) rather than silently losing the record. See
			// internal/dirsync's doc comment and cmd/gateway/audit.go's
			// auditingForward doc comment for the full reasoning.
			if err := l.syncDir(l.dir); err != nil {
				return fmt.Errorf("failed to fsync audit log directory after creating new day file: %w", err)
			}
		}
	}

	if _, err := l.f.Write(line); err != nil {
		return fmt.Errorf("failed to write audit record: %w", err)
	}
	return l.f.Sync()
}

// Close releases the currently open audit log file, if any.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		err := l.f.Close()
		l.f = nil
		return err
	}
	return nil
}
