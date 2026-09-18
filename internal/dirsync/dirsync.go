// Package dirsync provides one small primitive: durably fsyncing a
// directory entry after a new file is created inside it.
//
// WHY THIS EXISTS: fsyncing a file's own contents (File.Sync) only makes
// the FILE'S DATA durable. On most POSIX filesystems, the directory entry
// that makes the file discoverable at all (the name -> inode link) is a
// separate piece of metadata, durable only once the DIRECTORY itself has
// been fsynced. Under a clean process crash this is invisible - the OS
// page cache still has both pieces of state and nothing is lost. It only
// shows up under a host power loss / hard reset: the file's bytes can have
// reached the physical disk while the directory entry that names it did
// not, so a newly created file can simply vanish (or the directory
// silently reverts to a state where the file never existed) even though
// its contents were durably written. Appending to a file that already has
// a durable directory entry does not have this problem, so this package
// is deliberately only ever called on file CREATION, not on every write -
// see the callers (internal/auditlog.Logger.Record, cmd/gateway's
// localSink.Forward) for how that "only on creation" decision is made.
//
// PLATFORM SCOPE (deliberate, not an oversight): this package targets
// exactly what this project targets. The Dockerfile builds for
// linux/amd64, CI runs on Linux, and development happens on macOS
// (darwin) - see CLAUDE.md. On both of those, opening a directory with
// os.Open and calling File.Sync on it is a well-supported way to fsync a
// directory's metadata. Windows is explicitly out of scope: os.Open on a
// directory fails outright on Windows before Sync is even reached, and
// this project never builds or ships for it. Rather than adding untested,
// unverifiable branching to paper over a platform this project doesn't
// run on, Sync documents the assumption plainly here and lets the error
// from the underlying os call surface like any other I/O error would.
// If this project ever needs to target Windows, that's a deliberate,
// separate piece of work, not a silent degrade bolted on here.
//
// On darwin specifically, this is stronger than a plain POSIX fsync:
// Go's os.File.Sync on darwin issues fcntl(F_FULLFSYNC), which asks the
// drive to flush its own write cache, not just hand the data to the OS -
// so on the platform this project is developed on, Sync's durability
// guarantee is actually tighter than "reached the OS", genuinely reaching
// stable storage.
//
// RESIDUAL CRASH WINDOW (narrowed, not eliminated): this package narrows
// the gap it exists to close; it does not close it completely, and
// callers/readers of this PR should not assume otherwise. If the process
// or host crashes / loses power after OpenAppendFile atomically creates a
// new file but before the caller's subsequent Sync call returns, that
// file's directory entry is not yet durably fsynced - and on restart,
// since the file now exists on disk, OpenAppendFile's O_EXCL check will
// (correctly) report created=false for it, so nothing will ever call Sync
// for that specific entry again. Before this package existed, the
// un-fsynced window was the entire life of every day file, unconditionally
// (from creation until the file was eventually removed/rotated); with this
// package, it is a few instructions, once per day file, immediately after
// creation. In practice it also tends to self-heal, though nothing in this
// package GUARANTEES that: Sync fsyncs the whole directory inode, not just
// one entry, so the next day-rollover's directory fsync in the same
// directory flushes any earlier stale entry too, and journaling
// filesystems commit directory metadata periodically on their own
// regardless of an explicit fsync. Fully closing this window would need a
// pending-create journal (write an intent record, create the file, fsync
// the directory, clear the intent record, replay on restart) - machinery
// disproportionate to how narrow this residual window already is;
// deliberately not implemented here.
package dirsync

import (
	"errors"
	"io/fs"
	"os"
)

// Sync fsyncs the directory at dir, so a file just created inside it has a
// durable directory entry (name -> inode link) surviving a host power
// loss, not just durable contents.
//
// Sync returns any error it encounters (opening the directory, or the
// fsync itself) rather than swallowing it. Callers must NOT treat a
// directory-fsync failure as a soft, ignorable condition: the whole point
// of this package is that a "successful" write without it can silently
// vanish. Concretely, both current callers (internal/auditlog.Logger.Record
// and cmd/gateway's localSink.Forward) propagate this error up to their own
// caller exactly like a data-fsync failure, which - per
// cmd/gateway/audit.go's documented choice - means "delivery not
// confirmed", triggering a retry (and possibly a duplicate delivery)
// rather than silently losing or under-reporting the signal. A duplicate
// is the accepted cost; a signal that left the bank with no durable
// record of it is not.
func Sync(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// OpenAppendFile opens path for appending, atomically creating it if (and
// only if) it does not already exist, and reports whether THIS call is
// the one that created it.
//
// This is deliberately a single O_EXCL-first open rather than a separate
// os.Stat followed by a plain O_CREATE|O_APPEND open. A Stat-then-Open
// sequence has a window between the two calls in which another writer -
// another process sharing this directory (e.g. a second gateway instance
// scaled out against a shared volume), or any external actor such as a
// backup or rotation script touching the directory - can create the file
// first. The dangerous ordering is: writer A's create makes the dirent
// visible before A calls Sync on the directory; writer B's Stat then
// observes the file already exists and (correctly, from its own
// perspective) concludes it is not responsible for the directory fsync.
// If A then dies before its own Sync completes, NO ONE ever fsyncs that
// directory entry - reintroducing this package's whole reason for
// existing, via two writers instead of one. The project's deployment
// model is single-container today (see CLAUDE.md's Architecture section),
// so this race is not reachable in the documented topology, but nothing
// in code enforces single-writer, so it would otherwise be a silent
// hazard the moment that assumption changed. Using O_EXCL makes
// "create the file" and "determine whether I created it" one atomic
// kernel operation instead of two racing ones, closing the window
// entirely regardless of how many writers share the directory.
//
// perm is applied only on the creating path; the fallback (appending to a
// file that already existed) uses whatever mode the file already has,
// exactly as a plain O_APPEND open would.
func OpenAppendFile(path string, perm os.FileMode) (f *os.File, created bool, err error) {
	f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, perm)
	if err == nil {
		return f, true, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, false, err
	}

	// Another writer won the race to create it (or it already existed
	// from an earlier run) - append to it without O_CREATE, so this path
	// can never itself create the file and can never be mistaken for the
	// creator.
	f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return nil, false, err
	}
	return f, false, nil
}
