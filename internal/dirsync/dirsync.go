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
package dirsync

import "os"

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
