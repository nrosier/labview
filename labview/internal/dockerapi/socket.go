package dockerapi

import (
	"errors"
	"io/fs"
	"os"

	"github.com/nrosier/labview/internal/payload"
)

// SocketState is the four states §10 requires a unix socket to be diagnosed into *before* the HTTP
// client ever sees it. Without the pre-check all four arrive as the same opaque dial failure, and an
// operator is told `connect` for a problem that has nothing to do with a listener.
type SocketState string

const (
	// SocketAbsent — nothing at that path.
	SocketAbsent SocketState = "absent"
	// SocketNotASocket — something is there and it is not a socket. This is the usual cause, and it
	// is worth its own state because Docker itself creates it: binding a host path that does not
	// exist produces an empty *directory* inside the container, so the mount silently succeeds and
	// the socket silently is not there.
	SocketNotASocket SocketState = "not-a-socket"
	// SocketUnreadable — the socket exists and this uid cannot use it. The fix is a group membership,
	// not a listener, which is why §10 classifies this as `authorize`.
	SocketUnreadable SocketState = "unreadable"
	// SocketPresent — a socket, and usable as far as the filesystem is concerned. Whether anything
	// is listening is the dial's business.
	SocketPresent SocketState = "present"
)

// Filesystem is the pre-check's whole access to the filesystem, and the pre-check is the only
// filesystem access this package makes (§10).
//
// It is an interface because otherwise three of the four states are untestable: producing an
// unreadable socket needs a second uid, and producing a real socket needs a listener. A fake here
// costs one type and makes all four reachable in a table.
type Filesystem interface {
	Stat(name string) (fs.FileInfo, error)
	// Usable reports whether this process may read and write the path. It returns an error
	// satisfying fs.ErrPermission when it may not.
	Usable(name string) error
}

// OSFilesystem is the real one.
type OSFilesystem struct{}

func (OSFilesystem) Stat(name string) (fs.FileInfo, error) { return os.Stat(name) }
func (OSFilesystem) Usable(name string) error              { return usable(name) }

// CheckSocket is the pre-check: one stat, then one access test, and nothing else.
//
// It deliberately does not try to connect. A dial is the next step and has its own phase; mixing
// the two would mean a socket that exists and is unusable could be reported as either, depending on
// which check happened to run first.
func CheckSocket(path string, fsys Filesystem) SocketState {
	info, err := fsys.Stat(path)
	switch {
	case err != nil && errors.Is(err, fs.ErrNotExist):
		return SocketAbsent
	case err != nil:
		// A stat that failed for any other reason is a permission problem in all but pathological
		// cases — a directory component this uid cannot traverse produces exactly this.
		return SocketUnreadable
	case info.Mode()&fs.ModeSocket == 0:
		return SocketNotASocket
	}
	if err := fsys.Usable(path); err != nil {
		return SocketUnreadable
	}
	return SocketPresent
}

// Phase is the socket pre-check's classifier — one of the two §15 says the Docker endpoint adds.
//
// The mapping is the whole value of the pre-check. `not-a-socket` is `not-found` rather than
// `connect` because a directory is not a listener that refused; `unreadable` is `authorize` rather
// than `connect` because the fix is a group membership.
func (s SocketState) Phase() payload.ConnectionPhase {
	switch s {
	case SocketAbsent, SocketNotASocket:
		return payload.PhaseNotFound
	case SocketUnreadable:
		return payload.PhaseAuthorize
	default:
		return payload.PhaseConnected
	}
}

// Detail is what the report says about this state, in the words of the cause rather than of the
// symptom. The `not-a-socket` sentence names the mechanism that produces it, because an operator
// staring at a working-looking bind mount has no other way to guess.
func (s SocketState) Detail(path string) string {
	switch s {
	case SocketAbsent:
		return "nothing exists at " + path
	case SocketNotASocket:
		return path + " exists and is not a socket — a bind mount of a host path that does not " +
			"exist is created as an empty directory"
	case SocketUnreadable:
		return path + " exists and is not usable by this user"
	default:
		return ""
	}
}
