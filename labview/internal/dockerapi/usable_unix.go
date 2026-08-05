//go:build unix

package dockerapi

import "syscall"

// usable asks the kernel whether this process may read and write the path, which is the only way to
// get the answer right.
//
// Deriving it from the mode bits is the tempting alternative and it is wrong: a container's uid
// usually reaches the Docker socket through a *supplementary* group, and a mode-bit calculation that
// compared owner and primary group would report `unreadable` for the arrangement almost every
// deployment actually uses.
//
// Read and write are both required. A socket is opened for both directions, so read access alone
// would pass the check and then fail the dial — reporting `connect` for a permission problem, which
// is precisely what the pre-check exists to prevent.
func usable(path string) error {
	const readWrite = 0x6 // R_OK|W_OK, spelled numerically because syscall does not name them
	return syscall.Access(path, readWrite)
}
