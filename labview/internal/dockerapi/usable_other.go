//go:build !unix

package dockerapi

// usable is unanswerable off unix, where there is no access(2) and no unix socket to ask about. It
// reports usable, which lets the dial produce the real phase.
//
// This file exists so the package builds everywhere rather than to support anything: the runtime
// image is linux (§2.3), and the only reason to compile on another platform is to run the tests —
// which inject a Filesystem and never reach this function.
func usable(string) error { return nil }
