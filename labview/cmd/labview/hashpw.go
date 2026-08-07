package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/nrosier/labview/internal/access"
)

// hashpw is §2.5's second subcommand: it prints one `user:hash` line for the passwd file of §19.
//
// It is in this binary rather than in a script because the hash has to be produced by the same
// implementation that verifies it — the cost, the caps and the accepted `$id$` prefixes are §19's and
// live in `internal/access`. A separate tool would be a second opinion about a credential format.
//
// **The password is read from stdin, never from an argument.** An argument is in the process table
// while it runs and in the shell history afterwards, and a credential this program can avoid seeing
// in either place is one it should avoid seeing in both. The usage line says `echo`-free deliberately:
//
//	printf 'the password' | labview hashpw ada >> /config/passwd
//
// Reading from stdin also means no terminal handling. Suppressing echo needs `golang.org/x/term`,
// which §2.1's dependency list does not permit — and the honest alternative is to say plainly that
// this reads a pipe, rather than to prompt on a terminal and echo the password into the scrollback.
func hashpw(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	flags := flag.NewFlagSet("hashpw", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if flags.NArg() != 1 {
		fmt.Fprint(stderr, `usage: labview hashpw <user>

The password is read from stdin, so it never appears in an argument or in shell history:

    printf 'the password' | labview hashpw ada >> /config/passwd

`)
		return 2
	}

	user := flags.Arg(0)
	// The same pattern the payload and the log lines hold to (§16), checked here rather than at
	// verification time: a name outside it can never match a session claim, so a line minted with one
	// would be an account that exists in the file and cannot be signed in to.
	if !access.ValidUsername(user) {
		fmt.Fprintf(stderr, "labview: %q is not a usable username — it must match ^[A-Za-z0-9._@-]{1,64}$\n", user)
		return 2
	}

	password, err := readPassword(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "labview: could not read the password: %v\n", err)
		return 1
	}
	if password == "" {
		// A blank password would hash and verify, which is worse than refusing: it produces a working
		// account whose credential is the empty string.
		fmt.Fprintln(stderr, "labview: the password is empty, and an empty password would be a working account")
		return 2
	}

	// Mint applies §19's cost 12 and its 1024-character cap. The error is the cap, and it is worth
	// distinguishing from a read failure: one is the operator's input and one is this program's.
	hash, err := access.Mint(password)
	if err != nil {
		fmt.Fprintf(stderr, "labview: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "%s:%s\n", user, hash)
	return 0
}

// readPassword reads the credential from a reader.
//
// **One trailing newline is stripped and nothing else is.** `printf 'pw'` sends no newline and
// `echo pw` sends one, and both should produce the same hash — but a password may legitimately begin
// or end with a space, so a general trim would silently hash something other than what was typed.
// The bound is §19's cap plus the newline: reading more than that from a pipe is refused rather than
// hashed, because bcrypt truncates at 72 bytes anyway and the cap is about the work of hashing a
// megabyte.
func readPassword(r io.Reader) (string, error) {
	limited := io.LimitReader(r, access.MaxPasswordChars+2)
	raw, err := io.ReadAll(bufio.NewReader(limited))
	if err != nil {
		return "", err
	}

	got := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if len(got) > access.MaxPasswordChars {
		return "", fmt.Errorf("more than %d characters arrived on stdin", access.MaxPasswordChars)
	}
	return got, nil
}
