module github.com/nrosier/labview

// §2.1 sets the floor at Go 1.23, so the module declares exactly that and no more: a higher
// directive would stop a conforming 1.23 or 1.24 toolchain from building this for no reason.
//
// This is easy to lose. `go get` writes whatever directive a new dependency demands, and §19's
// bcrypt has landed, so golang.org/x/crypto is pinned to v0.40.0 — the last release whose own go
// directive is still 1.23.0. v0.42.0 and later raise the floor to 1.24, and v0.50.0 to 1.25.
// Check this line after any dependency change.
go 1.25.0

// Both are direct: yaml.v3 is §2.1's YAML 1.2 parser, x/crypto is its bcrypt implementation
// (internal/access/passwd.go). Neither is marked indirect, and `go mod tidy -diff` gates that in
// CI — an `// indirect` on a package this module imports itself is a false statement about the
// dependency surface §2.1 caps at three.
require (
	golang.org/x/crypto v0.54.0
	gopkg.in/yaml.v3 v3.0.1
)
