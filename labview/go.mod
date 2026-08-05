module github.com/nrosier/labview

// §2.1 sets the floor at Go 1.23, so the module declares exactly that and no more: a higher
// directive would stop a conforming 1.23 or 1.24 toolchain from building this for no reason.
//
// This is easy to lose. `go get` writes whatever directive a new dependency demands, so when
// §19's bcrypt lands, golang.org/x/crypto must be pinned to v0.40.0 — the last release whose
// own go directive is still 1.23.0. v0.42.0 and later raise the floor to 1.24, and v0.50.0
// to 1.25. Check this line after any dependency change.
go 1.23.0

require gopkg.in/yaml.v3 v3.0.1
