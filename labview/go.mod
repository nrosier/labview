module github.com/nrosier/labview

// §2.1 sets the floor at Go 1.27. It used to read 1.23: golang.org/x/crypto's SSH advisories
// (CVE-2026-39830 et al.) forced a bump past v0.40.0, and every later release raises this
// module's own go directive — v0.42.0 to 1.24, v0.50.0 to 1.25, v0.52.0 to 1.25 as well. Rather
// than land on a floor that matched nothing but a transitive requirement, §2.1 was raised to
// 1.27 to match the toolchain the Dockerfile already ships, collapsing floor and toolchain into
// one number. Check this line after any dependency change.
go 1.27.0

// Both are direct: yaml.v3 is §2.1's YAML 1.2 parser, x/crypto is its bcrypt implementation
// (internal/access/passwd.go). Neither is marked indirect, and `go mod tidy -diff` gates that in
// CI — an `// indirect` on a package this module imports itself is a false statement about the
// dependency surface §2.1 caps at three.
require (
	golang.org/x/crypto v0.55.0
	gopkg.in/yaml.v3 v3.0.1
)
