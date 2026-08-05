package scan

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/secrets"
)

// The bounds of §6.1. The sidecar is untrusted input served verbatim on the API, so every
// one of them is a limit on what a file can make this program hold or a reader render.
const (
	maxSidecarBytes   = 64 << 10 // over-size ⇒ ignored, with a warning naming both numbers
	maxSidecarString  = 2000     // characters, per string
	maxSidecarEntries = 32       // links / dependencies / depends_on
	maxSidecarAuth    = 8        // auth entries per service
)

// sidecarInput is what reading one stack's declaration file needs.
type sidecarInput struct {
	// Dir is the stack directory as joined from the configured root.
	Dir string
	// Root is the containment check (§6, I8). It matters here even though LabView builds
	// the path itself out of configured names, because a symlink is a way out of the tree
	// that no amount of careful joining prevents.
	Root Root
	// Filenames are the candidates in order; the first that exists wins.
	Filenames []string
	// Services are the names the compose file defines, so a declaration for a service that
	// does not exist can be reported rather than silently doing nothing.
	Services []string
	// RedactURI is secrets.redactUriCredentials (§20).
	RedactURI bool
}

// sidecarResult is one declaration file, read.
type sidecarResult struct {
	Stack    *payload.Declaration
	Services map[string]*payload.ServiceDeclaration
	Warnings []string
}

// sidecarParser is the state one declaration file is read with.
//
// There is no interpolator here, deliberately. §6.1 forbids substituting the stack's
// environment into a declaration: declarations are prose, and an operator who writes
// `${VAR}` in a description means those six characters.
type sidecarParser struct {
	in   sidecarInput
	file string // the basename, which is the root of every `where` and the recorded name
	// svcs is the compose file's service names, for the unknown-service check.
	svcs  map[string]bool
	warns []string
}

// readSidecar finds and reads a stack's declaration file.
//
// It returns an empty result and no warnings when there is no such file: a stack without a
// sidecar is the ordinary case and not a finding.
func readSidecar(in sidecarInput) sidecarResult {
	name, path, found := findSidecar(in)
	if !found {
		return sidecarResult{}
	}

	p := &sidecarParser{in: in, file: name, svcs: map[string]bool{}}
	for _, s := range in.Services {
		p.svcs[s] = true
	}

	data, ok := p.read(path)
	if !ok {
		return sidecarResult{Warnings: p.warns}
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		p.reject(p.file, "is not valid YAML: "+err.Error())
		return sidecarResult{Warnings: p.warns}
	}
	return p.parse(docRoot(&doc))
}

// findSidecar returns the first candidate name that exists. §6.1 makes the first win rather
// than merging, so two sidecars in one directory can never half-apply.
//
// Existence is tested with Lstat so that a dangling symlink counts as a file that is there:
// a link out of the tree must be found and refused, not skipped in favour of the next
// candidate.
func findSidecar(in sidecarInput) (name, path string, found bool) {
	for _, candidate := range in.Filenames {
		if candidate == "" || strings.ContainsRune(candidate, filepath.Separator) {
			continue // a configured name with a path in it is not a name in this directory
		}
		full := filepath.Join(in.Dir, candidate)
		if _, err := os.Lstat(full); err == nil {
			return candidate, full, true
		}
	}
	return "", "", false
}

// read is the guarded read: containment, then size.
func (p *sidecarParser) read(path string) ([]byte, bool) {
	if !p.in.Root.Allows(path) {
		// The escape this check exists for is quiet: whatever the link points at would be
		// parsed and served back as a description on the API (§6, I8).
		p.reject(p.file, "resolves outside the scan root")
		return nil, false
	}
	info, err := os.Stat(path)
	switch {
	case err != nil:
		p.reject(p.file, "could not be read")
		return nil, false
	case info.IsDir():
		p.reject(p.file, "is a directory")
		return nil, false
	case info.Size() > maxSidecarBytes:
		p.reject(p.file, itoa(int(info.Size()))+" bytes is over the "+
			itoa(maxSidecarBytes)+" byte limit")
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		p.reject(p.file, "could not be read")
		return nil, false
	}
	return data, true
}

// ---------------------------------------------------------------------------
// Warnings
// ---------------------------------------------------------------------------

// reject is the formula of §6.1: `${where}: <what was wrong>; ignored`.
func (p *sidecarParser) reject(where, what string) {
	p.warns = append(p.warns, where+": "+what+"; ignored")
}

// truncated is the one warning that does not end in "ignored", because nothing was: the
// value is kept, shortened, with an ellipsis marking where it stopped.
func (p *sidecarParser) truncated(where string) {
	p.warns = append(p.warns, where+": truncated to "+itoa(maxSidecarString)+" characters")
}

// capped is the entry-count formula, which ends differently for the same reason: the
// entries up to the limit were kept.
func (p *sidecarParser) capped(where string, limit int) {
	p.warns = append(p.warns, where+": more than "+itoa(limit)+" entries; the rest ignored")
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

// topKeys and serviceKeys are the two accepted-key tables of §6.1. A key outside them is
// named in a warning rather than dropped, because silently ignoring a typo is the one
// failure mode a format where everything is optional has: the operator believes it applied.
var topKeys = map[string]bool{
	"description": true, "owner": true, "criticality": true, "notes": true,
	"data": true, "links": true, "dependencies": true, "services": true,
}

var serviceKeys = map[string]bool{
	"description": true, "owner": true, "criticality": true, "notes": true,
	"data": true, "links": true, "dependencies": true,
	"depends_on": true, "auth": true, "unauthenticated": true, "expected": true,
}

func (p *sidecarParser) parse(root *yaml.Node) sidecarResult {
	out := sidecarResult{Warnings: nil}
	if isNull(root) {
		return sidecarResult{} // an empty file declares nothing, which is not a mistake
	}
	if !isMapping(root) {
		p.reject(p.file, "expected a mapping")
		return sidecarResult{Warnings: p.warns}
	}

	p.unknownKeys(root, topKeys, p.file)

	stack := p.declaration(root, p.file)
	if !emptyDeclaration(stack) {
		stack.File = p.file
		out.Stack = &stack
	}

	out.Services = p.services(field(root, "services"))
	out.Warnings = p.warns
	return out
}

// unknownKeys names every key outside the accepted table in one warning, in the order the
// file writes them. `depends_on` at stack level gets its own message instead: it is a real
// key written at the wrong level, and lumping it in with typos would not tell the operator
// what to do about it (§14).
func (p *sidecarParser) unknownKeys(n *yaml.Node, accepted map[string]bool, where string) {
	var unknown []string
	for _, e := range entries(n) {
		if accepted[e.Key] {
			continue
		}
		if e.Key == "depends_on" {
			p.reject(where, `"depends_on" is a service-level key — at stack level it cannot `+
				`say which service depends on the target`)
			continue
		}
		unknown = append(unknown, `"`+e.Key+`"`)
	}
	if len(unknown) > 0 {
		p.reject(where, "unknown key(s) "+strings.Join(unknown, ", "))
	}
}

// services reads the per-service table.
func (p *sidecarParser) services(n *yaml.Node) map[string]*payload.ServiceDeclaration {
	if isNull(n) {
		return nil
	}
	if !isMapping(n) {
		p.reject(p.file+".services", "expected a mapping")
		return nil
	}

	out := map[string]*payload.ServiceDeclaration{}
	for _, e := range entries(n) {
		where := p.file + " services." + e.Key
		if !p.svcs[e.Key] {
			// Usually a rename nobody carried over. Reporting it is the whole point: the
			// declaration would otherwise sit here looking as if it applied (§6.1).
			p.reject(where, `the compose file defines no service "`+e.Key+`"`)
			continue
		}
		if isNull(e.Node) {
			continue
		}
		if !isMapping(e.Node) {
			p.reject(where, "expected a mapping")
			continue
		}
		p.unknownKeys(e.Node, serviceKeys, where)

		decl := payload.ServiceDeclaration{
			Declaration: p.declaration(e.Node, where),
			Auth:        p.auth(e.Node, where),
			DependsOn:   p.dependsOn(e.Node, where),
		}
		decl.UnauthenticatedAccepted = p.unauthenticated(e.Node, where)
		decl.ExpectedIngress = p.expected(e.Node, where)

		if emptyServiceDeclaration(decl) {
			// §6.1: an all-empty block produces no declaration. An empty one would render
			// as a declaration nobody made.
			continue
		}
		decl.File = p.file
		out[e.Key] = &decl
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// declaration reads the fields a stack and a service share.
func (p *sidecarParser) declaration(n *yaml.Node, where string) payload.Declaration {
	return payload.Declaration{
		Description:  p.str(n, "description", where),
		Owner:        p.str(n, "owner", where),
		Criticality:  p.str(n, "criticality", where),
		Notes:        p.str(n, "notes", where),
		Data:         p.str(n, "data", where),
		Links:        p.links(n, where),
		Dependencies: p.dependencies(n, where),
	}
}

func emptyDeclaration(d payload.Declaration) bool {
	return d.Description == "" && d.Owner == "" && d.Criticality == "" &&
		d.Notes == "" && d.Data == "" && len(d.Links) == 0 && len(d.Dependencies) == 0
}

func emptyServiceDeclaration(d payload.ServiceDeclaration) bool {
	return emptyDeclaration(d.Declaration) && len(d.Auth) == 0 && len(d.DependsOn) == 0 &&
		d.UnauthenticatedAccepted == nil && len(d.ExpectedIngress) == 0
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

// str reads one string field and applies the per-string cap.
func (p *sidecarParser) str(n *yaml.Node, key, base string) string {
	v := field(n, key)
	if isNull(v) {
		return ""
	}
	where := base + "." + key
	if !isScalar(v) {
		p.reject(where, "expected text")
		return ""
	}
	return p.capString(text(v), where)
}

// required reads a field a mapping entry cannot do without.
//
// It reports the missing half with what — `needs a "url"` — when the field is absent or
// written empty, and stays silent when the field is there but is the wrong type, because
// str has already said so. One mistake produces one warning either way.
func (p *sidecarParser) required(n *yaml.Node, key, at, what string) (string, bool) {
	v := field(n, key)
	if isNull(v) {
		p.reject(at, what)
		return "", false
	}
	s := p.str(n, key, at)
	if s == "" {
		if isScalar(v) {
			p.reject(at, what) // written, and still not there
		}
		return "", false
	}
	return s, true
}

// capString bounds one string. It counts characters rather than bytes, because §6.1 says
// characters and because cutting UTF-8 by byte count produces a value that is not text.
func (p *sidecarParser) capString(s, where string) string {
	if len(s) <= maxSidecarString {
		return s // bytes ≥ characters, so this settles the common case without a conversion
	}
	r := []rune(s)
	if len(r) <= maxSidecarString {
		return s
	}
	p.truncated(where)
	return string(r[:maxSidecarString]) + "…"
}

// listOf is §6.1's list-first rule: a value that may be a list or a single entry is tried as
// a list **first**, because a list reaching the single-entry reader is reported as the wrong
// type — a warning about the operator's correct file.
func listOf(v *yaml.Node) []*yaml.Node {
	switch {
	case isNull(v):
		return nil
	case isSequence(v):
		return items(v)
	default:
		return []*yaml.Node{v}
	}
}

// links reads the link list. The URL is redacted **before** the label falls back to it
// (§6.1, §20): the other order puts a password in visible link text.
func (p *sidecarParser) links(n *yaml.Node, base string) []payload.DeclaredLink {
	nodes := listOf(field(n, "links"))
	if len(nodes) == 0 {
		return nil
	}
	where := base + ".links"
	if len(nodes) > maxSidecarEntries {
		p.capped(where, maxSidecarEntries)
		nodes = nodes[:maxSidecarEntries]
	}

	var out []payload.DeclaredLink
	for i, it := range nodes {
		at := where + "[" + itoa(i) + "]"
		if !isMapping(it) {
			p.reject(at, "expected {label, url}")
			continue
		}
		url, ok := p.required(it, "url", at, `needs a "url"`)
		if !ok {
			continue
		}
		if p.in.RedactURI {
			url = secrets.RedactURIs(url)
		}
		label := p.str(it, "label", at)
		if label == "" {
			label = url
		}
		out = append(out, payload.DeclaredLink{Label: label, URL: url})
	}
	return out
}

// dependencies reads the free-text dependencies on things outside the fleet.
func (p *sidecarParser) dependencies(n *yaml.Node, base string) []payload.DeclaredDependency {
	nodes := listOf(field(n, "dependencies"))
	if len(nodes) == 0 {
		return nil
	}
	where := base + ".dependencies"
	if len(nodes) > maxSidecarEntries {
		p.capped(where, maxSidecarEntries)
		nodes = nodes[:maxSidecarEntries]
	}

	var out []payload.DeclaredDependency
	for i, it := range nodes {
		at := where + "[" + itoa(i) + "]"
		switch {
		case isScalar(it):
			out = append(out, payload.DeclaredDependency{Name: p.capString(text(it), at)})
		case isMapping(it):
			name, ok := p.required(it, "name", at, `needs a "name"`)
			if !ok {
				continue
			}
			out = append(out, payload.DeclaredDependency{Name: name, Detail: p.str(it, "detail", at)})
		default:
			p.reject(at, "expected a name or {name, detail}")
		}
	}
	return out
}

// dependsOn reads declared dependencies on scanned services. The reference is stored
// **unresolved**, exactly as typed: this parser cannot see other stacks, and the reference
// as written is the object a rescan compares (§8, §14).
func (p *sidecarParser) dependsOn(n *yaml.Node, base string) []payload.DeclaredServiceDependency {
	nodes := listOf(field(n, "depends_on"))
	if len(nodes) == 0 {
		return nil
	}
	where := base + ".depends_on"
	if len(nodes) > maxSidecarEntries {
		p.capped(where, maxSidecarEntries)
		nodes = nodes[:maxSidecarEntries]
	}

	var out []payload.DeclaredServiceDependency
	for i, it := range nodes {
		at := where + "[" + itoa(i) + "]"
		var ref, detail string
		switch {
		case isScalar(it):
			ref = p.capString(text(it), at)
		case isMapping(it):
			var ok bool
			ref, ok = p.required(it, "service", at, `needs a "service"`)
			if !ok {
				continue
			}
			detail = p.str(it, "detail", at)
		default:
			p.reject(at, `expected "stack/service" or {service, detail}`)
			continue
		}
		if !validServiceRef(ref) {
			p.reject(at, `"`+ref+`" is not a service reference — write "stack/service", `+
				`or the service name on its own`)
			continue
		}
		out = append(out, payload.DeclaredServiceDependency{Ref: ref, Detail: detail})
	}
	return out
}

// validServiceRef checks the shape and nothing else. Whether it names anything is settled
// later against the whole fleet, and a reference that resolves to nothing is drift rather
// than a parse error (§14) — so this rejects only what cannot be a reference at all.
func validServiceRef(ref string) bool {
	if ref == "" {
		return false
	}
	parts := strings.Split(ref, "/")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.ContainsAny(part, " \t") {
			return false
		}
	}
	return true
}

// auth reads the mechanisms an operator claims. Both spellings are accepted — a bare name
// for when there is nothing to add, and a mapping when there is.
func (p *sidecarParser) auth(n *yaml.Node, base string) []payload.DeclaredAuth {
	nodes := listOf(field(n, "auth"))
	if len(nodes) == 0 {
		return nil
	}
	where := base + ".auth"
	if len(nodes) > maxSidecarAuth {
		p.capped(where, maxSidecarAuth)
		nodes = nodes[:maxSidecarAuth]
	}

	var out []payload.DeclaredAuth
	for i, it := range nodes {
		at := where + "[" + itoa(i) + "]"
		var mech, detail, mechAt string
		switch {
		case isScalar(it):
			mech, mechAt = text(it), at
		case isMapping(it):
			var ok bool
			mechAt = at + ".mechanism"
			mech, ok = p.required(it, "mechanism", at, `needs a "mechanism"`)
			if !ok {
				continue
			}
			detail = p.str(it, "detail", at)
		default:
			p.reject(at, "expected a mechanism name or {mechanism, detail}")
			continue
		}

		if !payload.ValidDeclaredAuthMechanism(mech) {
			// The vocabulary is about who enforces the login, not which vendor supplies it,
			// so a product name is the mistake this warning exists for (§4.5).
			p.reject(mechAt, `"`+mech+`" is not a known mechanism (`+mechanismList()+`)`)
			continue
		}
		if payload.DeclaredAuthMechanism(mech) == payload.MechanismOther && detail == "" {
			p.reject(at, `needs a "detail" — "other" names no mechanism on its own`)
			continue
		}
		out = append(out, payload.DeclaredAuth{
			Mechanism: payload.DeclaredAuthMechanism(mech),
			Detail:    detail,
		})
	}
	return out
}

// mechanismList is the closed set as a warning names it, in the order of §4.5.
func mechanismList() string {
	names := make([]string, 0, len(payload.DeclaredAuthMechanisms))
	for _, m := range payload.DeclaredAuthMechanisms {
		names = append(names, string(m))
	}
	return strings.Join(names, ", ")
}

// unauthenticated reads an accepted exposure. The reason is mandatory: an acceptance with no
// reason cannot be told from a stray key, and this is the one line in a sidecar that
// silences a finding (§14).
func (p *sidecarParser) unauthenticated(n *yaml.Node, base string) *payload.AcceptedExposure {
	v := field(n, "unauthenticated")
	if isNull(v) {
		return nil
	}
	where := base + ".unauthenticated"
	if !isMapping(v) {
		p.reject(where, "expected {intentional, reason}")
		return nil
	}

	intentional := text(field(v, "intentional")) == "true"
	reason := p.str(v, "reason", where)
	if !intentional {
		p.reject(where, `needs "intentional: true" to apply`)
		return nil
	}
	if reason == "" {
		p.reject(where, `"intentional: true" needs a "reason" — an acceptance with no reason `+
			`cannot be told from a mistake`)
		return nil
	}
	return &payload.AcceptedExposure{Reason: reason}
}

// expected reads a declared expected ingress. It never becomes an ingress kind (§14, rule 1);
// it is compared, in both directions, and reported.
func (p *sidecarParser) expected(n *yaml.Node, base string) []payload.IngressKind {
	v := field(n, "expected")
	if isNull(v) {
		return nil
	}
	where := base + ".expected"
	if !isMapping(v) {
		p.reject(where, "expected {ingress}")
		return nil
	}

	ingress := field(v, "ingress")
	if isNull(ingress) {
		return nil
	}
	at := where + ".ingress"
	var nodes []*yaml.Node
	switch {
	case isSequence(ingress):
		nodes = items(ingress)
	case isScalar(ingress):
		// The single-kind spelling, `ingress: lan`. Tried after the list, never before.
		nodes = []*yaml.Node{ingress}
	default:
		p.reject(at, "expected a list")
		return nil
	}

	var out []payload.IngressKind
	for i, it := range nodes {
		kind := text(it)
		if !payload.ValidIngressKind(kind) {
			p.reject(at+"["+itoa(i)+"]", `"`+kind+`" is not one of `+ingressList())
			continue
		}
		out = append(out, payload.IngressKind(kind))
	}
	return out
}

// ingressList is the closed set of §4.1 as a warning names it.
func ingressList() string {
	names := make([]string, 0, len(payload.IngressKinds))
	for _, k := range payload.IngressKinds {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}
