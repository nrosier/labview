package scan

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nrosier/labview/internal/payload"
)

// composeInput is everything reading one stack's compose file needs.
type composeInput struct {
	// StackID is the directory name: the stack's id and its default project name (§6).
	StackID string
	// Dir is the stack directory as joined from the configured root, so every path this
	// parser builds is spelled the way the operator spelled the root (I7).
	Dir string
	// Root is the containment check every file named by a file must pass (§6, I8).
	Root Root
	// Env is the stack's .env in file order, or nil when it has none.
	Env []envEntry
}

// composeFile is one parsed compose file.
type composeFile struct {
	Name        string
	ProjectName string
	Services    []payload.Service
	Networks    []payload.NetworkDecl
	Volumes     []payload.VolumeDecl
	Warnings    []string
}

// composeParser is the state one compose file is read with.
type composeParser struct {
	in      composeInput
	interp  interpolator
	project string
	// nets maps a compose network key to the real network name a container joins. It is
	// what makes cross-stack identity work: two stacks on one `external: true` network
	// both resolve to the same string, so the membership index of §8 is a string join.
	nets map[string]string
	// vols is the same table for volumes, so a mount's named source is answerable.
	vols  map[string]string
	warns []string
}

// parseCompose reads one compose file. The error is a YAML parse failure and nothing else:
// everything a document can get wrong short of not being YAML is a warning, because §6
// requires a stack whose compose file will not parse to still be listed (I4).
func parseCompose(data []byte, in composeInput) (composeFile, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return composeFile{}, err
	}

	vars := envMap(in.Env)
	p := &composeParser{
		in:     in,
		interp: interpolator{vars: vars},
		nets:   map[string]string{},
		vols:   map[string]string{},
	}

	root := docRoot(&doc)
	if isNull(root) {
		// An empty file. Not a parse error, and not a stack with services either.
		p.warns = append(p.warns, "the compose file is empty")
		return composeFile{Name: in.StackID, ProjectName: normalizeProjectName(in.StackID), Warnings: p.warns}, nil
	}
	if !isMapping(root) {
		p.warns = append(p.warns, "the compose file is not a mapping; no services were read")
		return composeFile{Name: in.StackID, ProjectName: normalizeProjectName(in.StackID), Warnings: p.warns}, nil
	}

	out := composeFile{Name: in.StackID}
	// Read once: reading it twice would report an unresolved variable in it twice.
	declaredName := p.textField(root, "name", "name")
	out.ProjectName = p.projectName(declaredName, vars)
	p.project = out.ProjectName
	if declaredName != "" {
		// `name:` is the project's own name, so it is also the best display name there is.
		out.Name = declaredName
	}

	out.Networks = p.declaredNetworks(field(root, "networks"))
	out.Volumes = p.declaredVolumes(field(root, "volumes"))
	out.Services = p.services(field(root, "services"))
	out.Warnings = p.warns
	return out, nil
}

// projectName is what Compose would call this project, because it is what the
// `com.docker.compose.project` label on a running container will say and what every real
// network name is built from (§6, §8).
func (p *composeParser) projectName(declared string, vars map[string]string) string {
	if declared != "" {
		return normalizeProjectName(declared)
	}
	if v := vars["COMPOSE_PROJECT_NAME"]; v != "" {
		return normalizeProjectName(v)
	}
	return normalizeProjectName(p.in.StackID)
}

// normalizeProjectName is Compose's own normalisation: lower-case, keep only the characters
// a project name may contain, and drop leading punctuation. It has to match, because the
// result is half of every network name and the value of the label containers are matched by.
func normalizeProjectName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	return strings.TrimLeft(b.String(), "_-")
}

// textField reads a top-level scalar, substituting variables and routing any note to the
// stack's warnings — a stack-level field has no service to carry a note.
func (p *composeParser) textField(n *yaml.Node, key, where string) string {
	v := field(n, key)
	if !isScalar(v) {
		return ""
	}
	out, _, notes := p.interp.expand(text(v), where)
	p.warns = append(p.warns, notes...)
	return out
}

// ---------------------------------------------------------------------------
// Declared networks and volumes
// ---------------------------------------------------------------------------

// declaredNetworks reads the top-level `networks:` table and, as it goes, records what each
// key resolves to as a real network name (§8).
//
// Three spellings decide that name and they are not interchangeable. `external: true` means
// the network already exists under exactly the name written, with no project prefix — which
// is the only way two stacks can be on one network. A `name:` override is likewise verbatim.
// Everything else is created by this project and is therefore `${project}_${key}`.
func (p *composeParser) declaredNetworks(n *yaml.Node) []payload.NetworkDecl {
	var out []payload.NetworkDecl
	for _, e := range entries(n) {
		real, external, driver := p.resolveDecl(e, "networks")
		p.nets[e.Key] = real
		out = append(out, payload.NetworkDecl{Name: real, External: external, Driver: driver})
	}
	return out
}

func (p *composeParser) declaredVolumes(n *yaml.Node) []payload.VolumeDecl {
	var out []payload.VolumeDecl
	for _, e := range entries(n) {
		real, external, driver := p.resolveDecl(e, "volumes")
		p.vols[e.Key] = real
		out = append(out, payload.VolumeDecl{Name: real, External: external, Driver: driver})
	}
	return out
}

// resolveDecl is the shared body of both tables: networks and volumes are named by the same
// rules, and writing it twice is how the two drift apart.
func (p *composeParser) resolveDecl(e entry, section string) (name string, external bool, driver string) {
	where := section + "." + e.Key
	body := e.Node

	if ext := field(body, "external"); !isNull(ext) {
		switch {
		case isScalar(ext):
			external = text(ext) == "true"
		case isMapping(ext):
			// The legacy `external: {name: shared}` form. Still written in the wild, and
			// dropping it would silently turn a shared network into a stack-local one.
			external = true
			if n := p.textField(ext, "name", where+".external.name"); n != "" {
				name = n
			}
		}
	}
	if n := p.textField(body, "name", where+".name"); n != "" {
		name = n
	}
	driver = p.textField(body, "driver", where+".driver")

	if name == "" {
		if external {
			name = e.Key // verbatim: an existing network carries no project prefix
		} else {
			name = p.project + "_" + e.Key
		}
	}
	return name, external, driver
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

// services reads the `services:` table, sorted by name so that two scans of one tree
// produce byte-identical payloads (I7).
func (p *composeParser) services(n *yaml.Node) []payload.Service {
	if isNull(n) {
		p.warns = append(p.warns, "the compose file declares no services")
		return nil
	}
	if !isMapping(n) {
		p.warns = append(p.warns, "services: expected a mapping; no services were read")
		return nil
	}

	var out []payload.Service
	for _, e := range entries(n) {
		out = append(out, p.service(e.Key, e.Node))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// serviceParser carries the notes one service accumulates. Notes are per-service because
// that is where §6 puts an unresolved variable and a refused read: an operator reading the
// service is the one who can act on it.
type serviceParser struct {
	*composeParser
	name  string
	notes []string
}

// expand substitutes one of this service's scalars, keeping the notes on the service.
func (s *serviceParser) expand(in string, where string) string {
	out, _, notes := s.interp.expand(in, where)
	s.notes = append(s.notes, notes...)
	return out
}

// expandSourced is expand for a value whose origin the payload records (§4.8).
func (s *serviceParser) expandSourced(in string, where string) (string, varSource) {
	out, src, notes := s.interp.expand(in, where)
	s.notes = append(s.notes, notes...)
	return out, src
}

func (s *serviceParser) text(n *yaml.Node, key string) string {
	v := field(n, key)
	if !isScalar(v) {
		return ""
	}
	return s.expand(text(v), key)
}

func (p *composeParser) service(name string, n *yaml.Node) payload.Service {
	s := &serviceParser{composeParser: p, name: name}
	out := payload.Service{Name: name}

	if !isMapping(n) {
		if !isNull(n) {
			p.warns = append(p.warns, "services."+name+": expected a mapping; read as an empty service")
		}
		out.ContainerName = p.project + "-" + name + "-1"
		return out
	}

	out.Image = s.text(n, "image")
	out.Restart = s.text(n, "restart")
	out.Command = s.command(n)

	out.ContainerName = s.text(n, "container_name")
	if out.ContainerName == "" {
		// Compose's own default. It matters: it is one of the two ways a service is matched
		// to a live container (§6) and one of the DNS aliases §9 resolves origins against.
		out.ContainerName = p.project + "-" + name + "-1"
	}

	out.DependsOn = s.dependsOn(n)
	out.Networks = s.networks(n)
	out.Ports = s.ports(n)
	out.Expose = s.expose(n)
	out.Mounts = s.mounts(n)
	out.Env = s.env(n)
	out.Labels = s.labels(n)
	out.Notes = s.notes
	return out
}

// command is kept as text because it is evidence to read, not something to execute. A list
// is joined with spaces, which is how it is written in a shell and how an operator
// recognises it.
func (s *serviceParser) command(n *yaml.Node) string {
	v := field(n, "command")
	switch {
	case isScalar(v):
		return s.expand(text(v), "command")
	case isSequence(v):
		parts := make([]string, 0, len(items(v)))
		for i, it := range items(v) {
			if isScalar(it) {
				parts = append(parts, s.expand(text(it), "command["+itoa(i)+"]"))
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

// dependsOn keeps document order. Both spellings mean the same thing and the long form's
// conditions say nothing this payload carries, so only the names are read.
func (s *serviceParser) dependsOn(n *yaml.Node) []string {
	v := field(n, "depends_on")
	var out []string
	switch {
	case isSequence(v):
		for i, it := range items(v) {
			if isScalar(it) {
				out = append(out, s.expand(text(it), "depends_on["+itoa(i)+"]"))
			}
		}
	case isMapping(v):
		for _, e := range entries(v) {
			out = append(out, e.Key)
		}
	}
	return out
}

// networks resolves this service's real networks (§8).
//
// The returned names are the real ones a container joins, not the compose keys, because
// every later stage joins on them: two stacks naming one `external: true` network have to
// produce the same string, or the membership index reports two networks where the fleet has
// one. Document order is kept — §8's `via` is "in the dependent's compose order".
func (s *serviceParser) networks(n *yaml.Node) []string {
	if mode := s.text(n, "network_mode"); mode != "" {
		// `network_mode: host` or `service:other` replaces compose networking entirely.
		// Saying so is the honest answer; deriving a network here would invent one.
		s.notes = append(s.notes, `network_mode is "`+mode+
			`", so this service joins no compose network`)
		return nil
	}

	v := field(n, "networks")
	var keys []string
	switch {
	case isSequence(v):
		for i, it := range items(v) {
			if isScalar(it) {
				keys = append(keys, s.expand(text(it), "networks["+itoa(i)+"]"))
			}
		}
	case isMapping(v):
		for _, e := range entries(v) {
			keys = append(keys, e.Key)
		}
	default:
		// No `networks:` key at all. Compose puts the container on the project's implicit
		// `default` network, where every other such service in the stack can reach it —
		// which is the whole of §8's "two services in one file are mutually reachable
		// without either declaring a network".
		return []string{s.defaultNetwork()}
	}

	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if real, ok := s.nets[key]; ok {
			out = append(out, real)
			continue
		}
		if key == "default" {
			// The implicit default needs no declaration, so naming it is not a mistake.
			out = append(out, s.defaultNetwork())
			continue
		}
		// Compose refuses to start a stack that names a network nobody declared. LabView
		// reports it and carries on with the name the project would have created (I4).
		s.notes = append(s.notes, "networks: \""+key+
			"\" is not declared by this compose file; read as a network of this project")
		out = append(out, s.project+"_"+key)
	}
	if len(out) == 0 {
		// An empty `networks:` list or mapping. Compose falls back to the default.
		return []string{s.defaultNetwork()}
	}
	return out
}

// defaultNetwork is the implicit `default`, honouring a declaration of it if the file has
// one — a stack may declare `default: {external: true, name: shared}` and mean it.
func (s *serviceParser) defaultNetwork() string {
	if real, ok := s.nets["default"]; ok {
		return real
	}
	return s.project + "_default"
}

// ports reads `ports:`. The presence of an entry is the signal and the raw text is the
// evidence; no rule anywhere may depend on a parsed port number (§8), which is why Raw is
// kept for every entry however it was written.
func (s *serviceParser) ports(n *yaml.Node) []payload.PortMapping {
	v := field(n, "ports")
	var out []payload.PortMapping
	for i, it := range items(v) {
		where := "ports[" + itoa(i) + "]"
		switch {
		case isScalar(it):
			out = append(out, shortPort(s.expand(text(it), where)))
		case isMapping(it):
			out = append(out, s.longPort(it, where))
		}
	}
	return out
}

// shortPort reads `[[host_ip:]host:]container[/protocol]`.
func shortPort(raw string) payload.PortMapping {
	m := payload.PortMapping{Raw: raw, Protocol: "tcp"}
	spec := raw
	if slash := strings.LastIndex(spec, "/"); slash >= 0 {
		if proto := spec[slash+1:]; proto != "" {
			m.Protocol = proto
			spec = spec[:slash]
		}
	}
	fields := strings.Split(spec, ":")
	switch len(fields) {
	case 1:
		m.Target = fields[0]
	default:
		// The host side is the second-to-last field; anything before it is an address the
		// publication is bound to, which stays in Raw. Published holds a port on its own
		// because §9 matches a tunnel origin's port against published host ports.
		m.Published = fields[len(fields)-2]
		m.Target = fields[len(fields)-1]
	}
	return m
}

// longPort reads the mapping form and rebuilds the short spelling as Raw, so that a rule
// reading Raw does not have to know which form the file used.
func (s *serviceParser) longPort(n *yaml.Node, where string) payload.PortMapping {
	m := payload.PortMapping{
		Target:    s.text(n, "target"),
		Published: s.text(n, "published"),
	}
	declaredProto := s.text(n, "protocol")
	hostIP := s.text(n, "host_ip")

	m.Protocol = declaredProto
	if m.Protocol == "" {
		m.Protocol = "tcp"
	}

	var b strings.Builder
	if hostIP != "" {
		b.WriteString(hostIP)
		b.WriteByte(':')
	}
	if m.Published != "" {
		b.WriteString(m.Published)
		b.WriteByte(':')
	}
	b.WriteString(m.Target)
	if declaredProto != "" {
		b.WriteByte('/')
		b.WriteString(declaredProto)
	}
	m.Raw = b.String()
	return m
}

// expose records that a container listens on a port without publishing it, which is
// `internal` ingress and nothing more (§8).
func (s *serviceParser) expose(n *yaml.Node) []string {
	v := field(n, "expose")
	var out []string
	for i, it := range items(v) {
		if isScalar(it) {
			out = append(out, s.expand(text(it), "expose["+itoa(i)+"]"))
		}
	}
	return out
}

// mounts reads `volumes:` on a service.
func (s *serviceParser) mounts(n *yaml.Node) []payload.MountSpec {
	v := field(n, "volumes")
	var out []payload.MountSpec
	for i, it := range items(v) {
		where := "volumes[" + itoa(i) + "]"
		switch {
		case isScalar(it):
			out = append(out, shortMount(s.expand(text(it), where)))
		case isMapping(it):
			out = append(out, s.longMount(it, where))
		}
	}
	return out
}

// shortMount reads `target`, `source:target` or `source:target:mode`.
//
// Source is kept exactly as written, unresolved. It is quoting the file: `./data` says the
// operator mounted a directory beside the compose file, and rewriting it as an absolute
// path would replace their statement with this scanner's filesystem (I2).
func shortMount(raw string) payload.MountSpec {
	m := payload.MountSpec{Raw: raw}
	fields := strings.Split(raw, ":")
	switch len(fields) {
	case 1:
		// An anonymous volume: a container path with nothing behind it.
		m.Type = payload.MountVolume
		m.Target = fields[0]
		return m
	case 2:
		m.Source, m.Target = fields[0], fields[1]
	default:
		m.Source, m.Target = fields[0], fields[1]
		for _, opt := range strings.Split(fields[2], ",") {
			if opt == "ro" {
				m.ReadOnly = true
			}
		}
	}
	m.Type = mountTypeOf(m.Source)
	return m
}

// mountTypeOf reads the type off the source, which is the only place the short form states
// it: a path is a bind, and a name is a volume.
func mountTypeOf(source string) payload.MountType {
	switch {
	case source == "":
		return payload.MountVolume
	case strings.HasPrefix(source, `\\.\pipe\`), strings.HasPrefix(source, "npipe://"):
		return payload.MountNpipe
	case strings.HasPrefix(source, "/"), strings.HasPrefix(source, "."), strings.HasPrefix(source, "~"):
		return payload.MountBind
	default:
		return payload.MountVolume
	}
}

// longMount reads the mapping form. The type is validated against the closed set of
// Appendix A rather than passed through, because an unlisted member would be a different
// protocol to a consumer (§16); anything else reads as `unknown`, which is a member.
func (s *serviceParser) longMount(n *yaml.Node, where string) payload.MountSpec {
	m := payload.MountSpec{
		Source: s.text(n, "source"),
		Target: s.text(n, "target"),
	}
	switch t := payload.MountType(s.text(n, "type")); t {
	case payload.MountBind, payload.MountVolume, payload.MountTmpfs, payload.MountNpipe:
		m.Type = t
	case "":
		m.Type = mountTypeOf(m.Source)
	default:
		m.Type = payload.MountUnknown
		s.notes = append(s.notes, where+`.type: "`+string(t)+`" is not a mount type; read as unknown`)
	}
	if ro := field(n, "read_only"); isScalar(ro) {
		m.ReadOnly = text(ro) == "true"
	}

	var b strings.Builder
	if m.Source != "" {
		b.WriteString(m.Source)
		b.WriteByte(':')
	}
	b.WriteString(m.Target)
	if m.ReadOnly {
		b.WriteString(":ro")
	}
	m.Raw = b.String()
	return m
}

// labels reads either spelling into one map. A label with no value is kept with an empty
// one: the key's presence is often the whole statement (`traefik.enable` aside, a bare
// label is how several tools mark a container).
func (s *serviceParser) labels(n *yaml.Node) map[string]string {
	v := field(n, "labels")
	out := map[string]string{}
	switch {
	case isMapping(v):
		for _, e := range entries(v) {
			where := "labels." + e.Key
			if !isScalar(e.Node) {
				if !isNull(e.Node) {
					s.notes = append(s.notes, where+": expected text; ignored")
					continue
				}
				out[e.Key] = ""
				continue
			}
			out[e.Key] = s.expand(text(e.Node), where)
		}
	case isSequence(v):
		for i, it := range items(v) {
			if !isScalar(it) {
				continue
			}
			raw := s.expand(text(it), "labels["+itoa(i)+"]")
			key, value, _ := strings.Cut(raw, "=")
			out[key] = value
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

// env assembles one service's environment: every `env_file` in order, then `environment:`
// over the top, sorted by key.
//
// The order is Compose's own and it decides what the running container holds, so getting it
// backwards would report values the service does not have.
func (s *serviceParser) env(n *yaml.Node) []payload.EnvVar {
	byKey := map[string]payload.EnvVar{}

	for _, e := range s.envFiles(n) {
		byKey[e.Key] = payload.EnvVar{
			Key:   e.Key,
			Value: e.Value,
			// An env file is never interpolated (§6), so its own text is the value and the
			// file is the source. A bare key is the shell's to supply.
			Source: envFileSource(e),
		}
	}

	v := field(n, "environment")
	switch {
	case isMapping(v):
		for _, e := range entries(v) {
			byKey[e.Key] = s.envEntry(e.Key, e.Node, "environment."+e.Key)
		}
	case isSequence(v):
		for i, it := range items(v) {
			if !isScalar(it) {
				continue
			}
			where := "environment[" + itoa(i) + "]"
			raw := text(it)
			key, value, hasValue := strings.Cut(raw, "=")
			if !hasValue {
				// `- TZ` takes whatever the shell had, which this scan cannot see.
				byKey[key] = payload.EnvVar{Key: key, Source: payload.EnvFromShellDefault}
				continue
			}
			out, src := s.expandSourced(value, where)
			byKey[key] = payload.EnvVar{
				Key:    key,
				Value:  &out,
				Source: sourceOf(src, payload.EnvFromEnvironment),
			}
		}
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]payload.EnvVar, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

// envEntry is one `environment:` mapping entry.
func (s *serviceParser) envEntry(key string, n *yaml.Node, where string) payload.EnvVar {
	if isNull(n) {
		// `TZ:` with nothing after it. Value null is the fact — a variable declared and
		// left to the shell — and it is a different reading from `TZ: ""` (§6).
		return payload.EnvVar{Key: key, Source: payload.EnvFromShellDefault}
	}
	if !isScalar(n) {
		s.notes = append(s.notes, where+": expected text; ignored")
		return payload.EnvVar{Key: key, Source: payload.EnvFromEnvironment}
	}
	out, src := s.expandSourced(text(n), where)
	return payload.EnvVar{Key: key, Value: &out, Source: sourceOf(src, payload.EnvFromEnvironment)}
}

// envFileSource is the source of a value that came out of an environment file.
func envFileSource(e envEntry) payload.EnvVarSource {
	if e.Value == nil {
		return payload.EnvFromShellDefault
	}
	return payload.EnvFromEnvFile
}

// envFiles reads every `env_file` this service names, in order, and returns their entries
// concatenated — so a later file's declaration overwrites an earlier one, as Compose does.
//
// This is the one place a *file in the tree* names a file to read, so it is the one place
// the containment check of §6 has to fire. A refusal is a note on the service; the values
// are not read.
func (s *serviceParser) envFiles(n *yaml.Node) []envEntry {
	v := field(n, "env_file")
	var out []envEntry

	read := func(path string, required bool, where string) {
		if path == "" {
			return
		}
		entries, notes := s.readEnvFile(path, required, where)
		s.notes = append(s.notes, notes...)
		out = append(out, entries...)
	}

	switch {
	case isScalar(v):
		read(s.expand(text(v), "env_file"), true, "env_file")
	case isSequence(v):
		for i, it := range items(v) {
			where := "env_file[" + itoa(i) + "]"
			switch {
			case isScalar(it):
				read(s.expand(text(it), where), true, where)
			case isMapping(it):
				// The long form, `- path: local.env` with an optional `required:`.
				required := true
				if r := field(it, "required"); isScalar(r) {
					required = text(r) != "false"
				}
				read(s.expand(text(field(it, "path")), where+".path"), required, where)
			}
		}
	}
	return out
}

// readEnvFile is the guarded read: containment first, then size, then parse.
func (s *serviceParser) readEnvFile(path string, required bool, where string) ([]envEntry, []string) {
	full := path
	if !filepath.IsAbs(full) {
		full = filepath.Join(s.in.Dir, path)
	}
	if !s.in.Root.Allows(full) {
		// §6: a refusal surfaces, never silence. The path is quoted as the file wrote it,
		// which is both the evidence and the only spelling that names no host path (I2).
		return nil, []string{where + `: "` + path + `" is outside the scan root; not read`}
	}

	info, err := os.Stat(full)
	switch {
	case err != nil && !required:
		// `required: false` says the operator meant this file to be optional, and Compose
		// starts the stack without it. Nothing went wrong, so nothing is reported.
		return nil, nil
	case err != nil:
		return nil, []string{where + `: "` + path + `" could not be read; ignored`}
	case info.IsDir():
		return nil, []string{where + `: "` + path + `" is a directory; ignored`}
	case info.Size() > maxEnvFileBytes:
		return nil, []string{where + `: "` + path + `" is larger than ` +
			itoa(maxEnvFileBytes>>20) + " MiB; ignored"}
	}

	data, err := os.ReadFile(full)
	if err != nil {
		return nil, []string{where + `: "` + path + `" could not be read; ignored`}
	}
	return parseEnvFile(data), nil
}
