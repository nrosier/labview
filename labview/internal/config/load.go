package config

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Lookup reads one environment variable. Every environment read in this program goes
// through one of these, so a test can supply an exact environment rather than mutating the
// process's own — which is what makes the corpus hermetic (§23).
type Lookup func(key string) (string, bool)

// OSEnv reads the process environment.
func OSEnv() Lookup { return os.LookupEnv }

// MapEnv reads a fixed map. MapEnv(nil) is an empty environment.
func MapEnv(m map[string]string) Lookup {
	return func(key string) (string, bool) {
		v, ok := m[key]
		return v, ok
	}
}

// Diagnostics is what a load has to say for itself.
//
// Logs go to the log as they are: a malformed configuration file, a number rejected for
// being out of range, an unrecognised cookie-secure mode. Warnings are the retired
// settings of §3.3, which both entry points report — the server as a payload warning, the
// one-shot scan on stderr.
type Diagnostics struct {
	Logs     []string
	Warnings []string
}

// Options is how a load is parameterised. Everything is explicit so that nothing reads the
// ambient process state by default.
type Options struct {
	// Env is the environment to read. Nil means an empty environment, not the process's.
	Env Lookup
	// SkipFile forces configuration-file loading to defaults. §23 requires it: the corpus
	// must not pick up an operator's config.yml.
	SkipFile bool
	// ConfigPath overrides LABVIEW_CONFIG. Empty means read the variable, then ./config.yml.
	ConfigPath string
}

// ConfigPathVar is the one variable naming the configuration file. It has no configuration
// key, for the obvious reason.
const ConfigPathVar = "LABVIEW_CONFIG"

// DefaultConfigPath is where the file is looked for when nothing names it.
const DefaultConfigPath = "./config.yml"

// Load builds the configuration: defaults, then the file, then the environment (§3).
//
// It never fails. A file that cannot be read or parsed produces a log line and leaves the
// defaults in place, because refusing to start over a bad config file would take the whole
// instrument down over a typo (I4).
func Load(o Options) (Config, Diagnostics) {
	env := o.Env
	if env == nil {
		env = MapEnv(nil)
	}
	var diag Diagnostics
	cfg := Defaults()

	var raw map[string]any
	if !o.SkipFile {
		path := o.ConfigPath
		if path == "" {
			if v, ok := env(ConfigPathVar); ok && strings.TrimSpace(v) != "" {
				path = strings.TrimSpace(v)
			} else {
				path = DefaultConfigPath
			}
		}
		var log string
		raw, log = applyFile(&cfg, path)
		if log != "" {
			diag.Logs = append(diag.Logs, log)
		}
	}

	blank, notes := applyEnv(&cfg, env)
	diag.Logs = append(diag.Logs, notes...)

	// Assigned, never appended: a configuration file that set blankCredentialVars has no
	// standing, because the fact being recorded is about the environment (§3.3).
	cfg.BlankCredentialVars = blank

	diag.Logs = append(diag.Logs, cfg.validate()...)
	diag.Warnings = append(diag.Warnings, retired(env, raw)...)
	return cfg, diag
}

// applyFile decodes the configuration file over the defaults and returns the raw tree.
//
// The same bytes are decoded twice on purpose. The typed decode gives the settings, with
// yaml.v3's own semantics doing the work the spec asks for: a key absent from the file
// leaves the default in place, and a sequence replaces the default slice rather than
// merging into it. The untyped decode keeps every key the file contained, including the
// ones this version does not know, which is what retired-key detection reads (§3).
func applyFile(cfg *Config, path string) (raw map[string]any, log string) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "" // no file is the normal case, not a fault
		}
		return nil, "[config] failed to read " + path + ": " + err.Error() + "; using defaults"
	}

	// Decode into a copy and commit only on success, so a file that parses halfway cannot
	// leave the configuration half-applied — "fall back to defaults" has to mean all of them.
	merged := *cfg
	if err := yaml.Unmarshal(data, &merged); err != nil {
		return nil, "[config] failed to parse " + path + ": " + yamlMessage(err) + "; using defaults"
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, "[config] failed to parse " + path + ": " + yamlMessage(err) + "; using defaults"
	}

	*cfg = merged
	for _, key := range flatten("", raw) {
		cfg.markProvided(key)
	}
	return raw, ""
}

// yamlMessage strips the line-noise yaml.v3 prefixes onto its messages, so the log line
// reads as §3 writes it.
func yamlMessage(err error) string {
	m := err.Error()
	m = strings.TrimPrefix(m, "yaml: ")
	return strings.ReplaceAll(m, "\n", "; ")
}

// flatten lists a raw tree's dotted keys. A mapping contributes its own path and its
// children's; a scalar or a sequence contributes only its own, because a list replaces
// wholesale and has no addressable interior.
func flatten(prefix string, node any) []string {
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	var keys []string
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		keys = append(keys, path)
		keys = append(keys, flatten(path, v)...)
	}
	return keys
}

// rawString returns a dotted key's value when it is a string.
func rawString(raw map[string]any, dotted string) (string, bool) {
	var node any = raw
	for _, part := range strings.Split(dotted, ".") {
		m, ok := node.(map[string]any)
		if !ok {
			return "", false
		}
		node, ok = m[part]
		if !ok {
			return "", false
		}
	}
	s, ok := node.(string)
	return s, ok
}

// ---------------------------------------------------------------------------
// The environment overlay (§3.2)
// ---------------------------------------------------------------------------

// The four credential variables of §3.3. Each has exactly one variable and no path form.
const (
	AuthentikTokenVar   = "LABVIEW_AUTHENTIK_TOKEN"
	TraefikPasswordVar  = "LABVIEW_TRAEFIK_PASSWORD"
	OIDCClientSecretVar = "LABVIEW_OIDC_CLIENT_SECRET"
	SessionSecretVar    = "LABVIEW_SESSION_SECRET"
)

// BuildSHAVar is environment-only and has no configuration key: the file is editable while
// LabView runs, so a key there would let a running instance claim to be a different build
// than it is (§3.3, I1).
const BuildSHAVar = "LABVIEW_BUILD_SHA"

// LogLevelVar is the log level. It is not a configuration setting — nothing in the payload
// depends on it.
const LogLevelVar = "LABVIEW_LOG_LEVEL"

// DefaultLogLevel is used when LABVIEW_LOG_LEVEL says nothing.
const DefaultLogLevel = "info"

// LogLevel reads the log level from an environment.
func LogLevel(env Lookup) string {
	if v, ok := env(LogLevelVar); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return DefaultLogLevel
}

// applyEnv overlays the environment onto an already-merged tree, in place.
//
// Every value is trimmed of surrounding whitespace before use. An environment variable
// carrying a stray newline is an artifact of how it was set — a here-doc, a file read, a
// CI template — never something an operator meant to be part of a path or a URL.
func applyEnv(c *Config, env Lookup) (blank []string, notes []string) {
	blank = []string{}

	str := func(name, key string, dst *string) {
		if v, ok := env(name); ok {
			*dst = strings.TrimSpace(v)
			c.markProvided(key)
		}
	}
	flag := func(name, key string, dst *bool) {
		if v, ok := env(name); ok {
			*dst = boolValue(v)
			c.markProvided(key)
		}
	}
	num := func(name, key string, dst *int) {
		v, ok := env(name)
		if !ok {
			return
		}
		n, ok := parseNumber(v)
		if !ok {
			notes = append(notes, "[config] "+name+" is not a number; ignoring it")
			return
		}
		*dst = n
		c.markProvided(key)
	}
	// A credential that is present and carries nothing is a different fact from one that
	// was never set: it becomes a credential phase for a scan target and a startup note
	// for LabView's own login. Nothing else records that, so it is recorded here — by name
	// only (§3.3, I6).
	credential := func(name, key string, dst *string) {
		if v, ok := env(name); ok {
			t := strings.TrimSpace(v)
			*dst = t
			c.markProvided(key)
			if t == "" {
				blank = append(blank, name)
			}
		}
	}

	str("LABVIEW_APPS_ROOT", "appsRoot", &c.AppsRoot)

	if v, ok := env("LABVIEW_SIDECAR_FILENAMES"); ok {
		if names := splitList(v, ","); len(names) > 0 {
			c.SidecarFilenames = names
			c.markProvided("sidecarFilenames")
		}
	}

	// Docker endpoint, in the order §3.2 tabulates: the generic variable first so the
	// LabView-specific one can win, then the port, then the socket which always wins.
	if v, ok := env("DOCKER_HOST"); ok {
		notes = append(notes, applyDockerHost(c, "DOCKER_HOST", v)...)
	}
	if v, ok := env("LABVIEW_DOCKER_HOST"); ok {
		notes = append(notes, applyDockerHost(c, "LABVIEW_DOCKER_HOST", v)...)
	}
	num("LABVIEW_DOCKER_PORT", "docker.port", &c.Docker.Port)
	if v, ok := env("LABVIEW_DOCKER_SOCKET"); ok {
		c.Docker.SocketPath = strings.TrimSpace(v)
		c.Docker.Host = ""
		c.markProvided("docker.socketPath")
	}
	flag("LABVIEW_DOCKER_ENABLED", "docker.enabled", &c.Docker.Enabled)
	num("LABVIEW_DOCKER_MAX_CONCURRENCY", "docker.maxConcurrency", &c.Docker.MaxConcurrency)
	num("LABVIEW_DOCKER_TIMEOUT", "docker.timeoutMs", &c.Docker.TimeoutMs)
	// Bytes, not megabytes. A unit-suffixed form would be friendlier and would also make this
	// the only setting in §3.2 that parses anything but an integer; validate's floor is what
	// catches the operator who writes 8 meaning 8 MiB.
	num("LABVIEW_DOCKER_BODY_CAP", "docker.bodyCapBytes", &c.Docker.BodyCapBytes)

	flag("LABVIEW_MASK_SECRETS", "secrets.maskValues", &c.Secrets.MaskValues)
	num("LABVIEW_CACHE_TTL", "cacheTtlSeconds", &c.CacheTTLSeconds)
	num("LABVIEW_PORT", "server.port", &c.Server.Port)
	str("LABVIEW_HOST", "server.host", &c.Server.Host)

	credential(AuthentikTokenVar, "authentik.token", &c.Authentik.Token)
	str("LABVIEW_AUTHENTIK_URL", "authentik.url", &c.Authentik.URL)
	flag("LABVIEW_AUTHENTIK_ENABLED", "authentik.enabled", &c.Authentik.Enabled)
	num("LABVIEW_AUTHENTIK_TIMEOUT", "authentik.timeoutMs", &c.Authentik.TimeoutMs)

	str("LABVIEW_TRAEFIK_URL", "traefik.url", &c.Traefik.URL)
	str("LABVIEW_TRAEFIK_USERNAME", "traefik.username", &c.Traefik.Username)
	credential(TraefikPasswordVar, "traefik.password", &c.Traefik.Password)
	flag("LABVIEW_TRAEFIK_ENABLED", "traefik.enabled", &c.Traefik.Enabled)
	num("LABVIEW_TRAEFIK_TIMEOUT", "traefik.timeoutMs", &c.Traefik.TimeoutMs)

	flag("LABVIEW_PROBE_ENABLED", "probe.enabled", &c.Probe.Enabled)
	str("LABVIEW_PROBE_LAN_HOST", "probe.lanHost", &c.Probe.LanHost)
	num("LABVIEW_PROBE_TIMEOUT", "probe.timeoutMs", &c.Probe.TimeoutMs)
	num("LABVIEW_PROBE_MAX_CONCURRENCY", "probe.maxConcurrency", &c.Probe.MaxConcurrency)

	flag("LABVIEW_AUTH_PASSWD_ENABLED", "auth.passwd.enabled", &c.Auth.Passwd.Enabled)
	str("LABVIEW_AUTH_PASSWD_FILE", "auth.passwd.file", &c.Auth.Passwd.File)
	num("LABVIEW_AUTH_MAX_FAILED_ATTEMPTS", "auth.maxFailedAttempts", &c.Auth.MaxFailedAttempts)
	num("LABVIEW_AUTH_LOCKOUT_SECONDS", "auth.lockoutSeconds", &c.Auth.LockoutSeconds)

	// Only the three literals are accepted; anything else keeps whatever the file or the
	// default left in place, and validate has the last word (§3.2).
	if v, ok := env("LABVIEW_AUTH_COOKIE_SECURE"); ok {
		switch t := strings.TrimSpace(v); t {
		case CookieSecureAuto, CookieSecureTrue, CookieSecureFalse:
			c.Auth.Session.Secure = t
			c.markProvided("auth.session.secure")
		default:
			notes = append(notes, "[config] LABVIEW_AUTH_COOKIE_SECURE must be auto, true or false; keeping "+c.Auth.Session.Secure)
		}
	}

	flag("LABVIEW_OIDC_ENABLED", "auth.oidc.enabled", &c.Auth.OIDC.Enabled)
	str("LABVIEW_OIDC_ISSUER", "auth.oidc.issuer", &c.Auth.OIDC.Issuer)
	str("LABVIEW_OIDC_CLIENT_ID", "auth.oidc.clientId", &c.Auth.OIDC.ClientID)
	credential(OIDCClientSecretVar, "auth.oidc.clientSecret", &c.Auth.OIDC.ClientSecret)
	str("LABVIEW_OIDC_REDIRECT_URI", "auth.oidc.redirectUri", &c.Auth.OIDC.RedirectURI)
	if v, ok := env("LABVIEW_OIDC_SCOPES"); ok {
		if scopes := splitScopes(v); len(scopes) > 0 {
			c.Auth.OIDC.Scopes = scopes
			c.markProvided("auth.oidc.scopes")
		}
	}
	str("LABVIEW_OIDC_USERNAME_CLAIM", "auth.oidc.usernameClaim", &c.Auth.OIDC.UsernameClaim)
	str("LABVIEW_OIDC_LABEL", "auth.oidc.label", &c.Auth.OIDC.Label)
	num("LABVIEW_OIDC_TIMEOUT", "auth.oidc.timeoutMs", &c.Auth.OIDC.TimeoutMs)

	credential(SessionSecretVar, "auth.session.secret", &c.Auth.Session.Secret)
	num("LABVIEW_SESSION_TTL_MINUTES", "auth.session.ttlMinutes", &c.Auth.Session.TTLMinutes)
	str("LABVIEW_SESSION_COOKIE_NAME", "auth.session.cookieName", &c.Auth.Session.CookieName)

	return blank, notes
}

// boolValue is §3.2's rule: true unless the value is exactly false. The variable being
// present at all means the operator meant something. Surrounding whitespace is trimmed
// first, because a trailing newline is an artifact of how the value was set rather than a
// statement that the answer is not "false".
func boolValue(v string) bool { return strings.TrimSpace(v) != "false" }

// parseNumber is §3.2's rule: parsed, required finite, floored. Range checking is separate,
// because an out-of-range value falls back to its default rather than being clamped.
func parseNumber(v string) (int, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	f = math.Floor(f)
	if f > float64(math.MaxInt32) || f < float64(math.MinInt32) {
		return 0, false
	}
	return int(f), true
}

// splitList splits on a separator, trims, and drops empties. An entirely empty result is
// returned as an empty slice, and the caller ignores it (§3.2).
func splitList(v, sep string) []string {
	out := []string{}
	for _, part := range strings.Split(v, sep) {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// scopeSep is §3.2's rule for LABVIEW_OIDC_SCOPES: split on commas or whitespace, so both
// "openid,email" and "openid email" work.
var scopeSep = regexp.MustCompile(`[,\s]+`)

func splitScopes(v string) []string {
	out := []string{}
	for _, part := range scopeSep.Split(strings.TrimSpace(v), -1) {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// applyDockerHost handles every form §3.2 lists: tcp://h:p, http(s)://h:p, h:p, bare h with
// the port defaulting to 2375, unix:///path and /path. A socket form sets socketPath and
// clears host, because the two are alternatives and holding both would leave the endpoint
// resolution order of §3.5 with nothing to choose between.
func applyDockerHost(c *Config, name, value string) (notes []string) {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}

	if path, isSocket := socketForm(v); isSocket {
		if path == "" {
			notes = append(notes, "[config] "+name+" names no socket path; ignoring it")
			return notes
		}
		c.Docker.SocketPath = path
		c.Docker.Host = ""
		c.markProvided("docker.socketPath")
		return nil
	}

	for _, scheme := range []string{"tcp://", "http://", "https://"} {
		if strings.HasPrefix(v, scheme) {
			v = strings.TrimPrefix(v, scheme)
			break
		}
	}
	// A path or query on a TCP form is not an endpoint LabView can use — the Engine API
	// paths are fixed (§10) — so only the authority is kept.
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}

	host, port, ok := splitHostPort(v)
	if !ok {
		notes = append(notes, "[config] "+name+" is not an address LabView can use; ignoring it")
		return notes
	}
	c.Docker.Host = host
	c.markProvided("docker.host")
	if port > 0 {
		c.Docker.Port = port
		c.markProvided("docker.port")
	} else {
		// Bare host: the port defaults to 2375 rather than to whatever a file had set, so
		// that one variable describes one endpoint (§3.2).
		c.Docker.Port = Defaults().Docker.Port
	}
	return notes
}

// socketForm reports whether a value uses one of the two socket spellings, and the path it
// names.
//
// A recognised spelling with no path is still a socket form. Saying so is what keeps
// "unix://" from falling through to the TCP branch, where stripping the scheme separator
// would leave the word "unix" and LabView would go looking for a host by that name.
func socketForm(v string) (path string, isSocket bool) {
	if strings.HasPrefix(v, "unix://") {
		return strings.TrimPrefix(v, "unix://"), true
	}
	if strings.HasPrefix(v, "/") {
		return v, true
	}
	return "", false
}

// splitHostPort accepts h, h:p and [v6]:p, and reports port 0 when none was given. It does
// not accept a port that is not a number, because an endpoint LabView cannot form is worth
// a diagnostic rather than a guess.
func splitHostPort(v string) (host string, port int, ok bool) {
	if v == "" {
		return "", 0, false
	}
	if strings.HasPrefix(v, "[") {
		end := strings.Index(v, "]")
		if end < 0 {
			return "", 0, false
		}
		host = v[:end+1]
		rest := v[end+1:]
		if rest == "" {
			return host, 0, true
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, false
		}
		p, err := strconv.Atoi(rest[1:])
		if err != nil {
			return "", 0, false
		}
		return host, p, true
	}
	i := strings.LastIndex(v, ":")
	if i < 0 {
		return v, 0, true
	}
	p, err := strconv.Atoi(v[i+1:])
	if err != nil {
		return "", 0, false
	}
	return v[:i], p, true
}
