// Package config is §3: the built-in defaults, the configuration file, the environment
// overlay, the four retired settings, and the build stamp.
//
// Three rules shape it.
//
// Precedence is defaults → file → environment, and arrays replace rather than merge, so a
// list an operator writes is the whole list.
//
// Nothing here fails. A malformed file logs and falls back to defaults; a number out of
// range falls back to its default; an unrecognised cookie-secure mode keeps the default
// (I4). The one thing that is not tolerated is silence about it: every fallback produces a
// diagnostic.
//
// `enabled` everywhere means allowed, not on (§3.1). An integration is live only when it
// is also usable, which is why no default TCP Docker host, no default Authentik or Traefik
// address, and no host-naming convention may ever ship (I2).
package config

import "strings"

// Version is the build version reported by the build stamp (§3.4).
const Version = "0.1.0"

// Config is the whole of §3.1. Every field's default is in Defaults, which is the only
// place a default value appears.
type Config struct {
	AppsRoot         string   `yaml:"appsRoot"`
	ComposeFilenames []string `yaml:"composeFilenames"`
	SidecarFilenames []string `yaml:"sidecarFilenames"`

	Docker    DockerConfig    `yaml:"docker"`
	Secrets   SecretsConfig   `yaml:"secrets"`
	Labels    LabelsConfig    `yaml:"labels"`
	Authentik AuthentikConfig `yaml:"authentik"`
	Traefik   TraefikConfig   `yaml:"traefik"`
	Probe     ProbeConfig     `yaml:"probe"`
	Auth      AuthConfig      `yaml:"auth"`

	CacheTTLSeconds int          `yaml:"cacheTtlSeconds"`
	Server          ServerConfig `yaml:"server"`

	// BlankCredentialVars holds the names of credential variables that were present and
	// carried nothing. It is assigned by environment resolution and never appended to, so
	// a configuration file setting this key has no standing (§3.3). Names only, never
	// values (I6).
	BlankCredentialVars []string `yaml:"blankCredentialVars"`

	// provided is the set of dotted setting keys an operator actually supplied, from the
	// file or the environment. §3.5 needs it: the built-in default socket path has to stay
	// distinguishable from an operator-supplied one, because the connection report says
	// "default" in one case and "config" in the other. Guessing that from the value would
	// mean an operator who writes the default path by hand gets told they never set it.
	provided map[string]bool
}

// DockerConfig is the Docker Engine endpoint and the bounds on reading it (§10).
type DockerConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	SocketPath string `yaml:"socketPath"`
	// MaxConcurrency bounds the inspect fan-out; TimeoutMs is per-request socket
	// inactivity, not total time (§3.2).
	MaxConcurrency int `yaml:"maxConcurrency"`
	TimeoutMs      int `yaml:"timeoutMs"`
}

// SecretsConfig is §20: which environment keys are masked, and how.
type SecretsConfig struct {
	MaskValues bool `yaml:"maskValues"`
	// KeyPatterns are substrings; KeysAlways and KeysNever are exact keys, and Never wins.
	KeyPatterns          []string `yaml:"keyPatterns"`
	KeysAlways           []string `yaml:"keysAlways"`
	KeysNever            []string `yaml:"keysNever"`
	RedactURICredentials bool     `yaml:"redactUriCredentials"`
}

// LabelsConfig is the label prefixes and the hint lists of §7. A prefix is configurable
// because an operator may have renamed it; a hint list is configurable because a hint is a
// guess about naming, never a mechanism (I3).
type LabelsConfig struct {
	Dockflare PrefixConfig         `yaml:"dockflare"`
	Traefik   PrefixConfig         `yaml:"traefik"`
	Authentik AuthentikHintsConfig `yaml:"authentik"`
}

// PrefixConfig is one label namespace.
type PrefixConfig struct {
	Prefix string `yaml:"prefix"`
}

// AuthentikHintsConfig is how a service is guessed to be talking to the identity provider
// when nothing confirms it. Everything found this way is inferred confidence at best (§7).
type AuthentikHintsConfig struct {
	HostHints     []string `yaml:"hostHints"`
	LDAPEnvHints  []string `yaml:"ldapEnvHints"`
	OAuthEnvHints []string `yaml:"oauthEnvHints"`
}

// AuthentikConfig is the identity-provider read (§11). Token is a credential and has
// exactly one environment variable and no path form (§3.3). MaxPages is file-only.
type AuthentikConfig struct {
	Enabled   bool   `yaml:"enabled"`
	URL       string `yaml:"url"`
	Token     string `yaml:"token"`
	TimeoutMs int    `yaml:"timeoutMs"`
	MaxPages  int    `yaml:"maxPages"`
}

// TraefikConfig is the reverse-proxy read (§12). Password is a credential — an app
// password, not an API token.
type TraefikConfig struct {
	Enabled   bool   `yaml:"enabled"`
	URL       string `yaml:"url"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	TimeoutMs int    `yaml:"timeoutMs"`
}

// ProbeConfig is the active probe (§13). Enabled is the default for a build, not the
// authority: a request may override it (§13.7). LanHost empty skips the LAN vantage
// entirely and is never guessed (I2).
type ProbeConfig struct {
	Enabled        bool   `yaml:"enabled"`
	LanHost        string `yaml:"lanHost"`
	TimeoutMs      int    `yaml:"timeoutMs"`
	MaxConcurrency int    `yaml:"maxConcurrency"`
}

// AuthConfig is LabView's own login (§19).
type AuthConfig struct {
	Passwd  PasswdConfig  `yaml:"passwd"`
	OIDC    OIDCConfig    `yaml:"oidc"`
	Session SessionConfig `yaml:"session"`

	// MaxFailedAttempts is per username; LockoutSeconds is both the window and the
	// Retry-After (§19).
	MaxFailedAttempts int `yaml:"maxFailedAttempts"`
	LockoutSeconds    int `yaml:"lockoutSeconds"`
}

// PasswdConfig is the file of bcrypt hashes. It is not HTTP Basic authentication and
// nothing in this program may call it basic (§4.7). The file is exempt from the
// credentials rule and is re-read on change (§3.3).
type PasswdConfig struct {
	Enabled bool   `yaml:"enabled"`
	File    string `yaml:"file"`
}

// OIDCConfig is the authorization-code login. ClientSecret is a credential; unset means a
// public client, and PKCE is used either way (§19).
type OIDCConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Issuer        string   `yaml:"issuer"`
	ClientID      string   `yaml:"clientId"`
	ClientSecret  string   `yaml:"clientSecret"`
	RedirectURI   string   `yaml:"redirectUri"`
	Scopes        []string `yaml:"scopes"`
	UsernameClaim string   `yaml:"usernameClaim"`
	// Label empty renders as "Sign in with <issuer host>" (§3.2).
	Label     string `yaml:"label"`
	TimeoutMs int    `yaml:"timeoutMs"`
}

// SessionConfig is the signed cookie. Secret is a credential; unset means a random secret
// per start, so restarts sign everyone out (§3.2).
type SessionConfig struct {
	Secret     string `yaml:"secret"`
	TTLMinutes int    `yaml:"ttlMinutes"`
	CookieName string `yaml:"cookieName"`
	// Secure is one of CookieSecure* and nothing else.
	Secure string `yaml:"secure"`
}

// The three accepted values of auth.session.secure. Anything else keeps the default (§3.2).
const (
	CookieSecureAuto  = "auto"
	CookieSecureTrue  = "true"
	CookieSecureFalse = "false"
)

// ServerConfig is the one inbound listener.
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// Defaults is §3.1, verbatim and in its order.
//
// It builds every slice inline rather than referring to package-level variables, so two
// calls share no memory. That is what makes the deep-copy requirement of §3 hold: the
// environment overlay is applied onto the merged tree in place, and if Defaults handed out
// the same backing arrays each time, one load's overrides would leak into the next.
func Defaults() Config {
	return Config{
		AppsRoot:         "/data/apps",
		ComposeFilenames: []string{"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"},
		SidecarFilenames: []string{".labview", ".labview.yml", ".labview.yaml"},

		Docker: DockerConfig{
			Enabled:        true,
			Host:           "",
			Port:           2375,
			SocketPath:     "/var/run/docker.sock",
			MaxConcurrency: 8,
			TimeoutMs:      5000,
		},
		Secrets: SecretsConfig{
			MaskValues: true,
			KeyPatterns: []string{"PASS", "SECRET", "TOKEN", "KEY", "APIKEY", "CREDENTIAL",
				"PRIVATE", "SALT", "PEPPER", "DSN"},
			KeysAlways: []string{"LABVIEW_AUTHENTIK_TOKEN", "LABVIEW_TRAEFIK_PASSWORD",
				"LABVIEW_OIDC_CLIENT_SECRET", "LABVIEW_SESSION_SECRET"},
			KeysNever:            []string{"PUBLIC_KEY_URL", "KEYCLOAK_REALM"},
			RedactURICredentials: true,
		},
		Labels: LabelsConfig{
			Dockflare: PrefixConfig{Prefix: "dockflare"},
			Traefik:   PrefixConfig{Prefix: "traefik"},
			Authentik: AuthentikHintsConfig{
				HostHints:    []string{"authentik", "goauthentik.io"},
				LDAPEnvHints: []string{"LDAP_HOST", "LDAP_URI", "LDAP_SERVER", "LDAP_URL"},
				OAuthEnvHints: []string{"OIDC", "OAUTH", "OPENID", "ISSUER", "CLIENT_ID",
					"CLIENT_SECRET", "SSO"},
			},
		},
		Authentik: AuthentikConfig{Enabled: true, URL: "", Token: "", TimeoutMs: 5000, MaxPages: 20},
		Traefik:   TraefikConfig{Enabled: true, URL: "", Username: "", Password: "", TimeoutMs: 5000},
		Probe:     ProbeConfig{Enabled: false, LanHost: "", TimeoutMs: 5000, MaxConcurrency: 4},
		Auth: AuthConfig{
			Passwd: PasswdConfig{Enabled: true, File: "/config/passwd"},
			OIDC: OIDCConfig{
				Enabled:       true,
				Issuer:        "",
				ClientID:      "",
				ClientSecret:  "",
				RedirectURI:   "",
				Scopes:        []string{"openid", "profile", "email"},
				UsernameClaim: "preferred_username",
				Label:         "",
				TimeoutMs:     5000,
			},
			Session: SessionConfig{
				Secret:     "",
				TTLMinutes: 720,
				CookieName: "labview_session",
				Secure:     CookieSecureAuto,
			},
			MaxFailedAttempts: 5,
			LockoutSeconds:    60,
		},
		CacheTTLSeconds:     60,
		Server:              ServerConfig{Host: "0.0.0.0", Port: 8080},
		BlankCredentialVars: []string{},

		provided: map[string]bool{},
	}
}

// Provided reports whether an operator supplied this dotted setting key, in the file or in
// the environment. It answers §3.5's question about the Docker endpoint's source; a value
// equal to its default answers nothing.
func (c Config) Provided(key string) bool { return c.provided[key] }

func (c *Config) markProvided(keys ...string) {
	if c.provided == nil {
		c.provided = map[string]bool{}
	}
	for _, k := range keys {
		c.provided[k] = true
	}
}

// Clone returns a copy that shares no memory with the original: every slice and the
// provided set are duplicated. §3.6 requires it — a request that overrides probe.enabled
// must not mutate the configuration, because the cache may have another build in flight
// still holding the old value (I7).
func (c Config) Clone() Config {
	out := c
	out.ComposeFilenames = cloneStrings(c.ComposeFilenames)
	out.SidecarFilenames = cloneStrings(c.SidecarFilenames)
	out.Secrets.KeyPatterns = cloneStrings(c.Secrets.KeyPatterns)
	out.Secrets.KeysAlways = cloneStrings(c.Secrets.KeysAlways)
	out.Secrets.KeysNever = cloneStrings(c.Secrets.KeysNever)
	out.Labels.Authentik.HostHints = cloneStrings(c.Labels.Authentik.HostHints)
	out.Labels.Authentik.LDAPEnvHints = cloneStrings(c.Labels.Authentik.LDAPEnvHints)
	out.Labels.Authentik.OAuthEnvHints = cloneStrings(c.Labels.Authentik.OAuthEnvHints)
	out.Auth.OIDC.Scopes = cloneStrings(c.Auth.OIDC.Scopes)
	out.BlankCredentialVars = cloneStrings(c.BlankCredentialVars)
	out.provided = make(map[string]bool, len(c.provided))
	for k, v := range c.provided {
		out.provided[k] = v
	}
	return out
}

// WithProbe returns a copy whose probe is on or off as given. It is the only
// request-scoped setting there is (§3.6).
func (c Config) WithProbe(enabled bool) Config {
	out := c.Clone()
	out.Probe.Enabled = enabled
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// validate applies the range rules of §3.2 after both the file and the environment have
// been merged. An out-of-range number is rejected in favour of its default — literally the
// built-in default, not the previous layer's value, because that is what the rule says.
//
// Two settings are deliberately exempt: docker.port and cacheTtlSeconds are "parsed,
// unvalidated" in §3.2, and server.port is not constrained either. Bounds that are not in
// the spec are not invented here.
func (c *Config) validate() []string {
	d := Defaults()
	var notes []string

	atLeastOne := func(name string, v *int, def int) {
		if *v < 1 {
			notes = append(notes, rangeNote(name, *v, def, "at least 1"))
			*v = def
		}
	}
	positive := func(name string, v *int, def int) {
		if *v <= 0 {
			notes = append(notes, rangeNote(name, *v, def, "greater than 0"))
			*v = def
		}
	}

	atLeastOne("docker.maxConcurrency", &c.Docker.MaxConcurrency, d.Docker.MaxConcurrency)
	atLeastOne("probe.maxConcurrency", &c.Probe.MaxConcurrency, d.Probe.MaxConcurrency)
	// maxPages bounds a read the same way maxConcurrency does. Zero would make the
	// integration report itself reachable having read nothing, which is a false statement
	// about the fleet (I1), so it is held to the same floor.
	atLeastOne("authentik.maxPages", &c.Authentik.MaxPages, d.Authentik.MaxPages)

	positive("docker.timeoutMs", &c.Docker.TimeoutMs, d.Docker.TimeoutMs)
	positive("authentik.timeoutMs", &c.Authentik.TimeoutMs, d.Authentik.TimeoutMs)
	positive("traefik.timeoutMs", &c.Traefik.TimeoutMs, d.Traefik.TimeoutMs)
	positive("probe.timeoutMs", &c.Probe.TimeoutMs, d.Probe.TimeoutMs)
	positive("auth.oidc.timeoutMs", &c.Auth.OIDC.TimeoutMs, d.Auth.OIDC.TimeoutMs)

	atLeastOne("auth.session.ttlMinutes", &c.Auth.Session.TTLMinutes, d.Auth.Session.TTLMinutes)
	atLeastOne("auth.maxFailedAttempts", &c.Auth.MaxFailedAttempts, d.Auth.MaxFailedAttempts)
	atLeastOne("auth.lockoutSeconds", &c.Auth.LockoutSeconds, d.Auth.LockoutSeconds)

	switch c.Auth.Session.Secure {
	case CookieSecureAuto, CookieSecureTrue, CookieSecureFalse:
	default:
		notes = append(notes, "[config] auth.session.secure must be auto, true or false; using "+d.Auth.Session.Secure)
		c.Auth.Session.Secure = d.Auth.Session.Secure
	}
	return notes
}

func rangeNote(name string, got, def int, want string) string {
	return "[config] " + name + " must be " + want + "; using " + itoa(def) + " instead of " + itoa(got)
}

// itoa avoids pulling strconv into this file's import list for one call site, and keeps
// the note text free of any formatting verb that could be handed a value by accident.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// Masked reports whether an environment key's value must be withheld (§20). KeysNever wins
// over everything, then KeysAlways, then a case-insensitive substring match on KeyPatterns.
func (c Config) Masked(key string) bool {
	if !c.Secrets.MaskValues {
		return false
	}
	for _, k := range c.Secrets.KeysNever {
		if strings.EqualFold(k, key) {
			return false
		}
	}
	for _, k := range c.Secrets.KeysAlways {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	upper := strings.ToUpper(key)
	for _, p := range c.Secrets.KeyPatterns {
		if p != "" && strings.Contains(upper, strings.ToUpper(p)) {
			return true
		}
	}
	return false
}
