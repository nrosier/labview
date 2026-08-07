package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/transport"
)

// defaultTable is §3.1 transcribed by hand, keyed by dotted setting path.
//
// It is deliberately a second copy of the specification rather than something derived from
// Defaults. Deriving it would only assert that the code agrees with itself; transcribing it
// catches a default that was changed, renamed, or quietly dropped — each of which changes
// what LabView does on a fleet where nobody wrote a configuration file, which is the common
// case.
var defaultTable = map[string]any{
	"appsRoot":         "/data/apps",
	"composeFilenames": []string{"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"},
	"sidecarFilenames": []string{".labview", ".labview.yml", ".labview.yaml"},

	"docker.enabled":        true,
	"docker.host":           "",
	"docker.port":           2375,
	"docker.socketPath":     "/var/run/docker.sock",
	"docker.maxConcurrency": 8,
	"docker.timeoutMs":      5000,
	// 8 MiB is about eight thousand containers at a kilobyte each: high enough that no real
	// fleet reaches it, low enough that a far end answering with a stream is not this
	// process's memory problem.
	"docker.bodyCapBytes": 8 << 20,

	"secrets.maskValues": true,
	"secrets.keyPatterns": []string{"PASS", "SECRET", "TOKEN", "KEY", "APIKEY", "CREDENTIAL",
		"PRIVATE", "SALT", "PEPPER", "DSN"},
	"secrets.keysAlways": []string{"LABVIEW_AUTHENTIK_TOKEN", "LABVIEW_TRAEFIK_PASSWORD",
		"LABVIEW_OIDC_CLIENT_SECRET", "LABVIEW_SESSION_SECRET"},
	"secrets.keysNever":            []string{"PUBLIC_KEY_URL", "KEYCLOAK_REALM"},
	"secrets.redactUriCredentials": true,

	"labels.dockflare.prefix":       "dockflare",
	"labels.traefik.prefix":         "traefik",
	"labels.authentik.hostHints":    []string{"authentik", "goauthentik.io"},
	"labels.authentik.ldapEnvHints": []string{"LDAP_HOST", "LDAP_URI", "LDAP_SERVER", "LDAP_URL"},
	"labels.authentik.oauthEnvHints": []string{"OIDC", "OAUTH", "OPENID", "ISSUER", "CLIENT_ID",
		"CLIENT_SECRET", "SSO"},

	"authentik.enabled":   true,
	"authentik.url":       "",
	"authentik.token":     "",
	"authentik.timeoutMs": 5000,
	"authentik.maxPages":  20,

	"traefik.enabled":   true,
	"traefik.url":       "",
	"traefik.username":  "",
	"traefik.password":  "",
	"traefik.timeoutMs": 5000,

	// The probe is off by default: it is the one stage that sends a request nobody asked for
	// (§13), so a build has to opt in.
	"probe.enabled":        false,
	"probe.lanHost":        "",
	"probe.timeoutMs":      5000,
	"probe.maxConcurrency": 4,

	"auth.passwd.enabled": true,
	"auth.passwd.file":    "/config/passwd",

	"auth.oidc.enabled":       true,
	"auth.oidc.issuer":        "",
	"auth.oidc.clientId":      "",
	"auth.oidc.clientSecret":  "",
	"auth.oidc.redirectUri":   "",
	"auth.oidc.scopes":        []string{"openid", "profile", "email"},
	"auth.oidc.usernameClaim": "preferred_username",
	"auth.oidc.label":         "",
	"auth.oidc.timeoutMs":     5000,

	"auth.session.secret":     "",
	"auth.session.ttlMinutes": 720,
	"auth.session.cookieName": "labview_session",
	"auth.session.secure":     CookieSecureAuto,

	"auth.maxFailedAttempts": 5,
	"auth.lockoutSeconds":    60,

	"cacheTtlSeconds": 60,
	"server.host":     "0.0.0.0",
	"server.port":     8080,

	"blankCredentialVars": []string{},
}

func TestDefaultsMatchTheSpecification(t *testing.T) {
	c := Defaults()
	for key, want := range defaultTable {
		got := get(t, c, key)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", key, got, want)
		}
	}
}

// TestEverySettingHasAStatedDefault closes the loop the other way: a setting added to Config
// without an entry in the table above is a setting whose default nobody wrote down.
func TestEverySettingHasAStatedDefault(t *testing.T) {
	for _, key := range leafKeys(reflect.TypeOf(Config{}), "") {
		if _, ok := defaultTable[key]; !ok {
			t.Errorf("setting %s has no entry in defaultTable — state its §3.1 default", key)
		}
	}
	for key := range defaultTable {
		if !hasLeaf(reflect.TypeOf(Config{}), key) {
			t.Errorf("defaultTable names %s, which is not a setting", key)
		}
	}
}

// TestDefaultsShareNoMemory is the deep-copy requirement of §3. The environment overlay is
// applied onto the merged tree in place, so if two loads shared a backing array, one load's
// overrides would appear in the next — and with the cache holding a build in flight, that is
// a payload describing a configuration that was never in effect (I7).
func TestDefaultsShareNoMemory(t *testing.T) {
	a, b := Defaults(), Defaults()
	for _, key := range leafKeys(reflect.TypeOf(Config{}), "") {
		av, bv := reflect.ValueOf(get(t, a, key)), reflect.ValueOf(get(t, b, key))
		if av.Kind() != reflect.Slice || av.Len() == 0 {
			continue
		}
		if av.Pointer() == bv.Pointer() {
			t.Errorf("%s: two Defaults() calls share one backing array", key)
		}
	}
	// The provenance set too, or marking a key provided in one load would mark it in every
	// other (§3.5).
	if reflect.ValueOf(a.provided).Pointer() == reflect.ValueOf(b.provided).Pointer() {
		t.Error("two Defaults() calls share one provided map")
	}
}

func TestCloneSharesNoMemory(t *testing.T) {
	a := Defaults()
	a.markProvided("docker.socketPath")
	b := a.Clone()

	b.ComposeFilenames[0] = "changed.yml"
	b.Secrets.KeyPatterns[0] = "CHANGED"
	b.Auth.OIDC.Scopes[0] = "changed"
	b.markProvided("probe.lanHost")

	if a.ComposeFilenames[0] != "compose.yml" {
		t.Errorf("clone shares composeFilenames: %q", a.ComposeFilenames[0])
	}
	if a.Secrets.KeyPatterns[0] != "PASS" {
		t.Errorf("clone shares secrets.keyPatterns: %q", a.Secrets.KeyPatterns[0])
	}
	if a.Auth.OIDC.Scopes[0] != "openid" {
		t.Errorf("clone shares auth.oidc.scopes: %q", a.Auth.OIDC.Scopes[0])
	}
	if a.Provided("probe.lanHost") {
		t.Error("clone shares the provided map")
	}
	if !b.Provided("docker.socketPath") {
		t.Error("clone lost a provided key")
	}
}

// TestWithProbeDoesNotMutate is §3.6: the request-scoped override is the only one there is,
// and it must not reach the configuration a concurrent build is reading.
func TestWithProbeDoesNotMutate(t *testing.T) {
	base := Defaults()
	on := base.WithProbe(true)

	if base.Probe.Enabled {
		t.Error("WithProbe(true) mutated the original")
	}
	if !on.Probe.Enabled {
		t.Error("WithProbe(true) did not take")
	}
	if off := on.WithProbe(false); off.Probe.Enabled {
		t.Error("WithProbe(false) did not take")
	}
	on.ComposeFilenames[0] = "changed.yml"
	if base.ComposeFilenames[0] != "compose.yml" {
		t.Error("WithProbe returned a shallow copy")
	}
}

// TestRangeFallbacksUseTheBuiltInDefault covers §3.2's range rules. An out-of-range value
// falls back to the built-in default rather than to whatever the previous layer held, and
// never to a clamp — and it says so, because a silently corrected number is a configuration
// an operator thinks is in effect.
func TestRangeFallbacksUseTheBuiltInDefault(t *testing.T) {
	cases := []struct {
		variable string
		value    string
		key      string
		want     any
		note     string
	}{
		{"LABVIEW_DOCKER_MAX_CONCURRENCY", "0", "docker.maxConcurrency", 8,
			"[config] docker.maxConcurrency must be at least 1; using 8 instead of 0"},
		{"LABVIEW_PROBE_MAX_CONCURRENCY", "-2", "probe.maxConcurrency", 4,
			"[config] probe.maxConcurrency must be at least 1; using 4 instead of -2"},
		{"LABVIEW_DOCKER_TIMEOUT", "0", "docker.timeoutMs", 5000,
			"[config] docker.timeoutMs must be greater than 0; using 5000 instead of 0"},
		{"LABVIEW_AUTHENTIK_TIMEOUT", "-1", "authentik.timeoutMs", 5000,
			"[config] authentik.timeoutMs must be greater than 0; using 5000 instead of -1"},
		{"LABVIEW_TRAEFIK_TIMEOUT", "0", "traefik.timeoutMs", 5000,
			"[config] traefik.timeoutMs must be greater than 0; using 5000 instead of 0"},
		{"LABVIEW_PROBE_TIMEOUT", "0", "probe.timeoutMs", 5000,
			"[config] probe.timeoutMs must be greater than 0; using 5000 instead of 0"},
		{"LABVIEW_OIDC_TIMEOUT", "0", "auth.oidc.timeoutMs", 5000,
			"[config] auth.oidc.timeoutMs must be greater than 0; using 5000 instead of 0"},
		{"LABVIEW_SESSION_TTL_MINUTES", "0", "auth.session.ttlMinutes", 720,
			"[config] auth.session.ttlMinutes must be at least 1; using 720 instead of 0"},
		{"LABVIEW_AUTH_MAX_FAILED_ATTEMPTS", "0", "auth.maxFailedAttempts", 5,
			"[config] auth.maxFailedAttempts must be at least 1; using 5 instead of 0"},
		{"LABVIEW_AUTH_LOCKOUT_SECONDS", "0", "auth.lockoutSeconds", 60,
			"[config] auth.lockoutSeconds must be at least 1; using 60 instead of 0"},
		// The setting is in bytes, so the operator who means eight megabytes and writes 8 asks
		// for eight bytes. Every read would then fail as a protocol error against an Engine
		// that answered correctly, which is the exact confusion this whole change removes — so
		// it falls back and says so rather than being honoured.
		{"LABVIEW_DOCKER_BODY_CAP", "8", "docker.bodyCapBytes", 8 << 20,
			"[config] docker.bodyCapBytes must be at least 64 KiB; using 8388608 instead of 8"},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			cfg, diag := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{c.variable: c.value})})
			if got := get(t, cfg, c.key); !reflect.DeepEqual(got, c.want) {
				t.Errorf("%s = %#v, want %#v", c.key, got, c.want)
			}
			requireLog(t, diag, c.note)
		})
	}
}

// TestTheDockerCapFloorIsTheSharedCap holds MinDockerBodyCap to transport.BodyCap.
//
// The config package imports nothing, on purpose — so the floor is a literal there and the
// two numbers can drift apart in silence. They must not: the floor's whole claim is that a
// Docker cap below what *every other read* already gets can only be a mistake, and if the
// shared cap moved that sentence would stop being true. The test is the import config.go
// deliberately does not have.
func TestTheDockerCapFloorIsTheSharedCap(t *testing.T) {
	if MinDockerBodyCap != transport.BodyCap {
		t.Errorf("MinDockerBodyCap = %d, transport.BodyCap = %d — the floor is meant to be the "+
			"shared default cap, so one of them moved without the other",
			MinDockerBodyCap, transport.BodyCap)
	}
	// And the default has to be above its own floor, or the fallback would fall to a value the
	// validation rejects.
	if got := Defaults().Docker.BodyCapBytes; got < MinDockerBodyCap {
		t.Errorf("default docker.bodyCapBytes = %d, below the floor of %d", got, MinDockerBodyCap)
	}
}

// authentik.maxPages has no environment variable — it is file-only (§3.2) — so the floor is
// reached through a file. Zero pages would let the integration report itself reachable
// having read nothing, which is a false statement about the fleet (I1).
func TestAuthentikMaxPagesFloor(t *testing.T) {
	path := writeConfig(t, "authentik:\n  maxPages: 0\n")
	cfg, diag := Load(Options{ConfigPath: path, Env: MapEnv(nil)})
	if cfg.Authentik.MaxPages != 20 {
		t.Errorf("authentik.maxPages = %d, want 20", cfg.Authentik.MaxPages)
	}
	requireLog(t, diag, "[config] authentik.maxPages must be at least 1; using 20 instead of 0")
}

// TestParsedUnvalidatedNumbersAreLeftAlone: §3.2 marks three numbers "parsed, unvalidated".
// Bounds that are not in the specification are not invented, and nothing is logged about
// them either.
func TestParsedUnvalidatedNumbersAreLeftAlone(t *testing.T) {
	cfg, diag := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		"LABVIEW_DOCKER_PORT": "0",
		"LABVIEW_CACHE_TTL":   "-5",
		"LABVIEW_PORT":        "0",
	})})
	if cfg.Docker.Port != 0 {
		t.Errorf("docker.port = %d, want the 0 it was given", cfg.Docker.Port)
	}
	if cfg.CacheTTLSeconds != -5 {
		t.Errorf("cacheTtlSeconds = %d, want the -5 it was given", cfg.CacheTTLSeconds)
	}
	if cfg.Server.Port != 0 {
		t.Errorf("server.port = %d, want the 0 it was given", cfg.Server.Port)
	}
	if len(diag.Logs) != 0 {
		t.Errorf("unvalidated settings produced logs: %q", diag.Logs)
	}
}

func TestCookieSecureAcceptsThreeLiterals(t *testing.T) {
	for _, want := range []string{CookieSecureAuto, CookieSecureTrue, CookieSecureFalse} {
		cfg, diag := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
			"LABVIEW_AUTH_COOKIE_SECURE": want,
		})})
		if cfg.Auth.Session.Secure != want {
			t.Errorf("auth.session.secure = %q, want %q", cfg.Auth.Session.Secure, want)
		}
		if len(diag.Logs) != 0 {
			t.Errorf("%q produced logs: %q", want, diag.Logs)
		}
	}

	// A fourth spelling keeps the default and says so, from either layer.
	cfg, diag := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		"LABVIEW_AUTH_COOKIE_SECURE": "yes",
	})})
	if cfg.Auth.Session.Secure != CookieSecureAuto {
		t.Errorf("auth.session.secure = %q, want auto", cfg.Auth.Session.Secure)
	}
	requireLog(t, diag, "[config] LABVIEW_AUTH_COOKIE_SECURE must be auto, true or false; keeping auto")

	path := writeConfig(t, "auth:\n  session:\n    secure: sometimes\n")
	cfg, diag = Load(Options{ConfigPath: path, Env: MapEnv(nil)})
	if cfg.Auth.Session.Secure != CookieSecureAuto {
		t.Errorf("auth.session.secure = %q, want auto", cfg.Auth.Session.Secure)
	}
	requireLog(t, diag, "[config] auth.session.secure must be auto, true or false; using auto")
}

// TestMasked is §20's precedence: never, then always, then a case-insensitive substring.
func TestMasked(t *testing.T) {
	c := Defaults()
	cases := []struct {
		key  string
		want bool
	}{
		{"PUBLIC_KEY_URL", false},        // keysNever, though it contains KEY
		{"public_key_url", false},        // and case does not rescue it
		{"KEYCLOAK_REALM", false},        // keysNever
		{"LABVIEW_SESSION_SECRET", true}, // keysAlways
		{"labview_session_secret", true}, // and case does not rescue it either
		{"POSTGRES_PASSWORD", true},      // PASS
		{"postgres_password", true},      // substring match is case-insensitive
		{"api_key", true},                // KEY
		{"DATABASE_DSN", true},           // DSN
		{"PUID", false},                  // nothing matches
		{"TZ", false},                    // nor here
		{"KEYCLOAK_REALM_SUFFIX", true},  // keysNever is exact, not a prefix
		{"MY_PUBLIC_KEY_URL", true},      // likewise
		{"PEPPERMINT_THEME", true},       // §20's rule is a substring, and admits this
	}
	for _, tc := range cases {
		if got := c.Masked(tc.key); got != tc.want {
			t.Errorf("Masked(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}

	// maskValues off withholds nothing, including the four credential keys.
	off := Defaults()
	off.Secrets.MaskValues = false
	for _, key := range []string{"POSTGRES_PASSWORD", "LABVIEW_SESSION_SECRET"} {
		if off.Masked(key) {
			t.Errorf("Masked(%q) = true with maskValues off", key)
		}
	}
}

func TestItoa(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want string
	}{{0, "0"}, {7, "7"}, {720, "720"}, {-2, "-2"}, {-1000, "-1000"}} {
		if got := itoa(tc.n); got != tc.want {
			t.Errorf("itoa(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// get reads a dotted setting path out of a Config by its yaml tags, so a test can name a
// setting the way §3 names it.
func get(t *testing.T, c Config, dotted string) any {
	t.Helper()
	v := reflect.ValueOf(c)
	for _, part := range strings.Split(dotted, ".") {
		if v.Kind() != reflect.Struct {
			t.Fatalf("%s: %s is not a block", dotted, part)
		}
		f, ok := fieldByYAML(v, part)
		if !ok {
			t.Fatalf("%s: no field tagged %q", dotted, part)
		}
		v = f
	}
	return v.Interface()
}

func fieldByYAML(v reflect.Value, name string) (reflect.Value, bool) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tag, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if tag == name {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

// leafKeys lists every dotted setting path in a config type. A block contributes its
// children; anything else is a leaf, including a list, which replaces wholesale.
func leafKeys(t reflect.Type, prefix string) []string {
	var keys []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if tag == "" || tag == "-" {
			continue
		}
		path := tag
		if prefix != "" {
			path = prefix + "." + tag
		}
		if f.Type.Kind() == reflect.Struct {
			keys = append(keys, leafKeys(f.Type, path)...)
			continue
		}
		keys = append(keys, path)
	}
	return keys
}

func hasLeaf(t reflect.Type, dotted string) bool {
	for _, k := range leafKeys(t, "") {
		if k == dotted {
			return true
		}
	}
	return false
}

// requireLog asserts a diagnostic was produced verbatim. The exact wording is part of the
// contract: it is what an operator reads to find out that the number they set is not the
// number in effect.
func requireLog(t *testing.T, d Diagnostics, want string) {
	t.Helper()
	for _, got := range d.Logs {
		if got == want {
			return
		}
	}
	t.Errorf("missing log line\n  want: %s\n  got:  %q", want, d.Logs)
}
