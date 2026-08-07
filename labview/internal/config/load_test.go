package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Precedence: defaults → file → environment (§3)
// ---------------------------------------------------------------------------

func TestPrecedenceDefaultsThenFileThenEnvironment(t *testing.T) {
	path := writeConfig(t, "appsRoot: /from/file\nserver:\n  host: 10.0.0.1\n")

	cfg, diag := Load(Options{ConfigPath: path, Env: MapEnv(map[string]string{
		"LABVIEW_APPS_ROOT": "/from/env",
	})})
	if len(diag.Logs) != 0 {
		t.Errorf("unexpected logs: %q", diag.Logs)
	}
	if cfg.AppsRoot != "/from/env" {
		t.Errorf("appsRoot = %q, want the environment's value", cfg.AppsRoot)
	}
	if cfg.Server.Host != "10.0.0.1" {
		t.Errorf("server.host = %q, want the file's value", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("server.port = %d, want the default", cfg.Server.Port)
	}
}

// TestListsReplaceRatherThanMerge is §3's array rule: a list an operator writes is the whole
// list. Merging would leave a filename in play that they had removed on purpose.
func TestListsReplaceRatherThanMerge(t *testing.T) {
	path := writeConfig(t, "composeFilenames:\n  - only.yml\nsecrets:\n  keyPatterns:\n    - MINE\n")
	cfg, _ := Load(Options{ConfigPath: path, Env: MapEnv(nil)})

	if want := []string{"only.yml"}; !reflect.DeepEqual(cfg.ComposeFilenames, want) {
		t.Errorf("composeFilenames = %#v, want %#v", cfg.ComposeFilenames, want)
	}
	if want := []string{"MINE"}; !reflect.DeepEqual(cfg.Secrets.KeyPatterns, want) {
		t.Errorf("secrets.keyPatterns = %#v, want %#v", cfg.Secrets.KeyPatterns, want)
	}
	// A list the file did not mention keeps its default in full.
	if len(cfg.SidecarFilenames) != 3 {
		t.Errorf("sidecarFilenames = %#v, want the three defaults", cfg.SidecarFilenames)
	}
}

func TestMissingFileIsNotAFault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.yml")
	cfg, diag := Load(Options{ConfigPath: path, Env: MapEnv(nil)})
	if len(diag.Logs) != 0 {
		t.Errorf("a missing file logged: %q", diag.Logs)
	}
	if cfg.AppsRoot != "/data/apps" {
		t.Errorf("appsRoot = %q, want the default", cfg.AppsRoot)
	}
}

func TestMalformedFileFallsBackToDefaults(t *testing.T) {
	path := writeConfig(t, "appsRoot: /x\n\tbad: y\n")
	cfg, diag := Load(Options{ConfigPath: path, Env: MapEnv(nil)})

	if cfg.AppsRoot != "/data/apps" {
		t.Errorf("appsRoot = %q, want the default", cfg.AppsRoot)
	}
	if len(diag.Logs) != 1 {
		t.Fatalf("logs = %q, want exactly one", diag.Logs)
	}
	log := diag.Logs[0]
	if !strings.HasPrefix(log, "[config] failed to parse "+path+": ") || !strings.HasSuffix(log, "; using defaults") {
		t.Errorf("log = %q, want the §3 parse-failure form", log)
	}
}

// TestAFileThatFailsPartWayThroughAppliesNothing is why the decode goes into a copy.
//
// yaml.v3 reports a type error only after it has decoded everything it could, so a file with
// one bad block would otherwise leave the good keys applied — "falling back to defaults"
// would silently mean some of them. An operator reading the log line has to be able to
// believe it.
func TestAFileThatFailsPartWayThroughAppliesNothing(t *testing.T) {
	path := writeConfig(t, "appsRoot: /from/file\ndocker: 5\n")
	cfg, diag := Load(Options{ConfigPath: path, Env: MapEnv(nil)})

	if cfg.AppsRoot != "/data/apps" {
		t.Errorf("appsRoot = %q — a refused file was applied anyway", cfg.AppsRoot)
	}
	if cfg.Provided("appsRoot") {
		t.Error("a refused file marked appsRoot as provided")
	}
	if len(diag.Logs) != 1 {
		t.Errorf("logs = %q, want exactly one", diag.Logs)
	}
}

func TestUnreadableFileFallsBackToDefaults(t *testing.T) {
	// A directory where a file is expected: readable as a path, not as a document.
	dir := t.TempDir()
	cfg, diag := Load(Options{ConfigPath: dir, Env: MapEnv(nil)})

	if cfg.AppsRoot != "/data/apps" {
		t.Errorf("appsRoot = %q, want the default", cfg.AppsRoot)
	}
	if len(diag.Logs) != 1 || !strings.HasSuffix(diag.Logs[0], "; using defaults") {
		t.Errorf("logs = %q, want one fallback line", diag.Logs)
	}
}

// TestConfigPathResolution: the explicit option, then LABVIEW_CONFIG, then ./config.yml.
func TestConfigPathResolution(t *testing.T) {
	named := writeConfig(t, "appsRoot: /named\n")
	cfg, _ := Load(Options{Env: MapEnv(map[string]string{ConfigPathVar: named})})
	if cfg.AppsRoot != "/named" {
		t.Errorf("appsRoot = %q, want the file LABVIEW_CONFIG named", cfg.AppsRoot)
	}

	// The option wins over the variable, which is what lets the corpus and the one-shot scan
	// name a file without touching the environment.
	other := writeConfig(t, "appsRoot: /option\n")
	cfg, _ = Load(Options{ConfigPath: other, Env: MapEnv(map[string]string{ConfigPathVar: named})})
	if cfg.AppsRoot != "/option" {
		t.Errorf("appsRoot = %q, want the option's file", cfg.AppsRoot)
	}

	// A blank variable falls through to the default path rather than reading "".
	cfg, diag := Load(Options{Env: MapEnv(map[string]string{ConfigPathVar: "   "})})
	if len(diag.Logs) != 0 {
		t.Errorf("a blank LABVIEW_CONFIG logged: %q", diag.Logs)
	}
	if cfg.AppsRoot != "/data/apps" {
		t.Errorf("appsRoot = %q, want the default", cfg.AppsRoot)
	}
}

// TestSkipFileForcesDefaults is §23's requirement: the corpus must not pick up an operator's
// config.yml, and must not have to rely on the working directory to avoid it.
func TestSkipFileForcesDefaults(t *testing.T) {
	path := writeConfig(t, "appsRoot: /from/file\n")
	cfg, diag := Load(Options{SkipFile: true, ConfigPath: path, Env: MapEnv(nil)})
	if cfg.AppsRoot != "/data/apps" {
		t.Errorf("appsRoot = %q, want the default", cfg.AppsRoot)
	}
	if len(diag.Logs) != 0 {
		t.Errorf("unexpected logs: %q", diag.Logs)
	}
}

// TestNilEnvIsAnEmptyEnvironment: nothing reads the process environment implicitly, which is
// the other half of what makes the corpus hermetic (§23).
func TestNilEnvIsAnEmptyEnvironment(t *testing.T) {
	t.Setenv("LABVIEW_APPS_ROOT", "/from/process")
	cfg, _ := Load(Options{SkipFile: true})
	if cfg.AppsRoot != "/data/apps" {
		t.Errorf("appsRoot = %q — Load read the ambient environment", cfg.AppsRoot)
	}

	// OSEnv is how a caller asks for it on purpose.
	cfg, _ = Load(Options{SkipFile: true, Env: OSEnv()})
	if cfg.AppsRoot != "/from/process" {
		t.Errorf("appsRoot = %q, want the process value under OSEnv", cfg.AppsRoot)
	}
}

// ---------------------------------------------------------------------------
// Provenance (§3.5)
// ---------------------------------------------------------------------------

// TestProvidedRecordsWhatAnOperatorSupplied: the connection report distinguishes a socket
// path from the configuration from the built-in default, and a value equal to its default
// cannot answer that question.
func TestProvidedRecordsWhatAnOperatorSupplied(t *testing.T) {
	cfg, _ := Load(Options{SkipFile: true, Env: MapEnv(nil)})
	if cfg.Provided("docker.socketPath") {
		t.Error("nothing was supplied, yet docker.socketPath reports as provided")
	}

	// Written by hand, and identical to the default: still supplied.
	path := writeConfig(t, "docker:\n  socketPath: /var/run/docker.sock\n")
	cfg, _ = Load(Options{ConfigPath: path, Env: MapEnv(nil)})
	if !cfg.Provided("docker.socketPath") {
		t.Error("a file wrote docker.socketPath, yet it reports as unprovided")
	}
	if !cfg.Provided("docker") {
		t.Error("the enclosing block should be marked too")
	}

	cfg, _ = Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		"LABVIEW_DOCKER_SOCKET": "/var/run/docker.sock",
	})})
	if !cfg.Provided("docker.socketPath") {
		t.Error("the environment set docker.socketPath, yet it reports as unprovided")
	}
}

// ---------------------------------------------------------------------------
// The environment overlay (§3.2)
// ---------------------------------------------------------------------------

func TestBoolValueIsTrueUnlessExactlyFalse(t *testing.T) {
	cases := map[string]bool{
		"false":   false,
		" false":  false, // trimmed: a stray space is an artifact of how it was set
		"false\n": false,
		"true":    true,
		"":        true, // present at all means the operator meant something
		"0":       true,
		"no":      true,
		"FALSE":   true, // the rule is the literal, not a case-insensitive match
		"False":   true,
		"falsey":  true,
	}
	for value, want := range cases {
		if got := boolValue(value); got != want {
			t.Errorf("boolValue(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestParseNumber(t *testing.T) {
	cases := []struct {
		value string
		want  int
		ok    bool
	}{
		{"8", 8, true},
		{" 8 ", 8, true},
		{"8.9", 8, true},   // floored
		{"-3.2", -4, true}, // floored, not truncated toward zero
		{"0", 0, true},
		{"1e3", 1000, true},
		{"", 0, false},
		{"eight", 0, false},
		{"NaN", 0, false},
		{"Inf", 0, false},
		{"-Inf", 0, false},
		{"1e30", 0, false}, // beyond int32: refused rather than wrapped
		{"-1e30", 0, false},
	}
	for _, c := range cases {
		got, ok := parseNumber(c.value)
		if ok != c.ok || got != c.want {
			t.Errorf("parseNumber(%q) = %d, %v; want %d, %v", c.value, got, ok, c.want, c.ok)
		}
	}
}

func TestNonNumericNumberIsIgnoredWithANote(t *testing.T) {
	cfg, diag := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		"LABVIEW_DOCKER_TIMEOUT": "soon",
	})})
	if cfg.Docker.TimeoutMs != 5000 {
		t.Errorf("docker.timeoutMs = %d, want the default", cfg.Docker.TimeoutMs)
	}
	if cfg.Provided("docker.timeoutMs") {
		t.Error("a rejected value marked the setting as provided")
	}
	requireLog(t, diag, "[config] LABVIEW_DOCKER_TIMEOUT is not a number; ignoring it")
}

func TestSplitList(t *testing.T) {
	if got := splitList(".labview, .labview.yml ,,", ","); !reflect.DeepEqual(got, []string{".labview", ".labview.yml"}) {
		t.Errorf("splitList = %#v", got)
	}
	if got := splitList(" , ", ","); len(got) != 0 {
		t.Errorf("splitList of blanks = %#v, want empty", got)
	}
}

// An environment variable that lists nothing is ignored rather than emptying the list: an
// empty set of compose filenames would find no applications at all, which is not something
// anyone types on purpose (§3.2).
func TestEmptyListVariableKeepsTheDefault(t *testing.T) {
	cfg, _ := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		"LABVIEW_SIDECAR_FILENAMES": " , ,",
	})})
	if len(cfg.SidecarFilenames) != 3 {
		t.Errorf("sidecarFilenames = %#v, want the three defaults", cfg.SidecarFilenames)
	}
	if cfg.Provided("sidecarFilenames") {
		t.Error("an ignored variable marked the setting as provided")
	}
}

func TestSplitScopesAcceptsCommasAndWhitespace(t *testing.T) {
	want := []string{"openid", "profile", "email"}
	for _, value := range []string{"openid,profile,email", "openid profile email",
		" openid, profile  email ", "openid,\tprofile\nemail"} {
		if got := splitScopes(value); !reflect.DeepEqual(got, want) {
			t.Errorf("splitScopes(%q) = %#v, want %#v", value, got, want)
		}
	}
	if got := splitScopes("  "); len(got) != 0 {
		t.Errorf("splitScopes of blanks = %#v, want empty", got)
	}
}

func TestEveryValueIsTrimmed(t *testing.T) {
	cfg, _ := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		"LABVIEW_APPS_ROOT":      "  /data/apps-2\n",
		"LABVIEW_PROBE_LAN_HOST": "\t192.0.2.10 ",
		"LABVIEW_AUTHENTIK_URL":  " https://id.example.com ",
	})})
	if cfg.AppsRoot != "/data/apps-2" {
		t.Errorf("appsRoot = %q, want it trimmed", cfg.AppsRoot)
	}
	if cfg.Probe.LanHost != "192.0.2.10" {
		t.Errorf("probe.lanHost = %q, want it trimmed", cfg.Probe.LanHost)
	}
	if cfg.Authentik.URL != "https://id.example.com" {
		t.Errorf("authentik.url = %q, want it trimmed", cfg.Authentik.URL)
	}
}

func TestLogLevel(t *testing.T) {
	if got := LogLevel(MapEnv(nil)); got != DefaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", got, DefaultLogLevel)
	}
	if got := LogLevel(MapEnv(map[string]string{LogLevelVar: " debug\n"})); got != "debug" {
		t.Errorf("LogLevel = %q, want debug", got)
	}
	if got := LogLevel(MapEnv(map[string]string{LogLevelVar: "  "})); got != DefaultLogLevel {
		t.Errorf("LogLevel = %q, want the default for a blank value", got)
	}
}

// ---------------------------------------------------------------------------
// The Docker endpoint (§3.2, §3.5)
// ---------------------------------------------------------------------------

func TestDockerHostForms(t *testing.T) {
	// Both fields start out holding something an earlier layer could have left, so the table
	// can say which of them each form is expected to touch.
	const (
		leftoverHost   = "leftover"
		leftoverPort   = 9999
		defaultSocket  = "/var/run/docker.sock"
		suppliedSocket = "/run/docker.sock"
	)
	cases := []struct {
		value  string
		host   string
		port   int
		socket string
		note   bool
	}{
		{value: "tcp://10.0.0.5:2376", host: "10.0.0.5", port: 2376, socket: defaultSocket},
		{value: "http://10.0.0.5:2375", host: "10.0.0.5", port: 2375, socket: defaultSocket},
		{value: "https://dockerd:2376", host: "dockerd", port: 2376, socket: defaultSocket},
		{value: "10.0.0.5:2376", host: "10.0.0.5", port: 2376, socket: defaultSocket},
		// A bare host takes the built-in port rather than whatever the earlier layer left, so
		// that one variable describes one whole endpoint.
		{value: "dockerd", host: "dockerd", port: 2375, socket: defaultSocket},
		{value: "[::1]:2375", host: "[::1]", port: 2375, socket: defaultSocket},
		{value: "[::1]", host: "[::1]", port: 2375, socket: defaultSocket},
		// A path or query on a TCP form is not part of an endpoint LabView can use: the
		// Engine API paths are fixed (§10).
		{value: "tcp://10.0.0.5:2376/v1.43", host: "10.0.0.5", port: 2376, socket: defaultSocket},
		// The socket forms clear the host, because the two are alternatives and holding both
		// would leave §3.5's resolution order with nothing to choose between. The port is
		// left as it was: it belongs to the other form and describes nothing here.
		{value: "unix://" + suppliedSocket, host: "", port: leftoverPort, socket: suppliedSocket},
		{value: "/run/user/1000/docker.sock", host: "", port: leftoverPort, socket: "/run/user/1000/docker.sock"},
		// Not an address: a diagnostic, and nothing changed. Guessing here would point the
		// Engine read at a host nobody named.
		{value: "tcp://dockerd:soon", host: leftoverHost, port: leftoverPort, socket: defaultSocket, note: true},
		{value: "dockerd:", host: leftoverHost, port: leftoverPort, socket: defaultSocket, note: true},
		{value: "unix://", host: leftoverHost, port: leftoverPort, socket: defaultSocket, note: true},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			cfg := Defaults()
			cfg.Docker.Host = leftoverHost
			cfg.Docker.Port = leftoverPort
			notes := applyDockerHost(&cfg, "LABVIEW_DOCKER_HOST", c.value)

			if cfg.Docker.Host != c.host {
				t.Errorf("host = %q, want %q", cfg.Docker.Host, c.host)
			}
			if cfg.Docker.Port != c.port {
				t.Errorf("port = %d, want %d", cfg.Docker.Port, c.port)
			}
			if cfg.Docker.SocketPath != c.socket {
				t.Errorf("socketPath = %q, want %q", cfg.Docker.SocketPath, c.socket)
			}
			if got := len(notes) > 0; got != c.note {
				t.Errorf("notes = %q, want a note: %v", notes, c.note)
			}
		})
	}
}

// A variable that is present and carries nothing changes nothing and says nothing: unlike a
// credential, an endpoint that was set to blank is not a fact worth reporting.
func TestBlankDockerHostIsIgnoredSilently(t *testing.T) {
	cfg := Defaults()
	if notes := applyDockerHost(&cfg, "DOCKER_HOST", "  "); len(notes) != 0 {
		t.Errorf("notes = %q, want none", notes)
	}
	if cfg.Docker.Host != "" || cfg.Docker.SocketPath != "/var/run/docker.sock" {
		t.Errorf("endpoint changed: host %q socket %q", cfg.Docker.Host, cfg.Docker.SocketPath)
	}
	if cfg.Provided("docker.host") || cfg.Provided("docker.socketPath") {
		t.Error("a blank value marked the endpoint as provided")
	}
}

// TestDockerEndpointVariableOrder is the order §3.2 tabulates: the generic variable first so
// the LabView-specific one can win, and the socket variable always last.
func TestDockerEndpointVariableOrder(t *testing.T) {
	cfg, _ := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		"DOCKER_HOST":         "tcp://generic:2375",
		"LABVIEW_DOCKER_HOST": "tcp://specific:2376",
	})})
	if cfg.Docker.Host != "specific" || cfg.Docker.Port != 2376 {
		t.Errorf("endpoint = %s:%d, want specific:2376", cfg.Docker.Host, cfg.Docker.Port)
	}

	cfg, _ = Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		"LABVIEW_DOCKER_HOST":   "tcp://specific:2376",
		"LABVIEW_DOCKER_SOCKET": "/run/docker.sock",
	})})
	if cfg.Docker.SocketPath != "/run/docker.sock" {
		t.Errorf("socketPath = %q, want the socket variable to win", cfg.Docker.SocketPath)
	}
	if cfg.Docker.Host != "" {
		t.Errorf("host = %q, want it cleared by the socket variable", cfg.Docker.Host)
	}

	// LABVIEW_DOCKER_PORT still applies to a host that named no port.
	cfg, _ = Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		"LABVIEW_DOCKER_HOST": "dockerd",
		"LABVIEW_DOCKER_PORT": "2376",
	})})
	if cfg.Docker.Host != "dockerd" || cfg.Docker.Port != 2376 {
		t.Errorf("endpoint = %s:%d, want dockerd:2376", cfg.Docker.Host, cfg.Docker.Port)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		ok   bool
	}{
		{"h", "h", 0, true},
		{"h:1", "h", 1, true},
		{"[::1]", "[::1]", 0, true},
		{"[::1]:2375", "[::1]", 2375, true},
		{"[::1", "", 0, false},
		{"[::1]x", "", 0, false},
		{"[::1]:x", "", 0, false},
		{"h:x", "", 0, false},
		{"", "", 0, false},
	}
	for _, c := range cases {
		host, port, ok := splitHostPort(c.in)
		if host != c.host || port != c.port || ok != c.ok {
			t.Errorf("splitHostPort(%q) = %q, %d, %v; want %q, %d, %v",
				c.in, host, port, ok, c.host, c.port, c.ok)
		}
	}
}

// ---------------------------------------------------------------------------
// Credentials (§3.3, I6)
// ---------------------------------------------------------------------------

// TestBlankCredentialVarsRecordsNamesOnly. A credential that is present and carries nothing
// is a different fact from one that was never set — it becomes a credential phase for a scan
// target and a startup note for LabView's own login — and nothing else records it. What is
// recorded is the variable's name, never its value.
func TestBlankCredentialVarsRecordsNamesOnly(t *testing.T) {
	cfg, _ := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		AuthentikTokenVar:   "   ",
		TraefikPasswordVar:  "",
		OIDCClientSecretVar: "a-real-secret",
	})})
	want := []string{AuthentikTokenVar, TraefikPasswordVar}
	if !reflect.DeepEqual(cfg.BlankCredentialVars, want) {
		t.Errorf("blankCredentialVars = %#v, want %#v", cfg.BlankCredentialVars, want)
	}
	for _, name := range cfg.BlankCredentialVars {
		if strings.Contains(name, "secret") || strings.Contains(name, "a-real") {
			t.Errorf("blankCredentialVars carries a value: %q", name)
		}
	}

	// A credential that was never set is not blank — it is absent, and says nothing.
	cfg, _ = Load(Options{SkipFile: true, Env: MapEnv(nil)})
	if len(cfg.BlankCredentialVars) != 0 {
		t.Errorf("blankCredentialVars = %#v, want empty", cfg.BlankCredentialVars)
	}
}

// TestBlankCredentialVarsIsAssignedNotAppended: the fact being recorded is about the
// environment, so a configuration file writing the key has no standing (§3.3).
func TestBlankCredentialVarsIsAssignedNotAppended(t *testing.T) {
	path := writeConfig(t, "blankCredentialVars:\n  - MADE_UP_VAR\n")
	cfg, _ := Load(Options{ConfigPath: path, Env: MapEnv(map[string]string{
		AuthentikTokenVar: "",
	})})
	if want := []string{AuthentikTokenVar}; !reflect.DeepEqual(cfg.BlankCredentialVars, want) {
		t.Errorf("blankCredentialVars = %#v, want %#v", cfg.BlankCredentialVars, want)
	}
}

func TestCredentialsAreTrimmedAndApplied(t *testing.T) {
	cfg, _ := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		AuthentikTokenVar:   " tok \n",
		TraefikPasswordVar:  "pw",
		OIDCClientSecretVar: "cs",
		SessionSecretVar:    "ss",
	})})
	if cfg.Authentik.Token != "tok" {
		t.Errorf("authentik.token = %q, want it trimmed", cfg.Authentik.Token)
	}
	for name, got := range map[string]string{
		"traefik.password":       cfg.Traefik.Password,
		"auth.oidc.clientSecret": cfg.Auth.OIDC.ClientSecret,
		"auth.session.secret":    cfg.Auth.Session.Secret,
	} {
		if got == "" {
			t.Errorf("%s was not applied", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Retired settings (§3.3)
// ---------------------------------------------------------------------------

// TestRetiredSettingsAreReportedByNameOnly. Retiring the `*_FILE` forms was about a
// credential no longer travelling by path; repeating the path in the warning would put it
// straight back into the payload (I6).
func TestRetiredSettingsAreReportedByNameOnly(t *testing.T) {
	path := writeConfig(t, strings.Join([]string{
		"authentik:",
		"  tokenFile: /run/secrets/authentik-token",
		"traefik:",
		"  passwordFile: /run/secrets/traefik-password",
		"auth:",
		"  oidc:",
		"    clientSecretFile: /run/secrets/oidc",
		"  session:",
		"    secretFile: /run/secrets/session",
		"",
	}, "\n"))

	cfg, diag := Load(Options{ConfigPath: path, Env: MapEnv(map[string]string{
		"LABVIEW_AUTHENTIK_TOKEN_FILE":    "/run/secrets/authentik-token",
		"LABVIEW_TRAEFIK_PASSWORD_FILE":   "",
		"LABVIEW_OIDC_CLIENT_SECRET_FILE": "/run/secrets/oidc",
		"LABVIEW_SESSION_SECRET_FILE":     "/run/secrets/session",
	})})

	want := []string{
		"LABVIEW_AUTHENTIK_TOKEN_FILE is no longer read — put the value in LABVIEW_AUTHENTIK_TOKEN instead",
		"authentik.tokenFile in the configuration file is no longer read — put the value in LABVIEW_AUTHENTIK_TOKEN instead",
		"LABVIEW_TRAEFIK_PASSWORD_FILE is no longer read — put the value in LABVIEW_TRAEFIK_PASSWORD instead",
		"traefik.passwordFile in the configuration file is no longer read — put the value in LABVIEW_TRAEFIK_PASSWORD instead",
		"LABVIEW_OIDC_CLIENT_SECRET_FILE is no longer read — put the value in LABVIEW_OIDC_CLIENT_SECRET instead",
		"auth.oidc.clientSecretFile in the configuration file is no longer read — put the value in LABVIEW_OIDC_CLIENT_SECRET instead",
		"LABVIEW_SESSION_SECRET_FILE is no longer read — put the value in LABVIEW_SESSION_SECRET instead",
		"auth.session.secretFile in the configuration file is no longer read — put the value in LABVIEW_SESSION_SECRET instead",
	}
	if !reflect.DeepEqual(diag.Warnings, want) {
		t.Errorf("warnings mismatch\n  got:  %#v\n  want: %#v", diag.Warnings, want)
	}
	for _, w := range diag.Warnings {
		if strings.Contains(w, "/run/secrets") {
			t.Errorf("a warning echoed the path: %q", w)
		}
	}
	// Recognising a retired key must not make it a setting.
	if cfg.Authentik.Token != "" {
		t.Errorf("authentik.token = %q — a retired key was read after all", cfg.Authentik.Token)
	}
}

// The asymmetry in §3.3: a variable is reported when present at all, a key only when it
// holds a non-blank string. Setting a variable to nothing is still an attempt to configure
// LabView the old way; an empty stanza in a file is more likely a leftover.
func TestRetiredVariablePresentButBlankIsStillReported(t *testing.T) {
	_, diag := Load(Options{SkipFile: true, Env: MapEnv(map[string]string{
		"LABVIEW_SESSION_SECRET_FILE": "",
	})})
	if len(diag.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one", diag.Warnings)
	}
}

func TestRetiredKeyBlankIsNotReported(t *testing.T) {
	path := writeConfig(t, "authentik:\n  tokenFile: \"\"\ntraefik:\n  passwordFile: \"   \"\n")
	_, diag := Load(Options{ConfigPath: path, Env: MapEnv(nil)})
	if len(diag.Warnings) != 0 {
		t.Errorf("warnings = %#v, want none", diag.Warnings)
	}
}

// A retired key holding something that is not a string says nothing either: the check is for
// a value an operator wrote, not for the key's presence in some shape.
func TestRetiredKeyOfANonStringIsNotReported(t *testing.T) {
	path := writeConfig(t, "authentik:\n  tokenFile:\n    - /run/secrets/tok\n")
	_, diag := Load(Options{ConfigPath: path, Env: MapEnv(nil)})
	if len(diag.Warnings) != 0 {
		t.Errorf("warnings = %#v, want none", diag.Warnings)
	}
}

func TestRawString(t *testing.T) {
	raw := map[string]any{
		"auth": map[string]any{
			"session": map[string]any{"secretFile": "/x", "ttlMinutes": 60},
		},
	}
	if v, ok := rawString(raw, "auth.session.secretFile"); !ok || v != "/x" {
		t.Errorf("rawString = %q, %v; want /x, true", v, ok)
	}
	for _, key := range []string{"auth.session.ttlMinutes", "auth.session", "auth.missing.x", "nope"} {
		if _, ok := rawString(raw, key); ok {
			t.Errorf("rawString(%q) reported a string", key)
		}
	}
	if _, ok := rawString(nil, "auth.session.secretFile"); ok {
		t.Error("rawString of a nil tree reported a string")
	}
}

func TestFlattenListsBlocksAndLeaves(t *testing.T) {
	raw := map[string]any{
		"appsRoot": "/x",
		"docker":   map[string]any{"enabled": true},
		"list":     []any{map[string]any{"inner": 1}},
	}
	got := map[string]bool{}
	for _, k := range flatten("", raw) {
		got[k] = true
	}
	for _, want := range []string{"appsRoot", "docker", "docker.enabled", "list"} {
		if !got[want] {
			t.Errorf("flatten missed %q", want)
		}
	}
	// A list replaces wholesale and has no addressable interior.
	if got["list.inner"] {
		t.Error("flatten descended into a list")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
