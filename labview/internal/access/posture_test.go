package access

import (
	"strings"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/payload"
)

// usable is a passwd file with one account in it.
func usable(t *testing.T) PasswdFile {
	t.Helper()
	return ParsePasswd([]byte("ada:" + hash(t, "one") + "\n"))
}

// §19's headline: *Open unless configured.*
func TestWithNoMethodEnabledNothingIsEnforcedAndNothingIsSaidAboutIt(t *testing.T) {
	got := Resolve(config.AuthConfig{}, PasswdFile{})

	if got.Enforced() {
		t.Fatal("an unconfigured LabView is enforcing authentication; §19 says open unless configured")
	}
	if len(got.Mode.Methods) != 0 {
		t.Fatalf("methods are live with nothing enabled: %v", got.Mode.Methods)
	}
	if len(got.Mode.Notes) != 0 {
		t.Fatalf("a default install carries notes about authentication: %v", got.Mode.Notes)
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("a default install warns about authentication: %v", got.Warnings)
	}
}

func TestPasswdIsLiveOnlyWhenEnabledAndTheFileYieldedAnEntry(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.PasswdConfig
		file PasswdFile
		live bool
	}{
		{"enabled with an entry", config.PasswdConfig{Enabled: true, File: "/p"}, usable(t), true},
		{"enabled with no file configured", config.PasswdConfig{Enabled: true}, usable(t), false},
		{"enabled but unreadable", config.PasswdConfig{Enabled: true, File: "/p"}, PasswdFile{Err: ErrPasswdMissing}, false},
		{"enabled but empty", config.PasswdConfig{Enabled: true, File: "/p"}, ParsePasswd([]byte("# nobody\n")), false},
		{"not enabled but usable", config.PasswdConfig{File: "/p"}, usable(t), false},
	} {
		got := Resolve(config.AuthConfig{Passwd: tc.cfg}, tc.file)

		if live := got.Live(payload.MethodPasswd); live != tc.live {
			t.Fatalf("%s: passwd live=%v, want %v", tc.name, live, tc.live)
		}
		if got.Enforced() != tc.live {
			t.Fatalf("%s: enforcement (%v) does not follow what is live (%v)", tc.name, got.Enforced(), tc.live)
		}
	}
}

func TestOIDCIsLiveOnlyWhenEnabledWithBothAnIssuerAndAClientID(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.OIDCConfig
		live bool
	}{
		{"both", config.OIDCConfig{Enabled: true, Issuer: "https://idp.example.com", ClientID: "labview"}, true},
		{"no issuer", config.OIDCConfig{Enabled: true, ClientID: "labview"}, false},
		{"no client id", config.OIDCConfig{Enabled: true, Issuer: "https://idp.example.com"}, false},
		{"neither", config.OIDCConfig{Enabled: true}, false},
		{"not enabled", config.OIDCConfig{Issuer: "https://idp.example.com", ClientID: "labview"}, false},
		// The secret is not required: a public client using PKCE has none.
		{"no secret", config.OIDCConfig{Enabled: true, Issuer: "https://idp.example.com", ClientID: "labview"}, true},
	} {
		got := Resolve(config.AuthConfig{OIDC: tc.cfg}, PasswdFile{})

		if live := got.Live(payload.MethodOIDC); live != tc.live {
			t.Fatalf("%s: oidc live=%v, want %v (notes %v)", tc.name, live, tc.live, got.Mode.Notes)
		}
	}
}

// §19: *An enabled-but-unusable method produces a note and a warning and **never** a lock-out — a typo
// in a path MUST NOT make the dashboard unopenable.*
func TestAnEnabledButUnusableMethodNeverLocksAnybodyOut(t *testing.T) {
	got := Resolve(config.AuthConfig{
		Passwd: config.PasswdConfig{Enabled: true, File: "/etc/labview/paswd"},
		OIDC:   config.OIDCConfig{Enabled: true, ClientID: "labview"},
	}, PasswdFile{Err: ErrPasswdMissing})

	if got.Enforced() {
		t.Fatal("two broken methods produced an enforcing gate with no way in; §19 forbids exactly this")
	}
	if len(got.Mode.Notes) == 0 {
		t.Fatal("nothing was said to the client about why sign-in is unavailable")
	}
	if len(got.Warnings) == 0 {
		t.Fatal("nothing was said to the operator about the broken configuration")
	}
}

// §19: the summary *reports **counts, never names***.
func TestNothingInThePostureNamesAUserOrAPath(t *testing.T) {
	file := ParsePasswd([]byte(strings.Join([]string{
		"ada:" + hash(t, "one"),
		"grace:plaintext",
		"alan:$6$rounds=5000$salt$digest",
	}, "\n")))

	got := Resolve(config.AuthConfig{
		Passwd: config.PasswdConfig{Enabled: true, File: "/etc/labview/secret-path/passwd"},
	}, file)

	joined := strings.Join(got.Mode.Notes, "\n")
	for _, forbidden := range []string{"ada", "grace", "alan", "secret-path", "plaintext"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("a note carried %q; §19 says counts, never names: %v", forbidden, got.Mode.Notes)
		}
	}
	if !strings.Contains(joined, "2") {
		t.Fatalf("the skipped lines were not counted: %v", got.Mode.Notes)
	}
}

// The path is a fact about the host and does not belong in anything served (I2).
func TestNoNoteCarriesTheConfiguredFilePathEvenWhenItIsTheProblem(t *testing.T) {
	got := Resolve(config.AuthConfig{
		Passwd: config.PasswdConfig{Enabled: true, File: "/srv/private/labview/passwd"},
	}, PasswdFile{Err: ErrPasswdDenied})

	for _, note := range got.Mode.Notes {
		if strings.Contains(note, "/srv/private") {
			t.Fatalf("a served note carried a host path: %q", note)
		}
	}
}

func TestBothMethodsLiveIsEnforcedWithBothOffered(t *testing.T) {
	got := Resolve(config.AuthConfig{
		Passwd: config.PasswdConfig{Enabled: true, File: "/p"},
		OIDC:   config.OIDCConfig{Enabled: true, Issuer: "https://idp.example.com", ClientID: "labview"},
	}, usable(t))

	if !got.Enforced() {
		t.Fatal("two live methods are not enforcing")
	}
	if len(got.Mode.Methods) != 2 {
		t.Fatalf("expected both methods, got %v", got.Mode.Methods)
	}
	// Sorted, so the payload is byte-identical for identical configuration (I7).
	if got.Mode.Methods[0] != payload.MethodOIDC || got.Mode.Methods[1] != payload.MethodPasswd {
		t.Fatalf("methods are not in a stable order: %v", got.Mode.Methods)
	}
}

func TestTheModeIsAlwaysConsistentWithItself(t *testing.T) {
	for _, cfg := range []config.AuthConfig{
		{},
		{Passwd: config.PasswdConfig{Enabled: true, File: "/p"}},
		{Passwd: config.PasswdConfig{Enabled: true}},
		{OIDC: config.OIDCConfig{Enabled: true, Issuer: "https://idp.example.com", ClientID: "labview"}},
		{OIDC: config.OIDCConfig{Enabled: true}},
		{
			Passwd: config.PasswdConfig{Enabled: true, File: "/p"},
			OIDC:   config.OIDCConfig{Enabled: true, Issuer: "https://idp.example.com", ClientID: "labview"},
		},
	} {
		got := Resolve(cfg, usable(t))
		if !got.Mode.Consistent() {
			t.Fatalf("%+v produced enforced=%v with methods %v", cfg, got.Mode.Enforced, got.Mode.Methods)
		}
	}
}

func TestTheOIDCLabelDefaultsRatherThanBeingEmpty(t *testing.T) {
	got := Resolve(config.AuthConfig{
		OIDC: config.OIDCConfig{Enabled: true, Issuer: "https://idp.example.com", ClientID: "labview"},
	}, PasswdFile{})
	if got.OIDCLabel != DefaultOIDCLabel {
		t.Fatalf("label is %q, want the default", got.OIDCLabel)
	}

	named := Resolve(config.AuthConfig{
		OIDC: config.OIDCConfig{Enabled: true, Issuer: "https://idp.example.com", ClientID: "labview", Label: "Lab SSO"},
	}, PasswdFile{})
	if named.OIDCLabel != "Lab SSO" {
		t.Fatalf("a configured label was not used: %q", named.OIDCLabel)
	}
}

func TestThePostureCarriesTheTableTheLoginRouteWillVerifyAgainst(t *testing.T) {
	got := Resolve(config.AuthConfig{Passwd: config.PasswdConfig{Enabled: true, File: "/p"}}, usable(t))

	if !Verify(got.Passwd, "ada", "one") {
		t.Fatal("the posture's table does not verify the account that made passwd live")
	}
}

func TestAPostureWithNoLiveMethodCarriesNoTable(t *testing.T) {
	got := Resolve(config.AuthConfig{Passwd: config.PasswdConfig{Enabled: false}}, usable(t))

	if len(got.Passwd) != 0 {
		t.Fatal("a disabled method still handed over its account table")
	}
}

// ---------------------------------------------------------------------------
// The 5000 ms cache
// ---------------------------------------------------------------------------

type postureClock struct{ at time.Time }

func (c *postureClock) now() time.Time      { return c.at }
func (c *postureClock) add(d time.Duration) { c.at = c.at.Add(d) }

func TestThePostureIsCachedForFiveThousandMilliseconds(t *testing.T) {
	clock := &postureClock{at: time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)}
	fsys := &memFS{files: map[string]*memFile{
		"/p": {content: []byte("ada:" + hash(t, "one") + "\n"), mtime: clock.at},
	}}
	postures := &Postures{
		Config: func() config.AuthConfig {
			return config.AuthConfig{Passwd: config.PasswdConfig{Enabled: true, File: "/p"}}
		},
		Passwd: &PasswdReader{FS: fsys},
		Now:    clock.now,
	}

	if !postures.Current().Enforced() {
		t.Fatal("the first resolution is not enforcing")
	}

	// The file goes away. Inside the window, the held posture stands.
	delete(fsys.files, "/p")
	clock.add(PostureTTL - time.Millisecond)
	if !postures.Current().Enforced() {
		t.Fatal("the posture was re-resolved inside the cache window")
	}

	// Past it, the change is seen — which is what makes dropping a file in take effect without a
	// restart, and taking one away take effect too.
	clock.add(2 * time.Millisecond)
	if postures.Current().Enforced() {
		t.Fatal("the posture was not re-resolved after the window closed")
	}
}

func TestThePostureIsReloggedOnlyWhenItChanges(t *testing.T) {
	clock := &postureClock{at: time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)}
	enabled := true
	changes := 0

	postures := &Postures{
		Config: func() config.AuthConfig {
			return config.AuthConfig{Passwd: config.PasswdConfig{Enabled: enabled, File: "/p"}}
		},
		Passwd: &PasswdReader{FS: &memFS{files: map[string]*memFile{
			"/p": {content: []byte("ada:" + hash(t, "one") + "\n"), mtime: clock.at},
		}}},
		Now:     clock.now,
		Changed: func(Posture) { changes++ },
	}

	postures.Current()
	if changes != 1 {
		t.Fatalf("the first resolution reported %d changes, want 1", changes)
	}

	// Ten more resolutions, all past the window, none of them different.
	for i := 0; i < 10; i++ {
		clock.add(PostureTTL)
		postures.Current()
	}
	if changes != 1 {
		t.Fatalf("an unchanged posture was re-logged %d times; §19 says only when it changes", changes)
	}

	enabled = false
	clock.add(PostureTTL)
	postures.Current()
	if changes != 2 {
		t.Fatalf("a changed posture was not re-logged (changes=%d)", changes)
	}
}

func TestAnAccountAppearingInTheFileIsNotAPostureChange(t *testing.T) {
	clock := &postureClock{at: time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)}
	file := &memFile{content: []byte("ada:" + hash(t, "one") + "\n"), mtime: clock.at}
	changes := 0

	postures := &Postures{
		Config: func() config.AuthConfig {
			return config.AuthConfig{Passwd: config.PasswdConfig{Enabled: true, File: "/p"}}
		},
		Passwd:  &PasswdReader{FS: &memFS{files: map[string]*memFile{"/p": file}}},
		Now:     clock.now,
		Changed: func(Posture) { changes++ },
	}

	postures.Current()
	file.content = append(file.content, []byte("grace:"+hash(t, "two")+"\n")...)
	file.mtime = clock.at.Add(time.Second)
	clock.add(PostureTTL)

	got := postures.Current()

	if len(got.Passwd) != 2 {
		t.Fatalf("the new account was not picked up: %v", len(got.Passwd))
	}
	if changes != 1 {
		t.Fatal("adding an account was logged as a posture change; it is a change in accounts, not in how LabView is gated")
	}
}

func TestADisabledPasswdMethodDoesNotReadTheFileAtAll(t *testing.T) {
	fsys := &memFS{files: map[string]*memFile{
		"/p": {content: []byte("ada:x\n"), mtime: time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)},
	}}
	postures := &Postures{
		Config: func() config.AuthConfig {
			return config.AuthConfig{Passwd: config.PasswdConfig{File: "/p"}}
		},
		Passwd: &PasswdReader{FS: fsys},
		Now:    func() time.Time { return time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC) },
	}

	postures.Current()

	if fsys.reads != 0 {
		t.Fatal("a disabled method read its passwd file")
	}
}
