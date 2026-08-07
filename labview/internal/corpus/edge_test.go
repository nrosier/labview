package corpus

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// The awkward root: eighteen directories, each one a case that broke something (§23).
//
// Every stack here is a regression, and most of them are a *pair* — a case and the near miss beside
// it, which is what makes the assertion about the rule rather than about the outcome. `declcompare`
// holds four services that differ only in what their sidecar declares; `otherprovider` holds five
// that differ only in which middleware they name; `tunnelorigin` holds two unresolvable origins that
// are unresolvable for different reasons.
//
// The counters are asserted here as they are for every root, and then each stack is asserted on its
// own terms. A stack that only moved a counter would be a stack whose point had been forgotten.

// ---------------------------------------------------------------------------
// The counters
// ---------------------------------------------------------------------------

func TestTheEdgeRootIsCountedExactlyOnce(t *testing.T) {
	got := scanRoot(t, "edge", scanOptions{}).Stats

	for _, c := range []struct {
		name string
		got  int
		want int
		why  string
	}{
		{"stacks", got.Stacks, 18, "eighteen directories, each holding one regression"},
		{"services", got.Services, 35, "and thirty-five services between them"},

		{"publicServices", got.PublicServices, 5, "five tunnel hostnames survive their `enable` check"},
		{"traefikServices", got.TraefikServices, 8, "eight carry a router with a rule"},
		{"lanServices", got.LanServices, 8, "eight publish a port"},
		{"internalServices", got.InternalServices, 16, "sixteen share a real network with a scanned service"},
		{"noIngressServices", got.NoIngressServices, 2, "two are on nothing at all"},

		{"authProtected", got.AuthProtected, 10, "ten name a gate of some kind"},
		{"exposedWithoutAuth", got.ExposedWithoutAuth, 10, "and ten are reachable while naming none"},

		// The declaration figures, which are what this root exists for above all. Each one is a
		// different reading of the same seven sidecar files, and §14's whole point is that they do
		// not collapse into one another.
		{"declaredAuth", got.DeclaredAuth, 7, "seven services declare a mechanism"},
		{"declaredAuthProtected", got.DeclaredAuthProtected, 1, "one declaration supplies a gate nothing detected"},
		{"declaredAuthUnconfirmed", got.DeclaredAuthUnconfirmed, 2, "two carry a claim the scan could not corroborate"},
		{"exposureAccepted", got.ExposureAccepted, 2, "two accept an exposure, and one of those acceptances is stale"},
		{"declarationDrift", got.DeclarationDrift, 4, "four drift entries across three services"},
		{"declaredDependencies", got.DeclaredDependencies, 0, "no declared dependency resolves to a scanned service"},

		{"networks", got.Networks, 16, "sixteen networks across eighteen stacks"},
		{"connectingNetworks", got.ConnectingNetworks, 7, "seven carry something between services"},
		{"crossStackNetworks", got.CrossStackNetworks, 1, "one is shared across stacks"},
		{"soloLocalNetworks", got.SoloLocalNetworks, 9, "and nine have a single member"},
	} {
		if c.got != c.want {
			t.Errorf("stats.%s = %d, want %d: %s", c.name, c.got, c.want, c.why)
		}
	}

	// An accepted exposure is still an exposure. The two figures stand beside each other and the
	// second is never subtracted from the first — a fleet where accepting an exposure made the
	// exposure count fall is a fleet where the count can be edited by writing a file (§14 rule 3).
	if got.ExposureAccepted == 0 || got.ExposureAccepted >= got.ExposedWithoutAuth {
		t.Errorf("exposureAccepted = %d against exposedWithoutAuth = %d: the acceptances are a subset "+
			"of the exposures and are not removed from them", got.ExposureAccepted, got.ExposedWithoutAuth)
	}
}

// ---------------------------------------------------------------------------
// §6 — interpolation
// ---------------------------------------------------------------------------

// Nested `${A:-${B}}` substitution, which is where a regex gives up (§6).
//
// A non-recursive pattern cannot brace-match these, and what it leaves behind is the inner expression
// sitting in the output as though it were a value. Each case below is a different way that goes wrong:
// two levels of default with only a literal at the bottom, an outer default falling through to an env
// file, an outer value that must stop the fall-through happening at all, and `$$`.
func TestNestedInterpolationResolvesToTheInnermostValueThatIsSet(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})
	svc := service(t, out, "interp/web")

	// The image tag comes down two levels of default and lands in the env file, which makes the
	// image name itself the shortest possible statement of the whole rule.
	if svc.Image != "nginx:1.27.2" {
		t.Errorf("image = %q, want nginx:1.27.2: `${IMAGE_TAG:-${DEFAULT_TAG:-1.27-alpine}}` with "+
			"IMAGE_TAG unset and DEFAULT_TAG set in .env", svc.Image)
	}

	for _, c := range []struct {
		name   string
		want   string
		source payload.EnvVarSource
		why    string
	}{
		// Both levels unset, so the value is the innermost literal — and the source says so: nothing
		// supplied it, a default in the file did.
		{"DEEP_LITERAL", "deep-literal", payload.EnvFromShellDefault,
			"`${A_MISSING:-${B_MISSING:-deep-literal}}` with neither name set"},

		// Outer unset, inner supplied by the env file.
		{"RESOLVED_HOST", "fallback.example.com", payload.EnvFromEnvFile,
			"`${WEB_HOST:-${FALLBACK_HOST}}` with FALLBACK_HOST in .env"},

		// The outer name is set, so the nested default must not be evaluated at all. This is the case
		// that catches an implementation which resolves the inside first and then the outside: the
		// value would be right, and `SHOULD_NOT_BE_READ` would have been read.
		{"PRESENT_WINS", "1.27.2", payload.EnvFromEnvFile,
			"`${DEFAULT_TAG:-${SHOULD_NOT_BE_READ}}` with DEFAULT_TAG set"},

		// `$$` is a literal dollar and not the start of a reference.
		{"LITERAL_DOLLAR", "cost is $5 per unit", payload.EnvFromEnvironment,
			"`$$5` is five dollars, not a variable named 5"},
	} {
		v, ok := env(svc, c.name)
		if !ok {
			t.Errorf("interp/web has no %s", c.name)
			continue
		}
		if v.Value == nil || *v.Value != c.want {
			t.Errorf("%s = %v, want %q: %s", c.name, v.Value, c.want, c.why)
		}
		if v.Source != c.source {
			t.Errorf("%s source = %q, want %q", c.name, v.Source, c.source)
		}
	}

	// Nothing anywhere on this service still carries an unresolved reference. The four entries above
	// are the cases; this is the one that catches a fifth appearing in the fixture tomorrow.
	if document := marshal(t, svc); strings.Contains(document, "${") {
		t.Errorf("an unresolved interpolation survived into the payload: %s", document)
	}
}

// ---------------------------------------------------------------------------
// §20 — a credential in a value
// ---------------------------------------------------------------------------

// URI credentials are redacted, and everything else about the URI is kept (§20).
//
// The four values below are all in one service's environment, under names no pattern matches, and the
// rule has to reach three different answers across them. Withholding more would hide how a service is
// configured, which is what this payload is for; withholding less publishes a password.
func TestACredentialEmbeddedInAValueIsRedactedAndTheRestOfTheURIIsKept(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})
	svc := service(t, out, "dbstack/api")

	for _, c := range []struct {
		name   string
		want   string
		masked bool
		why    string
	}{
		// A password under a name that says nothing about secrets. This is where credentials most
		// often actually are, so a masking stage that read only keys would leak the common case.
		{"DATABASE_URL", "postgresql://appuser:********@db:5432/app", true,
			"the account and the host survive; only the password is the secret"},

		// Userinfo with an empty user half, which is what a Redis URL looks like.
		{"REDIS_URL", "redis://:********@cache:6379/0", true,
			"an empty username is still a password after the colon"},

		// Userinfo with no colon. There is nothing to withhold, and inventing a mask for it would
		// hide which account a service connects as while protecting nothing.
		{"SMTP_URL", "smtp://notify@mail.example.com:587", false,
			"`notify` names an account, and an account is not a credential"},

		// No userinfo at all.
		{"PUBLIC_ENDPOINT", "https://api.example.com/health", false, "nothing to redact"},
	} {
		v, ok := env(svc, c.name)
		if !ok {
			t.Errorf("dbstack/api has no %s", c.name)
			continue
		}
		if v.Value == nil || *v.Value != c.want {
			t.Errorf("%s = %v, want %q: %s", c.name, v.Value, c.want, c.why)
		}
		if v.Masked != c.masked {
			t.Errorf("%s masked = %v, want %v", c.name, v.Masked, c.masked)
		}
	}

	// The same password is set plainly on the database beside this one, under a name a pattern does
	// match. Both must be gone from the document, and only one of them was caught by its name.
	if document := marshal(t, out); strings.Contains(document, "sup3rs3cret") ||
		strings.Contains(document, "redi5pw") {
		t.Error("a password from the dbstack fixture appears verbatim in the payload")
	}
}

// ---------------------------------------------------------------------------
// I8 — containment
// ---------------------------------------------------------------------------

// A path that escapes the scan root is refused, and the refusal is said out loud (§6, I8).
//
// Two of them, at two different layers, because they are refused by different code and a fix to one
// does not protect the other: an `env_file` entry that climbs out of the tree, and a `.labview`
// symlink pointing outside it. Both must be declined *and reported* — a silent refusal is
// indistinguishable from a file that was not there, and I4 is degrade and say so.
func TestAPathThatLeavesTheScanRootIsRefusedAndTheRefusalIsReported(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})

	// The env file. The service is told, because the missing variables are its own.
	api := service(t, out, "dbstack/api")
	if !noted(api, "is outside the scan root; not read") {
		t.Errorf("dbstack/api was not told its env_file was refused; notes = %v", api.Notes)
	}
	if _, leaked := env(api, "LEAKED_FROM_OUTSIDE_ROOT"); leaked {
		t.Error("dbstack/api carries a variable from outside the scan root")
	}

	// The one entry that was inside the directory still loaded. A containment check that refused the
	// whole list on one bad entry would lose configuration that was never in question.
	if v, ok := env(api, "LOCAL_ENV_FILE_LOADED"); !ok || v.Value == nil || *v.Value != "yes" {
		t.Error("the env_file entry inside the stack directory was not read")
	}

	// The sidecar symlink. The stack is told, because a declaration is the stack's.
	escape := stack(t, out, "escapedecl")
	if escape.Declared != nil {
		t.Errorf("escapedecl carries a declaration read from outside the scan root: %v", escape.Declared)
	}
	found := false
	for _, w := range escape.Warnings {
		if strings.Contains(w, "resolves outside the scan root") {
			found = true
		}
	}
	if !found {
		t.Errorf("escapedecl was not told its .labview was refused; warnings = %v", escape.Warnings)
	}

	// The stack is still scanned. Refusing one file is not refusing the directory.
	if svc := find(out, "escapedecl/app"); svc == nil {
		t.Error("escapedecl/app is missing: a refused sidecar file dropped the whole stack")
	}

	// And nothing from either outside file reached the document by any route.
	if document := marshal(t, out); strings.Contains(document, "LEAKED_FROM_OUTSIDE_ROOT") ||
		strings.Contains(document, "outside-root.labview") && !strings.Contains(document, "resolves outside") {
		t.Error("content from outside the scan root appears in the payload")
	}
}

// ---------------------------------------------------------------------------
// §6.1 — the sidecar file
// ---------------------------------------------------------------------------

// A sidecar file with four faults in it, and the valid half is still read (§6.1).
//
// This is the shape of every parse in this program: a document written by hand is going to have
// mistakes in it, and refusing the file over one of them would punish the operator for the part they
// got right. Each fault gets its own warning naming the key, because "your file is invalid" is not
// something anybody can act on.
func TestABadSidecarFileIsReportedFaultByFaultAndItsValidHalfIsKept(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})
	st := stack(t, out, "badsidecar")

	if st.Declared == nil {
		t.Fatal("badsidecar has no declaration at all: four faults refused a file with a valid half")
	}
	if st.Declared.Description == "" {
		t.Error("the valid description was discarded along with the faults")
	}

	for _, want := range []string{
		// A misspelled key. Named, so the operator can see it is a typo and not a version difference.
		`unknown key(s) "descripton"`,

		// A mechanism outside the closed vocabulary, and the warning lists the vocabulary — a
		// rejection that did not say what was allowed would send a reader to the source.
		`"authentik-proxy" is not a known mechanism`,
		"app-local-accounts, app-ldap, app-oidc, app-saml, app-token, mtls, network-restricted",

		// An acceptance with no reason. The reason is the whole content of an acceptance: without
		// one, a deliberate decision cannot be told from a mistake, so it is refused rather than
		// honoured.
		`needs a "reason" — an acceptance with no reason cannot be told from a mistake`,

		// A declaration for a service the compose file does not define. Almost always a rename, and
		// silently ignoring it would leave the operator believing a service is documented.
		`the compose file defines no service "ghost"`,
	} {
		found := false
		for _, w := range st.Warnings {
			if strings.Contains(w, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("badsidecar was not warned about %q; warnings = %v", want, st.Warnings)
		}
	}

	// The refused mechanism did not survive as a declaration. A warning plus the value would be the
	// worst of both.
	app := service(t, out, "badsidecar/app")
	for _, a := range app.DeclaredAuthMechanisms() {
		if a.Mechanism == "authentik-proxy" {
			t.Error("badsidecar/app carries the mechanism that was rejected as unknown")
		}
	}
	// The valid mechanism beside it did.
	if len(app.DeclaredAuthMechanisms()) != 1 {
		t.Errorf("badsidecar/app declares %d mechanisms, want the one valid entry",
			len(app.DeclaredAuthMechanisms()))
	}
}

// The `.labview.yml` spelling is read when there is no bare `.labview` beside it (§6.1).
func TestTheSidecarFileIsFoundUnderItsAlternativeName(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})

	st := stack(t, out, "sidecaryml")
	if st.Declared == nil {
		t.Fatal("sidecaryml has no declaration: the .labview.yml spelling was not read")
	}
	// The file name is carried on the declaration, because a reader who wants to edit it needs to
	// know which of the two names is actually there.
	if st.Declared.File != ".labview.yml" {
		t.Errorf("declared.file = %q, want .labview.yml", st.Declared.File)
	}
}

// A sidecar link whose label was left out falls back to its URL, *after* redaction (§6.1, §20).
func TestALinkWithNoLabelFallsBackToItsRedactedURL(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})

	st := stack(t, out, "declared")
	if st.Declared == nil {
		t.Fatal("declared has no declaration")
	}
	if len(st.Declared.Links) != 2 {
		t.Fatalf("links = %v, want the labelled one and the bare one", st.Declared.Links)
	}
	if got := st.Declared.Links[0]; got.Label != "Admin UI" {
		t.Errorf("the labelled link lost its label: %v", got)
	}
	if got := st.Declared.Links[1]; got.Label != got.URL {
		t.Errorf("link = %v, want the label to fall back to the URL", got)
	}
}

// ---------------------------------------------------------------------------
// §14 — what a declaration can and cannot do
// ---------------------------------------------------------------------------

// The four agreements, on four services that differ in nothing but their sidecar (§14).
//
// `declcompare` is the whole of rule 1 in one directory: the same detected posture, four different
// declarations, four different readings. Holding them in one test is deliberate — the interesting
// property is that they *differ*, and a test per service would let two of them quietly converge.
func TestADeclarationIsComparedToWhatWasDetectedAndTheReadingIsNamed(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})

	for _, c := range []struct {
		key       string
		agreement payload.DeclaredAuthAgreement
		why       string
	}{
		// Declared what the scan already found. Nothing to report, and saying nothing is the point:
		// an operator who documented their LDAP bind correctly should not be shown a finding for it.
		{"declcompare/redundant", payload.AgreementRedundant,
			"declares the `app-ldap` the scan detected from LDAP_HOST"},

		// Declared OIDC where the scan found LDAP — same layer, different mechanism. This is the only
		// one of the four that is a contradiction, and it is drift.
		{"declcompare/conflict", payload.AgreementConflicts,
			"declares `app-oidc` in the layer where `ldap` was detected"},

		// Declared its own login *behind* the detected proxy gate. Two different layers, so both are
		// true at once and there is nothing to reconcile — a rule that compared mechanisms without
		// comparing layers would report this working setup as a contradiction.
		{"declcompare/defence", payload.AgreementSupplements,
			"declares `app-oidc` behind a detected `authentik-forward-auth`"},

		// Declared a gate in a layer no scan can see. This is what §14 exists for: an operator
		// telling the scan something it could not have found out.
		{"declared/media", payload.AgreementSupplies,
			"declares local accounts on a service where nothing was detected"},
	} {
		svc := service(t, out, c.key)
		if svc.Declared == nil {
			t.Errorf("%s has no declaration", c.key)
			continue
		}
		if svc.Declared.AuthAgreement != c.agreement {
			t.Errorf("%s authAgreement = %q, want %q: %s",
				c.key, svc.Declared.AuthAgreement, c.agreement, c.why)
		}
	}

	// Only the conflict produced a drift entry, and it names both mechanisms and the layer they share
	// — a drift entry that said only "mismatch" would leave an operator to work out which of the two
	// documents is wrong.
	conflict := service(t, out, "declcompare/conflict")
	if len(conflict.Declared.Drift) != 1 {
		t.Fatalf("declcompare/conflict drift = %v, want one entry", conflict.Declared.Drift)
	}
	for _, want := range []string{"app-oidc", "ldap", "the same layer"} {
		if !strings.Contains(conflict.Declared.Drift[0], want) {
			t.Errorf("the drift entry does not mention %q: %q", want, conflict.Declared.Drift[0])
		}
	}

	// A declaration in a layer nothing was detected in is *unconfirmed*, not drift. The difference is
	// the difference between "the scan disagrees" and "the scan cannot see that far", and collapsing
	// them would make every honest declaration about an application's own login into a finding.
	layered := service(t, out, "declcompare/layered")
	if len(layered.Declared.Drift) != 0 {
		t.Errorf("declcompare/layered drift = %v, want none: local accounts are invisible to a scan, "+
			"not contradicted by one", layered.Declared.Drift)
	}
}

// A declaration never changes the method, and it clears the finding (§14 rules 1 and 2).
//
// Both halves of the same service, because they are easy to conflate and the consequence of getting
// it wrong runs in opposite directions. If the declaration changed the method, the histogram would
// count a gate nobody detected. If it did not clear the finding, an operator would be unable to
// answer the question the finding asks.
func TestADeclarationClearsTheFindingAndLeavesTheMethodAlone(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})
	svc := service(t, out, "declared/media")

	if svc.Auth.Method != payload.AuthNone {
		t.Errorf("auth.method = %q, want %q: a declaration is not a detection",
			svc.Auth.Method, payload.AuthNone)
	}
	if svc.Auth.ExposedWithoutAuth {
		t.Error("declared/media is still in the exposure finding: its declaration answers the question")
	}
	if !noted(svc, "the method stays `none` because nothing was detected") {
		t.Errorf("the note does not say the method was left alone; notes = %v", svc.Notes)
	}

	// One of its two declared mechanisms could not be corroborated, and it is listed as such. The
	// other one supplied the gate. Both readings on one service is the case that catches an
	// implementation which stops at the first mechanism it can classify.
	if len(svc.Declared.Unconfirmed) != 1 {
		t.Errorf("unconfirmed = %v, want the one mechanism the scan could not corroborate",
			svc.Declared.Unconfirmed)
	}
}

// An acceptance is compared to the exposure it accepts, and a stale one is reported (§14 rule 3).
//
// The pair is the point. `accepted/status` publishes a port and accepts the consequence, so the
// acceptance stands and carries a reason. `staledecl/worker` accepts an exposure it no longer has —
// the port was removed and the file was not updated — and an acceptance for something that cannot
// happen is a file drifting away from the fleet it describes.
func TestAnAcceptedExposureIsStillAnExposureAndAStaleAcceptanceIsDrift(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})

	live := service(t, out, "accepted/status")
	if live.Declared == nil || live.Declared.UnauthenticatedAccepted == nil {
		t.Fatal("accepted/status has no acceptance")
	}
	if live.Declared.UnauthenticatedAccepted.Reason == "" {
		t.Error("the acceptance has no reason, and the reason is its entire content")
	}
	// Still counted. The acceptance records a decision; it does not make the service unreachable.
	if !live.Auth.ExposedWithoutAuth {
		t.Error("accepted/status left the exposure finding: accepting an exposure is not removing it")
	}
	if len(live.Declared.Drift) != 0 {
		t.Errorf("accepted/status drift = %v, want none: it is exposed, as its file says", live.Declared.Drift)
	}

	stale := service(t, out, "staledecl/worker")
	if stale.Auth.ExposedWithoutAuth {
		t.Error("staledecl/worker is in the exposure finding, and it publishes no port")
	}
	if len(stale.Declared.Drift) != 2 {
		t.Fatalf("staledecl/worker drift = %v, want two: the stale acceptance and the expected ingress",
			stale.Declared.Drift)
	}
	found := false
	for _, d := range stale.Declared.Drift {
		if strings.Contains(d, "is stale") && strings.Contains(d, "no longer") {
			found = true
		}
	}
	if !found {
		t.Errorf("no drift entry says the acceptance is stale: %v", stale.Declared.Drift)
	}
}

// A declared ingress set is compared to the detected one, and the difference is stated both ways.
//
// Naming what is missing and what is unexpected separately is what makes the entry actionable: the
// two halves have different causes and different fixes, and a message that said only "does not match"
// would leave the reader to diff two lists by eye.
func TestADeclaredIngressSetIsComparedInBothDirections(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})

	api := service(t, out, "partialdrift/api")
	if len(api.Declared.Drift) != 1 {
		t.Fatalf("partialdrift/api drift = %v, want one entry", api.Declared.Drift)
	}
	entry := api.Declared.Drift[0]
	for _, want := range []string{"missing: lan", "unexpected: traefik"} {
		if !strings.Contains(entry, want) {
			t.Errorf("the drift entry does not say %q: %q", want, entry)
		}
	}

	// The service is not otherwise touched: the declaration was about ingress, and its posture came
	// from a middleware. A drift entry is a sentence, not a correction.
	if api.Auth.Method != payload.AuthAuthentikForwardAuth {
		t.Errorf("auth.method = %q: an ingress declaration changed a posture", api.Auth.Method)
	}

	// And the one that agrees says nothing. `declcompare/defence` declares exactly the two kinds it
	// has, so the comparison produces no entry — a check that reported a match would put a line on
	// every correctly documented service in the fleet.
	defence := service(t, out, "declcompare/defence")
	for _, d := range defence.Declared.Drift {
		if strings.Contains(d, "expected ingress") {
			t.Errorf("declcompare/defence has an ingress drift entry and its declaration is correct: %q", d)
		}
	}
}

// ---------------------------------------------------------------------------
// §7 — which gate, and how strongly
// ---------------------------------------------------------------------------

// Five services that differ only in the middleware they name (§7, §4.2).
//
// `otherprovider` is the precedence order and the confidence ladder in one directory. The two that
// matter most are the last two: a middleware whose definition is nowhere in the scanned tree, which is
// a gate *inferred* from its own name, and a service whose only router middleware sets headers, which
// is no gate at all.
func TestAGateIsAttributedToWhatCanActuallyBeSeen(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})

	for _, c := range []struct {
		key        string
		method     payload.AuthMethod
		detail     string
		confidence payload.AuthConfidence
		why        string
	}{
		// A forward-auth to a service in the same fleet that is not the identity provider. A real
		// gate, and `forward-auth` rather than `authentik-forward-auth`, because nothing tied it to
		// this fleet's provider and naming one would be inventing an attribution.
		{"otherprovider/app", payload.AuthForwardAuth, "fwdauth@docker", payload.ConfidenceObserved,
			"a forwardauth to `gatekeeper`, which is not the provider"},

		// Environment alone, with no middleware anywhere: `other-oauth`, because the client id says a
		// gate is configured and says nothing about who runs it.
		{"otherprovider/oidconly", payload.AuthOtherOAuth, "OIDC_CLIENT_ID", payload.ConfidenceObserved,
			"OIDC_CLIENT_ID and nothing else"},

		// The weakest reading in the vocabulary, and the only place it is reached: the middleware is
		// named on a router and defined in no scanned file, so its name is the only evidence there is.
		{"otherprovider/unresolved", payload.AuthForwardAuth, "sso-gate@file", payload.ConfidenceInferred,
			"a middleware defined by the proxy's file provider, which a file scan cannot see"},

		// A middleware that is not a gate. A rule keyed on "has a middleware" would clear this
		// exposure, which is the most dangerous mistake this program can make.
		{"otherprovider/headersonly", payload.AuthNone, "", payload.ConfidenceObserved,
			"its only middleware sets headers"},

		// The gate's own far end, which nothing gates.
		{"otherprovider/gatekeeper", payload.AuthNone, "", payload.ConfidenceObserved,
			"the forward-auth target itself"},
	} {
		got := service(t, out, c.key).Auth
		if got.Method != c.method {
			t.Errorf("%s auth.method = %q, want %q: %s", c.key, got.Method, c.method, c.why)
		}
		if got.Detail != c.detail {
			t.Errorf("%s auth.detail = %q, want %q", c.key, got.Detail, c.detail)
		}
		if got.Confidence != c.confidence {
			t.Errorf("%s auth.confidence = %q, want %q: %s", c.key, got.Confidence, c.confidence, c.why)
		}
	}

	// The inferred gate says why it is inferred, on the service, in a sentence. A confidence field
	// alone is a word in a badge; the note is what tells an operator where to look.
	unresolved := service(t, out, "otherprovider/unresolved")
	if !noted(unresolved, "is not defined in any scanned compose file") {
		t.Errorf("otherprovider/unresolved does not say why its gate is inferred; notes = %v",
			unresolved.Notes)
	}

	// The headers-only service is reachable and gateless, so it is in the finding. This is the
	// assertion that makes the row above consequential rather than cosmetic.
	if !service(t, out, "otherprovider/headersonly").Auth.ExposedWithoutAuth {
		t.Error("otherprovider/headersonly is not in the exposure finding, and a header is not a gate")
	}
}

// The stronger method is reported and the weaker one is kept as evidence (§4.2).
//
// `otherprovider/app` has both a forward-auth middleware and an OIDC client id. Only one method can
// be the reported one, and the loser's evidence is appended rather than discarded — an operator
// looking at this service needs to know both things are configured.
func TestTheStrongerMethodWinsAndTheWeakerOneSurvivesAsEvidence(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})
	got := service(t, out, "otherprovider/app").Auth

	if got.Method != payload.AuthForwardAuth {
		t.Fatalf("auth.method = %q, want %q: a middleware in the request path outranks a client id",
			got.Method, payload.AuthForwardAuth)
	}

	var mentions bool
	for _, e := range got.Evidence {
		if strings.Contains(e, "other-oauth") && strings.Contains(e, "OIDC_CLIENT_ID") {
			mentions = true
		}
	}
	if !mentions {
		t.Errorf("the losing method left no evidence behind: %v", got.Evidence)
	}
}

// ---------------------------------------------------------------------------
// §8, §9 — ingress and where a tunnel route really goes
// ---------------------------------------------------------------------------

// `expose:` is internal, a published port is not, and nothing at all is `none` (§8).
//
// The three readings are easy to collapse into two, and each collapse is wrong in a way an operator
// would feel: `expose` counted as a published port would put a container-only service in the exposure
// finding, and `none` folded into `internal` would claim a network that does not exist.
func TestExposeIsInternalAndNothingAtAllIsNone(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})

	for _, c := range []struct {
		key  string
		want []payload.IngressKind
		why  string
	}{
		{"exposeonly/cache", []payload.IngressKind{payload.IngressInternal},
			"`expose: 6379` is reachable inside the network and nowhere else"},
		{"interp/web", []payload.IngressKind{payload.IngressNone},
			"no ports, no expose, no shared network"},
		{"ldapapp/wiki", []payload.IngressKind{payload.IngressNone},
			"gated, and with no way in — both readings at once"},

		// A socket proxy on the LAN. Named because of what it is: :2375 on the host is the Docker
		// socket over TCP, and it is in the exposure finding like anything else.
		{"hostport/socketproxy", []payload.IngressKind{payload.IngressLan}, "2375 published on the host"},
	} {
		if got := service(t, out, c.key).Ingress; marshal(t, got) != marshal(t, c.want) {
			t.Errorf("%s ingress = %s, want %s: %s", c.key, marshal(t, got), marshal(t, c.want), c.why)
		}
	}

	// `none` is the whole set or not in it. A service with no ingress that also claimed `internal`
	// would be claiming a network with another scanned service on it.
	for _, key := range []string{"interp/web", "ldapapp/wiki"} {
		if len(service(t, out, key).Ingress) != 1 {
			t.Errorf("%s carries `none` beside another kind, and `none` is an empty set", key)
		}
	}
}

// A tunnel route whose `enable` is false is not ingress at all (§8).
//
// The pair differs in that one label. Reading a hostname without reading the switch beside it would
// draw a route from the internet to a service that is not published, which is a diagram an operator
// would act on.
func TestATunnelRouteThatIsSwitchedOffIsNotIngress(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})

	off := service(t, out, "cfdisabled/app")
	if marshal(t, off.Ingress) != marshal(t, []payload.IngressKind{payload.IngressInternal}) {
		t.Errorf("cfdisabled/app ingress = %s, want internal only: its dockflare.enable is false",
			marshal(t, off.Ingress))
	}
	if len(off.Cloudflare) != 0 {
		t.Errorf("cfdisabled/app carries %d tunnel routes from a disabled label", len(off.Cloudflare))
	}
	if off.Auth.ExposedWithoutAuth {
		t.Error("cfdisabled/app is in the exposure finding on the strength of a switched-off route")
	}

	// The service beside it, with the same labels and `enable` true.
	on := service(t, out, "cfdisabled/live")
	if !fleetHas(on.Ingress, payload.IngressPublic) {
		t.Errorf("cfdisabled/live ingress = %s, want public: its dockflare.enable is true",
			marshal(t, on.Ingress))
	}
}

// An unresolvable tunnel origin is drawn straight to the service and the doubt is written down (§9).
//
// Two of them, unresolvable for opposite reasons: one host port that nothing publishes, and one that
// *two* services publish. Both notes have to name the reason rather than say "could not resolve",
// because the two situations call for completely different actions — one is a stale origin, the other
// is a port collision.
func TestAnUnresolvableTunnelOriginIsDrawnDirectlyAndSaysWhy(t *testing.T) {
	out := scanRoot(t, "edge", scanOptions{})

	offsite := service(t, out, "tunnelorigin/offsite")
	if !noted(offsite, "no scanned service publishes host port 19999") {
		t.Errorf("tunnelorigin/offsite does not name the unpublished port; notes = %v", offsite.Notes)
	}

	ambiguous := service(t, out, "tunnelorigin/ambiguous")
	if !noted(ambiguous, "is published by") {
		t.Errorf("tunnelorigin/ambiguous does not name the candidates; notes = %v", ambiguous.Notes)
	}
	for _, want := range []string{"tunnelorigin/edge-a", "tunnelorigin/edge-b"} {
		if !noted(ambiguous, want) {
			t.Errorf("the ambiguity note does not name %s: %v", want, ambiguous.Notes)
		}
	}

	// Both notes end the same way, and that sentence is the honest part: the route is drawn to the
	// service the label is on, because that much is certain, and the path it really takes is not.
	for _, svc := range []payload.Service{offsite, ambiguous} {
		if !noted(svc, "the path it really takes is unknown") {
			t.Errorf("%s does not say the drawn route is a fallback; notes = %v", svc.Name, svc.Notes)
		}
	}

	// Drawn to the service all the same. A route the scan declines to draw is a route an operator
	// cannot see at all, which is worse than one drawn with a caveat.
	for _, key := range []string{"tunnelorigin/offsite", "tunnelorigin/ambiguous"} {
		if !fleetHas(service(t, out, key).Ingress, payload.IngressPublic) {
			t.Errorf("%s is not public, and a tunnel hostname points at it", key)
		}
	}
}

// fleetHas is `Has` without importing the fleet package for one predicate.
func fleetHas(kinds []payload.IngressKind, want payload.IngressKind) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}
