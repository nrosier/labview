package corpus

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/fleet"
	"github.com/nrosier/labview/internal/payload"
)

// The plain root: six stacks, nine services, nothing switched on (§23).
//
// This is the corpus's baseline, and the one root where every integration is off and no transport is
// injected at all. What it pins is therefore the whole of what a scan can conclude from files alone:
// the ingress classes, the label and environment attributions, the exposure finding, the masking, the
// network arithmetic, and the four sentences a reader gets about the four reads that did not happen.
//
// Every other root in this package adds something to this picture. If a change breaks the picture
// itself, it breaks here first and with the smallest possible explanation.

// ---------------------------------------------------------------------------
// The counters
// ---------------------------------------------------------------------------

// Every figure in the summary, held against the files.
//
// These are asserted as a block rather than one test per counter because they are one claim: the
// nine services were each counted once, into the classes they belong to. A single wrong figure is
// almost never a wrong figure — it is a service that moved class, and seeing the whole block is what
// tells a reader which one.
func TestTheAppsRootIsCountedExactlyOnce(t *testing.T) {
	got := scanRoot(t, "apps", scanOptions{}).Stats

	for _, c := range []struct {
		name string
		got  int
		want int
		why  string
	}{
		{"stacks", got.Stacks, 6, "six directories hold a compose file"},
		{"services", got.Services, 9, "and nine services between them"},
		{"running", got.Running, 0, "Docker was not read, so nothing is known to be running"},

		// The ingress classes overlap on purpose: a service reachable through a tunnel *and* a
		// published port is in both figures, because both are true and a reader deciding what to
		// close needs both. Only `internal` and `noIngress` are exclusive of everything.
		{"publicServices", got.PublicServices, 4, "four hostnames arrive from outside the fleet"},
		{"traefikServices", got.TraefikServices, 4, "four carry a proxy router"},
		{"lanServices", got.LanServices, 5, "five publish a port to the host"},
		{"internalServices", got.InternalServices, 3, "two databases and a cache"},
		{"noIngressServices", got.NoIngressServices, 0, "every service here is on a network"},

		{"authProtected", got.AuthProtected, 3, "three services name a gate"},
		{"exposedWithoutAuth", got.ExposedWithoutAuth, 3, "three are reachable and name none"},

		// Nothing in this root declares anything, so the declaration figures are all zero and the
		// drift figure has nothing to compare. `fixtures/edge` is where those come alive.
		{"declaredAuth", got.DeclaredAuth, 0, "no service declares its own posture"},
		{"declaredAuthProtected", got.DeclaredAuthProtected, 0, "so none can be confirmed"},
		{"declaredAuthUnconfirmed", got.DeclaredAuthUnconfirmed, 0, "and none can be unconfirmed"},
		{"exposureAccepted", got.ExposureAccepted, 0, "nobody accepted an exposure"},
		{"declarationDrift", got.DeclarationDrift, 0, "and there is no declaration to drift from"},
		{"declaredDependencies", got.DeclaredDependencies, 0, "nor a declared dependency"},

		// The probe never ran, and both figures are zero rather than absent — a reader has to be able
		// to tell a probe that found nothing from a probe that never ran, and `meta.probe` is where
		// that difference is stated (§13.7).
		{"probeGated", got.ProbeGated, 0, "the probe is off"},
		{"probeOpen", got.ProbeOpen, 0, "so it read nothing either way"},

		{"networks", got.Networks, 4, "one shared, two implicit defaults with members, one solo"},
		{"connectingNetworks", got.ConnectingNetworks, 3, "three carry something between services"},
		{"crossStackNetworks", got.CrossStackNetworks, 1, "`proxy`, declared external by all six"},
		{"soloLocalNetworks", got.SoloLocalNetworks, 1, "`emby_default`, whose only member is emby"},
	} {
		if c.got != c.want {
			t.Errorf("stats.%s = %d, want %d: %s", c.name, c.got, c.want, c.why)
		}
	}

	// The method histogram, with an entry for every method in the vocabulary and not only for the
	// ones this fleet uses. A histogram that omitted its zeroes would make the Auth view's rows
	// appear and disappear between scans of the same fleet, and would leave a reader unable to tell
	// "no service uses basic auth" from "this build does not know about basic auth" (§16).
	want := map[payload.AuthMethod]int{}
	for _, m := range payload.AuthMethods {
		want[m] = 0
	}
	want[payload.AuthAuthentikForwardAuth] = 1
	want[payload.AuthAuthentikLDAP] = 1
	want[payload.AuthAuthentikOAuth] = 1
	want[payload.AuthNone] = 6

	if have := marshal(t, got.ByAuthMethod); have != marshal(t, want) {
		t.Errorf("stats.byAuthMethod = %s, want %s", have, marshal(t, want))
	}

	total := 0
	for _, n := range got.ByAuthMethod {
		total += n
	}
	if total != got.Services {
		t.Errorf("byAuthMethod totals %d across %d services: every service has exactly one method",
			total, got.Services)
	}
}

// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------

// What each service is reachable through, and nothing more.
//
// The set is ordered — public, traefik, lan, internal — because it is rendered as a row of badges and
// a set that reordered itself between scans would make two identical fleets look different (§16).
func TestIngressIsWhatTheComposeFilesShow(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	for _, c := range []struct {
		key  string
		want []payload.IngressKind
		why  string
	}{
		// A tunnel hostname, a proxy router and a published port, all three on one service.
		{"authentik/server", []payload.IngressKind{payload.IngressPublic, payload.IngressTraefik, payload.IngressLan},
			"a dockflare hostname, a traefik router and 9000:9000"},

		// A tunnel and a port with no router — the arrangement that makes `traefik` a separate class
		// rather than a synonym for public.
		{"emby/emby", []payload.IngressKind{payload.IngressPublic, payload.IngressLan},
			"a dockflare hostname and 8096:8096, and no proxy router at all"},

		{"jellyfin/jellyfin", []payload.IngressKind{payload.IngressPublic, payload.IngressTraefik, payload.IngressLan},
			"a dockflare hostname, a gated router and 8097:8096"},

		// A router and no port: reachable from outside, unreachable from the host's own network.
		{"nextcloud/nextcloud", []payload.IngressKind{payload.IngressTraefik},
			"a traefik router and no published port"},

		{"outline/outline", []payload.IngressKind{payload.IngressPublic, payload.IngressTraefik, payload.IngressLan},
			"a dockflare hostname, a router and 3000:3000"},

		// The proxy itself: three published ports and nothing routing to it, since it *is* the router.
		{"proxy/gateway", []payload.IngressKind{payload.IngressLan},
			"80, 443 and 8080 on the host, and no route to itself"},

		// `internal` is the whole set or none of it. A service on a network with no way in is not
		// *also* something else.
		{"authentik/postgresql", []payload.IngressKind{payload.IngressInternal}, "a database on one internal network"},
		{"authentik/redis", []payload.IngressKind{payload.IngressInternal}, "a cache on the same one"},
		{"nextcloud/db", []payload.IngressKind{payload.IngressInternal}, "a database on nextcloud's default"},
	} {
		if got := service(t, out, c.key).Ingress; marshal(t, got) != marshal(t, c.want) {
			t.Errorf("%s ingress = %s, want %s: %s", c.key, marshal(t, got), marshal(t, c.want), c.why)
		}
	}
}

// ---------------------------------------------------------------------------
// Posture
// ---------------------------------------------------------------------------

// Every gate, what named it, and how strongly.
//
// `detail` is asserted alongside the method because a method on its own is not a finding an operator
// can act on: `authentik-oauth` says a gate exists somewhere, `OIDC_AUTH_URI` says which line of
// which file to read.
func TestAuthPostureNamesItsSourceAndItsStrength(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	for _, c := range []struct {
		key    string
		method payload.AuthMethod
		detail string
	}{
		// A forward-auth middleware, attributed to this fleet's own provider.
		{"jellyfin/jellyfin", payload.AuthAuthentikForwardAuth, "authentik@docker"},

		// Two environment attributions, which are the reason §7 reads environment at all: neither of
		// these services carries a single label about authentication.
		{"nextcloud/nextcloud", payload.AuthAuthentikLDAP, "LDAP_HOST"},
		{"outline/outline", payload.AuthAuthentikOAuth, "OIDC_AUTH_URI"},

		// The provider itself names no gate for itself, which is correct and is also the finding:
		// its own API is on a public hostname, a router and a published port.
		{"authentik/server", payload.AuthNone, ""},
		{"emby/emby", payload.AuthNone, ""},
		{"proxy/gateway", payload.AuthNone, ""},
		{"authentik/postgresql", payload.AuthNone, ""},
		{"authentik/redis", payload.AuthNone, ""},
		{"nextcloud/db", payload.AuthNone, ""},
	} {
		got := service(t, out, c.key).Auth
		if got.Method != c.method {
			t.Errorf("%s auth.method = %q, want %q", c.key, got.Method, c.method)
		}
		if got.Detail != c.detail {
			t.Errorf("%s auth.detail = %q, want %q", c.key, got.Detail, c.detail)
		}

		// Nothing in this root is read from a live source, so nothing can be `confirmed`; and every
		// posture here was read out of a file, so nothing is `inferred` either. A posture that
		// arrived at `confirmed` from files alone would be claiming the proxy said something.
		if got.Confidence != payload.ConfidenceObserved {
			t.Errorf("%s auth.confidence = %q, want %q: it was read from a compose file",
				c.key, got.Confidence, payload.ConfidenceObserved)
		}
		if len(got.Evidence) == 0 {
			t.Errorf("%s auth has no evidence: every posture says how it was reached, including `none`", c.key)
		}
	}
}

// The one service where four sources agree, in the order they were read.
//
// This is the evidence chain §7 requires, and its order is the order of the reasoning: the router
// applies a middleware, the middleware is a forward-auth to an address, the address names the
// provider. Then a second, weaker method from a second source, appended rather than merged, because
// §4.2's stronger-wins rule decides which method is *reported* and never discards what the loser saw.
func TestTheEvidenceChainReadsAsTheReasoningThatProducedIt(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})
	got := service(t, out, "jellyfin/jellyfin").Auth

	want := []string{
		"router `jellyfin` applies middleware `authentik@docker`",
		"middleware `authentik` is a forwardauth to http://authentik-server:9000/outpost.goauthentik.io/auth/traefik, defined by authentik/server",
		"its address names `authentik-server`",
		"also other-oauth (observed) from Cloudflare Access",
		"tunnel route `jellyfin.example.com` carries a Cloudflare Access policy",
		"its policy is `authenticate`",
		"its group is `media-users`",
	}
	if marshal(t, got.Evidence) != marshal(t, want) {
		t.Errorf("jellyfin evidence =\n%s\nwant\n%s", marshal(t, got.Evidence), marshal(t, want))
	}

	// The forward-auth address was resolved back to the service that answers it — a name match on a
	// compose file, which is what `defined by` records. It is not the provider *confirming* anything;
	// the API was not read here. `fixtures/traefik` is where that stronger attribution happens.
	if !strings.Contains(got.Evidence[1], "defined by authentik/server") {
		t.Error("the forward-auth address was not resolved to the service that answers it")
	}
}

// ---------------------------------------------------------------------------
// The exposure finding
// ---------------------------------------------------------------------------

// Reachable, and naming no gate. Three services, and six that are not.
//
// The six are as much of the test as the three. Two of them are reachable and gated, one is gated
// with no way in, and three have no way in at all — four different reasons to stay out of a finding,
// and a rule that collapsed any of them would show an operator a list they would learn to ignore.
func TestTheExposureFindingIsReachableWithNoGateAndNothingElse(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	for _, c := range []struct {
		key     string
		exposed bool
		why     string
	}{
		// The identity provider's own admin interface, on a public hostname, with no gate in front of
		// it. The most consequential row in this fixture and the reason the finding exists.
		{"authentik/server", true, "public, routed, published — and no gate named anywhere"},

		// A media server with its own login screen. The scan cannot see it: a login rendered by the
		// application is not in any file this scan reads, and §13's probe — which is what *could* see
		// it — is off. So this row is a question for an operator, not an assertion about emby, and
		// that is exactly what the wording of the finding has to survive.
		{"emby/emby", true, "a tunnel hostname and a published port, with nothing in front of either"},

		// The router's own dashboard on :8080.
		{"proxy/gateway", true, "three published ports and no gate on any of them"},

		{"jellyfin/jellyfin", false, "reachable, and a forward-auth middleware stands in front"},
		{"outline/outline", false, "reachable, and its environment configures OIDC"},

		// Gated *and* unreachable from outside. Either alone would keep it out.
		{"nextcloud/nextcloud", false, "a router, no published port, and LDAP against the provider"},

		// No way in. A database with no gate is not an exposure, it is a database.
		{"authentik/postgresql", false, "internal only"},
		{"authentik/redis", false, "internal only"},
		{"nextcloud/db", false, "internal only"},
	} {
		s := service(t, out, c.key)
		if s.Auth.ExposedWithoutAuth != c.exposed {
			t.Errorf("%s exposedWithoutAuth = %v, want %v: %s", c.key, s.Auth.ExposedWithoutAuth, c.exposed, c.why)
		}

		// The field and the expression are held against each other, because the summary counts the
		// field and the view filters on it: a payload where they disagreed would show a figure of
		// three above a table of four.
		if want := fleet.External(s.Ingress) && !s.HasEdgeAuth(); s.Auth.ExposedWithoutAuth != want {
			t.Errorf("%s exposedWithoutAuth = %v but reachable=%v hasEdgeAuth=%v",
				c.key, s.Auth.ExposedWithoutAuth, fleet.External(s.Ingress), s.HasEdgeAuth())
		}
	}
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// A value is masked by what it is called, and never by where it came from (§20).
//
// The pairs below are the whole rule: two values out of the same env file where one is redacted and
// one is not, and two values written inline in the same compose file where the same is true. Masking
// by source instead would leak every inline password and redact every `PG_USER` — and the second
// mistake is the one that makes a reader stop trusting the mask.
//
// `source` is asserted alongside, because it is what tells a reader which file to open: `env_file`
// means the compose file interpolated the value from `.env`, `environment` means the literal text is
// in the compose file itself.
func TestASecretIsMaskedByItsNameAndNotByItsSource(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	for _, c := range []struct {
		key    string
		name   string
		masked bool
		source payload.EnvVarSource
		why    string
	}{
		{"nextcloud/nextcloud", "DB_PASSWORD", true, payload.EnvFromEnvFile,
			"a password, interpolated out of .env"},
		{"nextcloud/nextcloud", "LDAP_BIND_PASSWORD", true, payload.EnvFromEnvFile,
			"and so is a bind password"},

		// Written inline, unmasked, and load-bearing: this address is what attributed the gate, so
		// masking it would leave a finding whose evidence had been withheld from the reader.
		{"nextcloud/nextcloud", "LDAP_HOST", false, payload.EnvFromEnvironment,
			"an address is the detection's own evidence"},
		{"nextcloud/nextcloud", "LDAP_BASE_DN", false, payload.EnvFromEnvironment, "and so is a base DN"},

		// The same env file supplied both of these, and only one is redacted.
		{"authentik/server", "AUTHENTIK_POSTGRESQL__PASSWORD", true, payload.EnvFromEnvFile, "a password"},
		{"authentik/server", "AUTHENTIK_POSTGRESQL__USER", false, payload.EnvFromEnvFile, "a username is not"},
		{"authentik/server", "AUTHENTIK_SECRET_KEY", true, payload.EnvFromEnvFile, "a key, whatever its value"},

		{"outline/outline", "OIDC_CLIENT_SECRET", true, payload.EnvFromEnvFile, "a client secret"},
		{"outline/outline", "OIDC_CLIENT_ID", false, payload.EnvFromEnvFile, "a client id is public by design"},

		// Both inline, and one of them a URL masked because its name contains `TOKEN`. The rule is
		// deliberately blunt in this direction: a redacted endpoint costs a reader one lookup, and the
		// opposite mistake costs them a credential in a browser tab.
		{"outline/outline", "OIDC_TOKEN_URI", true, payload.EnvFromEnvironment, "its name says token"},
		{"outline/outline", "OIDC_AUTH_URI", false, payload.EnvFromEnvironment,
			"the authorize endpoint is what named this gate"},
	} {
		v, ok := env(service(t, out, c.key), c.name)
		if !ok {
			t.Errorf("%s has no %s in its environment", c.key, c.name)
			continue
		}
		if v.Masked != c.masked {
			t.Errorf("%s %s masked = %v, want %v: %s", c.key, c.name, v.Masked, c.masked, c.why)
		}
		if v.Source != c.source {
			t.Errorf("%s %s source = %q, want %q", c.key, c.name, v.Source, c.source)
		}

		// A masked entry keeps its key *and* a placeholder value. Null is reserved for a variable
		// declared with no value at all, which is a different reading from one that is set and
		// withheld (§6, §20) — and an operator scanning for what is configured needs to see the
		// difference at a glance.
		if c.masked && (v.Value == nil || *v.Value == "") {
			t.Errorf("%s %s masked to nothing: a reader has to see that the value is set", c.key, c.name)
		}
	}
}

// No secret from any env file appears anywhere in the served bytes.
//
// The test above checks the four values it names. This one checks the whole document, because masking
// is not a property of the environment list: a value interpolated into a label, a router rule, a
// forward-auth address or a warning is the same leak, and each of those is a different code path.
// Reading the fixture's own `.env` files rather than restating their contents is deliberate — a
// secret added to a fixture tomorrow is covered by this test today.
func TestNoEnvFileSecretSurvivesIntoThePayload(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})
	document := marshal(t, out)

	// Names whose values are shown on purpose; everything else in an env file is treated as secret
	// for the length of this test, which is stricter than §20 and is meant to be.
	shown := map[string]bool{
		"PG_USER": true, "OIDC_CLIENT_ID": true,
	}

	for name, value := range envFileValues(t, root("apps")) {
		if shown[name] || len(value) < 6 {
			continue
		}
		if strings.Contains(document, value) {
			t.Errorf("the value of %s from an env file appears verbatim in the payload", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

// Drawn network nodes plus solo local networks equal the network count (§8).
//
// A network with one member connects nothing, so drawing it adds a node and an edge that say only
// that a service is on a network — which every service is. It is still *counted*, because an operator
// looking for a network they created and expected two things to be on needs to find it.
func TestASoloLocalNetworkIsCountedAndDrawnNowhere(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	drawn := map[string]bool{}
	for _, n := range out.Graph.Nodes {
		if n.Kind == payload.NodeNetwork {
			drawn[strings.TrimPrefix(n.ID, "net:")] = true
		}
	}

	if len(drawn)+out.Stats.SoloLocalNetworks != out.Stats.Networks {
		t.Errorf("%d drawn + %d solo != %d networks", len(drawn), out.Stats.SoloLocalNetworks, out.Stats.Networks)
	}

	// Named rather than counted, because which network dropped out is the whole point.
	if drawn["emby_default"] {
		t.Error("emby_default is drawn: its only member is emby, so the node carries no information")
	}
	for _, name := range []string{"proxy", "authentik_default", "nextcloud_default"} {
		if !drawn[name] {
			t.Errorf("%s is not drawn, and it connects two or more services", name)
		}
	}

	// The solo network is still on its member's list. A service's networks are what the file says,
	// not what the diagram chose to draw.
	if got := service(t, out, "emby/emby").Networks; marshal(t, got) != marshal(t, []string{"emby_default", "proxy"}) {
		t.Errorf("emby networks = %s, want both including the solo one", marshal(t, got))
	}
}

// The proxy network is external in all six stacks, and joins them.
func TestTheSharedNetworkIsWhatMakesTheFleetOneDiagram(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	for _, name := range []string{"authentik", "emby", "jellyfin", "nextcloud", "outline", "proxy"} {
		st := stack(t, out, name)
		found := false
		for _, n := range st.DeclaredNetworks {
			if n.Name != "proxy" {
				continue
			}
			found = true
			if !n.External {
				t.Errorf("stack %s declares proxy as its own, and every other stack declares it external", name)
			}
		}
		if !found {
			t.Errorf("stack %s does not declare the proxy network", name)
		}
	}

	// A network declared external can carry containers this scan never saw, which is why §8 counts it
	// cross-stack on the strength of the declaration and not only on the members it found.
	if out.Stats.CrossStackNetworks != 1 {
		t.Errorf("crossStackNetworks = %d, want 1", out.Stats.CrossStackNetworks)
	}
}

// ---------------------------------------------------------------------------
// The reads that did not happen
// ---------------------------------------------------------------------------

// Four switched-off reads, each with the setting that would switch it on (§15).
//
// `disabled` is a phase like any other and it carries an action like any other. A report that said
// only "not ok" would leave a reader with nothing to do, and I4 is *degrade and say so*.
func TestEveryReadThatDidNotHappenSaysSoAndSaysWhatWouldChangeIt(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	if len(out.Meta.Connections) != 4 {
		t.Fatalf("connections = %d, want one each for docker, authentik, traefik and the probe",
			len(out.Meta.Connections))
	}

	for _, target := range []conn.Target{conn.TargetDocker, conn.TargetAuthentik, conn.TargetTraefik, conn.TargetProbe} {
		r := report(t, out, target)
		if r.OK {
			t.Errorf("%s reports ok, and it was never asked", target)
		}
		if r.Phase != payload.PhaseDisabled {
			t.Errorf("%s phase = %q, want %q", target, r.Phase, payload.PhaseDisabled)
		}
		if !strings.Contains(r.Hint, "LABVIEW_") {
			t.Errorf("%s hint = %q, and it does not name the setting that would enable it", target, r.Hint)
		}
		if len(r.Attempts) != 0 {
			t.Errorf("%s recorded %d attempts against a disabled read", target, len(r.Attempts))
		}

		// A disabled read has no endpoint, and inventing one would break I2: an address is discovered
		// or supplied, and an unconfigured integration has neither.
		if r.Endpoint != "" {
			t.Errorf("%s reports endpoint %q against a read that never resolved one", target, r.Endpoint)
		}
	}

	// Both summaries are present and both say off. Absent summaries would leave the Diagnostics view
	// unable to distinguish "switched off" from "this build has no such integration".
	if out.Meta.Authentik == nil || out.Meta.Authentik.Enabled {
		t.Errorf("meta.authentik = %v, want a summary saying it is off", out.Meta.Authentik)
	}
	if out.Meta.Traefik == nil || out.Meta.Traefik.Enabled {
		t.Errorf("meta.traefik = %v, want a summary saying it is off", out.Meta.Traefik)
	}
	if out.Meta.DockerAvailable {
		t.Error("meta.dockerAvailable is true, and the Docker read is disabled")
	}

	// Off by configuration, and every service skipped — so `skipped` accounts for the whole fleet
	// and a reader can tell this from a probe that ran and found nothing (§13.7).
	if out.Meta.Probe.Enabled {
		t.Error("meta.probe.enabled is true against a disabled probe")
	}
	if out.Meta.Probe.Source != payload.ProbeSourceConfig {
		t.Errorf("meta.probe.source = %q, want %q: nothing overrode this scan",
			out.Meta.Probe.Source, payload.ProbeSourceConfig)
	}
	if out.Meta.Probe.Skipped != out.Stats.Services {
		t.Errorf("meta.probe.skipped = %d across %d services, want every one accounted for",
			out.Meta.Probe.Skipped, out.Stats.Services)
	}

	if len(out.Meta.Warnings) != 0 {
		t.Errorf("warnings = %v, and a root where every integration is off is not a degraded scan",
			out.Meta.Warnings)
	}
}

// A read that did not happen says nothing about anybody's posture.
//
// This is §23's revert contract for the distinction between *the proxy reported no gate here* and
// *nobody asked the proxy*. The proxy read is off in this root, as it is in most real deployments, so
// a rule that concluded from an empty snapshot would put two sentences on almost every labelled
// service in almost every fleet — one saying its router is not being served, one saying its chain
// contains no authentication middleware. Both false, and the second reads as a bypass.
func TestNoServiceIsToldWhatAnUnreadProxySaid(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	for _, key := range keys(out) {
		s := service(t, out, key)
		for _, note := range s.Notes {
			if strings.Contains(note, "proxy") || strings.Contains(note, "router") {
				t.Errorf("%s is told %q, and the proxy was never read", key, note)
			}
		}
		if s.TraefikLive != nil {
			t.Errorf("%s carries %d live routers from a read that did not happen", key, len(s.TraefikLive))
		}
		if s.Authentik != nil {
			t.Errorf("%s carries an Authentik match from a read that did not happen", key)
		}
		if s.Docker != nil {
			t.Errorf("%s carries Docker state from a read that did not happen", key)
		}
		if s.Probe != nil {
			t.Errorf("%s carries a probe result from a probe that did not run", key)
		}
	}

	// The label-derived chain is untouched by all of that: the middleware is in the compose file, and
	// a proxy that was never asked cannot contradict it.
	if got := service(t, out, "jellyfin/jellyfin").Auth.Method; got != payload.AuthAuthentikForwardAuth {
		t.Errorf("jellyfin auth.method = %q: an unread proxy suppressed a posture the labels state", got)
	}
}
