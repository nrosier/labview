package authentik

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------------

// TestACountThatIsNotAWholeNumberIsNoCount is §11's requirement that a non-numeric or negative
// count is treated as *no count* rather than as zero.
//
// The reason it matters is arithmetic: `configured` feeds `withheld = configured − listed`, so a
// count of −3 against a listed 4 would produce a withheld of −7 and a UI that reports a finding
// about a fleet with nothing wrong with it. A quoted number is still a number, because a proxy that
// stringifies it has not changed what Authentik said.
func TestACountThatIsNotAWholeNumberIsNoCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want *int
	}{
		{"a whole number", `{"pagination":{"count":12},"results":[]}`, intp(12)},
		{"zero", `{"pagination":{"count":0},"results":[]}`, intp(0)},
		{"a number a proxy quoted", `{"pagination":{"count":"12"},"results":[]}`, intp(12)},
		{"a fraction", `{"pagination":{"count":1.5},"results":[]}`, nil},
		{"a negative", `{"pagination":{"count":-3},"results":[]}`, nil},
		{"a word", `{"pagination":{"count":"lots"},"results":[]}`, nil},
		{"null", `{"pagination":{"count":null},"results":[]}`, nil},
		{"no count key", `{"pagination":{"next":0},"results":[]}`, nil},
		{"no pagination block", `{"results":[]}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var env envelope
			if err := json.Unmarshal([]byte(tc.body), &env); err != nil {
				t.Fatalf("the envelope must absorb %s rather than fail the page it arrived on (I4): %v", tc.name, err)
			}
			got := env.total()
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("total() = %d, want no count", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("total() = no count, want %d", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("total() = %d, want %d", *got, *tc.want)
			}
		})
	}
}

// TestTheLastPageSaysSoWithAZero is the shape Authentik actually sends.
//
// `next` is a page *number*, and it is 0 on the last page rather than absent. Reading the field's
// presence as the answer would ask for a page that does not exist, and Authentik answers a page out
// of range with a 404 — which would turn a complete read of a one-page fleet into a `path` failure.
func TestTheLastPageSaysSoWithAZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"a further page", `{"pagination":{"next":2},"results":[]}`, true},
		{"the last page", `{"pagination":{"next":0},"results":[]}`, false},
		{"next omitted", `{"pagination":{"count":3},"results":[]}`, false},
		{"next null", `{"pagination":{"next":null},"results":[]}`, false},
		{"no pagination block", `{"results":[]}`, false},
		{"a bare array", `[]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var env envelope
			if err := json.Unmarshal([]byte(tc.body), &env); err != nil && tc.name != "a bare array" {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := env.hasNext(); got != tc.want {
				t.Fatalf("hasNext() = %v, want %v for %s", got, tc.want, tc.body)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Redirect URIs
// ---------------------------------------------------------------------------

// TestARedirectURIListIsReadInEveryShapeItHasEverHad is I4 at the field level.
//
// Authentik has sent this field as a newline-separated string and as a list of objects, and a
// release may send a third thing. A strict decode would fail the whole *page*, losing every other
// provider on it — so an unreadable field becomes no URIs, which is a weaker reading rather than a
// broken one.
func TestARedirectURIListIsReadInEveryShapeItHasEverHad(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{
			"the newline-separated string of older releases",
			`"https://a.example.com/cb\nhttps://b.example.com/cb"`,
			[]string{"https://a.example.com/cb", "https://b.example.com/cb"},
		},
		{
			"the object list of newer ones",
			`[{"matching_mode":"strict","url":"https://a.example.com/cb"}]`,
			[]string{"https://a.example.com/cb"},
		},
		{"a plain list of strings", `["https://a/cb","https://b/cb"]`, []string{"https://a/cb", "https://b/cb"}},
		{"an object with no url", `[{"matching_mode":"strict"}]`, nil},
		{"a shape nobody has sent", `42`, nil},
		{"an object", `{"url":"https://a/cb"}`, nil},
		{"null", `null`, nil},
		{"an empty string", `""`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got redirectURIs
			if err := got.UnmarshalJSON([]byte(tc.body)); err != nil {
				t.Fatalf("a redirect URI list must never fail its provider's page (I4): %v", err)
			}
			if !reflect.DeepEqual([]string(got), tc.want) {
				t.Fatalf("redirect URIs = %#v, want %#v", []string(got), tc.want)
			}
		})
	}
}

// TestOneProviderWithAnUnreadableFieldDoesNotTakeThePageWithIt is the same guarantee at the level
// the failure would actually be noticed: a list of three providers where the middle one's redirect
// URIs are a shape nobody has sent still yields three providers.
func TestOneProviderWithAnUnreadableFieldDoesNotTakeThePageWithIt(t *testing.T) {
	body := `[
	  {"pk":1,"name":"first","redirect_uris":"https://a/cb"},
	  {"pk":2,"name":"second","redirect_uris":42},
	  {"pk":3,"name":"third","redirect_uris":[{"url":"https://c/cb"}]}
	]`
	var got []wireProvider
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("the page must decode: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d providers, want 3 — one unreadable field must not lose the others (I4)", len(got))
	}
	if len(got[1].RedirectURIs) != 0 {
		t.Fatalf("the unreadable provider has %v redirect URIs, want none", got[1].RedirectURIs)
	}
	if len(got[2].RedirectURIs) != 1 {
		t.Fatalf("the provider after the unreadable one lost its URIs: %v", got[2].RedirectURIs)
	}
}

// ---------------------------------------------------------------------------
// Kind normalisation
// ---------------------------------------------------------------------------

// TestAKindIsReadFromWhicheverFieldTheReleasePopulated pins the three fields and their order.
//
// Which of `meta_model_name`, `component` and `verbose_name` a release fills has changed, and all
// three are read in descending specificity. A kind normalised from an empty string would be `other`
// for a provider whose type is perfectly knowable.
func TestAKindIsReadFromWhicheverFieldTheReleasePopulated(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  wireProviderRef
		want string
	}{
		{
			"the most specific field wins",
			wireProviderRef{MetaModelName: "authentik_providers_proxy.proxyprovider", Component: "ak-provider-oauth2-form"},
			"authentik_providers_proxy.proxyprovider",
		},
		{"the component when there is no model name", wireProviderRef{Component: "ak-provider-proxy-form"}, "ak-provider-proxy-form"},
		{"the verbose name when there is neither", wireProviderRef{VerboseName: "Proxy Provider"}, "Proxy Provider"},
		{"nothing at all", wireProviderRef{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ref.rawKind(); got != tc.want {
				t.Fatalf("rawKind() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEveryWordingOfAKindNormalisesToTheClosedSet is §4.3's closed set against the three wordings
// each kind arrives in.
//
// `oauth2` is asked before `oauth` so that an OAuth2 provider is never read as an unknown one, and a
// kind nobody recognises is `other` rather than a guess — with the raw string kept beside it so the
// answer is still available to a reader (I3).
func TestEveryWordingOfAKindNormalisesToTheClosedSet(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want payload.AuthentikProviderKind
	}{
		{"authentik_providers_proxy.proxyprovider", payload.ProviderProxy},
		{"ak-provider-proxy-form", payload.ProviderProxy},
		{"Proxy Provider", payload.ProviderProxy},
		{"authentik_providers_oauth2.oauth2provider", payload.ProviderOAuth2},
		{"ak-provider-oauth2-form", payload.ProviderOAuth2},
		{"OAuth2/OpenID Provider", payload.ProviderOAuth2},
		{"authentik_providers_ldap.ldapprovider", payload.ProviderLDAP},
		{"LDAP Provider", payload.ProviderLDAP},
		{"authentik_providers_saml.samlprovider", payload.ProviderSAML},
		{"SAML Provider", payload.ProviderSAML},
		{"authentik_providers_radius.radiusprovider", payload.ProviderRADIUS},
		{"RADIUS Provider", payload.ProviderRADIUS},
		{"authentik_providers_scim.scimprovider", payload.ProviderSCIM},
		{"SCIM Provider", payload.ProviderSCIM},
		{"authentik_providers_teleport.teleportprovider", payload.ProviderOther},
		{"", payload.ProviderOther},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			if got := kindOf(tc.raw); got != tc.want {
				t.Fatalf("kindOf(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestAnOAuth2ProviderIsNeverReadAsAnUnknownOne is the ordering above stated as its own fact,
// because the token search is what makes it true and a reordering would not fail any other test:
// `oauth2` contains no substring that any other probe would claim, but `oauth` does not exist as a
// probe at all, so a version that wrote only `OAuth` would be `other`.
func TestAnOAuth2ProviderIsNeverReadAsAnUnknownOne(t *testing.T) {
	if got := kindOf("ak-provider-oauth2-form"); got != payload.ProviderOAuth2 {
		t.Fatalf("kindOf = %q, want oauth2 — the oauth2 token must be searched before proxy", got)
	}
}

// ---------------------------------------------------------------------------
// What a provider means
// ---------------------------------------------------------------------------

// TestWhetherAKindIsEnforcedIsAboutWhoIsInTheRequestPath is §11's provider-meaning table.
//
// A proxy, LDAP or RADIUS provider is enforced by an *outpost*, so one assigned to no outpost
// protects nothing. OAuth2 and SAML are enforced by the Authentik server itself and so always do.
// SCIM is outbound provisioning and enforces nothing ever — reporting it as a gate would be the
// single most misleading thing this package could say.
func TestWhetherAKindIsEnforcedIsAboutWhoIsInTheRequestPath(t *testing.T) {
	for _, tc := range []struct {
		kind         payload.AuthentikProviderKind
		withOutpost  bool
		withoutPost  bool
		needsOutpost bool
	}{
		{payload.ProviderProxy, true, false, true},
		{payload.ProviderLDAP, true, false, true},
		{payload.ProviderRADIUS, true, false, true},
		{payload.ProviderOAuth2, true, true, false},
		{payload.ProviderSAML, true, true, false},
		{payload.ProviderSCIM, false, false, false},
		{payload.ProviderOther, false, false, false},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			if got := Enforced(tc.kind, []string{"edge"}); got != tc.withOutpost {
				t.Fatalf("Enforced(%q, one outpost) = %v, want %v", tc.kind, got, tc.withOutpost)
			}
			if got := Enforced(tc.kind, nil); got != tc.withoutPost {
				t.Fatalf("Enforced(%q, no outpost) = %v, want %v", tc.kind, got, tc.withoutPost)
			}
			if got := NeedsOutpost(tc.kind); got != tc.needsOutpost {
				t.Fatalf("NeedsOutpost(%q) = %v, want %v", tc.kind, got, tc.needsOutpost)
			}
		})
	}
}

// TestThreeKindsMapToNoAuthMethodAtAll is what keeps a SAML-protected service out of the exposure
// finding without claiming a mechanism §4.2 has no member for.
//
// SAML and RADIUS are real gates the posture vocabulary cannot name, and SCIM is not a gate. All
// three return false rather than a generic member, because a generic member would put a service in
// the *protected* count on evidence that names nothing.
func TestThreeKindsMapToNoAuthMethodAtAll(t *testing.T) {
	for _, tc := range []struct {
		kind   payload.AuthentikProviderKind
		method payload.AuthMethod
		ok     bool
	}{
		{payload.ProviderProxy, payload.AuthAuthentikForwardAuth, true},
		{payload.ProviderOAuth2, payload.AuthAuthentikOAuth, true},
		{payload.ProviderLDAP, payload.AuthAuthentikLDAP, true},
		{payload.ProviderSAML, "", false},
		{payload.ProviderRADIUS, "", false},
		{payload.ProviderSCIM, "", false},
		{payload.ProviderOther, "", false},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			method, ok := Method(tc.kind)
			if ok != tc.ok || method != tc.method {
				t.Fatalf("Method(%q) = (%q, %v), want (%q, %v)", tc.kind, method, ok, tc.method, tc.ok)
			}
		})
	}
}

// TestAProviderNamesTheApplicationItIsAssignedTo is what makes pass two possible: neither provider
// list applies a policy filter, so a provider naming an application the application list withheld
// is evidence that the application exists.
//
// The backchannel assignment is a different fact from the primary one — a backchannel provider is
// not in a browser's request path — and it is only ever read when there is no primary.
func TestAProviderNamesTheApplicationItIsAssignedTo(t *testing.T) {
	for _, tc := range []struct {
		name        string
		provider    wireProvider
		slug        string
		backchannel bool
	}{
		{"a primary assignment", wireProvider{AssignedApplicationSlug: "grafana"}, "grafana", false},
		{"a backchannel one", wireProvider{AssignedBackchannelApplicationSlug: "gitea"}, "gitea", true},
		{
			"both, where the primary wins",
			wireProvider{AssignedApplicationSlug: "grafana", AssignedBackchannelApplicationSlug: "gitea"},
			"grafana", false,
		},
		{"neither", wireProvider{}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			slug, backchannel := tc.provider.slug()
			if slug != tc.slug || backchannel != tc.backchannel {
				t.Fatalf("slug() = (%q, %v), want (%q, %v)", slug, backchannel, tc.slug, tc.backchannel)
			}
		})
	}
}

func intp(n int) *int { return &n }
