package authentik

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// The four endpoints §11 permits, and nothing else. They are written once so that the claim
// "these are the only reads" is checkable by grep rather than by trust.
const (
	pathRootConfig   = "/api/v3/root/config/"
	pathApplications = "/api/v3/core/applications/"
	pathProxy        = "/api/v3/providers/proxy/"
	pathOAuth2       = "/api/v3/providers/oauth2/"
	pathOutposts     = "/api/v3/outposts/instances/"
)

// pageSize is the 100 per page §11 states. It is sent explicitly rather than left to the
// server's default so that maxPages bounds a known number of records (I8).
const pageSize = 100

// envelope is the paged response every list endpoint returns.
//
// Pagination is optional and stays optional. Some deployments and some proxies return the bare
// array, and one that does is not a broken read — it is a read with no unfiltered total, which
// §11 requires treated as *no count* rather than as zero.
type envelope struct {
	Pagination *struct {
		// Count is what Authentik says exists, before its policy engine filtered the page.
		Count looseNumber `json:"count"`
		// Next is the number of the following page, and is **zero** when there is none.
		// Authentik writes it that way rather than omitting it, which is why the presence of
		// the field cannot be what decides whether to ask for another page.
		Next looseNumber `json:"next"`
	} `json:"pagination"`
	Results json.RawMessage `json:"results"`
}

// looseNumber is a number that may not be one, and that never fails the read it arrived in.
//
// §11 requires a non-numeric count treated as *no count*. A strict decode cannot do that: a
// count a proxy stringified to `"12"` would fail the whole envelope and take every application
// on the page with it, which is precisely the degradation I4 forbids. So the shape is absorbed
// here and the judgement is made by the two accessors below.
type looseNumber struct {
	// Present is whether the key appeared at all with a value other than null. Numeric is
	// whether that value could be read as an integer.
	Present bool
	Numeric bool
	Value   int64
}

func (l *looseNumber) UnmarshalJSON(b []byte) error {
	*l = looseNumber{}
	text := strings.TrimSpace(string(b))
	if text == "" || text == "null" {
		return nil
	}
	l.Present = true

	// A quoted number is still a number. Anything else stays non-numeric, which is a fact the
	// caller acts on rather than an error the caller has to handle.
	if n, err := strconv.ParseInt(strings.Trim(text, `"`), 10, 64); err == nil {
		l.Numeric, l.Value = true, n
	}
	return nil
}

// total is the unfiltered count, or nil when the envelope carried none.
//
// A non-numeric or negative count is no count. Authentik has never sent one, but a proxy in
// front of it might, and a negative `configured` would make `withheld` a negative number that
// the UI would render as a finding (§11).
func (e envelope) total() *int {
	if e.Pagination == nil {
		return nil
	}
	c := e.Pagination.Count
	if !c.Present || !c.Numeric || c.Value < 0 {
		return nil
	}
	count := int(c.Value)
	return &count
}

// hasNext reports whether the envelope named a further page.
//
// A further page is a *positive* page number. Authentik sends `"next": 0` on the last page, so
// reading the field's presence as an answer would ask for a page that does not exist — and
// Authentik answers a page out of range with a 404, which would turn a complete read of a
// one-page fleet into a `path` failure. An absent pagination block is the same answer as a
// zero: there is nothing further to ask for.
func (e envelope) hasNext() bool {
	if e.Pagination == nil {
		return false
	}
	n := e.Pagination.Next
	return n.Present && n.Numeric && n.Value > 0
}

// ---------------------------------------------------------------------------
// Applications
// ---------------------------------------------------------------------------

// wireApplication is one record from `core/applications/`.
//
// The provider objects are read for their *kind and name*, which is all they carry — the hosts,
// the mode and the redirect URIs live on the provider detail records and are merged in by pk.
// Reading them here is what makes an LDAP or SAML gate visible at all: neither has a detail list
// among the four endpoints, so the application's own view of its provider is the only evidence.
type wireApplication struct {
	Name  string `json:"name"`
	Slug  string `json:"slug"`
	Group string `json:"group"`

	// Both launch-URL fields, because either can be the only one that carries an address.
	//
	// `launch_url` is what Authentik computed for the user this token authenticated as, and
	// `meta_launch_url` is what the operator configured. They differ in the case that matters: a
	// per-user template is stored in the second and the first is either the substituted result or
	// null, depending on release. Reading only the computed field would mean an application whose
	// launch URL is a template hands out no URL at all as far as the matcher is concerned — and
	// §11's refusal to match on a per-user template would then be a rule about a value nothing
	// ever supplies.
	LaunchURL     string `json:"launch_url"`
	MetaLaunchURL string `json:"meta_launch_url"`

	Provider             *wireProviderRef  `json:"provider_obj"`
	BackchannelProviders []wireProviderRef `json:"backchannel_providers_obj"`
}

// launchURL is the one the payload carries: the computed one when there is one, and the configured
// one when there is not.
//
// The template is carried rather than discarded. It is what the operator wrote, it is what the
// Authentik admin interface shows, and a reader looking at an application that matched nothing is
// owed the reason in the form the reason exists in — a placeholder they can recognise, rather than
// a blank field that reads as *nothing configured*.
func (a wireApplication) launchURL() string {
	if url := strings.TrimSpace(a.LaunchURL); url != "" {
		return url
	}
	return strings.TrimSpace(a.MetaLaunchURL)
}

// wireProviderRef is an application's view of one of its providers.
type wireProviderRef struct {
	PK   json.Number `json:"pk"`
	Name string      `json:"name"`
	// The three fields Authentik uses to say what a provider is, in descending specificity.
	// All three are read because which of them a version populates has changed, and a kind
	// normalised from an empty string would be `other` for a provider whose type is knowable.
	MetaModelName string `json:"meta_model_name"`
	Component     string `json:"component"`
	VerboseName   string `json:"verbose_name"`
}

func (r wireProviderRef) pk() string { return strings.TrimSpace(r.PK.String()) }

// rawKind is what the API actually said, kept so that a kind normalised to `other` is still
// answerable (§4.3).
func (r wireProviderRef) rawKind() string {
	for _, candidate := range []string{r.MetaModelName, r.Component, r.VerboseName} {
		if strings.TrimSpace(candidate) != "" {
			return strings.TrimSpace(candidate)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Provider details
// ---------------------------------------------------------------------------

// wireProvider is one record from `providers/proxy/` or `providers/oauth2/`.
//
// The two assigned-application fields are what make pass two possible: neither provider list
// applies a policy filter, so a provider naming an application the application list withheld is
// evidence that the application exists (§11).
type wireProvider struct {
	PK   json.Number `json:"pk"`
	Name string      `json:"name"`

	MetaModelName string `json:"meta_model_name"`
	Component     string `json:"component"`
	VerboseName   string `json:"verbose_name"`

	Mode         string       `json:"mode"`
	InternalHost string       `json:"internal_host"`
	ExternalHost string       `json:"external_host"`
	RedirectURIs redirectURIs `json:"redirect_uris"`

	AssignedApplicationSlug string `json:"assigned_application_slug"`
	AssignedApplicationName string `json:"assigned_application_name"`

	AssignedBackchannelApplicationSlug string `json:"assigned_backchannel_application_slug"`
	AssignedBackchannelApplicationName string `json:"assigned_backchannel_application_name"`
}

func (p wireProvider) pk() string { return strings.TrimSpace(p.PK.String()) }

func (p wireProvider) rawKind() string {
	return wireProviderRef{
		MetaModelName: p.MetaModelName,
		Component:     p.Component,
		VerboseName:   p.VerboseName,
	}.rawKind()
}

// slug is the application this provider is assigned to, and whether that assignment is a
// backchannel one. A backchannel provider is not in the request path of a browser reaching the
// application; it is how something else authenticates *against* it, which is why LDAP gates are
// only ever found here (§11).
func (p wireProvider) slug() (string, bool) {
	if s := strings.TrimSpace(p.AssignedApplicationSlug); s != "" {
		return s, false
	}
	return strings.TrimSpace(p.AssignedBackchannelApplicationSlug), true
}

// redirectURIs absorbs both shapes Authentik has used for this field: a newline-separated string
// in older releases, and a list of `{matching_mode, url}` objects in newer ones.
//
// It absorbs a third shape too — anything it cannot read at all becomes no URIs. A provider list
// that failed to decode because one provider grew a field would lose every *other* provider with
// it, and an application with no redirect URIs is a weaker reading, not a broken one (I4).
type redirectURIs []string

func (r *redirectURIs) UnmarshalJSON(b []byte) error {
	*r = nil

	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		for _, line := range strings.Fields(one) {
			*r = append(*r, line)
		}
		return nil
	}

	var many []struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(b, &many); err == nil {
		for _, entry := range many {
			if entry.URL != "" {
				*r = append(*r, entry.URL)
			}
		}
		return nil
	}

	var plain []string
	if err := json.Unmarshal(b, &plain); err == nil {
		for _, entry := range plain {
			if entry != "" {
				*r = append(*r, entry)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Outposts
// ---------------------------------------------------------------------------

// wireOutpost is one record from `outposts/instances/`. Only the name and the provider pks are
// read: an outpost is evidence that a proxy, LDAP or RADIUS provider is actually in a request
// path, and nothing else about it changes any conclusion (§11).
type wireOutpost struct {
	Name      string        `json:"name"`
	Providers []json.Number `json:"providers"`
}

// ---------------------------------------------------------------------------
// Kind normalisation
// ---------------------------------------------------------------------------

// kindOf normalises whatever Authentik called a provider into the closed set of §4.3.
//
// It reads tokens out of the raw string rather than matching it whole, because the same kind
// arrives as `authentik_providers_proxy.proxyprovider`, as `ak-provider-proxy-form` and as
// `Proxy Provider` depending on which field and which release answered. `oauth2` is asked before
// `oauth` so that an OAuth2 provider is never read as an unknown one.
func kindOf(raw string) payload.AuthentikProviderKind {
	low := strings.ToLower(raw)
	for _, probe := range []struct {
		token string
		kind  payload.AuthentikProviderKind
	}{
		{"oauth2", payload.ProviderOAuth2},
		{"proxy", payload.ProviderProxy},
		{"ldap", payload.ProviderLDAP},
		{"saml", payload.ProviderSAML},
		{"radius", payload.ProviderRADIUS},
		{"scim", payload.ProviderSCIM},
	} {
		if strings.Contains(low, probe.token) {
			return probe.kind
		}
	}
	// A kind Authentik grew after this was written. `other` rather than a guess, and RawKind
	// keeps what it said so the answer is still available to a reader (I3).
	return payload.ProviderOther
}

// Enforced reports whether a gate of this kind can exist at all, and what has to be true for it
// to (§11).
//
// The distinction is who is in the request path. A proxy, LDAP or RADIUS provider is enforced by
// an *outpost*, so one assigned to no outpost protects nothing. OAuth2 and SAML are enforced by
// the Authentik server itself and so always do. SCIM is outbound provisioning: it enforces
// nothing, ever, and reporting it as a gate would be the single most misleading thing this
// package could say.
// The table itself is on the payload type, because the exposure verdict asks this question and the
// verdict may not depend on an integration package. This is the same question asked from here, not
// a second copy of the answer — SCIM and anything normalised to `other` come back false there for
// the reason they would here: I1 does not license a conclusion from a name nobody recognises.
func Enforced(kind payload.AuthentikProviderKind, outposts []string) bool {
	return payload.AuthentikProvider{Kind: kind, Outposts: outposts}.Enforced()
}

// NeedsOutpost reports whether this kind is one an outpost has to carry. It is separate from
// Enforced so that "assigned to no outpost" can be *stated as the reason* rather than reported
// as a bare absence (§11).
func NeedsOutpost(kind payload.AuthentikProviderKind) bool {
	switch kind {
	case payload.ProviderProxy, payload.ProviderLDAP, payload.ProviderRADIUS:
		return true
	default:
		return false
	}
}

// Method is the AuthMethod a provider kind maps to, and false where it maps to none.
//
// Three of the six kinds have no member: SAML and RADIUS are real gates §4.2 has no vocabulary
// for, and SCIM is not a gate. Returning false rather than a generic member is what keeps a
// SAML-protected service out of the exposure finding without claiming it is protected by
// something it is not (§11).
func Method(kind payload.AuthentikProviderKind) (payload.AuthMethod, bool) {
	switch kind {
	case payload.ProviderProxy:
		return payload.AuthAuthentikForwardAuth, true
	case payload.ProviderOAuth2:
		return payload.AuthAuthentikOAuth, true
	case payload.ProviderLDAP:
		return payload.AuthAuthentikLDAP, true
	default:
		return "", false
	}
}

// sortedUnique is the one place a list of names built from a map becomes a payload field.
func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
