package traefikapi

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// Shapes the document may arrive in
// ---------------------------------------------------------------------------

// TestAnErrorListIsAbsorbedInEveryShapeItHasHad is I4 at the field level.
//
// Traefik writes a router's `error` as an array and a released version has written it as a bare
// string. A strict decode would fail the whole rawdata document and take every router with it — the
// degradation I4 forbids — so an unreadable shape has to become *no errors* rather than no snapshot.
func TestAnErrorListIsAbsorbedInEveryShapeItHasHad(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{"the documented array", `{"error":["cannot create service","no such host"]}`,
			[]string{"cannot create service", "no such host"}},
		{"one bare string", `{"error":"cannot create service"}`, []string{"cannot create service"}},
		{"an empty array", `{"error":[]}`, nil},
		{"an empty string", `{"error":""}`, nil},
		{"blanks are not errors", `{"error":["  ",""]}`, nil},
		{"null", `{"error":null}`, nil},
		{"absent", `{}`, nil},
		{"a number", `{"error":7}`, nil},
		{"an object", `{"error":{"detail":"nope"}}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got wireRouter
			if err := json.Unmarshal([]byte(tc.body), &got); err != nil {
				t.Fatalf("the router must absorb %s rather than fail the document it arrived in (I4): %v", tc.name, err)
			}
			if !reflect.DeepEqual([]string(got.Error), tc.want) {
				t.Fatalf("error = %#v, want %#v", []string(got.Error), tc.want)
			}
		})
	}
}

// TestTheVersionIsReadInBothSpellings pins that a reader who sees no version cannot tell a proxy
// that did not say from one this program failed to ask.
//
// Traefik v2 answers `Version` and some builds answer `version`. Reading one spelling would report
// an empty version against a proxy that stated it plainly.
func TestTheVersionIsReadInBothSpellings(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"PascalCase, which is what v3 sends", `{"Version":"3.1.2","Codename":"mimolette"}`, "3.1.2"},
		{"lowercase", `{"version":"2.11.0"}`, "2.11.0"},
		{"both, PascalCase wins", `{"Version":"3.1.2","version":"nonsense"}`, "3.1.2"},
		{"padded", `{"Version":"  3.1.2  "}`, "3.1.2"},
		{"neither", `{"Codename":"mimolette"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got wireVersion
			if err := json.Unmarshal([]byte(tc.body), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if v := got.version(); v != tc.want {
				t.Fatalf("version() = %q, want %q", v, tc.want)
			}
		})
	}
}

// TestATLSKeyThatIsNullIsNotTLS is presence read as presence.
//
// Traefik writes an object here for a TLS router and omits the key otherwise, and a `null` is the
// absent key spelled out. Reading the field's presence in the JSON rather than its content would
// report every plain-HTTP router as encrypted.
func TestATLSKeyThatIsNullIsNotTLS(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"a cert resolver", `{"tls":{"certResolver":"le"}}`, true},
		{"an empty object, which is what a default TLS router sends", `{"tls":{}}`, true},
		{"null", `{"tls":null}`, false},
		{"absent", `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got wireRouter
			if err := json.Unmarshal([]byte(tc.body), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if v := got.tls(); v != tc.want {
				t.Fatalf("tls() = %v, want %v for %s", v, tc.want, tc.body)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A middleware's type
// ---------------------------------------------------------------------------

// TestAMiddlewaresTypeIsTheDefinitionsOwnKeyAndNotItsName is the reason `/api/rawdata` is read at
// all (§12).
//
// A middleware defined in a Traefik file provider has no definition in any scanned stack, so
// without the proxy's own copy its type is unknowable and a gate could only ever be `inferred` from
// its name. The type is the one key that is not metadata, which is how a middleware this program
// models nothing about is still reported by its real type.
func TestAMiddlewaresTypeIsTheDefinitionsOwnKeyAndNotItsName(t *testing.T) {
	for _, tc := range []struct {
		name, key, body string
		want            RawMiddleware
	}{
		{
			name: "a forwardauth, with the address a conclusion rests on",
			key:  "authentik@file",
			body: `{"forwardAuth":{"address":"http://authentik-server:9000/outpost.goauthentik.io/auth/traefik","trustForwardHeader":true},
			        "status":"enabled","name":"authentik@file","provider":"file","usedBy":["wiki-web@docker"]}`,
			want: RawMiddleware{
				Name:    "authentik@file",
				Type:    "forwardAuth",
				Address: "http://authentik-server:9000/outpost.goauthentik.io/auth/traefik",
				Status:  "enabled",
			},
		},
		{
			name: "a basicauth, whose users are configuration this program does not report",
			key:  "dashboard-auth@file",
			body: `{"basicAuth":{"users":["admin:$apr1$abc"]},"status":"enabled"}`,
			want: RawMiddleware{Name: "dashboard-auth@file", Type: "basicAuth", Status: "enabled"},
		},
		{
			name: "a chain, whose references are followed",
			key:  "secured@file",
			body: `{"chain":{"middlewares":["ratelimit@file","  ","authentik@file"]},"status":"enabled"}`,
			want: RawMiddleware{
				Name:   "secured@file",
				Type:   "chain",
				Chain:  []string{"ratelimit@file", "authentik@file"},
				Status: "enabled",
			},
		},
		{
			name: "a type nobody here models is still reported by its real type",
			key:  "compress@file",
			body: `{"compress":{"minResponseBodyBytes":1024},"status":"enabled"}`,
			want: RawMiddleware{Name: "compress@file", Type: "compress", Status: "enabled"},
		},
		{
			name: "the definition's own name wins over the key it was filed under",
			key:  "authentik",
			body: `{"forwardAuth":{"address":"http://a:9000/x"},"name":"authentik@file"}`,
			want: RawMiddleware{Name: "authentik@file", Type: "forwardAuth", Address: "http://a:9000/x"},
		},
		{
			name: "metadata alone is a middleware with no type, not a middleware with none of it read",
			key:  "broken@file",
			body: `{"status":"","name":"broken@file","provider":"file","usedBy":[],"error":["invalid configuration"]}`,
			want: RawMiddleware{Name: "broken@file", Errors: []string{"invalid configuration"}},
		},
		{
			name: "not an object at all: named by whatever referred to it and nothing claimed",
			key:  "odd@file",
			body: `"forwardAuth"`,
			want: RawMiddleware{Name: "odd@file"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMiddleware(tc.key, json.RawMessage(tc.body))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseMiddleware() =\n  %#v\nwant\n  %#v", got, tc.want)
			}
		})
	}
}

// TestDigestAndBasicAreOneMemberAndAChainIsNoGate pins the mapping from a proxy's own spelling into
// §4.2's closed set.
//
// Digest and basic both yield `basic-auth`: §4.2 has no separate member, and inventing one would
// widen a closed set to record a distinction no other source in this program can make. A chain is
// not a gate — it is a container for whatever it names, which is why `docs`'s `secured@file` has to
// be expanded before anything is concluded from it.
func TestDigestAndBasicAreOneMemberAndAChainIsNoGate(t *testing.T) {
	for _, tc := range []struct {
		mwType string
		want   payload.AuthMethod
		ok     bool
	}{
		{"forwardAuth", payload.AuthForwardAuth, true},
		{"forwardauth", payload.AuthForwardAuth, true},
		{"  ForwardAuth  ", payload.AuthForwardAuth, true},
		{"basicAuth", payload.AuthBasicAuth, true},
		{"digestAuth", payload.AuthBasicAuth, true},
		{"chain", "", false},
		{"compress", "", false},
		{"ipWhiteList", "", false},
		{"", "", false},
	} {
		t.Run(tc.mwType, func(t *testing.T) {
			got, ok := authMethodOf(tc.mwType)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("authMethodOf(%q) = %q, %v; want %q, %v", tc.mwType, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Wording
// ---------------------------------------------------------------------------

// TestAHumanListIsTheSameListOnTwoReads is I7 in the notes.
//
// A note or a trace line assembled from a map's iteration order would differ between two identical
// reads, and §17's change note would then report a change to a fleet nothing happened to.
func TestAHumanListIsTheSameListOnTwoReads(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want string
	}{
		{"nothing", nil, "nothing"},
		{"one", []string{"authentik@file"}, "`authentik@file`"},
		{"two", []string{"b@file", "a@file"}, "`a@file` and `b@file`"},
		{"three, sorted regardless of arrival order",
			[]string{"c@file", "a@file", "b@file"}, "`a@file`, `b@file` and `c@file`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := list(tc.in); got != tc.want {
				t.Fatalf("list(%#v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// And it does not reorder its caller's slice, which is shared with the payload.
	in := []string{"b", "a"}
	_ = list(in)
	if !reflect.DeepEqual(in, []string{"b", "a"}) {
		t.Fatalf("list() sorted its caller's slice in place: %#v", in)
	}
}
