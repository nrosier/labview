// Package traefikapi is §12: the reverse-proxy read, and the match that ties its live routers
// onto scanned services.
//
// The same split as §11, for the same reason. Read does every network operation, holds no fleet
// knowledge and never throws — a failure becomes a connection report. Everything after it is a
// pure function of a Snapshot plus the fleet index, which is what makes the three matching rules,
// the chain expansion and the downgrade assertable as tables of literals rather than against a
// live proxy.
package traefikapi

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// The three endpoints §12 permits, and nothing else. They are written once so that the claim
// "these are the only reads" is checkable by grep rather than by trust.
const (
	pathVersion     = "/api/version"
	pathRawData     = "/api/rawdata"
	pathEntrypoints = "/api/entrypoints"
)

// internalAPIService is Traefik's own name for its API.
//
// A router whose service is this is the operator declaring that this container serves the API,
// which is the strongest of §12's three discovery signals and the only one that also yields the
// exact public hostname the API answers on.
const internalAPIService = "api@internal"

// ---------------------------------------------------------------------------
// Loose shapes
// ---------------------------------------------------------------------------

// looseStrings is a list that may have arrived as a single string, and that never fails the read
// it arrived in.
//
// Traefik writes a router's `error` as an array, but a released version has written it as a bare
// string, and a proxy in front of the API could rewrite either. A strict decode would fail the
// whole rawdata document and take every router with it — the degradation I4 forbids. So the shape
// is absorbed here, and an unreadable one becomes no errors rather than no snapshot.
type looseStrings []string

func (l *looseStrings) UnmarshalJSON(b []byte) error {
	*l = nil
	text := strings.TrimSpace(string(b))
	if text == "" || text == "null" {
		return nil
	}

	var many []string
	if err := json.Unmarshal(b, &many); err == nil {
		for _, v := range many {
			if v = strings.TrimSpace(v); v != "" {
				*l = append(*l, v)
			}
		}
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		if one = strings.TrimSpace(one); one != "" {
			*l = append(*l, one)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// /api/version
// ---------------------------------------------------------------------------

// wireVersion is the version document. Both spellings are read because Traefik v2 answers
// `Version` and some builds answer `version`, and a reader who sees no version cannot tell a
// proxy that did not say from one this program failed to ask.
type wireVersion struct {
	Upper string `json:"Version"`
	Lower string `json:"version"`
}

func (w wireVersion) version() string {
	if v := strings.TrimSpace(w.Upper); v != "" {
		return v
	}
	return strings.TrimSpace(w.Lower)
}

// ---------------------------------------------------------------------------
// /api/rawdata
// ---------------------------------------------------------------------------

// wireRawData is the routing table. The three sections this reads are the three §12 names; the
// TCP and UDP router sections are deliberately absent, because §4.1's evidence for a Traefik
// route is an HTTP route and a TCP router carries no host rule to match on.
type wireRawData struct {
	Routers     map[string]wireRouter      `json:"routers"`
	Middlewares map[string]json.RawMessage `json:"middlewares"`
	Services    map[string]wireService     `json:"services"`
}

type wireRouter struct {
	Name        string   `json:"name"`
	Provider    string   `json:"provider"`
	Status      string   `json:"status"`
	Rule        string   `json:"rule"`
	Service     string   `json:"service"`
	EntryPoints []string `json:"entryPoints"`
	Middlewares []string `json:"middlewares"`

	// TLS is read for presence only. Traefik writes an object here for a TLS router and omits
	// the key otherwise, so what the object *contains* — a cert resolver, options, domains — is
	// configuration this program does not report, while the key's presence is the fact it does.
	TLS json.RawMessage `json:"tls"`

	Error looseStrings `json:"error"`
}

// tls reports whether the router terminates TLS. A `null` is the absent key spelled out, and
// reading it as presence would report every plain-HTTP router as encrypted.
func (w wireRouter) tls() bool {
	text := strings.TrimSpace(string(w.TLS))
	return text != "" && text != "null"
}

type wireService struct {
	Provider     string `json:"provider"`
	Status       string `json:"status"`
	LoadBalancer *struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
	} `json:"loadBalancer"`

	// ServerStatus is keyed on the backend URL. A URL absent from it has *no known status*,
	// which Appendix A requires kept distinct from `UP` — so the zero value stays empty and no
	// default is substituted anywhere.
	ServerStatus map[string]string `json:"serverStatus"`

	Error looseStrings `json:"error"`
}

// ---------------------------------------------------------------------------
// Middlewares
// ---------------------------------------------------------------------------

// middlewareMeta is the keys of a middleware object that describe the record rather than its
// type. Everything else is the type — which is how the type is *taken from the definition
// Traefik holds* (§12) instead of from the name, and why a middleware this program models
// nothing about is still reported by its real type.
var middlewareMeta = map[string]bool{
	"status": true, "usedby": true, "name": true, "provider": true, "error": true,
}

// The three middleware types §12 draws a conclusion from. They are compared case-insensitively
// against what Traefik spelled, and the spelling Traefik used is what gets reported.
const (
	typeForwardAuth = "forwardauth"
	typeBasicAuth   = "basicauth"
	typeDigestAuth  = "digestauth"
	typeChain       = "chain"
)

// RawMiddleware is one middleware definition as the proxy holds it.
//
// This is the whole reason `/api/rawdata` is read rather than only the router list: a middleware
// defined in a Traefik **file provider** has no definition in any scanned stack, so without the
// proxy's own copy its type is unknowable and a gate could only ever be `inferred` from its name.
type RawMiddleware struct {
	// Name is `name@provider`, as Traefik reports it.
	Name string
	// Type is Traefik's own spelling — `forwardAuth`, `basicAuth`, `plugin`, anything.
	Type string
	// Address is set for a forward-auth middleware, and is what resolves back to a service.
	Address string
	// Chain is the references a `chain` middleware pulls in, in order.
	Chain  []string
	Status string
	Errors []string
}

// authMethodOf is which gate a middleware type is, in §4.2's vocabulary, and false for a type
// that leaves the request answerable by anyone.
//
// Digest and basic both yield `basic-auth`: §4.2 has no separate member, and inventing one would
// widen a closed set to record a distinction no other source in this program can make.
//
// It takes the type as a string because the same question is asked of a definition the proxy holds
// and of a middleware already resolved onto a router, and two switches would be two answers.
func authMethodOf(mwType string) (payload.AuthMethod, bool) {
	switch strings.ToLower(strings.TrimSpace(mwType)) {
	case typeForwardAuth:
		return payload.AuthForwardAuth, true
	case typeBasicAuth, typeDigestAuth:
		return payload.AuthBasicAuth, true
	default:
		return "", false
	}
}

func (m RawMiddleware) isChain() bool {
	return strings.EqualFold(strings.TrimSpace(m.Type), typeChain)
}

// parseMiddleware reads one middleware object.
//
// The type is the one key that is not metadata. Keys are walked in sorted order so that a
// document with two type-shaped keys — which no Traefik writes, but a proxy rewriting the body
// might — resolves to the same type on two reads (I7).
func parseMiddleware(key string, raw json.RawMessage) RawMiddleware {
	out := RawMiddleware{Name: strings.TrimSpace(key)}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		// Not an object. The middleware is still *named* by whatever referred to it, so it is
		// reported by name with nothing claimed about it (I4).
		return out
	}

	var names []string
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		switch strings.ToLower(name) {
		case "name":
			var v string
			if json.Unmarshal(fields[name], &v) == nil && strings.TrimSpace(v) != "" {
				out.Name = strings.TrimSpace(v)
			}
		case "status":
			var v string
			if json.Unmarshal(fields[name], &v) == nil {
				out.Status = strings.TrimSpace(v)
			}
		case "error":
			var v looseStrings
			if json.Unmarshal(fields[name], &v) == nil {
				out.Errors = []string(v)
			}
		default:
			if middlewareMeta[strings.ToLower(name)] || out.Type != "" {
				continue
			}
			out.Type = name
			out.readBody(name, fields[name])
		}
	}
	return out
}

// readBody pulls the two fields a conclusion rests on out of the type's own object: a
// forward-auth address, and a chain's references. Nothing else is read — this program reports
// that a gate is there and where it forwards, and the rest of a middleware's settings are the
// proxy's configuration rather than this fleet's posture.
func (m *RawMiddleware) readBody(typeName string, body json.RawMessage) {
	switch strings.ToLower(typeName) {
	case typeForwardAuth:
		var v struct {
			Address string `json:"address"`
		}
		if json.Unmarshal(body, &v) == nil {
			m.Address = strings.TrimSpace(v.Address)
		}
	case typeChain:
		var v struct {
			Middlewares []string `json:"middlewares"`
		}
		if json.Unmarshal(body, &v) == nil {
			for _, ref := range v.Middlewares {
				if ref = strings.TrimSpace(ref); ref != "" {
					m.Chain = append(m.Chain, ref)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// /api/entrypoints
// ---------------------------------------------------------------------------

// wireEntrypoint is one entrypoint. Its HTTP middleware list is the whole reason this third
// request exists: a gate attached at an entrypoint appears in no router's own middleware list,
// so without it an empty chain cannot be told from a chain whose gate is one level up (§12).
type wireEntrypoint struct {
	Name string `json:"name"`
	HTTP *struct {
		Middlewares []string `json:"middlewares"`
	} `json:"http"`
}

// ---------------------------------------------------------------------------
// Wording
// ---------------------------------------------------------------------------

func quote(s string) string { return "`" + s + "`" }

// list is a human list, sorted so that a note or a trace line is the same line on two reads (I7).
func list(in []string) string {
	got := append([]string{}, in...)
	sort.Strings(got)
	for i, v := range got {
		got[i] = quote(v)
	}
	switch len(got) {
	case 0:
		return "nothing"
	case 1:
		return got[0]
	case 2:
		return got[0] + " and " + got[1]
	default:
		return strings.Join(got[:len(got)-1], ", ") + " and " + got[len(got)-1]
	}
}

func appendOnce(into []string, v string) []string {
	for _, existing := range into {
		if existing == v {
			return into
		}
	}
	return append(into, v)
}

func appendKeys(into, keys []string) []string {
	for _, k := range keys {
		into = appendOnce(into, k)
	}
	return into
}
