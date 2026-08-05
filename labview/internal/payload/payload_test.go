package payload

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The table below is Appendix A transcribed by hand: for every payload type, the JSON
// field names in the order the appendix writes them, and which of them carry a `?`.
//
// It is deliberately a second copy of the contract rather than something derived from the
// structs. Derived from the structs it would assert only that the code agrees with
// itself; transcribed, it fails when a field is renamed, reordered, added, dropped, or
// quietly made optional — each of which is a breaking change to the wire and to the UI
// (§16).
type shape struct {
	fields   []string // every JSON key, in appendix order
	optional []string // the subset marked `?` — a key that may be absent entirely
}

var appendixA = map[string]struct {
	value any
	shape shape
}{
	"Overview": {Overview{}, shape{
		fields: []string{"meta", "stats", "stacks", "graph"},
	}},
	"ScanRequest": {ScanRequest{}, shape{
		fields:   []string{"probe"},
		optional: []string{"probe"},
	}},
	"ScanMeta": {ScanMeta{}, shape{
		fields: []string{"scannedAt", "appsRoot", "dockerAvailable", "dockerError",
			"authentik", "traefik", "connections", "probe", "durationMs", "warnings", "build"},
		optional: []string{"dockerError", "authentik", "traefik"},
	}},
	"ProbeRun": {ProbeRun{}, shape{
		fields: []string{"enabled", "source", "skipped"},
	}},
	"BuildStamp": {BuildStamp{}, shape{
		fields:   []string{"version", "commit", "source"},
		optional: []string{"commit"},
	}},
	"OverviewStats": {OverviewStats{}, shape{
		fields: []string{"stacks", "services", "running",
			"publicServices", "traefikServices", "lanServices", "internalServices",
			"noIngressServices",
			"authProtected", "exposedWithoutAuth", "byAuthMethod",
			"declaredAuth", "declaredAuthProtected", "declaredAuthUnconfirmed",
			"exposureAccepted", "declarationDrift", "declaredDependencies",
			"probeGated", "probeOpen",
			"networks", "connectingNetworks", "crossStackNetworks", "soloLocalNetworks"},
	}},
	"AppStack": {AppStack{}, shape{
		fields: []string{"id", "name", "dir", "composeFile", "hasEnvFile", "projectName",
			"services", "declaredNetworks", "declaredVolumes", "declared", "warnings"},
		optional: []string{"declared"},
	}},
	"NetworkDecl": {NetworkDecl{}, shape{
		fields:   []string{"name", "external", "driver"},
		optional: []string{"driver"},
	}},
	"VolumeDecl": {VolumeDecl{}, shape{
		fields:   []string{"name", "external", "driver"},
		optional: []string{"driver"},
	}},
	"Service": {Service{}, shape{
		fields: []string{"name", "containerName", "image", "restart", "command",
			"dependsOn", "networks", "ports", "expose", "mounts", "env", "labels",
			"cloudflare", "traefik", "ingress", "auth",
			"docker", "authentik", "traefikLive", "declared", "probe", "notes"},
		optional: []string{"image", "restart", "command",
			"docker", "authentik", "traefikLive", "declared", "probe"},
	}},
	"EnvVar": {EnvVar{}, shape{
		// value is required and nullable — `str|null`, not `str?`. The key is always
		// written; null is the reading that the variable has no value at all (§6).
		fields: []string{"key", "value", "masked", "source"},
	}},
	"PortMapping": {PortMapping{}, shape{
		fields:   []string{"published", "target", "protocol", "raw"},
		optional: []string{"published"},
	}},
	"MountSpec": {MountSpec{}, shape{
		fields:   []string{"type", "source", "target", "readOnly", "raw"},
		optional: []string{"source"},
	}},
	"DockerState": {DockerState{}, shape{
		fields: []string{"id", "name", "image", "imageDigest", "state", "status", "health",
			"running", "restartCount", "createdAt", "startedAt",
			"networks", "ipAddresses", "publishedPorts"},
		optional: []string{"imageDigest", "health", "restartCount", "createdAt", "startedAt"},
	}},
	"AuthPosture": {AuthPosture{}, shape{
		fields: []string{"method", "detail", "evidence", "confidence", "exposedWithoutAuth"},
	}},
	"CloudflareRoute": {CloudflareRoute{}, shape{
		fields:   []string{"hostname", "service", "path", "access", "noTlsVerify", "raw", "origin"},
		optional: []string{"path", "access", "noTlsVerify", "origin"},
	}},
	"CloudflareAccess": {CloudflareAccess{}, shape{
		fields:   []string{"group", "policy", "emails"},
		optional: []string{"group", "policy", "emails"},
	}},
	"OriginTarget": {OriginTarget{}, shape{
		fields:   []string{"address", "host", "port", "kind", "hopKey", "evidence"},
		optional: []string{"hopKey"},
	}},
	"TraefikRoute": {TraefikRoute{}, shape{
		fields: []string{"router", "rule", "hosts", "pathPrefixes", "entrypoints", "tls",
			"certResolver", "middlewares", "servicePort", "service"},
		optional: []string{"rule", "certResolver", "servicePort", "service"},
	}},
	"AuthentikProvider": {AuthentikProvider{}, shape{
		fields: []string{"name", "kind", "rawKind", "mode",
			"internalHost", "externalHost", "redirectUris", "backchannel", "outposts"},
		optional: []string{"mode", "internalHost", "externalHost", "redirectUris"},
	}},
	"AuthentikApplication": {AuthentikApplication{}, shape{
		fields:   []string{"name", "slug", "group", "launchUrl", "providers", "discoveredVia"},
		optional: []string{"group", "launchUrl"},
	}},
	"AuthentikMatch": {AuthentikMatch{}, shape{
		fields: []string{"applications", "evidence", "strength"},
	}},
	"UnmatchedApplication": {UnmatchedApplication{}, shape{
		fields: []string{"application", "reason", "detail", "considered"},
	}},
	"AuthentikSummary": {AuthentikSummary{}, shape{
		fields: []string{"enabled", "configured", "reachable", "endpoint", "endpointSource",
			"error", "applications", "applicationsConfigured", "applicationsWithheld",
			"applicationsRecovered", "providers", "outposts", "matchedServices",
			"unmatchedApplications"},
		optional: []string{"endpoint", "endpointSource", "error", "applicationsConfigured"},
	}},
	"TraefikLiveMiddleware": {TraefikLiveMiddleware{}, shape{
		fields:   []string{"name", "type", "address", "errors", "viaChain", "viaEntrypoint"},
		optional: []string{"address", "viaChain", "viaEntrypoint"},
	}},
	"TraefikLiveServer": {TraefikLiveServer{}, shape{
		fields:   []string{"url", "status"},
		optional: []string{"status"},
	}},
	"TraefikLiveRouter": {TraefikLiveRouter{}, shape{
		// entryPoints, not entrypoints: the live shape mirrors the proxy's own API
		// spelling while TraefikRoute mirrors the label key. Both are contract.
		fields: []string{"router", "provider", "status", "errors", "rule",
			"hosts", "entryPoints", "middlewares", "service", "servers", "tls", "evidence"},
		optional: []string{"status", "rule", "service"},
	}},
	"UnmatchedRouter": {UnmatchedRouter{}, shape{
		fields: []string{"router", "reason", "detail", "considered"},
	}},
	"TraefikSummary": {TraefikSummary{}, shape{
		fields: []string{"enabled", "configured", "reachable", "endpoint", "endpointSource",
			"credential", "version", "entrypointsRead", "error",
			"routers", "middlewares", "services", "matchedServices", "unmatchedRouters"},
		optional: []string{"endpoint", "endpointSource", "version", "error"},
	}},
	"ConnectionAttempt": {ConnectionAttempt{}, shape{
		fields:   []string{"endpoint", "why", "phase", "code", "detail"},
		optional: []string{"code"},
	}},
	"ConnectionReport": {ConnectionReport{}, shape{
		fields: []string{"target", "ok", "phase", "endpoint", "source", "detail", "code",
			"hint", "read", "attempts"},
		optional: []string{"endpoint", "source", "detail", "code", "hint", "read"},
	}},
	"ProbeRedirect": {ProbeRedirect{}, shape{
		fields: []string{"to", "crossOrigin"},
	}},
	"ProbeState": {ProbeState{}, shape{
		fields:   []string{"asked", "refusedAt", "status", "challenge"},
		optional: []string{"refusedAt", "status", "challenge"},
	}},
	"ProbeAnon": {ProbeAnon{}, shape{
		fields:   []string{"textChars", "links", "loginHref", "loginLabel"},
		optional: []string{"loginHref", "loginLabel"},
	}},
	"LoginFormShape": {LoginFormShape{}, shape{
		fields:   []string{"password", "username", "submit", "otp", "action"},
		optional: []string{"action"},
	}},
	"ServiceProbe": {ServiceProbe{}, shape{
		fields: []string{"endpoint", "vantage", "phase", "status", "gate", "mediaType",
			"redirect", "refresh", "truncated", "form", "state", "anon", "detail", "attempts"},
		optional: []string{"status", "gate", "mediaType", "redirect", "refresh", "truncated",
			"form", "state", "anon"},
	}},
	"DeclaredAuth": {DeclaredAuth{}, shape{
		fields:   []string{"mechanism", "detail"},
		optional: []string{"detail"},
	}},
	"DeclaredLink": {DeclaredLink{}, shape{
		fields: []string{"label", "url"},
	}},
	"DeclaredDependency": {DeclaredDependency{}, shape{
		fields:   []string{"name", "detail"},
		optional: []string{"detail"},
	}},
	"DeclaredServiceDependency": {DeclaredServiceDependency{}, shape{
		fields:   []string{"ref", "detail"},
		optional: []string{"detail"},
	}},
	"Declaration": {Declaration{}, shape{
		fields: []string{"file", "description", "owner", "criticality", "notes", "data",
			"links", "dependencies"},
		optional: []string{"description", "owner", "criticality", "notes", "data"},
	}},
	"AcceptedExposure": {AcceptedExposure{}, shape{
		fields: []string{"reason"},
	}},
	"ServiceDeclaration": {ServiceDeclaration{}, shape{
		// Declaration is embedded, so its keys sit flat and first.
		fields: []string{"file", "description", "owner", "criticality", "notes", "data",
			"links", "dependencies",
			"auth", "dependsOn", "unauthenticatedAccepted", "expectedIngress",
			"drift", "unconfirmed", "authAgreement"},
		optional: []string{"description", "owner", "criticality", "notes", "data",
			"unauthenticatedAccepted", "expectedIngress", "authAgreement"},
	}},
	"GraphNode": {GraphNode{}, shape{
		fields: []string{"id", "label", "kind", "stack", "auth", "ingress", "running",
			"role", "scope", "memberCount", "stackCount"},
		optional: []string{"stack", "auth", "ingress", "running", "role", "scope",
			"memberCount", "stackCount"},
	}},
	"EdgeDeclaredBy": {EdgeDeclaredBy{}, shape{
		fields:   []string{"file", "detail"},
		optional: []string{"detail"},
	}},
	"GraphEdge": {GraphEdge{}, shape{
		fields: []string{"id", "source", "target", "kind", "label", "flow", "flowSource",
			"declaredBy", "via"},
		optional: []string{"label", "flow", "flowSource", "declaredBy", "via"},
	}},
	"Graph": {Graph{}, shape{
		fields: []string{"nodes", "edges"},
	}},
	"AccessMode": {AccessMode{}, shape{
		fields: []string{"enforced", "methods", "notes"},
	}},
	"SessionUser": {SessionUser{}, shape{
		fields: []string{"name", "via"},
	}},
	"SessionInfo": {SessionInfo{}, shape{
		fields:   []string{"enforced", "methods", "notes", "user", "oidcLabel"},
		optional: []string{"user", "oidcLabel"},
	}},
	"Health": {Health{}, shape{
		fields: []string{"ok"},
	}},
}

func TestAppendixAFieldNames(t *testing.T) {
	for name, entry := range appendixA {
		t.Run(name, func(t *testing.T) {
			got, gotOptional := jsonShape(reflect.TypeOf(entry.value))
			if !reflect.DeepEqual(got, entry.shape.fields) {
				t.Errorf("field names differ from Appendix A\n got: %v\nwant: %v", got, entry.shape.fields)
			}
			want := entry.shape.optional
			if want == nil {
				want = []string{}
			}
			if !reflect.DeepEqual(gotOptional, want) {
				t.Errorf("optional fields differ from Appendix A\n got: %v\nwant: %v", gotOptional, want)
			}
		})
	}
}

// TestEveryPayloadTypeIsInTheTable guards the table itself: a new exported struct in this
// package has to be transcribed into Appendix A's shape or the test says so. Without it,
// a type added to the payload would simply never be checked.
func TestEveryPayloadTypeIsInTheTable(t *testing.T) {
	// Every struct reachable from the four wire roots, by construction of the walk below.
	for _, root := range []any{Overview{}, ScanRequest{}, SessionInfo{}, Health{}} {
		for _, name := range reachableStructs(reflect.TypeOf(root)) {
			if _, ok := appendixA[name]; !ok {
				t.Errorf("%s is reachable from the payload but is not in the Appendix A table", name)
			}
		}
	}
}

// jsonShape returns a type's JSON keys in declaration order — which is the order the
// encoder writes them — and the subset that may be absent. Anonymous embedded structs are
// flattened, exactly as encoding/json flattens them.
func jsonShape(t reflect.Type) (fields, optional []string) {
	fields, optional = []string{}, []string{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if f.Anonymous && tag == "" && f.Type.Kind() == reflect.Struct {
			ef, eo := jsonShape(f.Type)
			fields, optional = append(fields, ef...), append(optional, eo...)
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" && opts == "" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		fields = append(fields, name)
		if !required(f) {
			optional = append(optional, name)
		}
	}
	return fields, optional
}

func reachableStructs(t reflect.Type) []string {
	seen := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t.Name()] {
			return
		}
		seen[t.Name()] = true
		for i := 0; i < t.NumField(); i++ {
			walk(t.Field(i).Type)
		}
	}
	walk(t)
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	return names
}

// TestNormalizeFillsRequiredListsOnly is the guarantee that lets every consumer stop
// handling null: after Normalize, a required list is [] and a required map is {}, while
// an optional one is still absent.
func TestNormalizeFillsRequiredListsOnly(t *testing.T) {
	var o Overview
	o.Stacks = []AppStack{{Services: []Service{{}}}}
	o.Meta.Connections = []ConnectionReport{{}}
	Normalize(&o)

	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	if strings.Contains(got, ":null") {
		t.Errorf("a required list or map still serialises as null:\n%s", got)
	}
	for _, want := range []string{
		`"warnings":[]`,         // ScanMeta
		`"byAuthMethod":{}`,     // OverviewStats
		`"declaredNetworks":[]`, // AppStack, reached through a slice
		`"labels":{}`,           // Service, reached two levels down
		`"evidence":[]`,         // AuthPosture, reached through a struct field
		`"attempts":[]`,         // ConnectionReport
		`"nodes":[],"edges":[]`, // Graph
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
	// Service.probe is deliberately not in this list: meta.probe carries the same key and
	// is never optional, so its presence is asserted separately below.
	for _, absent := range []string{"docker", "authentik", "traefikLive", "declared", "via", "hint"} {
		if strings.Contains(got, `"`+absent+`":`) {
			t.Errorf("optional field %q was filled in; absence is the fact (§16):\n%s", absent, got)
		}
	}
	// meta.probe is the one probe key that is never optional (§13.7).
	if !strings.Contains(got, `"probe":{"enabled":false,"source":"","skipped":0}`) {
		t.Errorf("meta.probe must always be written:\n%s", got)
	}
}

// TestNormalizeLeavesOptionalPointersAlone pins the other half: a nil pointer stays nil
// even when the type it points at contains required lists.
func TestNormalizeLeavesOptionalPointersAlone(t *testing.T) {
	s := Service{}
	Normalize(&s)
	if s.Docker != nil || s.Authentik != nil || s.Declared != nil || s.Probe != nil {
		t.Error("Normalize allocated an optional pointer")
	}
	s.Authentik = &AuthentikMatch{}
	Normalize(&s)
	if s.Authentik.Applications == nil || s.Authentik.Evidence == nil || s.Authentik.Strength == nil {
		t.Error("Normalize did not descend into a non-nil optional pointer")
	}
}

func TestAccessModeConsistency(t *testing.T) {
	for _, tc := range []struct {
		mode AccessMode
		want bool
	}{
		{AccessMode{Enforced: false, Methods: nil}, true},
		{AccessMode{Enforced: true, Methods: []LoginMethod{MethodPasswd}}, true},
		{AccessMode{Enforced: true, Methods: nil}, false},
		{AccessMode{Enforced: false, Methods: []LoginMethod{MethodOIDC}}, false},
	} {
		if got := tc.mode.Consistent(); got != tc.want {
			t.Errorf("Consistent(%+v) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}
