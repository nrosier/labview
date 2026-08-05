package fleet

import (
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// TestIngressSetWithholdsInternal is the one rule that makes the set worth reading: a set carrying
// an external kind does not also say `internal` (§8).
//
// Without it nearly every service in a fleet would carry `internal`, and the set would restate that
// a container listens on a network instead of answering *is a neighbour the only way in*.
func TestIngressSetWithholdsInternal(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []payload.IngressKind
		want []payload.IngressKind
	}{
		{
			name: "internal alone survives",
			in:   []payload.IngressKind{payload.IngressInternal},
			want: []payload.IngressKind{payload.IngressInternal},
		},
		{
			name: "public withholds internal",
			in:   []payload.IngressKind{payload.IngressInternal, payload.IngressPublic},
			want: []payload.IngressKind{payload.IngressPublic},
		},
		{
			name: "traefik withholds internal",
			in:   []payload.IngressKind{payload.IngressInternal, payload.IngressTraefik},
			want: []payload.IngressKind{payload.IngressTraefik},
		},
		{
			// `lan` is external in this vocabulary, so it withholds too — the same reading that
			// makes a LAN-published service count as reachable in the exposure verdict (§4.1).
			name: "lan withholds internal",
			in:   []payload.IngressKind{payload.IngressInternal, payload.IngressLan},
			want: []payload.IngressKind{payload.IngressLan},
		},
		{
			name: "canonical order, most exposed first",
			in: []payload.IngressKind{
				payload.IngressLan, payload.IngressTraefik, payload.IngressPublic,
			},
			want: []payload.IngressKind{
				payload.IngressPublic, payload.IngressTraefik, payload.IngressLan,
			},
		},
		{
			name: "repeats collapse",
			in: []payload.IngressKind{
				payload.IngressLan, payload.IngressLan, payload.IngressLan,
			},
			want: []payload.IngressKind{payload.IngressLan},
		},
		{
			// Never empty. Nothing detected is itself an answer, and an empty array would read as
			// "not yet determined".
			name: "nothing detected is none",
			in:   nil,
			want: []payload.IngressKind{payload.IngressNone},
		},
		{
			// `none` is the answer only when there is nothing else to say, however it arrived.
			name: "none never sits beside another kind",
			in:   []payload.IngressKind{payload.IngressNone, payload.IngressInternal},
			want: []payload.IngressKind{payload.IngressInternal},
		},
		{
			name: "empty kinds are dropped",
			in:   []payload.IngressKind{"", payload.IngressLan, ""},
			want: []payload.IngressKind{payload.IngressLan},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IngressSet(tc.in...); !equalKinds(got, tc.want) {
				t.Errorf("IngressSet(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestRollupDoesNotWithhold is the one place withholding MUST NOT apply (§8). A stack with one
// published service and one internal-only service is both things at once, and a roll-up that
// dropped `internal` would say the stack has no internal-only service in it.
func TestRollupDoesNotWithhold(t *testing.T) {
	got := Rollup(
		[]payload.IngressKind{payload.IngressPublic},
		[]payload.IngressKind{payload.IngressInternal},
	)
	want := []payload.IngressKind{payload.IngressPublic, payload.IngressInternal}
	if !equalKinds(got, want) {
		t.Errorf("Rollup = %v, want %v", got, want)
	}

	// A stack whose every service is internal-only is internal, not none.
	got = Rollup([]payload.IngressKind{payload.IngressInternal}, []payload.IngressKind{payload.IngressNone})
	if !equalKinds(got, []payload.IngressKind{payload.IngressInternal}) {
		t.Errorf("Rollup with a none member = %v, want [internal]", got)
	}

	// A stack whose every service reaches nothing is none.
	got = Rollup([]payload.IngressKind{payload.IngressNone}, []payload.IngressKind{payload.IngressNone})
	if !equalKinds(got, []payload.IngressKind{payload.IngressNone}) {
		t.Errorf("Rollup of two none sets = %v, want [none]", got)
	}
}

// TestStackRollupOverTheCorpus is the same rule read off a real stack: `lonely` has a service on an
// external network and one alone on its own, so the stack is internal — and `disjoint`, whose two
// services are each alone on their own network, reaches nothing at all.
func TestStackRollupOverTheCorpus(t *testing.T) {
	a := analyze(t, "nets")

	for _, tc := range []struct {
		stack string
		want  []payload.IngressKind
	}{
		// Neither service has a scanned neighbour and neither publishes a port.
		{"lonely", []payload.IngressKind{payload.IngressNone}},
		{"disjoint", []payload.IngressKind{payload.IngressNone}},
		// Two services on one stack-local network: each is a neighbour of the other.
		{"badref", []payload.IngressKind{payload.IngressInternal}},
		{"layered", []payload.IngressKind{payload.IngressInternal}},
	} {
		var stack payload.AppStack
		for _, s := range a.Stacks {
			if s.ID == tc.stack {
				stack = s
			}
		}
		if stack.ID == "" {
			t.Errorf("no stack %q", tc.stack)
			continue
		}
		if got := StackIngress(stack); !equalKinds(got, tc.want) {
			t.Errorf("%s rollup = %v, want %v", tc.stack, got, tc.want)
		}
	}
}

// TestServiceIngressReadsPresenceNotPorts pins the signal §4.1 names: the presence of a `ports:` or
// `expose:` entry, never a parsed port number. A service publishing a port nobody could route to is
// still publishing a port.
func TestServiceIngressReadsPresenceNotPorts(t *testing.T) {
	nets := NewNetworks(nil)

	for _, tc := range []struct {
		name string
		svc  payload.Service
		want []payload.IngressKind
	}{
		{
			name: "ports is lan whatever the numbers say",
			svc:  payload.Service{Ports: []payload.PortMapping{{Published: "", Target: ""}}},
			want: []payload.IngressKind{payload.IngressLan},
		},
		{
			// `expose:` publishes nothing to the host; it says the container answers on the
			// container network, which is exactly `internal`.
			name: "expose is internal",
			svc:  payload.Service{Expose: []string{"8080"}},
			want: []payload.IngressKind{payload.IngressInternal},
		},
		{
			name: "a tunnel route with a hostname is public",
			svc:  payload.Service{Cloudflare: []payload.CloudflareRoute{{Hostname: "app.example.com"}}},
			want: []payload.IngressKind{payload.IngressPublic},
		},
		{
			// A route object with no hostname claims no reachability, so it contributes nothing.
			name: "a tunnel route without a hostname is not public",
			svc:  payload.Service{Cloudflare: []payload.CloudflareRoute{{Service: "http://x:80"}}},
			want: []payload.IngressKind{payload.IngressNone},
		},
		{
			name: "a traefik router with hosts is traefik",
			svc:  payload.Service{Traefik: []payload.TraefikRoute{{Hosts: []string{"app.lan"}}}},
			want: []payload.IngressKind{payload.IngressTraefik},
		},
		{
			// A rule with no extractable host is still a router that answers for something.
			name: "a traefik router with only a rule is traefik",
			svc:  payload.Service{Traefik: []payload.TraefikRoute{{Rule: "PathPrefix(`/api`)"}}},
			want: []payload.IngressKind{payload.IngressTraefik},
		},
		{
			name: "expose beside ports withholds internal",
			svc: payload.Service{
				Expose: []string{"8080"},
				Ports:  []payload.PortMapping{{Published: "8080"}},
			},
			want: []payload.IngressKind{payload.IngressLan},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ServiceIngress(tc.svc, nets, "stack/svc")
			if !equalKinds(got, tc.want) {
				t.Errorf("ingress = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWinnerAndExternal covers the two readings a set is reduced to, each of which exists for
// exactly one caller: one fill colour on a graph node, and the reachability test the exposure
// verdict turns on.
func TestWinnerAndExternal(t *testing.T) {
	for _, tc := range []struct {
		set      []payload.IngressKind
		winner   payload.IngressKind
		external bool
	}{
		{IngressSet(payload.IngressPublic, payload.IngressLan), payload.IngressPublic, true},
		{IngressSet(payload.IngressTraefik, payload.IngressLan), payload.IngressTraefik, true},
		{IngressSet(payload.IngressLan), payload.IngressLan, true},
		{IngressSet(payload.IngressInternal), payload.IngressInternal, false},
		{IngressSet(), payload.IngressNone, false},
	} {
		if got := Winner(tc.set); got != tc.winner {
			t.Errorf("Winner(%v) = %q, want %q", tc.set, got, tc.winner)
		}
		if got := External(tc.set); got != tc.external {
			t.Errorf("External(%v) = %v, want %v", tc.set, got, tc.external)
		}
	}
}

// TestMissingAndUnexpectedRunsBothWays is drift check 4 (§14). Reporting only what is missing would
// hide a service that picked up an exposure nobody expected, which is the more interesting half.
func TestMissingAndUnexpectedRunsBothWays(t *testing.T) {
	for _, tc := range []struct {
		name                string
		expected, detected  []payload.IngressKind
		missing, unexpected []payload.IngressKind
	}{
		{
			name:     "agreement in both directions",
			expected: []payload.IngressKind{payload.IngressTraefik},
			detected: []payload.IngressKind{payload.IngressTraefik},
		},
		{
			name:     "an expectation that did not happen",
			expected: []payload.IngressKind{payload.IngressTraefik, payload.IngressLan},
			detected: []payload.IngressKind{payload.IngressTraefik},
			missing:  []payload.IngressKind{payload.IngressLan},
		},
		{
			name:       "an exposure nobody expected",
			expected:   []payload.IngressKind{payload.IngressInternal},
			detected:   []payload.IngressKind{payload.IngressPublic},
			missing:    []payload.IngressKind{payload.IngressInternal},
			unexpected: []payload.IngressKind{payload.IngressPublic},
		},
		{
			name:       "both directions at once, in canonical order",
			expected:   []payload.IngressKind{payload.IngressLan},
			detected:   []payload.IngressKind{payload.IngressPublic, payload.IngressTraefik},
			missing:    []payload.IngressKind{payload.IngressLan},
			unexpected: []payload.IngressKind{payload.IngressPublic, payload.IngressTraefik},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			missing, unexpected := MissingAndUnexpected(tc.expected, tc.detected)
			if !equalKinds(missing, tc.missing) {
				t.Errorf("missing = %v, want %v", missing, tc.missing)
			}
			if !equalKinds(unexpected, tc.unexpected) {
				t.Errorf("unexpected = %v, want %v", unexpected, tc.unexpected)
			}
		})
	}
}
