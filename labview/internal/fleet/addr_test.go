package fleet

import "testing"

// TestParseAddress covers the shapes a compose label actually holds. The reason this parser exists
// rather than net/url is the second case: `10.10.0.5:8096` has no scheme, and net/url reads it as a
// path with an opaque scheme.
func TestParseAddress(t *testing.T) {
	for _, tc := range []struct {
		raw                      string
		scheme, host, port, path string
		portFrom                 PortSource
		isIP, isBareName, isFQDN bool
	}{
		{
			raw: "http://emby:8096", scheme: "http", host: "emby", port: "8096",
			portFrom: PortWritten, isBareName: true,
		},
		{
			// Scheme-less host:port, the shape that motivates this parser.
			raw: "10.10.0.5:8096", host: "10.10.0.5", port: "8096",
			portFrom: PortWritten, isIP: true,
		},
		{
			// The port the scheme names. Reading it is reading the operator's value; PortScheme is
			// what lets the evidence say so rather than claiming the label held 443.
			raw: "https://10.10.0.5", scheme: "https", host: "10.10.0.5", port: "443",
			portFrom: PortScheme, isIP: true,
		},
		{
			raw: "http://gateway", scheme: "http", host: "gateway", port: "80",
			portFrom: PortScheme, isBareName: true,
		},
		{
			// No default is invented for a scheme whose default port is not fixed.
			raw: "tcp://backend", scheme: "tcp", host: "backend", portFrom: PortAbsent,
			isBareName: true,
		},
		{
			raw: "https://app.example.com/health", scheme: "https", host: "app.example.com",
			port: "443", portFrom: PortScheme, path: "/health", isFQDN: true,
		},
		{
			// Case is folded on the host so that a lookup finds it however the label spelled it.
			raw: "http://Emby.Local:8096", scheme: "http", host: "emby.local", port: "8096",
			portFrom: PortWritten, isFQDN: true,
		},
		{
			// A bracketed IPv6 literal: brackets are stripped from the host and the trailing port
			// is still separated.
			raw: "http://[fd00::1]:8080", scheme: "http", host: "fd00::1", port: "8080",
			portFrom: PortWritten, isIP: true,
		},
		{
			// A bare IPv6 literal, whose colons are part of the address rather than a port.
			raw: "fd00::1", host: "fd00::1", portFrom: PortAbsent, isIP: true,
		},
		{
			// Credentials never travel further than this parser (I6, §20).
			raw: "https://admin:hunter2@internal.example.com/api", scheme: "https",
			host: "internal.example.com", port: "443", portFrom: PortScheme, path: "/api",
			isFQDN: true,
		},
		{
			// An `@` after the authority is part of a path and does not truncate the host.
			raw: "http://gateway/x@y", scheme: "http", host: "gateway", port: "80",
			portFrom: PortScheme, path: "/x@y", isBareName: true,
		},
		{
			raw: "http://gateway:8080/api?x=1#top", scheme: "http", host: "gateway", port: "8080",
			portFrom: PortWritten, path: "/api?x=1#top", isBareName: true,
		},
		{
			// Nothing understood stays empty rather than becoming a plausible-looking wrong host,
			// which is what lets a conclusion say "the origin address names no host".
			raw: "   ", portFrom: PortAbsent,
		},
		{raw: "", portFrom: PortAbsent},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			a := ParseAddress(tc.raw)
			if a.Raw != tc.raw {
				t.Errorf("Raw = %q, want %q — the raw value is the evidence", a.Raw, tc.raw)
			}
			if a.Scheme != tc.scheme {
				t.Errorf("Scheme = %q, want %q", a.Scheme, tc.scheme)
			}
			if a.Host != tc.host {
				t.Errorf("Host = %q, want %q", a.Host, tc.host)
			}
			if a.Port != tc.port {
				t.Errorf("Port = %q, want %q", a.Port, tc.port)
			}
			if a.PortFrom != tc.portFrom {
				t.Errorf("PortFrom = %d, want %d", a.PortFrom, tc.portFrom)
			}
			if a.Path != tc.path {
				t.Errorf("Path = %q, want %q", a.Path, tc.path)
			}
			if a.IsIP() != tc.isIP {
				t.Errorf("IsIP = %v, want %v", a.IsIP(), tc.isIP)
			}
			if a.IsBareName() != tc.isBareName {
				t.Errorf("IsBareName = %v, want %v", a.IsBareName(), tc.isBareName)
			}
			if a.IsFQDN() != tc.isFQDN {
				t.Errorf("IsFQDN = %v, want %v", a.IsFQDN(), tc.isFQDN)
			}
		})
	}
}

// TestAddressKindsPartition is the property §9's table rests on: every host is an IP literal, a
// single label, or a dotted name, and never two of them. The three cases of the table are chosen by
// exactly these predicates, so an overlap would make the table's order significant where it is not.
func TestAddressKindsPartition(t *testing.T) {
	for _, raw := range []string{
		"10.10.0.5", "fd00::1", "emby", "app.example.com", "http://gateway:80", "",
	} {
		a := ParseAddress(raw)
		n := 0
		for _, is := range []bool{a.IsIP(), a.IsBareName(), a.IsFQDN()} {
			if is {
				n++
			}
		}
		want := 1
		if a.Host == "" {
			want = 0
		}
		if n != want {
			t.Errorf("%q matched %d of the three host kinds, want %d", raw, n, want)
		}
	}
}

// TestCredentialsNeverSurviveParsing is I6 as a property rather than as a case: no part of a parsed
// address may carry a password, whatever the authority looked like.
func TestCredentialsNeverSurviveParsing(t *testing.T) {
	for _, raw := range []string{
		"https://admin:hunter2@host.example.com/api",
		"http://user@gateway:8080",
		"http://user:pass@10.10.0.5:9000/path",
	} {
		a := ParseAddress(raw)
		for name, field := range map[string]string{
			"Scheme": a.Scheme, "Host": a.Host, "Port": a.Port, "Path": a.Path,
		} {
			for _, secret := range []string{"hunter2", "pass", "user", "admin"} {
				if field == secret {
					t.Errorf("%q: %s = %q, which is a credential", raw, name, field)
				}
			}
		}
	}
}
