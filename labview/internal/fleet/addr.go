package fleet

import (
	"net"
	"strings"
)

// Address is one origin or endpoint address, split into the parts §9 reasons about. It is a
// deliberately small parser rather than net/url: a compose label may hold `10.10.0.5:8096` with
// no scheme at all, which net/url reads as a path.
type Address struct {
	// Raw is the value exactly as the label held it — the evidence (I1).
	Raw    string
	Scheme string
	Host   string
	// Port is the explicit port, or the port the scheme names when there was none. PortFrom
	// says which, so a conclusion can quote the right evidence.
	Port     string
	PortFrom PortSource
	Path     string
}

// PortSource is where a port in an Address came from.
type PortSource uint8

const (
	// PortAbsent: the address named no port and its scheme names no default.
	PortAbsent PortSource = iota
	// PortWritten: the address named the port.
	PortWritten
	// PortScheme: the scheme names it. `https://10.10.0.5` addresses port 443 by the rules of
	// URLs, so reading it is reading the operator's value rather than guessing at one.
	PortScheme
)

// schemePorts are the only defaults applied. http and https are the schemes whose default port
// is fixed and universally understood; a `tcp://` origin with no port names no port, and
// inventing one for it would be a claim rather than a reading.
var schemePorts = map[string]string{"http": "80", "https": "443"}

// ParseAddress splits an address. Everything it cannot understand it leaves empty rather than
// guessing, so a caller sees "no host" instead of a plausible-looking wrong one.
func ParseAddress(raw string) Address {
	a := Address{Raw: raw}
	rest := strings.TrimSpace(raw)

	if i := strings.Index(rest, "://"); i >= 0 {
		a.Scheme = strings.ToLower(rest[:i])
		rest = rest[i+3:]
	}
	// Credentials in an authority are dropped here and never carried further: an address with a
	// password in it must not reach the payload (I6, §20).
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		if slash := strings.IndexAny(rest, "/?#"); slash < 0 || at < slash {
			rest = rest[at+1:]
		}
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		a.Path = rest[i:]
		rest = rest[:i]
	}

	host, port := splitHostPort(rest)
	a.Host = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	switch {
	case port != "":
		a.Port, a.PortFrom = port, PortWritten
	case schemePorts[a.Scheme] != "":
		a.Port, a.PortFrom = schemePorts[a.Scheme], PortScheme
	}
	return a
}

// splitHostPort separates a trailing `:port` without rejecting a bare IPv6 literal, which holds
// colons of its own.
func splitHostPort(authority string) (host, port string) {
	if strings.HasPrefix(authority, "[") {
		if end := strings.Index(authority, "]"); end >= 0 {
			host = authority[:end+1]
			if rest := authority[end+1:]; strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
			return host, port
		}
		return authority, ""
	}
	i := strings.LastIndex(authority, ":")
	if i < 0 || strings.Contains(authority[:i], ":") {
		// No colon, or several — the several case is a bare IPv6 literal, whose colons are
		// part of the address.
		return authority, ""
	}
	return authority[:i], authority[i+1:]
}

// IsIP reports whether the host is an IP literal. §9 turns on this: an IP literal addresses the
// *host*, so its port is a published host port, while a name addresses a container.
func (a Address) IsIP() bool { return a.Host != "" && net.ParseIP(a.Host) != nil }

// IsBareName reports whether the host is a single label — a container DNS name, which is what
// compose publishes for a service's name and its `container_name`.
func (a Address) IsBareName() bool {
	return a.Host != "" && !a.IsIP() && !strings.Contains(a.Host, ".")
}

// IsFQDN reports whether the host is a dotted name. §9 leaves these unresolved: a name with a
// dot in it is resolved by DNS outside this fleet, and the scan cannot see what it points at.
func (a Address) IsFQDN() bool {
	return a.Host != "" && !a.IsIP() && strings.Contains(a.Host, ".")
}
