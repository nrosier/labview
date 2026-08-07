package labels

import (
	"sort"
	"strconv"
	"strings"

	"github.com/nrosier/labview/internal/payload"
)

// flatIndex is the route the unindexed labels declare. It sorts before every indexed one.
const flatIndex = -1

// Cloudflare reads the tunnel routes one service's labels declare (§7).
//
// Both label forms are read. The flat form — `dockflare.hostname` — declares the one route
// almost every deployment writes; the indexed form `dockflare.<n>.<key>` declares several
// on one container, and a top-level `enable` governs all of them unless a route carries its
// own.
//
// A route needs a hostname, because the hostname is what makes a service `public` (§4.1) and
// a tunnel label set without one routes nothing. `enable=false` suppresses the route
// entirely — the staged-but-switched-off route is a common pattern, and reporting it as live
// would invent public exposure on a service that has none. An `enable` value that is neither
// true nor false keeps the route and says so in a note (I4).
//
// Every label of a route is kept in its Raw map, whether this reader understood it or not:
// the raw map is what lets a reader see which label produced which conclusion (§22.2), and
// what keeps `dockflare.http2_origin` answerable without inventing a payload field for it.
func Cloudflare(lbls map[string]string, prefix string) ([]payload.CloudflareRoute, []string) {
	groups := map[int]*cfGroup{}
	var order []int
	for _, key := range sortedKeys(lbls) {
		rest, ok := afterPrefix(key, prefix)
		if !ok {
			continue
		}
		idx, field := cfSplitIndex(rest)
		g := groups[idx]
		if g == nil {
			g = &cfGroup{raw: map[string]string{}, fields: map[string]string{}}
			groups[idx] = g
			order = append(order, idx)
		}
		g.raw[key] = lbls[key]
		if f := cfField(field); f != "" {
			g.fields[f] = lbls[key]
		}
	}
	sort.Ints(order)

	governing, hasGoverning := "", false
	if flat := groups[flatIndex]; flat != nil {
		governing, hasGoverning = flat.fields["enable"]
	}

	var routes []payload.CloudflareRoute
	var notes []string
	for _, idx := range order {
		g := groups[idx]

		enable, has := g.fields["enable"]
		if !has && idx != flatIndex && hasGoverning {
			enable, has = governing, true
		}
		if has && falsy(enable) {
			continue
		}

		hostname := strings.TrimSpace(g.fields["hostname"])
		if hostname == "" {
			// A flat group holding nothing but the flag that governs the indexed routes is
			// not a route missing a hostname; it is the flag.
			if idx == flatIndex && len(g.fields) == 1 && has {
				continue
			}
			notes = append(notes, "Cloudflare tunnel labels "+cfWhere(idx)+
				" declare no hostname, so no route was recorded")
			continue
		}
		if has && !truthy(enable) {
			notes = append(notes, "Cloudflare tunnel label "+cfWhere(idx)+" sets enable to "+
				quote(enable)+", which is neither true nor false; the route for "+hostname+
				" is reported as declared")
		}

		route := payload.CloudflareRoute{
			Hostname: hostname,
			Service:  strings.TrimSpace(g.fields["service"]),
			Path:     strings.TrimSpace(g.fields["path"]),
			Access:   cfAccess(g.fields),
			Raw:      g.raw,
		}
		if v, ok := g.fields["notlsverify"]; ok {
			// A pointer, because a label that said false and no label at all are two
			// different readings of how the origin is contacted.
			route.NoTLSVerify = payload.Ptr(truthy(v))
		}
		routes = append(routes, route)
	}
	return routes, notes
}

// cfGroup is one route's labels: the raw pairs exactly as written, and the fields this
// reader recognised among them.
type cfGroup struct {
	raw    map[string]string
	fields map[string]string
}

// cfSplitIndex separates a route index from the field name after it.
func cfSplitIndex(rest string) (int, string) {
	head, tail, found := strings.Cut(rest, ".")
	if !found || head == "" {
		return flatIndex, rest
	}
	n := 0
	for i := 0; i < len(head); i++ {
		if head[i] < '0' || head[i] > '9' {
			return flatIndex, rest
		}
		n = n*10 + int(head[i]-'0')
		if n > 1<<20 {
			return flatIndex, rest // not an index anybody wrote on purpose
		}
	}
	return n, tail
}

// cfField is the field name this reader knows, or "" for one it does not.
//
// The three flag spellings collapse to one because the tunnel's own configuration key is
// camel-case and operators write it in label case either way; the access keys keep their
// dot, because `access.group` and `access.policy` are two settings and not one.
func cfField(field string) string {
	lower := strings.ToLower(field)
	switch lower {
	case "enable", "hostname", "service", "path",
		"access.group", "access.policy", "access.emails":
		return lower
	}
	if strings.NewReplacer("_", "", "-", "").Replace(lower) == "notlsverify" {
		return "notlsverify"
	}
	return ""
}

// cfAccess is the access policy a route declared, or nothing.
func cfAccess(fields map[string]string) *payload.CloudflareAccess {
	group := strings.TrimSpace(fields["access.group"])
	policy := strings.TrimSpace(fields["access.policy"])
	emails := splitList(fields["access.emails"])
	if group == "" && policy == "" && len(emails) == 0 {
		return nil
	}
	return &payload.CloudflareAccess{Group: group, Policy: policy, Emails: emails}
}

// cfWhere names the route a note is about, for the indexed form only — "on this service" is
// the whole truth when there is one route and would be a half-truth when there are six.
func cfWhere(idx int) string {
	if idx == flatIndex {
		return "on this service"
	}
	return "at index " + strconv.Itoa(idx)
}
