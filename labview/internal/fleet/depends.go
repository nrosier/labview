package fleet

import "github.com/nrosier/labview/internal/payload"

// Dependency is the **resolved** half of one dependency: source, target, file, detail and the
// real networks the pair shares (§8). The other half — the reference exactly as the sidecar typed
// it, plus its optional detail — stays on the service's declaration, because the parser cannot see
// other stacks and because that as-written object is what a rescan compares (§17).
//
// Observed and Declared are separate booleans rather than one provenance enum because a pair can
// be both: compose orders their startup and a sidecar adds a detail about why. That case is one
// edge, and it is an observed one — a renderer must not dash it (§14).
type Dependency struct {
	From string
	To   string
	// Via is the real networks the pair shares, in the dependent's compose order. Non-empty is
	// normal and means the direct edge is not drawn, because `flow` on the two membership edges
	// already shows it. Empty means neither container can address the other, which is itself the
	// finding.
	Via []string

	Observed bool
	Declared bool
	// File and Detail are the sidecar's, when a sidecar declared this dependency.
	File   string
	Detail string
}

// DeclaredOnly reports whether the only account of this dependency is a declaration. It is the
// one test a renderer needs: a declared-only edge carries `declaredBy` and renders dashed, and an
// edge compose also states does not (§8).
func (d Dependency) DeclaredOnly() bool { return d.Declared && !d.Observed }

// Refusal is a declared reference that did not resolve to exactly one service. It draws nothing —
// guessing would put a line in a picture whose whole point is that a line means something — and
// it becomes a drift entry in §14's one walk.
type Refusal struct {
	From string
	Ref  string
	File string
	// Reason is the sentence a drift entry is written from.
	Reason string
	// Considered is what was weighed, so an ambiguous reference is answerable rather than merely
	// reported.
	Considered []string
}

// Deps is the fleet's dependency relation: what resolved, and what a declaration asked for and
// could not have.
type Deps struct {
	Resolved []Dependency
	Refused  []Refusal
}

// Dependencies resolves compose `depends_on` and declared `depends_on` across the whole fleet, in
// scan order, and writes the notes §8 requires where a pair shares no network.
//
// The two sources are resolved in one walk so that the merge rule of §14 — a pair the compose
// files already resolved is one edge, silently — cannot be missed by resolving them separately
// and unioning afterwards.
func Dependencies(ix *Index, nets *Networks) Deps {
	var out Deps
	// at indexes Resolved by from→to so a declaration naming a pair compose already stated
	// lands on the existing edge instead of adding a second one.
	at := map[string]int{}

	add := func(d Dependency) {
		d.Via = nets.Shared(d.From, d.To)
		pair := d.From + "→" + d.To
		if i, ok := at[pair]; ok {
			existing := &out.Resolved[i]
			existing.Observed = existing.Observed || d.Observed
			existing.Declared = existing.Declared || d.Declared
			// The declaration only adds a detail; the compose reading of the pair stands.
			if existing.Detail == "" {
				existing.Detail, existing.File = d.Detail, d.File
			}
			return
		}
		at[pair] = len(out.Resolved)
		out.Resolved = append(out.Resolved, d)
	}

	for _, key := range ix.Keys() {
		stackID, _ := SplitKey(key)
		svc := ix.Service(key)

		// Compose `depends_on` names a service in the same project and nothing further, which
		// is why a bare declared reference beside a service of that name means the sibling.
		for _, name := range svc.DependsOn {
			target, ok := ix.InStack(stackID, name)
			if !ok {
				svc.Notes = append(svc.Notes, "`depends_on` names `"+name+
					"`, which is not a service in this stack")
				continue
			}
			if target == key {
				continue
			}
			add(Dependency{From: key, To: target, Observed: true})
		}

		if svc.Declared == nil {
			continue
		}
		for _, ref := range svc.Declared.DependsOn {
			target, refusal := resolveRef(ix, key, stackID, ref, svc.Declared.File)
			if refusal != nil {
				out.Refused = append(out.Refused, *refusal)
				continue
			}
			add(Dependency{
				From: key, To: target, Declared: true,
				File: svc.Declared.File, Detail: ref.Detail,
			})
		}
	}

	noteUnreachablePairs(ix, out.Resolved)
	return out
}

// resolveRef is the resolution table of §14, in the order it states it. Resolution prefers the
// declaring stack's own service for a bare name, then the fleet.
func resolveRef(ix *Index, from, stackID string, ref payload.DeclaredServiceDependency, file string) (string, *Refusal) {
	refuse := func(reason string, considered ...string) (string, *Refusal) {
		return "", &Refusal{From: from, Ref: ref.Ref, File: file, Reason: reason, Considered: considered}
	}

	// A qualified reference names one service or none; there is nothing to prefer and nothing to
	// be ambiguous about, which is why it is the form that is never ambiguous.
	if stack, name, qualified := cutRef(ref.Ref); qualified {
		key := Key(stack, name)
		switch {
		case key == from:
			return refuse("names this very service; a dependency on itself is not a relation")
		case !ix.Has(key):
			return refuse("names no scanned service")
		default:
			return key, nil
		}
	}

	// A local service and others, written bare: the local one wins, silently.
	if key, ok := ix.InStack(stackID, ref.Ref); ok {
		if key == from {
			return refuse("names this very service; a dependency on itself is not a relation")
		}
		return key, nil
	}

	var candidates []string
	for _, key := range ix.Keys() {
		if _, name := SplitKey(key); name == ref.Ref && key != from {
			candidates = append(candidates, key)
		}
	}
	switch len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		return refuse("names no scanned service")
	default:
		return refuse("names "+itoa(len(candidates))+
			" services and no service of that name in this stack, so the reference has to be "+
			"written as `stack/service`", candidates...)
	}
}

// cutRef splits a qualified `stack/service` reference. A reference with no slash is bare, and one
// with an empty half is neither — the sidecar parser has already refused those (§6.1).
func cutRef(ref string) (stack, name string, qualified bool) {
	for i := 0; i < len(ref); i++ {
		if ref[i] == '/' {
			return ref[:i], ref[i+1:], ref[:i] != "" && ref[i+1:] != ""
		}
	}
	return "", ref, false
}

// noteUnreachablePairs states in words the finding an empty `via` is (§8): compose orders the two
// containers' startup, or an operator declared a relation, yet neither container can address the
// other. The direct edge is the only honest drawing of it, and a line on a diagram does not say
// why it is there.
func noteUnreachablePairs(ix *Index, deps []Dependency) {
	for _, d := range deps {
		if len(d.Via) > 0 {
			continue
		}
		svc := ix.Service(d.From)
		if svc == nil {
			continue
		}
		svc.Notes = append(svc.Notes, "depends on `"+d.To+
			"`, and the two share no network: whatever they do together, they do it over "+
			"something this scan cannot see")
	}
}

// itoa keeps this package free of strconv for the one number it formats into prose.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
