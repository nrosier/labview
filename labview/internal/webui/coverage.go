package webui

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/nrosier/labview/internal/payload"
)

// §22.1's first rule, and §23's first check: **payload-complete.** Every field in Appendix A MUST be
// reachable in the UI, and adding a payload field without giving it a place to appear MUST fail.
//
// The check is a comparison of two lists that are each derived rather than written:
//
//   - PayloadPaths walks payload.Overview by reflection and returns one dotted path per leaf, using
//     the JSON tags — the same spelling a reader with the JSON in hand would use.
//   - RenderedPaths collects the Fields declared by every view column (§22.2) and every drawer
//     section (§22.4), **excluding the Raw section**, which §22.4 forbids as a way to satisfy this
//     rule: a subtree dump makes every field technically visible and none of them findable.
//
// Neither list is a hand-maintained inventory of the payload, because an inventory is what the check
// exists to make unnecessary. The failure is stated as a path so the fix is obvious: give the field a
// column or a drawer section, or state why it does not need one.
//
// Paths are **leaves only** and slices, maps and pointers are transparent: `stacks.services.auth.method`
// is one path however many stacks or services there are. A declared path that names a subtree rather
// than a leaf is reported as an error rather than accepted, since accepting it would let one
// declaration wave through every field beneath it — the Raw escape hatch by another name.

// PathSeparator joins one path's segments. A dot, because that is how the field is spelled in a
// reader's notes and in `jq`.
const PathSeparator = "."

// PayloadPaths is every leaf of Appendix A, sorted.
func PayloadPaths() []string {
	seen := map[string]bool{}
	walkType(reflect.TypeOf(payload.Overview{}), "", map[reflect.Type]bool{}, func(path string) {
		seen[path] = true
	})
	return sortedKeys(seen)
}

// walkType emits one path per leaf below t.
//
// visiting is the set of struct types on the current path, so a payload that ever gained a recursive
// shape (a graph node holding nodes) walks it once instead of forever. It is a map on the path rather
// than a global set because the same type legitimately appears in two places — a ConnectionReport
// hangs off several parents, and each of them needs its own paths.
func walkType(t reflect.Type, prefix string, visiting map[reflect.Type]bool, emit func(string)) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		// Transparent: a list of services is the same field as a service.
		t = t.Elem()
	}

	switch {
	case t == reflect.TypeOf(time.Time{}):
		// A timestamp is a value, not a struct with a wall clock and a monotonic reading.
		emit(prefix)
		return
	case t == reflect.TypeOf(json.RawMessage{}):
		// Operator-supplied data (§14) whose shape this program does not define. One leaf.
		emit(prefix)
		return
	}

	if t.Kind() == reflect.Map {
		// A map's keys are members of a closed set, not fields — `stats.byAuthMethod` is one place in
		// the UI showing every member, so the map is the leaf. Its values are descended into only
		// when they are structs, because a distribution of counters is a leaf and a map of records is
		// not.
		v := t.Elem()
		for v.Kind() == reflect.Pointer || v.Kind() == reflect.Slice {
			v = v.Elem()
		}
		if v.Kind() == reflect.Struct && v != reflect.TypeOf(time.Time{}) {
			walkType(t.Elem(), prefix, visiting, emit)
			return
		}
		emit(prefix)
		return
	}

	if t.Kind() != reflect.Struct || visiting[t] {
		emit(prefix)
		return
	}

	fields := jsonFields(t)
	if len(fields) == 0 {
		// A struct with nothing serialised is a leaf as far as a reader of the JSON is concerned.
		emit(prefix)
		return
	}

	visiting[t] = true
	defer delete(visiting, t)

	for _, f := range fields {
		child := f.name
		if prefix != "" {
			child = prefix + PathSeparator + f.name
		}
		if f.inline {
			// An embedded struct with no JSON name flattens into its parent (ServiceDeclaration
			// embeds Declaration), so its fields are the parent's fields and the path must not gain a
			// segment the JSON does not have.
			child = prefix
		}
		walkType(f.typ, child, visiting, emit)
	}
}

type jsonField struct {
	name   string
	typ    reflect.Type
	inline bool
}

// jsonFields is t's serialised fields in declaration order.
func jsonFields(t reflect.Type) []jsonField {
	out := make([]jsonField, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			out = append(out, jsonField{typ: f.Type, inline: true})
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, jsonField{name: name, typ: f.Type})
	}
	return out
}

// ---------------------------------------------------------------------------
// The other half: where each field appears
// ---------------------------------------------------------------------------

// Place is one declared render place: which view, card or drawer section shows a field.
type Place struct {
	// View is the view slug, or "" when the place is a drawer section.
	View string
	// Section is the drawer section id, or "" when the place is a view column.
	Section string
	// Column is the column key, or "" when the place is a whole section.
	Column string
	// Card is the overview card id, or "" when the place is not a card.
	Card string
}

// String names the place for a failure message: `services/auth`, `drawer:verdict` or `card:stacks`.
func (p Place) String() string {
	switch {
	case p.Section != "":
		return "drawer:" + p.Section
	case p.Card != "":
		return "card:" + p.Card
	case p.Column != "":
		return p.View + "/" + p.Column
	default:
		return p.View
	}
}

// RenderedPaths maps every declared field to the places that show it.
//
// A field with more than one place is normal and good — the auth method belongs in the Services table
// and in the drawer's verdict — so this returns places per path rather than a set of paths, which is
// also what lets a failure say *nothing shows this* and a reader find where it should have been.
func RenderedPaths() map[string][]Place {
	out := map[string][]Place{}
	add := func(path string, p Place) {
		out[path] = append(out[path], p)
	}

	for _, v := range Views {
		for _, c := range v.Columns {
			for _, f := range c.Fields {
				add(f, Place{View: v.Slug, Column: c.Key})
			}
		}
		for _, f := range v.Fields {
			add(f, Place{View: v.Slug})
		}
	}

	for _, f := range Chrome.Fields {
		add(f, Place{View: "chrome"})
	}

	// A counter's place in the UI is its overview card (§22.3), so the card table is read here too.
	// Without it every counter in `stats` would report as uncovered while being perfectly visible — and
	// a card is a stronger place than a column, not a weaker one: it is labelled, it is a link, and
	// §23's second check asserts its destination shows exactly the rows it counted.
	//
	// The cards with no path are the two that count their destination's rows and the build stamp; they
	// name no payload leaf, so there is nothing for them to cover.
	for _, c := range CardTable {
		if c.Path == "" {
			continue
		}
		add(c.Path, Place{View: SlugOverview, Card: c.ID})
	}

	for _, d := range Drawers {
		for _, s := range d.Sections {
			if s.Raw {
				// §22.4: the Raw section "MUST NOT be how a field satisfies the §22.1 coverage rule".
				// Skipped here rather than trusted not to declare anything, so the exclusion is a
				// property of the check instead of a convention.
				continue
			}
			for _, f := range s.Fields {
				add(f, Place{Section: d.Kind + ":" + s.ID})
			}
		}
	}
	return out
}

// Uncovered is every payload leaf with no place to appear: §23's check 1, as the list to fix.
func Uncovered() []string {
	rendered := RenderedPaths()
	var out []string
	for _, path := range PayloadPaths() {
		if len(rendered[path]) == 0 {
			out = append(out, path)
		}
	}
	return out
}

// Unknown is every declared field that is not a payload leaf, with where it was declared.
//
// This is the other direction of the same check and it is not redundant. A misspelled path leaves the
// real field uncovered, which Uncovered catches — but it catches it as *a field nobody shows*, which
// sends a reader looking for a missing column that is already written. Reporting the typo says what
// actually happened. It also catches a declaration that names a subtree, which would otherwise pass
// silently and cover nothing.
func Unknown() map[string][]Place {
	leaves := map[string]bool{}
	for _, p := range PayloadPaths() {
		leaves[p] = true
	}

	out := map[string][]Place{}
	for path, places := range RenderedPaths() {
		if !leaves[path] {
			out[path] = places
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
