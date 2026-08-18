package webui

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// -update regenerates the committed asset instead of asserting against it.
//
// A generated file that no command regenerates gets edited by hand the first time a table changes, so
// the generator is the test: `go test ./internal/webui -run TestContractAsset -update`.
var update = flag.Bool("update", false, "rewrite dist/assets/contract.js from the tables")

// The contract asset is regenerated from the tables and MUST match what is committed.
//
// This is the drift check §16 asks for, applied to the one place the UI's tables are duplicated by
// necessity: a build step. A member added to a vocabulary in Go without regenerating would ship a
// browser that filters by last release's vocabulary, and would fail nothing — so it fails here.
func TestContractAsset(t *testing.T) {
	want, err := ContractJS()
	if err != nil {
		t.Fatalf("generate contract: %v", err)
	}

	path := filepath.Join("dist", ContractAsset)

	if *update {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(want))
		return
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — run: go test ./internal/webui -run TestContractAsset -update", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s is stale: the tables in Go have changed.\n"+
			"The browser reads this file, so a table edited without regenerating ships a UI that\n"+
			"evaluates last build's rules. Regenerate with:\n"+
			"  go test ./internal/webui -run TestContractAsset -update", path)
	}
}

// The contract is byte-identical across builds (I7).
//
// Determinism is what lets the drift check above be a byte comparison. A map serialised anywhere in
// the document would make the asset differ between runs and the check would have to be rewritten as a
// semantic comparison — which is the point at which it stops catching reordering.
func TestContractIsDeterministic(t *testing.T) {
	first, err := ContractJSON()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for i := 0; i < 4; i++ {
		again, err := ContractJSON()
		if err != nil {
			t.Fatalf("encode %d: %v", i, err)
		}
		if string(again) != string(first) {
			t.Fatalf("contract differs between encodings (run %d): a map is being serialised", i)
		}
	}
}

// Every name in the contract's name table has a value, and no name is declared twice.
//
// The bundle refers to these by name and would render `undefined` for a missing one — a chip that
// filters by the string "undefined" matches nothing and looks like a payload with a gap.
func TestContractNamesAreComplete(t *testing.T) {
	seen := map[string]string{}
	for _, n := range names() {
		if n.Name == "" {
			t.Errorf("a name entry has no name (value %q)", n.Value)
			continue
		}
		if n.Value == "" {
			t.Errorf("name %q has no value: the bundle would filter by the empty string", n.Name)
		}
		if prev, dup := seen[n.Name]; dup {
			t.Errorf("name %q declared twice (%q then %q)", n.Name, prev, n.Value)
		}
		seen[n.Name] = n.Value
	}
}

// The contract carries every table the browser needs to build a view.
//
// Stated as a presence check rather than a golden document: the assertion is that no section of the
// contract is empty, because an empty section is a table the browser silently has no rules for.
func TestContractCarriesEveryTable(t *testing.T) {
	c := TheContract()

	if c.Version != ContractVersion {
		t.Errorf("version = %d, want %d", c.Version, ContractVersion)
	}

	empties := []struct {
		what string
		n    int
	}{
		{"grammar.params", len(c.Grammar.Params)},
		{"grammar.navParams", len(c.Grammar.NavParams)},
		{"groups", len(c.Groups)},
		{"views", len(c.Views)},
		{"chrome.fields", len(c.Chrome.Fields)},
		{"dimensions", len(c.Dimensions)},
		{"sets", len(c.Sets)},
		{"rules", len(c.Rules)},
		{"conds", len(c.Conds)},
		{"cards", len(c.Cards)},
		{"drawers", len(c.Draws)},
		{"panels", len(c.Panel)},
		{"diagrams", len(c.Diags)},
		{"names", len(c.Names)},
	}
	for _, e := range empties {
		if e.n == 0 {
			t.Errorf("contract.%s is empty: the browser has no table for it", e.what)
		}
	}

	// The fallback is carried as the template §22.1 describes: the tone, the mark and the sentence,
	// with the spelling filled in from whatever the payload sent. So the label is empty on purpose and
	// what must be present is the non-colour carrier and the reason — a fallback chip with no mark and
	// no note would render as an unexplained blank.
	if !c.Unknown.Unknown || c.Unknown.Mark == "" || c.Unknown.Note == "" {
		t.Errorf("contract.unknown = %+v, want the unknown template with a mark and a note", c.Unknown)
	}
	if c.Unknown.Member != "" || c.Unknown.Label != "" {
		t.Errorf("contract.unknown carries a spelling (%+v): it is a template, and the browser fills "+
			"the member in from the payload", c.Unknown)
	}

	// Every view names its navigation glyph. The bundle draws a fallback for a token it has no shape
	// for, so a missing one is not a broken page — it is a navigation entry that reads differently from
	// the other thirteen, which is the kind of thing nobody notices until the screenshot.
	for _, v := range c.Views {
		if v.Icon == "" {
			t.Errorf("view %q declares no icon: its navigation entry would draw the fallback", v.Slug)
		}
	}

	// Every view's declared dimension must exist, or the browser would render a filter control with no
	// vocabulary and no parameter to write.
	for _, v := range c.Views {
		for _, d := range v.Dims {
			if _, ok := DimensionOf(d); !ok {
				t.Errorf("view %q declares dimension %q, which is not in Dimensions", v.Slug, d)
			}
		}
	}

	// Every card's destination must name a view the contract carries, and every card must have an id
	// and a label — the browser keys the grid off the id.
	slugs := map[string]bool{}
	for _, v := range c.Views {
		slugs[v.Slug] = true
	}
	for _, card := range c.Cards {
		if card.ID == "" || card.Label == "" {
			t.Errorf("card %+v has no id or no label", card)
		}
		if !slugs[card.View] {
			t.Errorf("card %q points at view %q, which is not a view", card.ID, card.View)
		}
	}
}
