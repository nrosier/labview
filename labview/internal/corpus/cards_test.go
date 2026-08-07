package corpus

import (
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/webui"
)

// §23's second UI check, and the second of the three the guide says MUST gate CI: **card destinations.**
// For every counter in `stats`, the card exists, it is a link, and its destination shows exactly the rows
// the number counted.
//
// It runs over every fixture root rather than over one, because a counter that is zero everywhere is a
// counter whose destination was never tested. Seven fleets between them put a non-zero number on nearly
// every card, and the ones that stay zero are named at the end rather than left implied — a check that
// quietly asserted nothing about six cards would be worse than one that says which six.

// fleet is one root's payload, kept with its name so a failure says which fleet disagreed.
type namedFleet struct {
	name string
	out  payload.Overview
}

// everyFleet scans all seven roots, each with whatever transport it needs. The integrations are given
// their ordinary successful mode: this check is about whether a number and a row set agree, and a
// partial read is the subject of the root's own test.
func everyFleet(t *testing.T) []namedFleet {
	t.Helper()

	_, ak := akRun(t, akMode{})
	_, tf := tfRun(t, tfMode{})
	_, pr := probeRun(t)

	return []namedFleet{
		{"apps", scanRoot(t, "apps", scanOptions{})},
		{"edge", scanRoot(t, "edge", scanOptions{})},
		{"nets", scanRoot(t, "nets", scanOptions{})},
		{"auth", scanRoot(t, "auth", scanOptions{})},
		{"authentik", ak},
		{"traefik", tf},
		{"probe", pr},
	}
}

// Every counter has a card. Derived from Appendix A on the left and from the table on the right, so a
// counter added to the payload without a card fails here rather than reaching the overview as a number
// nobody can follow.
func TestEveryCounterInStatsHasACard(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	carded := map[string]string{}
	for _, c := range webui.Cards(out) {
		if c.Path != "" {
			carded[c.Path] = c.ID
		}
	}

	for _, path := range webui.StatsPaths() {
		if carded[path] != "" {
			continue
		}
		// The distribution is carded as segments, one per member, so its own path is covered by the
		// card it expands from rather than by a card of its own.
		if _, ok := carded[path+webui.PathSeparator+string(payload.AuthNone)]; ok {
			continue
		}
		t.Errorf("%q has no card: §22.3 requires every counter in stats to have one, and to be a link", path)
	}
}

// Every card is a link, and a link to one of §22.3's two allowed destinations: a view with a filter
// pre-applied, or a view with a panel that lists the records behind the number. A card that is a bare
// number is a claim a reader cannot check.
func TestEveryCardIsALinkToAViewThatExists(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	for _, c := range webui.Cards(out) {
		slug := c.Dest.ViewSlug()
		if slug == "" {
			t.Errorf("card %s has no destination", c.ID)
			continue
		}
		if _, ok := webui.ViewOf(slug); !ok {
			t.Errorf("card %s links to view %q, which does not exist", c.ID, slug)
		}
		if !strings.HasPrefix(c.Dest.Link(), "?") {
			t.Errorf("card %s renders as %q, which is not a link", c.ID, c.Dest.Link())
		}
		// §22.3 requires the reading, not just the number: what the count includes, what it does not,
		// or what would make an absent one available.
		if strings.TrimSpace(c.Note) == "" {
			t.Errorf("card %s has no note, so its number is offered without a reading", c.ID)
		}
		if strings.TrimSpace(c.Label) == "" {
			t.Errorf("card %s has no label", c.ID)
		}
	}
}

// The check itself: the number and its destination's row count are the same, on every fleet.
//
// This is what makes the overview honest. A card saying *4 exposed without authentication* whose link
// lands on a table of six rows has told the reader two different things, and one of them is wrong.
func TestEachExactCardsDestinationShowsExactlyTheRowsItCounted(t *testing.T) {
	for _, f := range everyFleet(t) {
		for _, c := range webui.Cards(f.out) {
			if !c.Exact {
				continue
			}
			count, reported := c.Count(f.out)
			if !reported {
				t.Errorf("%s: card %s counts an exact row set but reported no number", f.name, c.ID)
				continue
			}
			if rows := len(webui.Rows(c.Dest, f.out)); rows != count {
				t.Errorf("%s: card %s says %d and its destination %s shows %d row%s",
					f.name, c.ID, count, c.Dest.Link(), rows, suffixOf(rows))
			}
		}
	}
}

// The one family that is not exact, and why. The integration summaries count records the *provider*
// holds: `providers`, `outposts` and `middlewares` have no row set in this fleet at all — a middleware
// is not a service — and `applications` counts what the identity provider listed, including
// applications that match nothing here.
//
// Reporting those numbers is right. Claiming a row-for-row correspondence with them would be the
// fiction §22.3 forbids, so each of them still links to the view that shows the records it can show and
// says so in its note. This test pins which cards are allowed the exemption, because the exemption is
// how a card could otherwise stop being checked.
func TestOnlyTheIntegrationSummariesAreExemptFromTheRowCheck(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	var inexact []string
	for _, c := range webui.Cards(out) {
		if !c.Exact {
			inexact = append(inexact, c.ID)
		}
	}

	want := []string{
		"authentikApplications",
		"authentikApplicationsConfigured",
		"authentikApplicationsWithheld",
		"authentikApplicationsRecovered",
		"authentikProviders",
		"authentikOutposts",
		"authentikMatchedServices",
		"traefikRouters",
		"traefikMiddlewares",
		"traefikServicesLive",
		"traefikMatchedServices",
		"build",
	}
	if !equalStrings(inexact, want) {
		t.Errorf("cards exempt from the row check =\n  %s\nwant\n  %s",
			strings.Join(inexact, "\n  "), strings.Join(want, "\n  "))
	}
}

// An optional count that is absent renders *not reported*, never `0` (§22.3, §15). The count returns a
// presence flag for exactly that reason, and the difference is why the field is a pointer in Appendix A:
// an integration count the provider never supplied is not a count of zero.
func TestAnAbsentOptionalCountIsNotReportedRatherThanZero(t *testing.T) {
	// `apps` runs with every integration off, so the optional integration counts have no source.
	out := scanRoot(t, "apps", scanOptions{})

	var optional []string
	for _, c := range webui.Cards(out) {
		if !c.Optional {
			continue
		}
		optional = append(optional, c.ID)
		if n, reported := c.Count(out); reported {
			t.Errorf("card %s reported %d with the integration switched off, and absent is not zero", c.ID, n)
		}
	}
	if len(optional) == 0 {
		t.Fatal("no card is marked Optional, so this rule has nothing to hold it up")
	}
}

// The distribution partitions: every member of the closed set gets a segment, each linking to the
// services with that method, and the segments add up to the counter they came from (§22.1's *never draw
// a partition that does not partition*).
func TestTheAuthMethodDistributionAddsUpAndEachSegmentLinksToItsOwnServices(t *testing.T) {
	for _, f := range everyFleet(t) {
		var total int
		seen := map[string]bool{}
		for _, c := range webui.Cards(f.out) {
			if c.Member == "" {
				continue
			}
			seen[c.Member] = true
			n, reported := c.Count(f.out)
			if !reported {
				t.Errorf("%s: segment %s reported no number, but a member of a partition is always a count",
					f.name, c.ID)
				continue
			}
			total += n
			if rows := len(webui.Rows(c.Dest, f.out)); rows != n {
				t.Errorf("%s: segment %s says %d and its destination shows %d", f.name, c.ID, n, rows)
			}
		}

		for _, m := range payload.AuthMethods {
			if !seen[string(m)] {
				t.Errorf("%s: the distribution has no segment for %q, which reads as a member that cannot occur",
					f.name, m)
			}
		}
		if total != f.out.Stats.Services {
			t.Errorf("%s: the auth-method segments sum to %d and the fleet has %d services",
				f.name, total, f.out.Stats.Services)
		}
	}
}

// A member the payload carries that this build does not know still gets a segment. §16 reads a payload
// from a later version as far as it can rather than filtering it to what this build expected — and a
// distribution that silently dropped a member would report a total that does not add up, which is the
// one thing the test above would then fail to notice.
func TestAnUnknownAuthMethodStillGetsItsOwnSegment(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})
	out.Stats.ByAuthMethod["mtls-from-a-later-version"] = 3

	var found bool
	for _, c := range webui.Cards(out) {
		if c.Member == "mtls-from-a-later-version" {
			found = true
			if n, _ := c.Count(out); n != 3 {
				t.Errorf("the unknown member's segment counts %d, want 3", n)
			}
		}
	}
	if !found {
		t.Error("a method this build does not know was dropped from the distribution")
	}
}

// The two cards that count their own destination's rows instead of naming a path. That is not an
// exception to *the number comes from the payload* — both are lengths of a payload list, one of them
// filtered by §22.8's banner test — and it makes their exactness structural rather than asserted.
func TestTheTwoSelfCountingCardsCountTheirOwnDestination(t *testing.T) {
	// `edge` is the root with warnings and connection reports in it.
	out := scanRoot(t, "edge", scanOptions{})

	for _, id := range []string{"failingConnections", "warnings"} {
		c, ok := webui.CardOf(out, id)
		if !ok {
			t.Fatalf("card %s is gone, and §22.8's banner needs it", id)
		}
		if c.Path != "" {
			t.Errorf("card %s names path %q, so it no longer counts its own destination", id, c.Path)
		}
		if !c.Exact {
			t.Errorf("card %s counts its own destination and so cannot be inexact", id)
		}
		n, reported := c.Count(out)
		if !reported {
			t.Errorf("card %s reported no number", id)
		}
		if rows := len(webui.Rows(c.Dest, out)); rows != n {
			t.Errorf("card %s says %d and its destination shows %d", id, n, rows)
		}
	}
}

// Exactly one card is the lead — §22.3 requires one number visible without scrolling, and it is the
// exposure finding, which is also the one place besides the by-method segment where the alert colour may
// appear (§22.5).
func TestTheLeadCardIsTheExposureFindingAndItAlone(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	var lead []string
	var alert []string
	for _, c := range webui.Cards(out) {
		if c.Lead {
			lead = append(lead, c.ID)
		}
		if c.Tone == webui.ToneAlert {
			alert = append(alert, c.ID)
		}
	}

	if !equalStrings(lead, []string{"exposedWithoutAuth"}) {
		t.Errorf("lead cards = %v, want exactly [exposedWithoutAuth]", lead)
	}
	if !equalStrings(alert, []string{"exposedWithoutAuth"}) {
		t.Errorf("cards in the alert colour = %v, and §22.5 reserves it for reachable without authentication", alert)
	}
}

// Card ids are stable and unique: an id is what a failure names and what the contract keys on, so two
// cards sharing one would make a message ambiguous and a lookup arbitrary.
func TestCardIdsAreUnique(t *testing.T) {
	out := scanRoot(t, "apps", scanOptions{})

	seen := map[string]bool{}
	for _, c := range webui.Cards(out) {
		if seen[c.ID] {
			t.Errorf("two cards share the id %q", c.ID)
		}
		seen[c.ID] = true
	}
}

// Which counters no fixture root exercises, said out loud. A card whose number is zero in all seven
// fleets passes the row check trivially — 0 rows for 0 — so naming them is the difference between a
// check that covers 23 counters and one that covers 23 minus however many nobody noticed.
//
// The assertion is that the list does not grow. A new root, or a fixture that puts a service behind a
// case nothing covered, should shorten it.
func TestTheCountersNoFixtureExercisesAreNamed(t *testing.T) {
	nonZero := map[string]bool{}
	for _, f := range everyFleet(t) {
		for _, c := range webui.Cards(f.out) {
			if c.Member != "" || c.Path == "" {
				continue
			}
			if n, reported := c.Count(f.out); reported && n > 0 {
				nonZero[c.ID] = true
			}
		}
	}

	var never []string
	for _, c := range webui.CardTable {
		if c.Path == "" || c.Segments {
			continue
		}
		if !nonZero[c.ID] {
			never = append(never, c.ID)
		}
	}

	want := untestedCounters
	if !equalStrings(never, want) {
		t.Errorf("counters no root puts a number on =\n  %s\nwant\n  %s\n\n"+
			"A shorter list is an improvement and this literal should be shortened with it. A longer one "+
			"means a fixture stopped covering something.",
			strings.Join(never, "\n  "), strings.Join(want, "\n  "))
	}
}

func suffixOf(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// untestedCounters is the list the test above asserts. Declared separately so the failure message and
// the expectation are the same value.
//
// `running` is the only one, and it is structural rather than an oversight: the corpus runs with Docker
// off (§23), so no container state reaches any of the seven payloads and every service is *not read*
// rather than running or stopped. Its card and its destination are both checked — 0 against 0 — and the
// non-zero case is the pipeline package's, where the Engine is a stub and container state is the point.
//
// It cannot be fixed by a fixture, because a fixture is a compose file and *running* is not a fact a
// compose file can state.
var untestedCounters = []string{"running"}
