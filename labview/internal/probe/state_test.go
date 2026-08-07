package probe

import (
	"context"
	"testing"
)

// recorder answers the state walk from a table and records the order it was asked in.
type recorder struct {
	answers map[string]StateAnswer
	asked   []string
}

func (r *recorder) ask(_ context.Context, address string) (StateAnswer, bool) {
	r.asked = append(r.asked, address)
	got, ok := r.answers[address]
	return got, ok
}

func TestTheFourAddressesAreAConstantListAgainstTheOriginThatAnswered(t *testing.T) {
	// **Nothing is parsed out of the page.** Reading the bundle's own fetch calls would mean executing
	// somebody else's JavaScript to find out where to send a request.
	got := StateAddresses("https://app.example.com/app/?next=1")

	want := []string{
		"https://app.example.com/api/",
		"https://app.example.com/api/me",
		"https://app.example.com/api/v1/me",
		"https://app.example.com/api/v1/user",
	}
	if !equal(got, want) {
		t.Fatalf("the origin, not the path, and the constant list in order\n got %v\nwant %v", got, want)
	}
}

func TestTheWalkIsSequentialAndStopsOnTheFirstRefusal(t *testing.T) {
	r := &recorder{answers: map[string]StateAnswer{
		"https://app.example.com/api/":      {Status: 200},
		"https://app.example.com/api/me":    {Status: 401, Challenge: true},
		"https://app.example.com/api/v1/me": {Status: 401, Challenge: true},
	}}

	got := AskState(context.Background(), base, r.ask)

	if got.Asked != 2 {
		t.Fatalf("the walk stops on the first refusal, so two were asked; got %d", got.Asked)
	}
	if len(r.asked) != 2 || r.asked[0] != "https://app.example.com/api/" {
		t.Fatalf("and it is sequential in the list's own order; got %v", r.asked)
	}
	if got.RefusedAt != "https://app.example.com/api/me" {
		t.Fatalf("the refusing address is recorded; got %q", got.RefusedAt)
	}
	if StateGate(got) == "" {
		t.Fatal("a refusal that named a scheme is a gate one address over")
	}
}

func TestABareRefusalIsRecordedAndIsNotAGate(t *testing.T) {
	// An anonymous-enabled Grafana and a world-readable Gitea both answer a bare 401 while serving
	// everybody, so reading it as a gate would take genuinely open applications out of the exposed count.
	r := &recorder{answers: map[string]StateAnswer{
		"https://app.example.com/api/": {Status: 401},
	}}

	got := AskState(context.Background(), base, r.ask)

	if StateGate(got) != "" {
		t.Fatal("a bare 401 is not a gate")
	}
	if !BareRefusal(got) {
		t.Fatal("it is still recorded, and named as a place to look")
	}
	if got.Status == nil || *got.Status != 401 {
		t.Fatalf("with its status; got %+v", got.Status)
	}
}

func TestA403IsNotARefusalHere(t *testing.T) {
	// nginx 403s a directory with no index, so a static site with no API at all answers that way.
	r := &recorder{answers: map[string]StateAnswer{
		"https://app.example.com/api/":        {Status: 403},
		"https://app.example.com/api/me":      {Status: 403},
		"https://app.example.com/api/v1/me":   {Status: 403},
		"https://app.example.com/api/v1/user": {Status: 403},
	}}

	got := AskState(context.Background(), base, r.ask)

	if got.Asked != 4 || got.RefusedAt != "" {
		t.Fatalf("all four were asked and none refused; got %+v", got)
	}
	if StateGate(got) != "" || BareRefusal(got) {
		t.Fatal("403 is excluded from the refusal test entirely")
	}
}

func TestOnlyThe401And407AreRefusals(t *testing.T) {
	for status, want := range map[int]bool{
		401: true, 407: true,
		200: false, 204: false, 302: false, 400: false, 403: false, 404: false, 500: false, 0: false,
	} {
		if got := Refusal(status); got != want {
			t.Fatalf("Refusal(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestAnAddressThatDidNotAnswerIsNeitherARefusalNorAPermission(t *testing.T) {
	// It is nothing, and the walk carries on.
	r := &recorder{answers: map[string]StateAnswer{
		"https://app.example.com/api/v1/me": {Status: 401, Challenge: true},
	}}

	got := AskState(context.Background(), base, r.ask)

	if got.Asked != 3 {
		t.Fatalf("two silent addresses and then a refusal; got %d asked", got.Asked)
	}
	if StateGate(got) == "" {
		t.Fatal("the refusal still decides")
	}
}

func TestNothingIsAskedWhenThereIsNoOriginToAskIt(t *testing.T) {
	if got := AskState(context.Background(), "not a url", func(context.Context, string) (StateAnswer, bool) {
		t.Fatal("no request may be issued")
		return StateAnswer{}, false
	}); got != nil {
		t.Fatalf("want nil, got %+v", got)
	}
}

func TestACancelledContextStopsTheWalk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := &recorder{answers: map[string]StateAnswer{}}
	if got := AskState(ctx, base, r.ask); got.Asked != 0 {
		t.Fatalf("a cancelled scan asks nothing; got %d", got.Asked)
	}
}
