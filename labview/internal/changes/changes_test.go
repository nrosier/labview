package changes

import (
	"strconv"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// scan is one minimal payload: two stacks, three services, both integrations reachable. Every test
// below starts from this and moves one thing, so what the note says is attributable to that move.
func scan() payload.Overview {
	out := payload.Overview{
		Meta: payload.ScanMeta{
			AppsRoot:        "/data/apps",
			DockerAvailable: true,
			Authentik: &payload.AuthentikSummary{
				Enabled: true, Configured: true, Reachable: true,
				Endpoint:     "https://sso.example.com",
				Applications: 4, Providers: 3, Outposts: 1, MatchedServices: 2,
			},
			Traefik: &payload.TraefikSummary{
				Enabled: true, Configured: true, Reachable: true,
				Endpoint: "http://edge:8080",
				Routers:  6, Middlewares: 2, Services: 5, MatchedServices: 2,
			},
			Connections: []payload.ConnectionReport{
				{Target: "docker", OK: true, Phase: payload.PhaseConnected,
					Endpoint: "/var/run/docker.sock", Read: "12 containers"},
				{Target: "authentik", OK: true, Phase: payload.PhaseConnected,
					Endpoint: "https://sso.example.com"},
			},
		},
		Stats:  payload.OverviewStats{Stacks: 2, Services: 3},
		Stacks: []payload.AppStack{stack("media", "jellyfin", "db"), stack("sso", "server")},
	}
	return out
}

func stack(id string, services ...string) payload.AppStack {
	out := payload.AppStack{ID: id, Name: id, Dir: "/data/apps/" + id,
		ComposeFile: "/data/apps/" + id + "/docker-compose.yaml"}
	for _, name := range services {
		out.Services = append(out.Services, payload.Service{
			Name: name, ContainerName: id + "-" + name + "-1",
			Image:  "ghcr.io/example/" + name + ":1.0",
			Labels: map[string]string{"com.example.role": name},
		})
	}
	return out
}

// with applies one edit to a copy, so a test reads as "this payload, but X moved".
//
// The copy goes deep enough that an edit cannot reach the original — including each label map, which
// a shallow copy would share, so that setting a label on the copy would set it on both and every
// test asserting that a label edit is a change would pass for the wrong reason.
func with(base payload.Overview, edit func(*payload.Overview)) payload.Overview {
	out := base
	out.Stacks = make([]payload.AppStack, len(base.Stacks))
	for i, s := range base.Stacks {
		s.Services = append([]payload.Service(nil), s.Services...)
		for j := range s.Services {
			labels := make(map[string]string, len(s.Services[j].Labels))
			for k, v := range s.Services[j].Labels {
				labels[k] = v
			}
			s.Services[j].Labels = labels
		}
		out.Stacks[i] = s
	}
	if base.Meta.Authentik != nil {
		a := *base.Meta.Authentik
		out.Meta.Authentik = &a
	}
	if base.Meta.Traefik != nil {
		tr := *base.Meta.Traefik
		out.Meta.Traefik = &tr
	}
	out.Meta.Connections = append([]payload.ConnectionReport(nil), base.Meta.Connections...)
	edit(&out)
	return out
}

// joined is the note as one string, for tests that assert a phrase is or is not present anywhere.
func joined(n Note) string { return strings.Join(n.Lines(), "\n") }

func mustContain(t *testing.T, n Note, want ...string) {
	t.Helper()
	got := joined(n)
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("want %q in the note\n got:\n%s", w, got)
		}
	}
}

func mustNotContain(t *testing.T, n Note, unwanted ...string) {
	t.Helper()
	got := joined(n)
	for _, u := range unwanted {
		if strings.Contains(got, u) {
			t.Fatalf("must not say %q\n got:\n%s", u, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Cadence
// ---------------------------------------------------------------------------

func TestTheFirstBuildStatesTheBaselineRatherThanADiff(t *testing.T) {
	// §17: *the first build states the baseline*. A first scan has nothing to compare against, and
	// "0 changes" would be a claim about a fleet nobody had looked at yet.
	n := Describe(nil, scan())

	mustContain(t, n, "LabView read 2 stacks, 3 services from /data/apps")
	if len(n.Config) != 0 {
		t.Fatalf("a first build has no configuration diff; got %v", n.Config)
	}
	if n.Quiet() {
		t.Fatal("a baseline is never quiet — it is the one thing the first build has to say")
	}
}

func TestOneStackAndOneServiceReadSingular(t *testing.T) {
	one := with(scan(), func(o *payload.Overview) {
		o.Stacks, o.Stats.Stacks, o.Stats.Services = []payload.AppStack{stack("media", "jellyfin")}, 1, 1
	})

	mustContain(t, Describe(nil, one), "LabView read 1 stack, 1 service from /data/apps")
}

func TestTwoIdenticalScansAreQuiet(t *testing.T) {
	// The property the whole canonical comparison exists for: a timer rebuild of an unedited fleet
	// says nothing, so the log does not fill with rescans nobody caused.
	prev := scan()
	n := Describe(&prev, scan())

	if !n.Quiet() {
		t.Fatalf("nothing moved, so the note is quiet; got %#v", n)
	}
	if len(n.Lines()) != 0 {
		t.Fatalf("a quiet note renders nothing; got %v", n.Lines())
	}
}

func TestQuietMeansBothDiffs(t *testing.T) {
	// §17 states this explicitly: *quiet means **both** diffs*. A fleet whose files did not move but
	// whose provider gained an application has something to say.
	prev := scan()
	next := with(prev, func(o *payload.Overview) { o.Meta.Authentik.Applications = 5 })

	n := Describe(&prev, next)
	if n.Quiet() {
		t.Fatal("the integration diff moved, so the build is not quiet")
	}
	if len(n.Config) != 0 {
		t.Fatalf("the configuration did not move; got %v", n.Config)
	}
	mustContain(t, n, "no config changes", "authentik +1 application")
}

func TestAnUnchangedConfigurationIsSaidOutLoudBesideAnIntegrationChange(t *testing.T) {
	// §17's sentence: *no config changes; authentik +1 application, -3 withheld*. A reader shown only
	// the second half would not know whether somebody had also edited a file.
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Meta.Authentik.Applications = 5
		o.Meta.Authentik.ApplicationsWithheld = 3
	})

	lines := Describe(&prev, next).Lines()
	if lines[0] != "no config changes" {
		t.Fatalf("the clause leads; got %q", lines[0])
	}
	mustContain(t, Describe(&prev, next), "+1 application", "+3 withheld")
}

func TestTheNoConfigChangesClauseIsAbsentWhenTheConfigurationDidMove(t *testing.T) {
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Stacks[0].Services[0].Image = "ghcr.io/example/jellyfin:2.0"
		o.Meta.Authentik.Applications = 5
	})

	mustNotContain(t, Describe(&prev, next), "no config changes")
}

// ---------------------------------------------------------------------------
// The two structures stay apart
// ---------------------------------------------------------------------------

func TestTheIntegrationDiffIsASecondStructureAndIsNotFoldedIn(t *testing.T) {
	// §17: *The integration diff is a second structure beside the configuration diff and MUST NOT be
	// folded into it*. One of these two facts means somebody edited a file; the other means somebody
	// clicked something in Authentik. A single merged list loses that.
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Stacks[0].Services[0].Image = "ghcr.io/example/jellyfin:2.0"
		o.Meta.Authentik.Applications = 5
	})

	n := Describe(&prev, next)
	for _, line := range n.Config {
		if strings.Contains(line, "authentik") {
			t.Fatalf("an integration fact landed in the configuration diff: %q", line)
		}
	}
	for _, line := range n.Integration {
		if strings.Contains(line, "stack ") {
			t.Fatalf("a configuration fact landed in the integration diff: %q", line)
		}
	}
	if len(n.Config) == 0 || len(n.Integration) == 0 {
		t.Fatalf("both moved, so both lists have content; got %#v", n)
	}
}

// ---------------------------------------------------------------------------
// The deny-list
// ---------------------------------------------------------------------------

func TestLiveDockerStateIsNotAConfigurationChange(t *testing.T) {
	// The first name on §17's volatile list. A container restarting has a new id, a new start time
	// and a new status, and none of that is somebody editing a file.
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Stacks[0].Services[0].Docker = &payload.DockerState{
			ID: "9f2c1a", Name: "media-jellyfin-1", State: "running", Status: "Up 3 seconds"}
	})

	if got := Describe(&prev, next).Config; len(got) != 0 {
		t.Fatalf("live state is volatile; got %v", got)
	}
}

func TestEveryFieldNamedVolatileIsIgnoredByTheComparison(t *testing.T) {
	// §17's list, one case per name, plus the two this implementation reasons its way to. Each moves
	// exactly one field, so a failure names which one leaked into the configuration digest.
	// A seed is configuration both sides share, for the two volatile fields that hang off a record
	// rather than standing alone: the tunnel route and the sidecar declaration are both file content,
	// so adding one is a real change and only what got attached to it is volatile.
	cases := []struct {
		name string
		seed func(*payload.Service)
		move func(*payload.Service)
	}{
		{"live docker state", nil, func(s *payload.Service) {
			s.Docker = &payload.DockerState{ID: "abc", State: "running"}
		}},
		{"the identity-provider match", nil, func(s *payload.Service) {
			s.Authentik = &payload.AuthentikMatch{
				Applications: []payload.AuthentikApplication{{Name: "Jellyfin", Slug: "jellyfin"}}}
		}},
		{"live proxy records", nil, func(s *payload.Service) {
			s.TraefikLive = []payload.TraefikLiveRouter{{Router: "jellyfin@docker"}}
		}},
		{"ingress", nil, func(s *payload.Service) {
			s.Ingress = []payload.IngressKind{payload.IngressTraefik}
		}},
		{"authentication", nil, func(s *payload.Service) {
			s.Auth = payload.AuthPosture{Method: payload.AuthForwardAuth, Detail: "authentik@docker"}
		}},
		{"notes", nil, func(s *payload.Service) {
			s.Notes = []string{"the proxy answered without a credential"}
		}},
		{
			name: "tunnel-route state",
			seed: func(s *payload.Service) {
				s.Cloudflare = []payload.CloudflareRoute{
					{Hostname: "app.example.com", Service: "http://x:80"}}
			},
			move: func(s *payload.Service) {
				s.Cloudflare[0].Origin = &payload.OriginTarget{
					Address: "http://x:80", Host: "x", Port: "80"}
			},
		},
		// Not enumerated by §17, denied by its governing sentence — see the comment in strip.
		{"the probe result", nil, func(s *payload.Service) {
			s.Probe = &payload.ServiceProbe{Endpoint: "https://app/", Phase: payload.PhaseConnected}
		}},
		{
			name: "a declaration verdict",
			seed: func(s *payload.Service) {
				s.Declared = &payload.ServiceDeclaration{
					Declaration: payload.Declaration{File: "labview.yaml", Owner: "media"}}
			},
			move: func(s *payload.Service) {
				s.Declared.Drift = []string{"declared internal, reachable from outside"}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prev := scan()
			if c.seed != nil {
				prev = with(prev, func(o *payload.Overview) { c.seed(&o.Stacks[0].Services[0]) })
			}
			next := with(prev, func(o *payload.Overview) {
				// The seed runs again so the move works on this copy's own record rather than on
				// the one the previous payload is still holding.
				if c.seed != nil {
					c.seed(&o.Stacks[0].Services[0])
				}
				c.move(&o.Stacks[0].Services[0])
			})

			if got := Describe(&prev, next).Config; len(got) != 0 {
				t.Fatalf("%s is volatile and must not read as a configuration change; got %v",
					c.name, got)
			}
		})
	}
}

func TestTheTunnelRouteItselfIsStillComparedWhenOnlyItsOriginIsNot(t *testing.T) {
	// The distinction the deny-list has to keep: the route is configuration, what its origin resolved
	// to is not. Zeroing the whole route would go quiet about somebody adding a hostname.
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Stacks[0].Services[0].Cloudflare = []payload.CloudflareRoute{
			{Hostname: "new.example.com", Service: "http://jellyfin:8096"}}
	})

	mustContain(t, Describe(&prev, next), `stack "media" changed`)
}

func TestWhatTheSidecarDeclaredIsComparedAndWhatWasConcludedAboutItIsNot(t *testing.T) {
	// The same distinction inside one struct: the declared inputs are file content, the three
	// verdicts are derived from ingress, auth and the probe — all three already denied.
	base := scan()
	prev := with(base, func(o *payload.Overview) {
		o.Stacks[0].Services[0].Declared = &payload.ServiceDeclaration{
			Declaration: payload.Declaration{File: "labview.yaml", Description: "the media server"}}
	})

	verdict := with(prev, func(o *payload.Overview) {
		o.Stacks[0].Services[0].Declared = &payload.ServiceDeclaration{
			Declaration:   payload.Declaration{File: "labview.yaml", Description: "the media server"},
			AuthAgreement: payload.AgreementSupplies, Unconfirmed: []string{"no probe result"}}
	})
	if got := Describe(&prev, verdict).Config; len(got) != 0 {
		t.Fatalf("a verdict is not file content; got %v", got)
	}

	edited := with(prev, func(o *payload.Overview) {
		o.Stacks[0].Services[0].Declared = &payload.ServiceDeclaration{
			Declaration: payload.Declaration{File: "labview.yaml", Description: "the media server, edited"}}
	})
	mustContain(t, Describe(&prev, edited), `stack "media" changed`)
}

func TestAFieldNobodyNamedIsComparedByDefault(t *testing.T) {
	// The deny-list property itself. Every scanned field is compared without anybody having listed
	// it, which is what makes a field added to Service tomorrow safe: it is compared until somebody
	// decides it is volatile, rather than silently uncompared until somebody notices.
	cases := []struct {
		name string
		move func(*payload.Service)
	}{
		{"image", func(s *payload.Service) { s.Image = "ghcr.io/example/jellyfin:2.0" }},
		{"restart", func(s *payload.Service) { s.Restart = "unless-stopped" }},
		{"command", func(s *payload.Service) { s.Command = "--trace" }},
		{"depends_on", func(s *payload.Service) { s.DependsOn = []string{"db"} }},
		{"networks", func(s *payload.Service) { s.Networks = []string{"edge"} }},
		{"ports", func(s *payload.Service) {
			s.Ports = []payload.PortMapping{{Published: "8096", Target: "8096"}}
		}},
		{"expose", func(s *payload.Service) { s.Expose = []string{"8096"} }},
		{"mounts", func(s *payload.Service) {
			s.Mounts = []payload.MountSpec{{Source: "/mnt/media", Target: "/media"}}
		}},
		{"env", func(s *payload.Service) {
			s.Env = []payload.EnvVar{{Key: "TZ", Source: payload.EnvFromEnvironment}}
		}},
		{"labels", func(s *payload.Service) { s.Labels["traefik.enable"] = "true" }},
		{"container name", func(s *payload.Service) { s.ContainerName = "jellyfin" }},
		{"label-derived proxy routes", func(s *payload.Service) {
			s.Traefik = []payload.TraefikRoute{{Router: "jellyfin", Rule: "Host(`j.example.com`)"}}
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prev := scan()
			next := with(prev, func(o *payload.Overview) { c.move(&o.Stacks[0].Services[0]) })

			mustContain(t, Describe(&prev, next), `stack "media" changed`)
		})
	}
}

func TestAStackLevelEditIsSeenToo(t *testing.T) {
	// The digest covers the stack, not only its services: an .env file appearing is a change.
	prev := scan()
	next := with(prev, func(o *payload.Overview) { o.Stacks[0].HasEnvFile = true })

	mustContain(t, Describe(&prev, next), `stack "media" changed`)
}

func TestTheFingerprintOfOneUnchangedStackIsOneString(t *testing.T) {
	// I7 at the digest layer, and the reason the comparison can be a string equality at all.
	s := stack("media", "jellyfin", "db")
	first := Fingerprint(s)
	for i := 0; i < 20; i++ {
		if again := Fingerprint(s); again != first {
			t.Fatalf("the same stack digested to\n%s\nthen\n%s", first, again)
		}
	}
}

func TestTheFingerprintIgnoresTheOrderMapsAreBuiltIn(t *testing.T) {
	// Canonical serialisation, concretely: two label maps with the same content digest alike however
	// they were populated, because encoding/json sorts map keys.
	a := stack("media", "jellyfin")
	a.Services[0].Labels = map[string]string{}
	for _, k := range []string{"z", "m", "a"} {
		a.Services[0].Labels[k] = k
	}
	b := stack("media", "jellyfin")
	b.Services[0].Labels = map[string]string{}
	for _, k := range []string{"a", "m", "z"} {
		b.Services[0].Labels[k] = k
	}

	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("map insertion order is not configuration")
	}
}

// ---------------------------------------------------------------------------
// The configuration diff
// ---------------------------------------------------------------------------

func TestAnAddedStackIsNamedWithItsServiceCount(t *testing.T) {
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Stacks = append(o.Stacks, stack("edge", "traefik"))
		o.Stats.Stacks, o.Stats.Services = 3, 4
	})

	mustContain(t, Describe(&prev, next),
		"+1 stack, +1 service", `stack "edge" added, 1 service`)
}

func TestARemovedStackIsNamedWithWhatItHad(t *testing.T) {
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Stacks, o.Stats.Stacks, o.Stats.Services = o.Stacks[1:], 1, 1
	})

	mustContain(t, Describe(&prev, next),
		"-1 stack, -2 services", `stack "media" removed, 2 services`)
}

func TestAChangedStackSaysSoAndSaysWhenItsServiceCountMoved(t *testing.T) {
	prev := scan()

	edited := with(prev, func(o *payload.Overview) {
		o.Stacks[0].Services[0].Image = "ghcr.io/example/jellyfin:2.0"
	})
	mustContain(t, Describe(&prev, edited), `stack "media" changed`)
	mustNotContain(t, Describe(&prev, edited), "service")

	grown := with(prev, func(o *payload.Overview) {
		o.Stacks[0].Services = append(o.Stacks[0].Services, payload.Service{Name: "redis"})
		o.Stats.Services = 4
	})
	mustContain(t, Describe(&prev, grown), `stack "media" changed: +1 service`)
}

func TestTheHeadlineNamesOnlyTheCountersThatMoved(t *testing.T) {
	// A label edit moves neither counter, so the headline is absent entirely rather than reading
	// "+0 stacks, +0 services".
	prev := scan()
	next := with(prev, func(o *payload.Overview) { o.Stacks[0].Services[0].Labels["x"] = "y" })

	n := Describe(&prev, next)
	if len(n.Config) != 1 {
		t.Fatalf("one stack moved and no counter did, so one line; got %v", n.Config)
	}
	mustNotContain(t, n, "+0", "-0")
}

func TestPerStackLinesCapAtTwelveWithTheRemainderStated(t *testing.T) {
	// §17: *capped at **12** lines with the remainder stated rather than silently dropped*. A reader
	// who is not told is a reader who thinks they saw everything.
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		for i := 0; i < 20; i++ {
			o.Stacks = append(o.Stacks, stack("added-"+strconv.Itoa(i), "app"))
		}
		o.Stats.Stacks, o.Stats.Services = 22, 23
	})

	n := Describe(&prev, next)
	// One headline plus twelve stack lines plus the remainder line.
	if len(n.Config) != 14 {
		t.Fatalf("a headline, 12 lines and the remainder; got %d:\n%s",
			len(n.Config), strings.Join(n.Config, "\n"))
	}
	mustContain(t, n, "and 8 stacks not listed")
}

func TestTheRemainderLineIsSingularForOne(t *testing.T) {
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		for i := 0; i < 13; i++ {
			o.Stacks = append(o.Stacks, stack("added-"+strconv.Itoa(i), "app"))
		}
		o.Stats.Stacks, o.Stats.Services = 15, 16
	})

	mustContain(t, Describe(&prev, next), "and 1 stack not listed")
}

func TestTheConfigurationDiffIsInAFixedOrder(t *testing.T) {
	// I7: two runs of one comparison give one note, byte for byte, so a diff of two logs is a diff of
	// what happened rather than of how the maps iterated.
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Stacks = append(o.Stacks[1:], stack("zeta", "a"), stack("alpha", "b"),
			stack("mid", "c"))
		o.Stats.Stacks, o.Stats.Services = 4, 4
	})

	first := joined(Describe(&prev, next))
	for i := 0; i < 20; i++ {
		if again := joined(Describe(&prev, next)); again != first {
			t.Fatalf("the same pair described as\n%s\nthen\n%s", first, again)
		}
	}
	// Added before removed, each sorted by id.
	if a, z := strings.Index(first, `"alpha" added`), strings.Index(first, `"zeta" added`); a > z {
		t.Fatalf("added stacks are sorted by id:\n%s", first)
	}
	if added, removed := strings.Index(first, `"zeta" added`),
		strings.Index(first, `"media" removed`); added > removed {
		t.Fatalf("added lines come before removed ones:\n%s", first)
	}
}

// ---------------------------------------------------------------------------
// Reachability, before any count
// ---------------------------------------------------------------------------

func TestATargetNeitherScanReadHasNothingToSay(t *testing.T) {
	// §17's first bullet: *neither read → no entry*. A disabled integration is not news on every
	// rescan.
	prev := with(scan(), func(o *payload.Overview) { o.Meta.Authentik.Reachable = false })
	next := with(prev, func(o *payload.Overview) { o.Meta.Authentik.Applications = 9 })

	mustNotContain(t, Describe(&prev, next), "authentik")
}

func TestATargetThatStartedAnsweringIsNotPhrasedAsANumber(t *testing.T) {
	// §17: *not-read → read = `started`* and *Those two are not numeric comparisons and MUST NOT be
	// phrased as ones*. A target that was not answering had no counts to be up or down from.
	prev := with(scan(), func(o *payload.Overview) {
		o.Meta.Authentik.Reachable, o.Meta.Authentik.Applications = false, 0
	})
	next := scan()

	n := Describe(&prev, next)
	mustContain(t, n, "authentik started answering at https://sso.example.com")
	mustNotContain(t, n, "+4 applications", "+3 providers")
}

func TestATargetThatStoppedAnsweringIsNotPhrasedAsANumberEither(t *testing.T) {
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Meta.Traefik.Reachable = false
		o.Meta.Traefik.Error = "connection refused"
		o.Meta.Traefik.Routers, o.Meta.Traefik.Middlewares = 0, 0
		o.Meta.Traefik.Services, o.Meta.Traefik.MatchedServices = 0, 0
	})

	n := Describe(&prev, next)
	mustContain(t, n, "traefik stopped answering: connection refused")
	mustNotContain(t, n, "-6 routers", "-2 middlewares")
}

func TestCountsAreComparedOnlyWhereBothSidesHaveAValue(t *testing.T) {
	// §17's second bullet. ApplicationsConfigured is the count the API itself claimed, absent when it
	// claimed none — so its appearing is not a delta, and treating absence as zero would report
	// "+11 configured" about a number that had simply started being reported.
	prev := scan()
	appearing := with(prev, func(o *payload.Overview) {
		eleven := 11
		o.Meta.Authentik.ApplicationsConfigured = &eleven
	})
	mustNotContain(t, Describe(&prev, appearing), "configured")

	both := with(appearing, func(o *payload.Overview) {
		twelve := 12
		o.Meta.Authentik.ApplicationsConfigured = &twelve
	})
	mustContain(t, Describe(&appearing, both), "authentik +1 configured")
}

// ---------------------------------------------------------------------------
// Wording
// ---------------------------------------------------------------------------

func TestNounsPluraliseAndModifiersDoNot(t *testing.T) {
	// §17: *Nouns are pluralised; modifiers stay identical in both directions (`+1 application`,
	// `-3 withheld`)*. "-3 withhelds" is not English.
	prev := with(scan(), func(o *payload.Overview) { o.Meta.Authentik.ApplicationsWithheld = 4 })
	next := with(prev, func(o *payload.Overview) {
		o.Meta.Authentik.Applications = 5
		o.Meta.Authentik.ApplicationsWithheld = 1
	})

	mustContain(t, Describe(&prev, next), "+1 application", "-3 withheld")
	mustNotContain(t, Describe(&prev, next), "withhelds", "+1 applications")
}

func TestSeveralApplicationsPluralise(t *testing.T) {
	prev := scan()
	next := with(prev, func(o *payload.Overview) { o.Meta.Authentik.Applications = 6 })

	mustContain(t, Describe(&prev, next), "+2 applications")
}

func TestTheProxysOwnServiceCountReadsAsLiveService(t *testing.T) {
	// §17: it *renders as **`live service`**, because *service* in this payload already means a
	// compose service*. A reader shown "traefik +1 service" would go looking for a new container.
	prev := scan()
	next := with(prev, func(o *payload.Overview) { o.Meta.Traefik.Services = 6 })

	n := Describe(&prev, next)
	mustContain(t, n, "traefik +1 live service")

	two := with(prev, func(o *payload.Overview) { o.Meta.Traefik.Services = 7 })
	mustContain(t, Describe(&prev, two), "+2 live services")
}

func TestAMatchedServiceCountIsStillDistinctFromTheProxysOwn(t *testing.T) {
	prev := scan()
	next := with(prev, func(o *payload.Overview) { o.Meta.Traefik.MatchedServices = 3 })

	mustContain(t, Describe(&prev, next), "traefik +1 matched service")
}

// ---------------------------------------------------------------------------
// Named records
// ---------------------------------------------------------------------------

func TestNamedRecordsAreReadOffThePayloadAndSorted(t *testing.T) {
	// §17: *Named records are read back off the payload — application slugs, router names — and
	// sorted (I7)*.
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Meta.Authentik.Applications = 6
		o.Meta.Authentik.UnmatchedApplications = []payload.UnmatchedApplication{
			{Application: payload.AuthentikApplication{Name: "Zulip", Slug: "zulip"}},
			{Application: payload.AuthentikApplication{Name: "Grafana", Slug: "grafana"}},
		}
	})

	n := Describe(&prev, next)
	mustContain(t, n, "authentik gained 2 applications: grafana, zulip")
}

func TestARecordThatMovedFromUnmatchedToMatchedIsNeitherGainedNorLost(t *testing.T) {
	// The reason both places are read. An application the scan learned to tie to a service is the
	// same application; announcing it as gained and lost at once would be two wrong sentences.
	prev := with(scan(), func(o *payload.Overview) {
		o.Meta.Authentik.UnmatchedApplications = []payload.UnmatchedApplication{
			{Application: payload.AuthentikApplication{Name: "Jellyfin", Slug: "jellyfin"}}}
	})
	next := with(scan(), func(o *payload.Overview) {
		o.Stacks[0].Services[0].Authentik = &payload.AuthentikMatch{
			Applications: []payload.AuthentikApplication{{Name: "Jellyfin", Slug: "jellyfin"}}}
	})

	mustNotContain(t, Describe(&prev, next), "jellyfin")
}

func TestALostRouterIsNamed(t *testing.T) {
	prev := with(scan(), func(o *payload.Overview) {
		o.Stacks[0].Services[0].TraefikLive = []payload.TraefikLiveRouter{
			{Router: "jellyfin@docker"}, {Router: "dashboard@internal"}}
	})
	next := with(scan(), func(o *payload.Overview) {
		o.Stacks[0].Services[0].TraefikLive = []payload.TraefikLiveRouter{
			{Router: "jellyfin@docker"}}
	})

	mustContain(t, Describe(&prev, next), "traefik lost 1 router: dashboard@internal")
}

func TestNameListsTruncateAtTwelveNamesPerLineAndNotAtTwelveLines(t *testing.T) {
	// §17 is explicit that this cap is a different cap: *Name lists truncate at **12 names per
	// line**, not 12 lines, with the remainder stated: each target contributes at most three lines,
	// so a fleet with forty applications still puts forty names into one of them.*
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Meta.Authentik.Applications = 44
		for i := 0; i < 40; i++ {
			o.Meta.Authentik.UnmatchedApplications = append(o.Meta.Authentik.UnmatchedApplications,
				payload.UnmatchedApplication{Application: payload.AuthentikApplication{
					Slug: "app-" + strconv.Itoa(100+i)}})
		}
	})

	n := Describe(&prev, next)
	if len(n.Integration) > 3 {
		t.Fatalf("a target contributes at most three lines; got %d:\n%s",
			len(n.Integration), strings.Join(n.Integration, "\n"))
	}
	mustContain(t, n, "authentik gained 40 applications: app-100,", "and 28 more")

	// And the names are on one line, not spread over the lines the other cap would have made.
	for _, line := range n.Integration {
		if strings.Count(line, "app-") > 0 && strings.Count(line, "app-") != MaxNames {
			t.Fatalf("the names belong on one line, %d of them; got %d in %q",
				MaxNames, strings.Count(line, "app-"), line)
		}
	}
}

func TestARecordWithNoSlugIsStillNamed(t *testing.T) {
	// An application the API returned without a slug is still a record a reader can look up; an empty
	// string in a name list is not.
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Meta.Authentik.Applications = 5
		o.Meta.Authentik.UnmatchedApplications = []payload.UnmatchedApplication{
			{Application: payload.AuthentikApplication{Name: "Nextcloud"}}}
	})

	mustContain(t, Describe(&prev, next), "Nextcloud")
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

func TestAConnectionIsComparedOnTargetOkPhaseAndEndpointAndNeverOnRead(t *testing.T) {
	// §15, quoted: *Comparing two scans' connections MUST COMPARE target, `ok`, phase and endpoint,
	// and MUST NOT compare `read`* — otherwise a container count ticking up re-announces a working
	// target on every rescan.
	prev := scan()
	next := with(prev, func(o *payload.Overview) { o.Meta.Connections[0].Read = "13 containers" })

	if got := Describe(&prev, next); !got.Quiet() {
		t.Fatalf("a container count is not a change in the connection; got %#v", got)
	}
}

func TestAConnectionThatChangedPhaseSpeaks(t *testing.T) {
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Meta.Connections[0].OK = false
		o.Meta.Connections[0].Phase = payload.PhaseConnect
		o.Meta.Connections[0].Detail = "no such file or directory"
	})

	mustContain(t, Describe(&prev, next),
		"docker is now connect at /var/run/docker.sock: no such file or directory")
}

func TestAConnectionThatMovedEndpointSpeaks(t *testing.T) {
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Meta.Connections[1].Endpoint = "https://sso.internal"
	})

	mustContain(t, Describe(&prev, next), "authentik is now connected at https://sso.internal")
}

func TestATargetPresentInOnlyOneScanIsNotAConnectionChange(t *testing.T) {
	// A probe target appearing because the probe was switched on is not a connection that moved; the
	// report itself is the first thing said about it, and §15 prints those in full.
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Meta.Connections = append(o.Meta.Connections, payload.ConnectionReport{
			Target: "probe", OK: true, Phase: payload.PhaseConnected})
	})

	if got := Describe(&prev, next); !got.Quiet() {
		t.Fatalf("a new target is not a changed one; got %#v", got)
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

func TestOneComparisonGivesOneNoteHoweverOftenItIsRun(t *testing.T) {
	// I7 over the whole note, config and integration together.
	prev := scan()
	next := with(prev, func(o *payload.Overview) {
		o.Stacks[0].Services[0].Labels["a"] = "b"
		o.Stacks = append(o.Stacks, stack("edge", "traefik"))
		o.Stats.Stacks, o.Stats.Services = 3, 4
		o.Meta.Authentik.Applications = 6
		o.Meta.Authentik.UnmatchedApplications = []payload.UnmatchedApplication{
			{Application: payload.AuthentikApplication{Slug: "zulip"}},
			{Application: payload.AuthentikApplication{Slug: "grafana"}},
		}
		o.Meta.Traefik.Routers = 8
		o.Meta.Connections[0].Phase = payload.PhasePartial
	})

	first := joined(Describe(&prev, next))
	for i := 0; i < 20; i++ {
		if again := joined(Describe(&prev, next)); again != first {
			t.Fatalf("the same pair described as\n%s\nthen\n%s", first, again)
		}
	}
}

func TestDescribeDoesNotTouchEitherPayload(t *testing.T) {
	// Describe is asked to compare, not to edit. The strip that makes the digest works on a copy, so
	// a caller holding the previous payload for the next comparison still holds all of it.
	prev := scan()
	prev.Stacks[0].Services[0].Docker = &payload.DockerState{ID: "abc", State: "running"}
	next := with(prev, func(o *payload.Overview) { o.Stacks[0].Services[0].Image = "x:2" })

	Describe(&prev, next)

	if prev.Stacks[0].Services[0].Docker == nil {
		t.Fatal("the previous payload lost its live state to the comparison")
	}
	if next.Stacks[0].Services[0].Docker == nil {
		t.Fatal("the next payload lost its live state to the comparison")
	}
}

func TestAScanWithNoIntegrationSummariesAtAllIsHandled(t *testing.T) {
	// I4: a payload from a build where both integrations were off compares without a panic, and says
	// nothing about targets it never had.
	bare := payload.Overview{Meta: payload.ScanMeta{AppsRoot: "/data/apps"}}

	if got := Describe(nil, bare); got.Baseline == "" {
		t.Fatal("a first build still states its baseline")
	}
	if got := Describe(&bare, bare); !got.Quiet() {
		t.Fatalf("nothing was read and nothing moved; got %#v", got)
	}
}
