package fleet

import (
	"path/filepath"
	"testing"

	"github.com/nrosier/labview/internal/labels"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/scan"
)

// analysis is one fixture root taken through every pure stage this package owns, in the order §5
// runs them. It is assembled here rather than by calling the pipeline so that a test failure names
// a rule in this package and not an orchestration bug somewhere else.
type analysis struct {
	Stacks  []payload.AppStack
	Nets    *Networks
	Index   *Index
	Deps    Deps
	Proxies map[string]bool
	Graph   payload.Graph
	Stats   payload.OverviewStats
}

// analyze scans a fixture root and runs the analysis over it.
//
// The label prefixes and filenames are §3.1's defaults written out rather than imported, so this
// package's tests keep depending on nothing that reads configuration.
func analyze(t *testing.T, root string) analysis {
	t.Helper()

	res := scan.Run(scan.Options{
		Root:             filepath.Join("..", "..", "fixtures", root),
		ComposeFilenames: []string{"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"},
		SidecarFilenames: []string{".labview", ".labview.yml", ".labview.yaml"},
		RedactURI:        true,
	})
	if len(res.Stacks) == 0 {
		t.Fatalf("fixtures/%s produced no stacks; warnings: %v", root, res.Warnings)
	}

	stacks := res.Stacks
	for si := range stacks {
		for vi := range stacks[si].Services {
			svc := &stacks[si].Services[vi]
			svc.Cloudflare, _ = labels.Cloudflare(svc.Labels, "dockflare")
			svc.Traefik, _ = labels.Traefik(svc.Labels, "traefik")
		}
	}

	nets := NewNetworks(stacks)
	ix := NewIndex(stacks)
	for _, key := range ix.Keys() {
		svc := ix.Service(key)
		svc.Ingress = ServiceIngress(*svc, nets, key)
	}
	proxies := Origins(ix, nets)
	deps := Dependencies(ix, nets)

	graph := BuildGraph(GraphInput{
		Stacks: stacks, Index: ix, Networks: nets, Deps: deps, Proxies: proxies,
	})
	stats := Stats(StatsInput{Stacks: stacks, Networks: nets, Deps: deps})

	return analysis{
		Stacks: stacks, Nets: nets, Index: ix, Deps: deps,
		Proxies: proxies, Graph: graph, Stats: stats,
	}
}

// dep finds one resolved dependency by its endpoints.
func (a analysis) dep(t *testing.T, from, to string) Dependency {
	t.Helper()
	for _, d := range a.Deps.Resolved {
		if d.From == from && d.To == to {
			return d
		}
	}
	t.Fatalf("no resolved dependency %s → %s; resolved: %v", from, to, a.Deps.Resolved)
	return Dependency{}
}

// edge finds one graph edge by id.
func (a analysis) edge(t *testing.T, id string) payload.GraphEdge {
	t.Helper()
	for _, e := range a.Graph.Edges {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("no graph edge %q", id)
	return payload.GraphEdge{}
}

func (a analysis) hasEdge(id string) bool {
	for _, e := range a.Graph.Edges {
		if e.ID == id {
			return true
		}
	}
	return false
}

func (a analysis) hasNode(id string) bool {
	for _, n := range a.Graph.Nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

// route is one service's first Cloudflare route, for the origin tests.
func (a analysis) route(t *testing.T, key string) payload.CloudflareRoute {
	t.Helper()
	svc := a.Index.Service(key)
	if svc == nil {
		t.Fatalf("no service %q", key)
	}
	if len(svc.Cloudflare) == 0 {
		t.Fatalf("service %q declares no tunnel route", key)
	}
	return svc.Cloudflare[0]
}

func equalKinds(got, want []payload.IngressKind) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
