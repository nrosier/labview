package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// parseIn parses one compose file for a stack directory that exists on disk, so that the
// reads a compose file can ask for — `env_file` — have somewhere real to land.
func parseIn(t *testing.T, dir, body string, env ...envEntry) composeFile {
	t.Helper()
	root := NewRoot(filepath.Dir(dir))
	out, err := parseCompose([]byte(body), composeInput{
		StackID: filepath.Base(dir),
		Dir:     dir,
		Root:    root.With(dir),
		Env:     env,
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return out
}

// stackDir makes apps/<id>/ under a temporary root and writes the given files into it.
func stackDir(t *testing.T, id string, files map[string]string) string {
	t.Helper()
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "apps", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// parse is parseIn for a case that reads no files beside the compose file.
func parse(t *testing.T, body string, env ...envEntry) composeFile {
	t.Helper()
	return parseIn(t, stackDir(t, "media", nil), body, env...)
}

// svc finds one service by name.
func svc(t *testing.T, f composeFile, name string) payload.Service {
	t.Helper()
	for _, s := range f.Services {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no service %q in %v", name, f.Services)
	return payload.Service{}
}

func TestNormalizeProjectName(t *testing.T) {
	// Compose's own normalisation. It has to match, because the result is half of every real
	// network name and the value of the label a container is matched by (§6, §8).
	tests := []struct{ in, want string }{
		{"media", "media"},
		{"Media", "media"},
		{"my.stack", "mystack"},
		{"my stack", "mystack"},
		{"_leading", "leading"},
		{"--leading", "leading"},
		{"keeps_under-score", "keeps_under-score"},
		{"ünïcode", "ncode"}, // every character outside the set is dropped, not transliterated
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeProjectName(tt.in); got != tt.want {
			t.Errorf("normalizeProjectName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestProjectName(t *testing.T) {
	t.Run("the directory name by default", func(t *testing.T) {
		f := parse(t, "services:\n  app:\n    image: a\n")
		if f.ProjectName != "media" || f.Name != "media" {
			t.Errorf("project %q name %q, want media", f.ProjectName, f.Name)
		}
	})

	t.Run("COMPOSE_PROJECT_NAME from the stack's .env", func(t *testing.T) {
		f := parse(t, "services:\n  app:\n    image: a\n",
			envEntry{Key: "COMPOSE_PROJECT_NAME", Value: val("Fleet.One")})
		if f.ProjectName != "fleetone" {
			t.Errorf("project = %q, want fleetone", f.ProjectName)
		}
		// The display name stays the directory: `name:` was not written.
		if f.Name != "media" {
			t.Errorf("name = %q, want media", f.Name)
		}
	})

	t.Run("a declared name wins and is also the display name", func(t *testing.T) {
		f := parse(t, "name: Home Media\nservices:\n  app:\n    image: a\n",
			envEntry{Key: "COMPOSE_PROJECT_NAME", Value: val("ignored")})
		if f.ProjectName != "homemedia" {
			t.Errorf("project = %q, want homemedia", f.ProjectName)
		}
		if f.Name != "Home Media" {
			t.Errorf("name = %q, want the declared spelling", f.Name)
		}
	})

	t.Run("an unresolved variable in the name is reported once", func(t *testing.T) {
		f := parse(t, "name: ${STACK_NAME}\nservices:\n  app:\n    image: a\n")
		want := []string{"name: ${STACK_NAME} is not set in this stack's .env; left as written"}
		if !reflect.DeepEqual(f.Warnings, want) {
			t.Errorf("warnings:\n got %#v\nwant %#v", f.Warnings, want)
		}
	})
}

// TestNetworks is §8's naming rules. Two stacks naming one `external: true` network have to
// produce the same string, or the membership index reports two networks where the fleet has
// one — so every case here is about the exact name a container joins.
func TestNetworks(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		want     []string
		declared []payload.NetworkDecl
		notes    []string
	}{{
		name: "no networks key at all joins the implicit default",
		body: "services:\n  app:\n    image: a\n",
		want: []string{"media_default"},
	}, {
		name: "an empty networks list falls back to the default",
		body: "services:\n  app:\n    image: a\n    networks: []\n",
		want: []string{"media_default"},
	}, {
		name:     "a stack-local network is prefixed with the project",
		body:     "services:\n  app:\n    image: a\n    networks: [backend]\nnetworks:\n  backend:\n",
		want:     []string{"media_backend"},
		declared: []payload.NetworkDecl{{Name: "media_backend"}},
	}, {
		// The only way two stacks can be on one network.
		name:     "external: true is verbatim, with no project prefix",
		body:     "services:\n  app:\n    image: a\n    networks: [proxy]\nnetworks:\n  proxy:\n    external: true\n",
		want:     []string{"proxy"},
		declared: []payload.NetworkDecl{{Name: "proxy", External: true}},
	}, {
		name: "the legacy external mapping form",
		body: "services:\n  app:\n    image: a\n    networks: [old]\n" +
			"networks:\n  old:\n    external:\n      name: shared-net\n",
		want:     []string{"shared-net"},
		declared: []payload.NetworkDecl{{Name: "shared-net", External: true}},
	}, {
		name: "a name override is verbatim",
		body: "services:\n  app:\n    image: a\n    networks: [db]\n" +
			"networks:\n  db:\n    name: legacy_db_net\n",
		want:     []string{"legacy_db_net"},
		declared: []payload.NetworkDecl{{Name: "legacy_db_net"}},
	}, {
		name: "the driver is kept",
		body: "services:\n  app:\n    image: a\nnetworks:\n  backend:\n    driver: bridge\n",
		want: []string{"media_default"},
		declared: []payload.NetworkDecl{
			{Name: "media_backend", Driver: "bridge"},
		},
	}, {
		name:     "naming the implicit default is not a mistake",
		body:     "services:\n  app:\n    image: a\n    networks: [default]\n",
		want:     []string{"media_default"},
		declared: nil,
	}, {
		// A stack may declare `default: {external: true, name: shared}` and mean it.
		name: "a declared default is honoured",
		body: "services:\n  app:\n    image: a\n" +
			"networks:\n  default:\n    external: true\n    name: shared\n",
		want:     []string{"shared"},
		declared: []payload.NetworkDecl{{Name: "shared", External: true}},
	}, {
		name:  "an undeclared network reads as a network of this project, with a note",
		body:  "services:\n  app:\n    image: a\n    networks: [ghost]\n",
		want:  []string{"media_ghost"},
		notes: []string{`networks: "ghost" is not declared by this compose file; read as a network of this project`},
	}, {
		// §8's `via` is "in the dependent's compose order", so document order is the payload.
		name: "document order is kept",
		body: "services:\n  app:\n    image: a\n    networks: [second, first]\n" +
			"networks:\n  first:\n  second:\n",
		want: []string{"media_second", "media_first"},
		declared: []payload.NetworkDecl{
			{Name: "media_first"}, {Name: "media_second"},
		},
	}, {
		name: "the mapping spelling with per-network options",
		body: "services:\n  app:\n    image: a\n    networks:\n      proxy:\n        aliases: [app]\n" +
			"networks:\n  proxy:\n    external: true\n",
		want:     []string{"proxy"},
		declared: []payload.NetworkDecl{{Name: "proxy", External: true}},
	}, {
		// Deriving a network here would invent one.
		name:  "network_mode replaces compose networking entirely",
		body:  "services:\n  app:\n    image: a\n    network_mode: host\n    networks: [proxy]\n",
		want:  nil,
		notes: []string{`network_mode is "host", so this service joins no compose network`},
	}, {
		name:  "network_mode: service is the same answer",
		body:  "services:\n  app:\n    image: a\n    network_mode: \"service:other\"\n",
		want:  nil,
		notes: []string{`network_mode is "service:other", so this service joins no compose network`},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parse(t, tt.body)
			app := svc(t, f, "app")
			if !reflect.DeepEqual(app.Networks, tt.want) {
				t.Errorf("networks:\n got %#v\nwant %#v", app.Networks, tt.want)
			}
			if tt.declared != nil && !reflect.DeepEqual(f.Networks, tt.declared) {
				t.Errorf("declared:\n got %#v\nwant %#v", f.Networks, tt.declared)
			}
			if !reflect.DeepEqual(app.Notes, tt.notes) {
				t.Errorf("notes:\n got %#v\nwant %#v", app.Notes, tt.notes)
			}
		})
	}
}

func TestDeclaredVolumes(t *testing.T) {
	// Volumes are named by the same rules as networks, which is why one function resolves
	// both: writing it twice is how the two drift apart.
	f := parse(t, `services:
  app:
    image: a
volumes:
  data:
  shared:
    external: true
  renamed:
    name: legacy_vol
  driven:
    driver: local
`)
	want := []payload.VolumeDecl{
		{Name: "media_data"},
		{Name: "media_driven", Driver: "local"},
		{Name: "legacy_vol"},
		{Name: "shared", External: true},
	}
	// Document order, which for this file is data, shared, renamed, driven.
	got := f.Volumes
	byName := map[string]payload.VolumeDecl{}
	for _, v := range got {
		byName[v.Name] = v
	}
	for _, w := range want {
		if got, ok := byName[w.Name]; !ok || got != w {
			t.Errorf("volume %q: got %#v, want %#v", w.Name, got, w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("read %d volumes, want %d: %#v", len(got), len(want), got)
	}
}

// TestPorts pins that the presence of an entry is the signal and the raw text is the
// evidence: no rule anywhere may depend on a parsed port number (§8). Published holds a port
// on its own because §9 matches a tunnel origin's port against published host ports.
func TestPorts(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []payload.PortMapping
	}{{
		name: "container port only publishes nothing addressable by number",
		body: "    ports:\n      - \"8096\"\n",
		want: []payload.PortMapping{{Target: "8096", Protocol: "tcp", Raw: "8096"}},
	}, {
		name: "host:container",
		body: "    ports:\n      - 18096:8096\n",
		want: []payload.PortMapping{{Published: "18096", Target: "8096", Protocol: "tcp", Raw: "18096:8096"}},
	}, {
		// The host address stays in Raw and out of Published, because §9 compares Published
		// against an origin's port and an address is not a port.
		name: "host_ip:host:container",
		body: "    ports:\n      - 127.0.0.1:8080:80\n",
		want: []payload.PortMapping{{Published: "8080", Target: "80", Protocol: "tcp", Raw: "127.0.0.1:8080:80"}},
	}, {
		name: "an explicit protocol",
		body: "    ports:\n      - 1900:1900/udp\n",
		want: []payload.PortMapping{{Published: "1900", Target: "1900", Protocol: "udp", Raw: "1900:1900/udp"}},
	}, {
		name: "a port range is text like any other",
		body: "    ports:\n      - 8000-8005:8000-8005\n",
		want: []payload.PortMapping{{Published: "8000-8005", Target: "8000-8005", Protocol: "tcp", Raw: "8000-8005:8000-8005"}},
	}, {
		name: "the long form, rebuilt into the short spelling as Raw",
		body: "    ports:\n      - target: 80\n        published: \"8080\"\n        protocol: tcp\n        mode: host\n",
		want: []payload.PortMapping{{Published: "8080", Target: "80", Protocol: "tcp", Raw: "8080:80/tcp"}},
	}, {
		name: "the long form with a host address and no protocol",
		body: "    ports:\n      - target: 80\n        published: \"8080\"\n        host_ip: 10.0.0.1\n",
		want: []payload.PortMapping{{Published: "8080", Target: "80", Protocol: "tcp", Raw: "10.0.0.1:8080:80"}},
	}, {
		name: "a substituted port",
		body: "    ports:\n      - ${HOST_PORT:-9000}:9000\n",
		want: []payload.PortMapping{{Published: "9000", Target: "9000", Protocol: "tcp", Raw: "9000:9000"}},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parse(t, "services:\n  app:\n    image: a\n"+tt.body)
			got := svc(t, f, "app").Ports
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ports:\n got %#v\nwant %#v", got, tt.want)
			}
		})
	}
}

func TestExpose(t *testing.T) {
	// `expose:` does not publish, so it is `internal` ingress and nothing more (§8).
	f := parse(t, "services:\n  app:\n    image: a\n    expose:\n      - \"9000\"\n      - 6379\n")
	want := []string{"9000", "6379"}
	if got := svc(t, f, "app").Expose; !reflect.DeepEqual(got, want) {
		t.Errorf("expose: got %#v, want %#v", got, want)
	}
}

func TestMounts(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		want  []payload.MountSpec
		notes []string
	}{{
		name: "an anonymous volume",
		body: "    volumes:\n      - /var/lib/data\n",
		want: []payload.MountSpec{{Type: payload.MountVolume, Target: "/var/lib/data", Raw: "/var/lib/data"}},
	}, {
		// Source is kept exactly as written: `./data` says the operator mounted a directory
		// beside the compose file, and resolving it would replace their statement with this
		// scanner's filesystem (I2).
		name: "a relative bind stays relative",
		body: "    volumes:\n      - ./config:/config\n",
		want: []payload.MountSpec{{Type: payload.MountBind, Source: "./config", Target: "/config", Raw: "./config:/config"}},
	}, {
		name: "an absolute bind, read-only",
		body: "    volumes:\n      - /mnt/media:/media:ro\n",
		want: []payload.MountSpec{{Type: payload.MountBind, Source: "/mnt/media", Target: "/media", ReadOnly: true, Raw: "/mnt/media:/media:ro"}},
	}, {
		name: "a home-relative bind",
		body: "    volumes:\n      - ~/data:/data\n",
		want: []payload.MountSpec{{Type: payload.MountBind, Source: "~/data", Target: "/data", Raw: "~/data:/data"}},
	}, {
		name: "a named volume",
		body: "    volumes:\n      - appdata:/var/lib/app\n",
		want: []payload.MountSpec{{Type: payload.MountVolume, Source: "appdata", Target: "/var/lib/app", Raw: "appdata:/var/lib/app"}},
	}, {
		name: "the docker socket, which is the mount that matters most",
		body: "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock:ro\n",
		want: []payload.MountSpec{{
			Type: payload.MountBind, Source: "/var/run/docker.sock", Target: "/var/run/docker.sock",
			ReadOnly: true, Raw: "/var/run/docker.sock:/var/run/docker.sock:ro",
		}},
	}, {
		name: "a named pipe",
		body: `    volumes:
      - '\\.\pipe\docker_engine:\\.\pipe\docker_engine'
`,
		want: []payload.MountSpec{{
			Type: payload.MountNpipe, Source: `\\.\pipe\docker_engine`, Target: `\\.\pipe\docker_engine`,
			Raw: `\\.\pipe\docker_engine:\\.\pipe\docker_engine`,
		}},
	}, {
		name: "the long form",
		body: "    volumes:\n      - type: bind\n        source: ./data\n        target: /data\n        read_only: true\n",
		want: []payload.MountSpec{{Type: payload.MountBind, Source: "./data", Target: "/data", ReadOnly: true, Raw: "./data:/data:ro"}},
	}, {
		name: "the long form with no type reads it off the source",
		body: "    volumes:\n      - source: appdata\n        target: /data\n",
		want: []payload.MountSpec{{Type: payload.MountVolume, Source: "appdata", Target: "/data", Raw: "appdata:/data"}},
	}, {
		name: "tmpfs",
		body: "    volumes:\n      - type: tmpfs\n        target: /tmp\n",
		want: []payload.MountSpec{{Type: payload.MountTmpfs, Target: "/tmp", Raw: "/tmp"}},
	}, {
		// An unlisted member would be a different protocol to a consumer (§16), so anything
		// outside the closed set reads as `unknown` — which is a member.
		name:  "a type outside the closed set",
		body:  "    volumes:\n      - type: cluster\n        source: vol\n        target: /data\n",
		want:  []payload.MountSpec{{Type: payload.MountUnknown, Source: "vol", Target: "/data", Raw: "vol:/data"}},
		notes: []string{`volumes[0].type: "cluster" is not a mount type; read as unknown`},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parse(t, "services:\n  app:\n    image: a\n"+tt.body)
			app := svc(t, f, "app")
			if !reflect.DeepEqual(app.Mounts, tt.want) {
				t.Errorf("mounts:\n got %#v\nwant %#v", app.Mounts, tt.want)
			}
			if !reflect.DeepEqual(app.Notes, tt.notes) {
				t.Errorf("notes:\n got %#v\nwant %#v", app.Notes, tt.notes)
			}
		})
	}
}

func TestLabels(t *testing.T) {
	t.Run("the list spelling", func(t *testing.T) {
		f := parse(t, `services:
  app:
    image: a
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`+"`app.example.com`"+`)"
      - "bare"
`)
		want := map[string]string{
			"traefik.enable":                "true",
			"traefik.http.routers.app.rule": "Host(`app.example.com`)",
			"bare":                          "",
		}
		if got := svc(t, f, "app").Labels; !reflect.DeepEqual(got, want) {
			t.Errorf("labels:\n got %#v\nwant %#v", got, want)
		}
	})

	t.Run("the mapping spelling, with values that are not strings in YAML", func(t *testing.T) {
		f := parse(t, `services:
  app:
    image: a
    labels:
      traefik.enable: true
      dockflare.port: 8080
      empty:
`)
		// A resolved YAML value is the wrong value: these are text to Compose, and §6 wants
		// the evidence as written.
		want := map[string]string{
			"traefik.enable": "true",
			"dockflare.port": "8080",
			"empty":          "",
		}
		if got := svc(t, f, "app").Labels; !reflect.DeepEqual(got, want) {
			t.Errorf("labels:\n got %#v\nwant %#v", got, want)
		}
	})

	t.Run("a substituted label", func(t *testing.T) {
		f := parse(t, "services:\n  app:\n    image: a\n    labels:\n"+
			"      - \"traefik.http.routers.app.rule=Host(`${DOMAIN}`)\"\n",
			envEntry{Key: "DOMAIN", Value: val("app.example.com")})
		want := "Host(`app.example.com`)"
		if got := svc(t, f, "app").Labels["traefik.http.routers.app.rule"]; got != want {
			t.Errorf("label = %q, want %q", got, want)
		}
	})

	t.Run("a label whose value is a structure", func(t *testing.T) {
		f := parse(t, "services:\n  app:\n    image: a\n    labels:\n      bad:\n        - a\n")
		want := []string{"labels.bad: expected text; ignored"}
		if got := svc(t, f, "app").Notes; !reflect.DeepEqual(got, want) {
			t.Errorf("notes:\n got %#v\nwant %#v", got, want)
		}
	})
}

func TestServiceBasics(t *testing.T) {
	t.Run("the default container name is Compose's own", func(t *testing.T) {
		// It matters: it is one of the two ways a service is matched to a live container
		// (§6) and one of the DNS aliases §9 resolves origins against.
		f := parse(t, "services:\n  app:\n    image: a\n")
		if got := svc(t, f, "app").ContainerName; got != "media-app-1" {
			t.Errorf("container name = %q, want media-app-1", got)
		}
	})

	t.Run("a declared container name wins", func(t *testing.T) {
		f := parse(t, "services:\n  app:\n    image: a\n    container_name: my-app\n")
		if got := svc(t, f, "app").ContainerName; got != "my-app" {
			t.Errorf("container name = %q, want my-app", got)
		}
	})

	t.Run("command in both spellings", func(t *testing.T) {
		one := parse(t, "services:\n  app:\n    image: a\n    command: serve --port 80\n")
		if got := svc(t, one, "app").Command; got != "serve --port 80" {
			t.Errorf("command = %q", got)
		}
		list := parse(t, "services:\n  app:\n    image: a\n    command: [serve, --port, \"80\"]\n")
		if got := svc(t, list, "app").Command; got != "serve --port 80" {
			t.Errorf("command = %q", got)
		}
	})

	t.Run("depends_on in both spellings, in document order", func(t *testing.T) {
		list := parse(t, "services:\n  app:\n    image: a\n    depends_on: [db, cache]\n")
		if got := svc(t, list, "app").DependsOn; !reflect.DeepEqual(got, []string{"db", "cache"}) {
			t.Errorf("depends_on = %#v", got)
		}
		long := parse(t, `services:
  app:
    image: a
    depends_on:
      db:
        condition: service_healthy
      cache:
        condition: service_started
`)
		if got := svc(t, long, "app").DependsOn; !reflect.DeepEqual(got, []string{"db", "cache"}) {
			t.Errorf("depends_on = %#v", got)
		}
	})

	t.Run("services are sorted by name", func(t *testing.T) {
		// Two scans of one tree must produce byte-identical payloads (I7).
		f := parse(t, "services:\n  web:\n    image: a\n  api:\n    image: b\n  db:\n    image: c\n")
		var names []string
		for _, s := range f.Services {
			names = append(names, s.Name)
		}
		if !reflect.DeepEqual(names, []string{"api", "db", "web"}) {
			t.Errorf("services: %#v", names)
		}
	})

	t.Run("restart and image are read", func(t *testing.T) {
		f := parse(t, "services:\n  app:\n    image: nginx:${TAG:-1.27}\n    restart: unless-stopped\n")
		app := svc(t, f, "app")
		if app.Image != "nginx:1.27" || app.Restart != "unless-stopped" {
			t.Errorf("image %q restart %q", app.Image, app.Restart)
		}
	})
}

// TestAnchorsAndMerges covers a spelling real compose files use heavily: an anchor with a
// `<<:` merge. An explicit key wins over a merged one, and the merge itself must be spliced
// rather than read as a key called "<<".
func TestAnchorsAndMerges(t *testing.T) {
	f := parse(t, `x-common: &common
  image: shared:1.0
  restart: always
  networks: [backend]
services:
  app:
    <<: *common
    restart: unless-stopped
networks:
  backend:
`)
	app := svc(t, f, "app")
	if app.Image != "shared:1.0" {
		t.Errorf("image = %q, want the merged value", app.Image)
	}
	if app.Restart != "unless-stopped" {
		t.Errorf("restart = %q, want the explicit value to win", app.Restart)
	}
	if !reflect.DeepEqual(app.Networks, []string{"media_backend"}) {
		t.Errorf("networks = %#v", app.Networks)
	}
}

// TestDegradedDocuments is I4 at the file level: everything a document can get wrong short
// of not being YAML is a warning, and the stack is still there.
func TestDegradedDocuments(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{{
		name: "an empty file",
		body: "",
		want: []string{"the compose file is empty"},
	}, {
		name: "a file that is not a mapping",
		body: "- a\n- b\n",
		want: []string{"the compose file is not a mapping; no services were read"},
	}, {
		name: "no services key",
		body: "networks:\n  backend:\n",
		want: []string{"the compose file declares no services"},
	}, {
		name: "services is not a mapping",
		body: "services:\n  - app\n",
		want: []string{"services: expected a mapping; no services were read"},
	}, {
		name: "one service is not a mapping",
		body: "services:\n  app: image-name\n",
		want: []string{"services.app: expected a mapping; read as an empty service"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parse(t, tt.body)
			if !reflect.DeepEqual(f.Warnings, tt.want) {
				t.Errorf("warnings:\n got %#v\nwant %#v", f.Warnings, tt.want)
			}
			// Whatever went wrong, the project name is still answerable.
			if f.ProjectName != "media" {
				t.Errorf("project = %q, want media", f.ProjectName)
			}
		})
	}

	t.Run("a service with a null body is not a warning", func(t *testing.T) {
		f := parse(t, "services:\n  app:\n")
		if len(f.Warnings) != 0 {
			t.Errorf("warnings: %#v", f.Warnings)
		}
		if got := svc(t, f, "app").ContainerName; got != "media-app-1" {
			t.Errorf("container name = %q", got)
		}
	})

	t.Run("only a YAML error is an error", func(t *testing.T) {
		_, err := parseCompose([]byte("services:\n  app:\n   image: [unclosed\n"), composeInput{StackID: "media"})
		if err == nil {
			t.Fatal("want a parse error")
		}
	})
}

// TestEnv is the assembly order of §6: every `env_file` in order, then `environment:` over
// the top. Getting it backwards would report values the service does not have.
func TestEnv(t *testing.T) {
	dir := stackDir(t, "media", map[string]string{
		"one.env": "SHARED=from-one\nONLY_ONE=1\n",
		"two.env": "SHARED=from-two\nONLY_TWO=2\n",
	})
	f := parseIn(t, dir, `services:
  app:
    image: a
    env_file:
      - one.env
      - two.env
    environment:
      SHARED: from-environment
      FROM_DOTENV: ${DOTENV_VALUE}
      LEFT_TO_SHELL:
      EMPTY: ""
`, envEntry{Key: "DOTENV_VALUE", Value: val("resolved")})

	app := svc(t, f, "app")
	if len(app.Notes) != 0 {
		t.Fatalf("notes: %#v", app.Notes)
	}

	type kv struct {
		key    string
		value  string
		unset  bool
		source payload.EnvVarSource
	}
	want := []kv{
		{key: "EMPTY", value: "", source: payload.EnvFromEnvironment},
		// Resolved out of the stack's .env, so the file pins it even though it is written
		// in the `environment:` block (§4.8).
		{key: "FROM_DOTENV", value: "resolved", source: payload.EnvFromEnvFile},
		{key: "LEFT_TO_SHELL", unset: true, source: payload.EnvFromShellDefault},
		{key: "ONLY_ONE", value: "1", source: payload.EnvFromEnvFile},
		{key: "ONLY_TWO", value: "2", source: payload.EnvFromEnvFile},
		{key: "SHARED", value: "from-environment", source: payload.EnvFromEnvironment},
	}
	if len(app.Env) != len(want) {
		t.Fatalf("read %d variables, want %d: %#v", len(app.Env), len(want), app.Env)
	}
	for i, w := range want {
		got := app.Env[i]
		if got.Key != w.key {
			t.Errorf("entry %d: key = %q, want %q (sorted by key)", i, got.Key, w.key)
			continue
		}
		switch {
		case w.unset && got.Value != nil:
			t.Errorf("%s = %q, want no value at all", w.key, *got.Value)
		case !w.unset && got.Value == nil:
			t.Errorf("%s has no value, want %q", w.key, w.value)
		case !w.unset && *got.Value != w.value:
			t.Errorf("%s = %q, want %q", w.key, *got.Value, w.value)
		}
		if got.Source != w.source {
			t.Errorf("%s source = %q, want %q", w.key, got.Source, w.source)
		}
	}
}

func TestEnvSpellings(t *testing.T) {
	dir := stackDir(t, "media", map[string]string{"local.env": "FROM_FILE=1\n"})

	t.Run("env_file as a scalar", func(t *testing.T) {
		f := parseIn(t, dir, "services:\n  app:\n    image: a\n    env_file: local.env\n")
		app := svc(t, f, "app")
		if len(app.Env) != 1 || app.Env[0].Key != "FROM_FILE" {
			t.Errorf("env: %#v", app.Env)
		}
	})

	t.Run("the long env_file form", func(t *testing.T) {
		f := parseIn(t, dir, "services:\n  app:\n    image: a\n    env_file:\n      - path: local.env\n")
		app := svc(t, f, "app")
		if len(app.Env) != 1 || app.Env[0].Key != "FROM_FILE" {
			t.Errorf("env: %#v", app.Env)
		}
	})

	t.Run("the environment list spelling", func(t *testing.T) {
		f := parseIn(t, dir, "services:\n  app:\n    image: a\n    environment:\n      - A=1\n      - TZ\n")
		app := svc(t, f, "app")
		if len(app.Env) != 2 {
			t.Fatalf("env: %#v", app.Env)
		}
		if app.Env[0].Key != "A" || app.Env[0].Value == nil || *app.Env[0].Value != "1" {
			t.Errorf("A: %#v", app.Env[0])
		}
		// `- TZ` takes whatever the shell had, which this scan cannot see.
		if app.Env[1].Key != "TZ" || app.Env[1].Value != nil ||
			app.Env[1].Source != payload.EnvFromShellDefault {
			t.Errorf("TZ: %#v", app.Env[1])
		}
	})

	t.Run("a variable whose value is a structure", func(t *testing.T) {
		f := parseIn(t, dir, "services:\n  app:\n    image: a\n    environment:\n      BAD:\n        - a\n")
		want := []string{"environment.BAD: expected text; ignored"}
		if got := svc(t, f, "app").Notes; !reflect.DeepEqual(got, want) {
			t.Errorf("notes:\n got %#v\nwant %#v", got, want)
		}
	})

	t.Run("a bare key in an env file is left to the shell", func(t *testing.T) {
		dir := stackDir(t, "media", map[string]string{"bare.env": "TZ\n"})
		f := parseIn(t, dir, "services:\n  app:\n    image: a\n    env_file: bare.env\n")
		app := svc(t, f, "app")
		if len(app.Env) != 1 || app.Env[0].Value != nil ||
			app.Env[0].Source != payload.EnvFromShellDefault {
			t.Errorf("env: %#v", app.Env)
		}
	})
}

// TestEnvFileRefusals is the containment check of §6 at the one place a file in the tree
// names a file to read. A refusal surfaces as a service note, never as silence.
func TestEnvFileRefusals(t *testing.T) {
	dir := stackDir(t, "media", map[string]string{
		"local.env": "INSIDE=1\n",
	})
	// The file the escape aims at, one level above the scan root.
	outside := filepath.Join(dir, "..", "..", "outside.env")
	if err := os.WriteFile(outside, []byte("LEAKED_FROM_OUTSIDE_ROOT=no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "adirectory.env"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked.env")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		body  string
		notes []string
	}{{
		name:  "a lexical escape",
		body:  "    env_file:\n      - local.env\n      - ../../outside.env\n",
		notes: []string{`env_file[1]: "../../outside.env" is outside the scan root; not read`},
	}, {
		name:  "a symlinked escape",
		body:  "    env_file: linked.env\n",
		notes: []string{`env_file: "linked.env" is outside the scan root; not read`},
	}, {
		name:  "an absolute path outside the root",
		body:  "    env_file: /etc/shadow\n",
		notes: []string{`env_file: "/etc/shadow" is outside the scan root; not read`},
	}, {
		name:  "a file that is not there",
		body:  "    env_file: missing.env\n",
		notes: []string{`env_file: "missing.env" could not be read; ignored`},
	}, {
		name:  "a directory",
		body:  "    env_file: adirectory.env\n",
		notes: []string{`env_file: "adirectory.env" is a directory; ignored`},
	}, {
		// `required: false` says the operator meant this to be optional and Compose starts
		// the stack without it, so nothing went wrong and nothing is reported.
		name:  "an optional file that is not there",
		body:  "    env_file:\n      - path: missing.env\n        required: false\n",
		notes: nil,
	}, {
		name:  "the long form still reports a required file",
		body:  "    env_file:\n      - path: missing.env\n        required: true\n",
		notes: []string{`env_file[0]: "missing.env" could not be read; ignored`},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseIn(t, dir, "services:\n  app:\n    image: a\n"+tt.body)
			app := svc(t, f, "app")
			if !reflect.DeepEqual(app.Notes, tt.notes) {
				t.Errorf("notes:\n got %#v\nwant %#v", app.Notes, tt.notes)
			}
			for _, e := range app.Env {
				if strings.HasPrefix(e.Key, "LEAKED") {
					t.Errorf("a refused file was read: %q", e.Key)
				}
			}
		})
	}
}

func TestEnvFileOverSize(t *testing.T) {
	// No legitimate environment file is a megabyte, and an unbounded read of a file named by
	// a file is a hazard whatever the format (I8). Over the limit the file is not read at
	// all rather than truncated: half an environment file is a set of values nobody had.
	dir := stackDir(t, "media", nil)
	big := "BIG=" + strings.Repeat("x", maxEnvFileBytes) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "big.env"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	f := parseIn(t, dir, "services:\n  app:\n    image: a\n    env_file: big.env\n")
	app := svc(t, f, "app")
	want := []string{`env_file: "big.env" is larger than 1 MiB; ignored`}
	if !reflect.DeepEqual(app.Notes, want) {
		t.Errorf("notes:\n got %#v\nwant %#v", app.Notes, want)
	}
	if len(app.Env) != 0 {
		t.Errorf("env: %#v", app.Env)
	}
}
