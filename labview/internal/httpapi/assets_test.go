package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// The bundle a build embeds: a document, a hashed script, a stylesheet and an icon. Nothing here is a
// fixture of any fleet — it is the shape of §22's output, which is what this file is about.
const (
	shellHTML  = `<!doctype html><title>LabView</title><div id="app"></div><script src="/assets/app-4f2c.js"></script>`
	scriptJS   = `export const view = () => "the dashboard";`
	styleCSS   = `:root{color-scheme:dark light}`
	iconSVG    = `<svg xmlns="http://www.w3.org/2000/svg"/>`
	listingBit = "app-4f2c.js"
)

func bundle() fstest.MapFS {
	return fstest.MapFS{
		IndexFile:                 {Data: []byte(shellHTML)},
		"assets/app-4f2c.js":      {Data: []byte(scriptJS)},
		"assets/app-4f2c.css":     {Data: []byte(styleCSS)},
		"favicon.svg":             {Data: []byte(iconSVG)},
		"assets/nested/deep.json": {Data: []byte(`{"depth":2}`)},
	}
}

// An embedded file is served as itself, with the type its extension implies. The hashed name is the whole
// point of a hashed name: it is served byte for byte or not at all.
func TestAnEmbeddedAssetIsServedAsItself(t *testing.T) {
	l := newLab(t, labOptions{assets: bundle()})

	for _, tc := range []struct{ path, body, kind string }{
		{"/assets/app-4f2c.js", scriptJS, "javascript"},
		{"/assets/app-4f2c.css", styleCSS, "css"},
		{"/favicon.svg", iconSVG, "svg"},
		{"/assets/nested/deep.json", `{"depth":2}`, "json"},
	} {
		rec := l.do(get(tc.path))

		if rec.Code != http.StatusOK {
			t.Fatalf("%s answered %d: %s", tc.path, rec.Code, rec.Body.String())
		}
		if rec.Body.String() != tc.body {
			t.Fatalf("%s answered %q, want the embedded bytes", tc.path, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); !strings.Contains(got, tc.kind) {
			t.Fatalf("%s was served as %q, want something containing %q", tc.path, got, tc.kind)
		}
	}
}

// §18: a single-page fallback to the index document. A UI route is a path with no extension, and the
// browser asking for one wants the shell, which will read the path and render it.
func TestAUIRouteIsAnsweredWithTheShell(t *testing.T) {
	l := newLab(t, labOptions{assets: bundle()})

	for _, path := range []string{"/", "/stacks", "/stack/media-library", "/diagnostics", "/settings/access"} {
		rec := l.do(get(path))

		if rec.Code != http.StatusOK {
			t.Fatalf("%s answered %d, want the shell", path, rec.Code)
		}
		if rec.Body.String() != shellHTML {
			t.Fatalf("%s answered %q", path, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
			t.Fatalf("%s was served as %q", path, got)
		}
	}
}

// The document by name is the document, not a redirect to it. net/http's file handler answers
// `/index.html` with a 301 to `./`, and a bookmark of the shell should not cost a round trip.
func TestTheIndexByNameIsTheDocumentAndNotARedirect(t *testing.T) {
	l := newLab(t, labOptions{assets: bundle()})

	rec := l.do(get("/" + IndexFile))

	if rec.Code != http.StatusOK {
		t.Fatalf("/%s answered %d (Location %q)", IndexFile, rec.Code, rec.Header().Get("Location"))
	}
	if rec.Body.String() != shellHTML {
		t.Fatalf("/%s answered %q", IndexFile, rec.Body.String())
	}
}

// **The failure this asserts against is a bundle served as HTML.** A missing file whose name has an
// extension is a 404, because answering an asset request with the index document makes the browser report
// a syntax error in a file that does not exist — and an operator debugging that reads the shell's HTML in
// a stack trace about JavaScript.
func TestAMissingAssetIsRefusedRatherThanAnsweredWithTheShell(t *testing.T) {
	l := newLab(t, labOptions{assets: bundle()})

	for _, path := range []string{
		"/assets/app-0000.js",
		"/assets/app-4f2c.js.map",
		"/favicon.ico",
		"/assets/nested/missing.json",
		"/robots.txt",
	} {
		rec := l.do(get(path))

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d, want 404", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "<div id=\"app\">") {
			t.Fatalf("%s was answered with the shell", path)
		}
		if got := rec.Header().Get("Content-Type"); got != ContentTypeJSON {
			t.Fatalf("%s answered as %q, want JSON", path, got)
		}
		var reply errorReply
		decode(t, rec, &reply)
		if reply.Error != "no such file" {
			t.Fatalf("%s answered %q", path, reply.Error)
		}
	}
}

// A directory is never listed. net/http's file handler renders a listing for one, and a listing of the
// bundle is a description of the build that nobody asked this server to publish — so a directory reaches
// the single-page fallback instead.
func TestADirectoryIsNotListed(t *testing.T) {
	l := newLab(t, labOptions{assets: bundle()})

	for _, path := range []string{"/assets", "/assets/", "/assets/nested"} {
		rec := l.do(get(path))

		if strings.Contains(rec.Body.String(), listingBit) && !strings.Contains(rec.Body.String(), "<div id=\"app\">") {
			t.Fatalf("%s was answered with a directory listing: %s", path, rec.Body.String())
		}
		if rec.Code != http.StatusOK || rec.Body.String() != shellHTML {
			t.Fatalf("%s answered %d %q, want the shell", path, rec.Code, rec.Body.String())
		}
	}
}

// §18: **the API MUST NOT depend on the presence of UI assets.** A build whose bundle failed to embed can
// still tell an operator what it can see, so every API route answers identically and the UI says which
// half is missing.
func TestWithNoAssetsEmbeddedTheAPIIsUnaffected(t *testing.T) {
	l := newLab(t, labOptions{assets: nil})

	if got := overviewOf(t, l.do(get("/api/overview"))); got.Stats.Stacks != 1 {
		t.Fatalf("the overview read build %d with no UI embedded", got.Stats.Stacks)
	}
	if rec := l.do(get("/api/healthz")); rec.Code != http.StatusOK {
		t.Fatalf("healthz answered %d with no UI embedded", rec.Code)
	}

	for _, path := range []string{"/", "/stacks", "/assets/app-4f2c.js"} {
		rec := l.do(get(path))

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d with no UI embedded", path, rec.Code)
		}
		var reply errorReply
		decode(t, rec, &reply)
		if !strings.Contains(reply.Error, "user interface") {
			t.Fatalf("%s answered %q; it must say which half of the build is missing", path, reply.Error)
		}
	}
}

// A bundle with no index document: every asset in it is still served, and a UI route is refused rather
// than answered with nothing. The shell is what a route needs, and it is not there.
func TestABundleWithNoIndexStillServesItsAssets(t *testing.T) {
	l := newLab(t, labOptions{assets: fstest.MapFS{
		"assets/app-4f2c.js": {Data: []byte(scriptJS)},
	}})

	if rec := l.do(get("/assets/app-4f2c.js")); rec.Code != http.StatusOK {
		t.Fatalf("the one embedded asset answered %d", rec.Code)
	}
	for _, path := range []string{"/", "/stacks"} {
		if rec := l.do(get(path)); rec.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d with no index document embedded", path, rec.Code)
		}
	}
}

// HEAD is how a health checker asks whether the UI is there, so it is answered — refusing it would make
// the shell look absent. The body is not sent, which is net/http's business and is asserted here because
// a shell that arrived as a body on a HEAD would be a shell nobody could cache correctly.
func TestAHeadRequestForTheShellIsAnswered(t *testing.T) {
	l := newLab(t, labOptions{assets: bundle()})

	for _, path := range []string{"/", "/stacks", "/assets/app-4f2c.js"} {
		rec := l.do(httptest.NewRequest(http.MethodHead, path, nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("HEAD %s answered %d", path, rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("HEAD %s carried a body of %d bytes", path, rec.Body.Len())
		}
	}
}

// Anything else is refused. Nothing is written to the UI, and a POST answered with the index document is
// a POST silently treated as a page load.
func TestTheUIRefusesEveryMethodButGetAndHead(t *testing.T) {
	l := newLab(t, labOptions{assets: bundle()})

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		r := httptest.NewRequest(method, "/", nil)
		r.Header.Set("Origin", "http://"+r.Host)
		rec := l.do(r)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s / answered %d, want 405", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
			t.Fatalf("%s / allows %q", method, got)
		}
	}
}

// §19's path rules apply to the UI too: a traversal is refused rather than resolved, and it never reaches
// the filesystem. The escaped form matters as much as the plain one — a handler that decoded before
// checking would refuse the first and serve the second.
func TestATraversalUnderTheUIIsRefusedAndReachesNoFile(t *testing.T) {
	l := newLab(t, labOptions{assets: bundle()})

	for _, path := range []string{
		"/../index.html",
		"/assets/../../index.html",
		"/assets/%2e%2e/%2e%2e/index.html",
		"/assets/..%2f..%2findex.html",
	} {
		rec := l.do(get(path))

		if rec.Code == http.StatusOK {
			t.Fatalf("%s answered 200: %s", path, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "<div id=\"app\">") {
			t.Fatalf("%s reached a file", path)
		}
	}
}
