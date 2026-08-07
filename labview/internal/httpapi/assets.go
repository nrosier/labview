package httpapi

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/nrosier/labview/internal/access"
)

// The UI (§18: `GET /*` — the embedded UI, with a single-page fallback to the index document).
//
// **The API does not depend on any of this.** The asset filesystem may be nil and every route above
// answers identically, because a build whose bundle failed to embed is a build that can still tell an
// operator what it can see. That is the requirement; this file is the half that can be absent.

// IndexFile is the single-page application's document.
const IndexFile = "index.html"

// assetFile serves one asset, or the index document for a UI route that is not a file.
func (s *Server) assetFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// HEAD as well as GET, because a HEAD is how a health checker asks whether the UI is there and
		// refusing it would make the shell look absent. Everything else is refused: nothing is posted to
		// the UI, and a POST answered with the index document is a POST silently treated as a page load.
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Normalised again here rather than trusted from the gate, because this handler is registered on the
	// router and a caller composing the router without the gate must not be able to reach the filesystem
	// with a path this program refuses to interpret (§19).
	normalised, ok := access.Normalise(r.URL.Path)
	if !ok {
		writeError(w, http.StatusBadRequest, "the request path could not be normalised")
		return
	}

	if s.files == nil {
		// A build with no assets. JSON, so the answer is machine-readable everywhere on this server, and
		// a sentence that says which half is missing — an operator seeing this has a working API and no
		// UI, and *not found* alone would send them looking for a route.
		writeError(w, http.StatusNotFound, "no user interface is embedded in this build")
		return
	}

	name := strings.TrimPrefix(normalised, "/")
	if name == "" {
		name = IndexFile
	}

	if name == IndexFile {
		// A request *for* the document is answered with it. net/http's file handler answers
		// `/index.html` with a 301 to `./`, which a browser follows to the same bytes — a round trip
		// for nothing, and a redirect where a document was asked for.
		s.serveShell(w, r)
		return
	}

	if regular(s.assets, name) {
		s.files.ServeHTTP(w, r)
		return
	}

	// **The single-page fallback**, and the condition is the whole of it: a path with no extension is a
	// UI route — `/stack/media`, `/diagnostics` — and a browser asking for one wants the shell, which
	// will read the path and render it. A path *with* an extension is an asset request, and answering it
	// with HTML is the failure mode this test exists to prevent: a bundle that failed to embed would be
	// served as `index.html` with a JavaScript content type, and the browser would report a syntax error
	// in a file that does not exist.
	if path.Ext(name) != "" {
		writeError(w, http.StatusNotFound, "no such file")
		return
	}

	s.serveShell(w, r)
}

// serveShell answers with the index document.
//
// It rewrites the path to the root rather than to `/index.html`, because net/http's file handler answers
// a request *for* `index.html` with a redirect to `./` — so naming the document would send a 301 where
// the document belongs. A directory request is answered with its index, which is the same bytes by a
// route that does not redirect.
func (s *Server) serveShell(w http.ResponseWriter, r *http.Request) {
	if !regular(s.assets, IndexFile) {
		// There is no document, and the root of the filesystem must not be served in its place: net/http
		// answers a directory that holds no index with a **listing**, and a listing of the bundle is a
		// description of the build that nobody asked this server to publish.
		writeError(w, http.StatusNotFound, "no such file")
		return
	}

	shell := r.Clone(r.Context())
	shell.URL.Path = "/"
	shell.URL.RawPath = ""
	s.files.ServeHTTP(w, shell)
}

// regular reports whether name is a file in this filesystem.
//
// A directory is not one, which is how directory listings stay unreachable: net/http's file handler
// renders a listing for a directory, and a listing of the asset bundle is a description of the build
// that nobody asked this server to publish. It reaches the SPA fallback instead.
func regular(fsys fs.FS, name string) bool {
	if fsys == nil || !fs.ValidPath(name) {
		return false
	}
	info, err := fs.Stat(fsys, name)
	return err == nil && info.Mode().IsRegular()
}
