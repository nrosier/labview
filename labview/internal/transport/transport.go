// Package transport is the one HTTP chokepoint. Every outbound request in the program — the three
// Docker reads, Authentik, Traefik, the probe and the OIDC issuer — is issued through it.
//
// Being the only way out is what makes I8's bounds checkable: the time budget, the 64 KiB body cap
// and the number of requests in flight are single numbers rather than a convention repeated at six
// call sites. It is also what makes the phase taxonomy single-valued — this package owns the elapsed
// time and the budget, so it is the only thing that *can* classify a transport error (§15), and a
// caller receives a phase it did not derive.
//
// Two structural refusals live here rather than in a rule a reader has to remember:
//
//   - Certificate verification cannot be switched off. There is no option, no environment variable
//     and no field (§21). An operator with a self-signed certificate adds the CA; the alternative is
//     a program that silently accepts an interception of every credential it holds.
//   - Anonymous takes no headers. The probe calls it, so no call path into the probe's fetch has a
//     credential in scope — which is §13's requirement that the probe send none *and not by
//     omission*. A rule that said "remember not to pass the token" would be a rule; a signature with
//     nowhere to put it is a guarantee.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
)

// BodyCap is the 64 KiB every network read in the program shares (I8, §13.6). It is one constant
// because two of them drift: a probe that read 64 KiB and an API that read 128 would make the
// truncation note mean different things in two panels of the same payload.
const BodyCap = 64 << 10

// AttemptCap is the number of rejected candidates a report keeps (§13.6). Discovery that tried
// forty addresses is a diagnosis nobody reads; the first eight are the diagnosis.
const AttemptCap = 8

// UserAgent identifies the reader to whatever it reads. It carries no fleet identifier and no
// version of anything on the far side — a scan is recognisable in a log without being a fingerprint
// of the host it ran on (I2).
const UserAgent = "labview"

// Options configures one client. There is deliberately no field that weakens TLS, no field that
// removes the body cap and no field that follows a redirect.
type Options struct {
	// Timeout is the per-request budget. Zero takes DefaultTimeout.
	Timeout time.Duration

	// MaxConcurrency bounds requests in flight through this client. Zero takes
	// DefaultConcurrency; a negative value means unbounded and exists only so a caller that
	// genuinely wants one request at a time is not forced to reason about the default.
	MaxConcurrency int

	// Endpoint is the credential-free endpoint this client talks to, for the reports its results
	// feed. When empty each result derives one from its own URL — which is right for the probe,
	// where every request goes somewhere else, and wrong for Docker, where every request goes to
	// one socket that is not in any URL.
	Endpoint string

	// UnixSocket makes every request dial this path instead of resolving the URL's host. The URL's
	// host then names nothing and is only there because HTTP requires one.
	UnixSocket string

	// RoundTripper replaces the real transport. This is how the corpus runs the whole pipeline with
	// no network (§23): the bounds, the classification and the body cap are all still this
	// package's, and only the bytes are the test's.
	RoundTripper http.RoundTripper

	// Now measures elapsed time. It is injected because the phase depends on it — a teardown at the
	// budget is `timeout` and the same teardown early is `connect` — and I7 requires a phase to be
	// reproducible. The deadline itself is real time regardless: a fake clock cannot make a socket
	// give up.
	Now func() time.Time
}

// The defaults §3.1 states for a target that names none of its own.
const (
	DefaultTimeout     = 3000 * time.Millisecond
	DefaultConcurrency = 8
)

// Client is one configured way out.
type Client struct {
	http     *http.Client
	budget   time.Duration
	endpoint string
	limit    chan struct{}
	now      func() time.Time
}

// New builds a client. It never fails: an unusable configuration produces a client whose every
// request reports a phase, because a constructor that returned an error would give each of the five
// readers its own way of describing the same failure (I4).
func New(o Options) *Client {
	budget := o.Timeout
	if budget <= 0 {
		budget = DefaultTimeout
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}

	var limit chan struct{}
	switch {
	case o.MaxConcurrency > 0:
		limit = make(chan struct{}, o.MaxConcurrency)
	case o.MaxConcurrency == 0:
		limit = make(chan struct{}, DefaultConcurrency)
	}

	rt := o.RoundTripper
	if rt == nil {
		rt = realTransport(o.UnixSocket)
	}

	return &Client{
		http: &http.Client{
			Transport: rt,
			// No redirect is ever followed. For the probe, where a 3xx points *is* the evidence and
			// following it would destroy the reading (§13.3). For an API, a 3xx means the API was
			// not read, and following one is how a request for a JSON document arrives at a login
			// page carrying a 200 (§15).
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			// No jar. A cookie set by one read is not carried into another by default: Traefik's
			// authenticated retry replays its own cookies within one exchange (§12), and that is
			// the only place a cookie should survive a response.
			Jar: nil,
		},
		budget:   budget,
		endpoint: o.Endpoint,
		limit:    limit,
		now:      now,
	}
}

// realTransport is the only place a *http.Transport is built, and the only place TLS is configured.
//
// TLSClientConfig sets a floor and nothing else. InsecureSkipVerify is not set to false here — it is
// not mentioned, which is a stronger statement: there is no line in this program that assigns it, so
// there is no line to flip (§21).
func realTransport(socket string) http.RoundTripper {
	t := &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:     false,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
		// No proxy from the environment. A homelab's HTTP_PROXY is for reaching the internet, and
		// routing a read of the Docker socket's neighbour through it would both fail and leak the
		// fleet's internal addresses to whatever the proxy is (I2).
		Proxy: nil,
	}
	if socket != "" {
		d := &net.Dialer{Timeout: 2 * time.Second}
		t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", socket)
		}
		// Nothing over a unix socket is TLS, and the host in the URL names nothing.
		t.TLSClientConfig = nil
	}
	return t
}

// Request is one credentialed read. Header is a map rather than an http.Header because a reader sets
// one value per name — and because the diagnostic that reports what was sent reports the *names*
// (I6), which a map makes trivially available.
type Request struct {
	Method string // GET, or POST for the OIDC token exchange only. Anything else is refused.
	URL    string
	Header map[string]string
	Body   []byte

	// Cookies are replayed within one exchange. Traefik's authenticated retry is the only caller
	// (§12): a session cookie set by a challenge is sent back on the retry, and it is not kept
	// anywhere afterwards.
	Cookies []*http.Cookie
}

// Result is one attempt's whole outcome. The phase is already classified, because this package owns
// the two facts the classification needs — the elapsed time and the budget — and a caller that
// re-derived it would be a second definition of `timeout` (§15).
type Result struct {
	Phase   payload.ConnectionPhase
	Code    string
	Err     error
	Status  int
	Header  http.Header
	Body    []byte
	Cookies []*http.Cookie

	// Truncated is set when the body reached the cap. The reading is still used — a truncated HTML
	// page carries its login form in the first 64 KiB or the page is not a login page — and the
	// fact that it was cut is reported rather than assumed away.
	Truncated bool

	Elapsed  time.Duration
	Endpoint string

	// Sent is the sorted names of the headers this request carried, and never their values. It is
	// what a diagnostic says about a credential (I6).
	Sent []string
}

// OK reports whether this result is usable. It is conn's definition and not a second one.
func (r Result) OK() bool { return conn.OK(r.Phase) }

// ErrMethod is the refusal that keeps the program read-only. GET is every fleet read; POST exists
// for the OIDC token exchange, which is a conversation with an identity provider and not a write to
// anything scanned. A PUT, PATCH or DELETE has no caller, so the chokepoint refuses one rather than
// leaving the capability lying around (I5).
var ErrMethod = errors.New("this transport issues GET, and POST only to an identity provider")

// Do issues one credentialed request.
func (c *Client) Do(ctx context.Context, req Request) Result {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost {
		return Result{
			Phase:    payload.PhaseNotConfigured,
			Err:      ErrMethod,
			Endpoint: c.endpointFor(req.URL),
			Sent:     headerNames(req.Header),
		}
	}
	return c.do(ctx, method, req)
}

// Anonymous issues one GET with no credential of any kind.
//
// The signature is the guarantee: there is no parameter for a header, a cookie, a body or a query
// string, so a call path into it cannot carry a credential even by accident. §13 asks for exactly
// this — *no credential, and not by omission* — and a reviewer can confirm it by reading one line
// rather than by tracing every caller.
//
// The query string is dropped rather than refused. An address assembled from a redirect URI can
// carry one, and a probe that skipped such a service would report *no answer* where the truth is
// that it declined to ask (I1).
func (c *Client) Anonymous(ctx context.Context, rawURL string) Result {
	return c.do(ctx, http.MethodGet, Request{URL: stripQuery(rawURL)})
}

func (c *Client) do(ctx context.Context, method string, req Request) Result {
	res := Result{
		Endpoint: c.endpointFor(req.URL),
		Sent:     headerNames(req.Header),
	}

	// The bound on requests in flight, taken before the clock starts: waiting for a slot is not
	// time the far end took to answer, and charging it to the budget would report a busy scan as a
	// fleet of timeouts.
	if err := c.acquire(ctx); err != nil {
		res.Phase = conn.FromError(err, 0, 0)
		res.Err = err
		return res
	}
	defer c.release()

	// The deadline is real time. A fake clock cannot make a socket give up, so this is the one place
	// an injected clock would be a lie; the measurement below is injected instead, because the
	// phase depends on the measurement and I7 requires the phase to be reproducible.
	ctx, cancel := context.WithTimeout(ctx, c.budget)
	defer cancel()

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	r, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		// A URL this program assembled and cannot parse is a configuration fault, not a network
		// one: nothing was dialled, so there is nothing to report a network phase about.
		res.Phase = payload.PhaseNotConfigured
		res.Err = err
		return res
	}
	r.Header.Set("User-Agent", UserAgent)
	for name, value := range req.Header {
		r.Header.Set(name, value)
	}
	for _, cookie := range req.Cookies {
		r.AddCookie(cookie)
	}

	start := c.now()
	resp, err := c.http.Do(r)
	res.Elapsed = c.now().Sub(start)
	if err != nil {
		res.Phase = conn.FromError(err, res.Elapsed, c.budget)
		res.Err = err
		return res
	}
	defer resp.Body.Close()

	res.Status = resp.StatusCode
	res.Code = conn.Code(resp.StatusCode)
	res.Header = resp.Header
	res.Cookies = resp.Cookies()
	res.Phase = conn.FromStatus(resp.StatusCode)

	// The body is read whatever the status. A 401's body says which realm; a 403's says which
	// permission; and a reader that only read 2xx bodies would have nothing to put in the detail of
	// the failures that most need one.
	res.Body, res.Truncated, err = readCapped(resp.Body)
	if err != nil {
		// The status already arrived, so the phase it produced stands unless the read itself failed
		// — and a read that failed mid-body is a connection fault, not a status one.
		res.Phase = conn.FromError(err, res.Elapsed, c.budget)
		res.Err = err
	}
	return res
}

// readCapped reads at most BodyCap bytes and says whether there were more.
//
// It reads one byte past the cap in order to know. Without that byte a body of exactly 64 KiB and a
// body of a megabyte are indistinguishable, and the truncation note would either be missing on the
// second or invented on the first.
func readCapped(r io.Reader) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r, BodyCap+1))
	if len(body) > BodyCap {
		// The stream is abandoned at the cap: whatever is still coming is not read, and the caller's
		// deferred Close cancels it (I8).
		return body[:BodyCap], true, nil
	}
	return body, false, err
}

func (c *Client) acquire(ctx context.Context) error {
	if c.limit == nil {
		return nil
	}
	select {
	case c.limit <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) release() {
	if c.limit != nil {
		<-c.limit
	}
}

func (c *Client) endpointFor(rawURL string) string {
	if c.endpoint != "" {
		return c.endpoint
	}
	return Endpoint(rawURL)
}

// headerNames is the sorted names of what was sent, and never a value (I6). Sorted because it ends
// up in a payload, and I7 does not exempt a diagnostic.
func headerNames(h map[string]string) []string {
	if len(h) == 0 {
		return nil
	}
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, http.CanonicalHeaderKey(name))
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// The one credential-free endpoint formatter
// ---------------------------------------------------------------------------

// Endpoint is the single formatter every endpoint field in the payload comes from (§20).
//
// It removes the three things that carry a credential: userinfo, the query string and the fragment.
// A token in a query string is the common accident — `?token=…` is how half the world's APIs are
// documented — and the query says nothing a reader of a connection report needs.
//
// The path is kept, because *which* path answered is often the whole diagnosis: an Authentik URL
// pointed at `/if/admin/` and one pointed at the API root fail differently and are told apart by
// nothing else.
//
// All userinfo goes, including a bare username with no password — which is where this parts company
// with secrets.RedactURIs. There a username is evidence about how a service is configured and is
// kept. Here it is not part of the address that answered, and `http://<apikey>@host` with no
// password is a real way to pass a token, so the shape that looks least like a credential is the one
// that most often is one.
//
// A string that will not parse is not passed through. It is replaced, because an unparseable URL is
// exactly where a credential would survive a formatter that gave up.
func Endpoint(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if strings.HasPrefix(rawURL, "unix://") || strings.HasPrefix(rawURL, "/") {
		// A socket path has no authority to strip and no query to drop. It is not a URL and is not
		// treated as one.
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "(unparseable endpoint withheld)"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return strings.TrimSuffix(u.String(), "/")
}

// Origin is the endpoint reduced to scheme and authority. It is what the probe's cross-origin test
// compares (§13.3) and what an attempt list shows when the path is not the point.
func Origin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// SameOrigin is the one comparison behind `redirect-origin`, the meta refresh and the media-type
// reading (§13.6 requires all three to share it). Scheme and authority, compared as written: a
// service reached as `http://x:8080` and redirecting to `https://x:8080` has sent the reader
// somewhere else, and calling that the same origin would lose the strongest gate signal there is.
func SameOrigin(a, b string) bool {
	oa, ob := Origin(a), Origin(b)
	return oa != "" && oa == ob
}

func stripQuery(rawURL string) string {
	if i := strings.IndexAny(rawURL, "?#"); i >= 0 {
		return rawURL[:i]
	}
	return rawURL
}
