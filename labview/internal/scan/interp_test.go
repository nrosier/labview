package scan

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nrosier/labview/internal/payload"
)

// The vars every case reads unless it says otherwise. SET_EMPTY is the one that separates
// the two spellings of each operator: `:-` and `:?` treat set-but-empty as missing, the
// bare forms treat it as a value.
var interpVars = map[string]string{
	"TAG":       "1.27.2",
	"HOST":      "app.example.com",
	"SET_EMPTY": "",
}

func TestExpand(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  string
		src   payload.EnvVarSource
		notes []string
	}{
		// ---- the five forms of §6, plus $$ ----------------------------------------
		{
			name: "no substitution at all",
			in:   "nginx:1.27-alpine",
			want: "nginx:1.27-alpine",
			src:  payload.EnvFromEnvironment,
		}, {
			name: "${VAR}",
			in:   "nginx:${TAG}",
			want: "nginx:1.27.2",
			src:  payload.EnvFromEnvFile,
		}, {
			name: "$VAR, the braceless form Compose also accepts",
			in:   "nginx:$TAG",
			want: "nginx:1.27.2",
			src:  payload.EnvFromEnvFile,
		}, {
			name: "${VAR:-default} with the variable set",
			in:   "${TAG:-fallback}",
			want: "1.27.2",
			src:  payload.EnvFromEnvFile,
		}, {
			name: "${VAR:-default} with the variable missing",
			in:   "${MISSING:-fallback}",
			want: "fallback",
			src:  payload.EnvFromShellDefault,
		}, {
			name: "${VAR:-default} treats set-but-empty as missing",
			in:   "${SET_EMPTY:-fallback}",
			want: "fallback",
			src:  payload.EnvFromShellDefault,
		}, {
			name: "${VAR-default} treats set-but-empty as a value",
			in:   "[${SET_EMPTY-fallback}]",
			want: "[]",
			src:  payload.EnvFromEnvFile,
		}, {
			name: "${VAR-default} with the variable missing",
			in:   "${MISSING-fallback}",
			want: "fallback",
			src:  payload.EnvFromShellDefault,
		}, {
			name: "${VAR:?err} with the variable set",
			in:   "${TAG:?tag is required}",
			want: "1.27.2",
			src:  payload.EnvFromEnvFile,
		}, {
			// Compose refuses to start the stack here. LabView reports it and carries on: a
			// whole fleet is not withheld over one stack's missing variable (I4).
			name:  "${VAR:?err} with the variable missing",
			in:    "${MISSING:?tag is required}",
			want:  "${MISSING:?tag is required}",
			src:   payload.EnvFromShellDefault,
			notes: []string{"image: ${MISSING} is required and not set: tag is required; left as written"},
		}, {
			name:  "${VAR:?} with no message",
			in:    "${MISSING:?}",
			want:  "${MISSING:?}",
			src:   payload.EnvFromShellDefault,
			notes: []string{"image: ${MISSING} is required and not set; left as written"},
		}, {
			name:  "${VAR?err} with the variable missing",
			in:    "${MISSING?gone}",
			want:  "${MISSING?gone}",
			src:   payload.EnvFromShellDefault,
			notes: []string{"image: ${MISSING} is required and not set: gone; left as written"},
		}, {
			name: "${VAR?err} treats set-but-empty as a value",
			in:   "[${SET_EMPTY?gone}]",
			want: "[]",
			src:  payload.EnvFromEnvFile,
		}, {
			name: "$$ is an escaped dollar and never a reference",
			in:   "cost is $$5 per unit",
			want: "cost is $5 per unit",
			src:  payload.EnvFromEnvironment,
		}, {
			name: "$$TAG is a literal dollar followed by text",
			in:   "$$TAG",
			want: "$TAG",
			src:  payload.EnvFromEnvironment,
		}, {
			name: "a dollar that begins nothing is a dollar sign",
			in:   "100$ or 50$",
			want: "100$ or 50$",
			src:  payload.EnvFromEnvironment,
		},

		// ---- the unresolved reference, which is a note and never a failure (I4) ----
		{
			name:  "an unset variable is left as written",
			in:    "nginx:${MISSING}",
			want:  "nginx:${MISSING}",
			src:   payload.EnvFromShellDefault,
			notes: []string{"image: ${MISSING} is not set in this stack's .env; left as written"},
		}, {
			name:  "an unset braceless variable",
			in:    "nginx:$MISSING",
			want:  "nginx:$MISSING",
			src:   payload.EnvFromShellDefault,
			notes: []string{"image: ${MISSING} is not set in this stack's .env; left as written"},
		}, {
			name: "two unset variables produce two notes, in order",
			in:   "${A_MISSING}:${B_MISSING}",
			want: "${A_MISSING}:${B_MISSING}",
			src:  payload.EnvFromShellDefault,
			notes: []string{
				"image: ${A_MISSING} is not set in this stack's .env; left as written",
				"image: ${B_MISSING} is not set in this stack's .env; left as written",
			},
		},

		// ---- nesting ---------------------------------------------------------------
		{
			name: "a nested default is evaluated when it is reached",
			in:   "nginx:${IMAGE_TAG:-${TAG:-1.27-alpine}}",
			want: "nginx:1.27.2",
			src:  payload.EnvFromEnvFile,
		}, {
			// `${A:-${B}}` takes B's source because B supplied every character of the value.
			name: "a default that is exactly one reference takes that reference's source",
			in:   "${MISSING:-${TAG}}",
			want: "1.27.2",
			src:  payload.EnvFromEnvFile,
		}, {
			// `${A:-port-${B}}` does not, because "port-" came from the expression.
			name: "a default that adds text of its own does not",
			in:   "${MISSING:-tag-${TAG}}",
			want: "tag-1.27.2",
			src:  payload.EnvFromShellDefault,
		}, {
			// The branch never taken must not produce a note about a variable nobody read.
			name: "the untaken branch is silent",
			in:   "${TAG:-${MUST_NOT_BE_READ}}",
			want: "1.27.2",
			src:  payload.EnvFromEnvFile,
		}, {
			name: "the brace counter closes the outer expression, not the first brace",
			in:   "[${MISSING:-${ALSO_MISSING:-deep}}]",
			want: "[deep]",
			src:  payload.EnvFromShellDefault,
		},

		// ---- the forms §6 does not list, which are never guessed at -----------------
		{
			name:  "a name that does not match the name rule",
			in:    "${1BAD}",
			want:  "${1BAD}",
			src:   payload.EnvFromShellDefault,
			notes: []string{`image: "${1BAD}" is not a variable reference; left as written`},
		}, {
			name:  "an empty expression",
			in:    "${}",
			want:  "${}",
			src:   payload.EnvFromShellDefault,
			notes: []string{`image: "${}" is not a variable reference; left as written`},
		}, {
			// Guessing at an unlisted form is how a scanner reports a value the fleet never
			// had, so `${VAR:+alt}` stays exactly as written.
			name:  "an operator §6 does not list",
			in:    "${TAG:+alternate}",
			want:  "${TAG:+alternate}",
			src:   payload.EnvFromShellDefault,
			notes: []string{`image: "${TAG:+alternate}" is not a variable reference; left as written`},
		}, {
			name:  "shell parameter expansion is not Compose interpolation",
			in:    "${TAG/a/b}",
			want:  "${TAG/a/b}",
			src:   payload.EnvFromShellDefault,
			notes: []string{`image: "${TAG/a/b}" is not a variable reference; left as written`},
		}, {
			name:  "no closing brace",
			in:    "nginx:${TAG",
			want:  "nginx:${TAG",
			src:   payload.EnvFromShellDefault,
			notes: []string{`image: "${TAG" has no closing brace; left as written`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := interpolator{vars: interpVars}
			got, src, notes := in.expand(tt.in, "image")
			if got != tt.want {
				t.Errorf("expand(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
			// The source is asserted through sourceOf, because that is the only question
			// §4.8 asks of it: do the files pin this value?
			if resolved := sourceOf(src, payload.EnvFromEnvironment); resolved != tt.src {
				t.Errorf("source = %q, want %q", resolved, tt.src)
			}
			if !reflect.DeepEqual(notes, tt.notes) {
				t.Errorf("notes:\n got %#v\nwant %#v", notes, tt.notes)
			}
		})
	}
}

// TestExpandDepthBound pins §6's bound at 32 levels of nesting. The note is what an
// operator sees; the point of the bound is that a file cannot make this scan recurse.
func TestExpandDepthBound(t *testing.T) {
	// 40 levels of `${MISSING_N:-` … each default being the next expression.
	const levels = 40
	var b strings.Builder
	for i := 0; i < levels; i++ {
		b.WriteString("${MISSING:-")
	}
	b.WriteString("floor")
	b.WriteString(strings.Repeat("}", levels))

	in := interpolator{vars: interpVars}
	got, src, notes := in.expand(b.String(), "labels[0]")

	if len(notes) != 1 {
		t.Fatalf("want exactly one note, got %#v", notes)
	}
	want := "labels[0]: nested substitution goes deeper than 32 levels; left as written"
	if notes[0] != want {
		t.Errorf("note\n got %q\nwant %q", notes[0], want)
	}
	if sourceOf(src, payload.EnvFromEnvironment) != payload.EnvFromShellDefault {
		t.Error("a refused expansion must not read as a value a file pins")
	}
	// The refusal leaves the expression it could not finish, so nothing is invented.
	if !strings.Contains(got, "floor") {
		t.Errorf("got %q, which does not carry the text it stopped on", got)
	}
}

// TestSourceOfTakesTheWeakest pins §4.8's rule for a value assembled from more than one
// source: the field answers whether the files pin the value, so a default or an unresolved
// reference decides it whatever else contributed.
func TestSourceOfTakesTheWeakest(t *testing.T) {
	tests := []struct {
		src  varSource
		want payload.EnvVarSource
	}{
		{0, payload.EnvFromEnvironment},
		{fromEnvFile, payload.EnvFromEnvFile},
		{fromDefault, payload.EnvFromShellDefault},
		{fromShell, payload.EnvFromShellDefault},
		{fromEnvFile | fromDefault, payload.EnvFromShellDefault},
		{fromEnvFile | fromShell, payload.EnvFromShellDefault},
	}
	for _, tt := range tests {
		if got := sourceOf(tt.src, payload.EnvFromEnvironment); got != tt.want {
			t.Errorf("sourceOf(%b) = %q, want %q", tt.src, got, tt.want)
		}
	}
	// With no substitution the answer is the key the value was written under, which for an
	// env_file entry is env_file and not the environment block.
	if got := sourceOf(0, payload.EnvFromEnvFile); got != payload.EnvFromEnvFile {
		t.Errorf("sourceOf(0, env_file) = %q, want env_file", got)
	}
}

// TestInterpolatorHoldsOnlyTheStackEnv is I6 in one assertion: this process's own
// environment must never reach a payload describing somebody else's service. The
// interpolator has one field and nothing fills it from os.Environ, so the test that it
// cannot is the test that an unset variable stays unset.
func TestInterpolatorHoldsOnlyTheStackEnv(t *testing.T) {
	t.Setenv("LABVIEW_AUTHENTIK_TOKEN", "a-real-credential")
	in := interpolator{vars: map[string]string{}}
	got, _, notes := in.expand("${LABVIEW_AUTHENTIK_TOKEN}", "environment.TOKEN")
	if strings.Contains(got, "a-real-credential") {
		t.Fatalf("the process environment reached a substitution: %q", got)
	}
	if len(notes) != 1 {
		t.Fatalf("want the unresolved note, got %#v", notes)
	}
}
