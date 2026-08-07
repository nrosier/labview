package scan

import (
	"reflect"
	"testing"
)

// value is a *string in envEntry so that a bare key — a name the shell supplies — stays a
// different fact from `KEY=`. These two helpers keep the tables readable.
func val(s string) *string { return &s }

func TestParseEnvFile(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []envEntry
	}{{
		name: "plain assignments",
		in:   "A=1\nB=two\n",
		want: []envEntry{{Key: "A", Value: val("1")}, {Key: "B", Value: val("two")}},
	}, {
		name: "blank lines and comments are skipped",
		in:   "\n# a comment\n\nA=1\n   # indented comment\n",
		want: []envEntry{{Key: "A", Value: val("1")}},
	}, {
		name: "a bare key is not an empty value",
		in:   "TZ\nSET=\n",
		want: []envEntry{{Key: "TZ"}, {Key: "SET", Value: val("")}},
	}, {
		name: "export prefix",
		in:   "export A=1\n",
		want: []envEntry{{Key: "A", Value: val("1")}},
	}, {
		name: "surrounding whitespace",
		in:   "  A =  1  \n",
		want: []envEntry{{Key: "A", Value: val("1")}},
	}, {
		name: "a trailing comment needs whitespace before it",
		in:   "A=1 # why\nB=http://h/#frag\nC=#111111\n",
		want: []envEntry{
			{Key: "A", Value: val("1")},
			{Key: "B", Value: val("http://h/#frag")},
			// A `#` in column zero of the value is a comment: nothing precedes it.
			{Key: "C", Value: val("")},
		},
	}, {
		name: "double quotes keep whitespace and hashes",
		in:   `A="  spaced # not a comment  "` + "\n",
		want: []envEntry{{Key: "A", Value: val("  spaced # not a comment  ")}},
	}, {
		name: "single quotes are literal",
		in:   `A='no \n escape'` + "\n",
		want: []envEntry{{Key: "A", Value: val(`no \n escape`)}},
	}, {
		name: "escapes inside double quotes",
		in:   `A="line\none\ttab\\end\"q\""` + "\n",
		want: []envEntry{{Key: "A", Value: val("line\none\ttab\\end\"q\"")}},
	}, {
		name: "an undefined escape stays as written",
		in:   `A="C:\program\zone"` + "\n",
		want: []envEntry{{Key: "A", Value: val(`C:\program\zone`)}},
	}, {
		// A PEM key in an environment file is an ordinary thing to find, and the only way
		// to write one is a quote that stays open across lines.
		name: "a quoted value spans lines",
		in:   "KEY=\"-----BEGIN-----\nline2\n-----END-----\"\nAFTER=1\n",
		want: []envEntry{
			{Key: "KEY", Value: val("-----BEGIN-----\nline2\n-----END-----")},
			{Key: "AFTER", Value: val("1")},
		},
	}, {
		// The file is malformed and there is no quoted value in it, so the text is taken as
		// written rather than half-unquoted into a value the file never had.
		name: "an unterminated quote takes the line verbatim",
		in:   `A="open` + "\n",
		want: []envEntry{{Key: "A", Value: val(`"open`)}},
	}, {
		name: "CRLF",
		in:   "A=1\r\nB=2\r\n",
		want: []envEntry{{Key: "A", Value: val("1")}, {Key: "B", Value: val("2")}},
	}, {
		name: "a byte order mark is not part of the first key",
		in:   "\ufeffA=1\n",
		want: []envEntry{{Key: "A", Value: val("1")}},
	}, {
		name: "a value may contain an equals sign",
		in:   "URL=a=b=c\n",
		want: []envEntry{{Key: "URL", Value: val("a=b=c")}},
	}, {
		name: "lines this format cannot mean are skipped",
		in:   "just some prose\n=novalue\nA=1\n",
		want: []envEntry{{Key: "A", Value: val("1")}},
	}, {
		// Nothing in an environment file is substituted: Compose does not interpolate
		// env_file values, and doing it here would invent values the stack never had.
		name: "a variable reference is text",
		in:   "A=${OTHER:-x}\n",
		want: []envEntry{{Key: "A", Value: val("${OTHER:-x}")}},
	}, {
		name: "no trailing newline",
		in:   "A=1",
		want: []envEntry{{Key: "A", Value: val("1")}},
	}, {
		name: "empty file",
		in:   "",
		want: nil,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEnvFile([]byte(tt.in))
			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries, want %d: %s", len(got), len(tt.want), show(got))
			}
			for i := range got {
				if got[i].Key != tt.want[i].Key {
					t.Errorf("entry %d key = %q, want %q", i, got[i].Key, tt.want[i].Key)
				}
				switch {
				case got[i].Value == nil && tt.want[i].Value == nil:
				case got[i].Value == nil:
					t.Errorf("entry %d %q has no value, want %q", i, got[i].Key, *tt.want[i].Value)
				case tt.want[i].Value == nil:
					t.Errorf("entry %d %q = %q, want no value", i, got[i].Key, *got[i].Value)
				case *got[i].Value != *tt.want[i].Value:
					t.Errorf("entry %d %q = %q, want %q", i, got[i].Key, *got[i].Value, *tt.want[i].Value)
				}
			}
		})
	}
}

func TestEnvMap(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{{
		name: "last declaration wins",
		in:   "A=1\nA=2\n",
		want: map[string]string{"A": "2"},
	}, {
		// A key declared with no value is left out so that `${KEY:-default}` reaches its
		// default: the shell would supply it, and this scan cannot see the shell (§6).
		name: "a bare key removes an earlier value",
		in:   "A=1\nA\n",
		want: map[string]string{},
	}, {
		name: "set to empty is a value",
		in:   "A=\n",
		want: map[string]string{"A": ""},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := envMap(parseEnvFile([]byte(tt.in)))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func show(entries []envEntry) string {
	out := ""
	for _, e := range entries {
		out += " " + e.Key
		if e.Value == nil {
			out += "=<unset>"
		} else {
			out += "=" + *e.Value
		}
	}
	return out
}
