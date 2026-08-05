package secrets

import "testing"

func TestMaskValue(t *testing.T) {
	if got := MaskValue("hunter2"); got != Mask {
		t.Errorf("MaskValue(%q) = %q, want %q", "hunter2", got, Mask)
	}
	// §20: the mask preserves shape and not content. Length is content — a mask that
	// matched it would publish the length of every password in the fleet.
	if MaskValue("a") != MaskValue("a-very-long-passphrase-indeed") {
		t.Error("the mask varies with the value's length")
	}
	// An environment variable named like a secret and set to nothing is a finding, not a
	// secret: masking it would report a credential the fleet does not have (I1).
	if got := MaskValue(""); got != "" {
		t.Errorf("MaskValue(%q) = %q, want the empty string back", "", got)
	}
}

func TestRedactURIs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{{
		name: "password in a database URI",
		in:   "postgresql://appuser:sup3rs3cret@db:5432/app",
		want: "postgresql://appuser:" + Mask + "@db:5432/app",
	}, {
		name: "empty username, as redis writes it",
		in:   "redis://:redi5pw@cache:6379/0",
		want: "redis://:" + Mask + "@cache:6379/0",
	}, {
		// The fixture comment on edge/dbstack pins this: userinfo with no password names
		// an account and has nothing to withhold.
		name: "userinfo with no password stays visible",
		in:   "smtp://notify@mail.example.com:587",
		want: "smtp://notify@mail.example.com:587",
	}, {
		name: "no credentials at all",
		in:   "https://api.example.com/health",
		want: "https://api.example.com/health",
	}, {
		// The reason the reader is anchored on "://" and not on "@" alone.
		name: "a bare email address is not a URI",
		in:   "ops@example.com",
		want: "ops@example.com",
	}, {
		name: "mailto has no authority",
		in:   "mailto:ops@example.com",
		want: "mailto:ops@example.com",
	}, {
		name: "an @ in the path is not userinfo",
		in:   "https://media.example.com/users/@alice/feed",
		want: "https://media.example.com/users/@alice/feed",
	}, {
		name: "an @ in the query is not userinfo",
		in:   "https://example.com/search?to=a@b.com",
		want: "https://example.com/search?to=a@b.com",
	}, {
		name: "userinfo and an @ further along",
		in:   "https://u:p@example.com/users/@alice",
		want: "https://u:" + Mask + "@example.com/users/@alice",
	}, {
		name: "two URIs in one value",
		in:   "postgres://a:1@x/db amqp://b:2@y/",
		want: "postgres://a:" + Mask + "@x/db amqp://b:" + Mask + "@y/",
	}, {
		name: "a URI inside prose ends where the prose resumes",
		in:   `mail ops@example.com, or use "https://u:p@h" instead`,
		want: `mail ops@example.com, or use "https://u:` + Mask + `@h" instead`,
	}, {
		name: "a colon in the host's port is not userinfo",
		in:   "http://10.10.0.5:8096",
		want: "http://10.10.0.5:8096",
	}, {
		name: "empty",
		in:   "",
		want: "",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactURIs(tt.in); got != tt.want {
				t.Errorf("RedactURIs(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestRedactURIsIdempotent matters because redaction happens on the producing side and a
// value may pass through more than one writer (§20). Masking a mask must be a no-op.
func TestRedactURIsIdempotent(t *testing.T) {
	once := RedactURIs("postgres://u:p@h/db")
	if twice := RedactURIs(once); twice != once {
		t.Errorf("second pass changed the value: %q then %q", once, twice)
	}
}
