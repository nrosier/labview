package config

import "strings"

// A retired setting is recognised for one purpose: saying it is gone. Neither the value nor
// the path is echoed (§3.3) — the whole point of retiring the `*_FILE` forms was that a
// credential no longer travels by path, and repeating the path in a warning would put it
// back into the payload.
type retiredSetting struct {
	variable string // the environment variable that is no longer read
	key      string // the configuration-file key that is no longer read
	now      string // the one variable that replaces both
}

// The four of §3.3, in the order the table lists them.
var retiredSettings = []retiredSetting{
	{variable: "LABVIEW_AUTHENTIK_TOKEN_FILE", key: "authentik.tokenFile", now: AuthentikTokenVar},
	{variable: "LABVIEW_TRAEFIK_PASSWORD_FILE", key: "traefik.passwordFile", now: TraefikPasswordVar},
	{variable: "LABVIEW_OIDC_CLIENT_SECRET_FILE", key: "auth.oidc.clientSecretFile", now: OIDCClientSecretVar},
	{variable: "LABVIEW_SESSION_SECRET_FILE", key: "auth.session.secretFile", now: SessionSecretVar},
}

// retired reports the retired settings an operator is still using.
//
// A variable is reported when it is present at all: setting it, even to nothing, is an
// attempt to configure LabView the old way. A configuration key is reported when the value
// it holds is a non-blank string, because an empty key in a file is more likely to be a
// leftover stanza than an instruction (§3.3).
//
// The order is the table's, so two identical environments produce identical warnings (I7).
func retired(env Lookup, raw map[string]any) []string {
	var out []string
	for _, r := range retiredSettings {
		if _, ok := env(r.variable); ok {
			out = append(out, r.variable+" is no longer read — put the value in "+r.now+" instead")
		}
		if v, ok := rawString(raw, r.key); ok && strings.TrimSpace(v) != "" {
			out = append(out, r.key+" in the configuration file is no longer read — put the value in "+r.now+" instead")
		}
	}
	return out
}
