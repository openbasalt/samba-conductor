package web

import (
	"context"
	"net"
	"strings"

	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// Premise P3 of the Google-first mode: Google keeps its own sign-in, so
// conductor-idp never serves Google while the mode is on. conductor checks
// it in both directions through conductor-idp's management API only:
//
//   - enabling the mode (and every save while it is on, every plan request
//     and every apply) is refused while any registered SAML service
//     provider or OIDC client targets Google;
//   - the Single sign-on section refuses to register or change such an
//     application while the mode is on.
//
// An application targets Google when its entity ID, an ACS URL, a redirect
// URI or a post-logout URI has google.com (or a host below it) as its
// host, or when the identifier itself ends with the Google domain as a
// path ("google.com/a/example.com"). A registered application counts even
// when it is disabled: enabling it again is one click.

// googlePreset is the conductor-idp preset of a Google Workspace SAML
// registration.
const googlePreset = "google-workspace"

// googleTarget reports whether one identifier or URL targets Google for
// the Google domain (lower case, may be empty).
func googleTarget(raw, domain string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return false
	}
	rest := v
	if i := strings.Index(v, "://"); i >= 0 {
		rest = v[i+3:]
	}
	host := rest
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if i := strings.LastIndexByte(host, '@'); i >= 0 {
		host = host[i+1:]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	if host == "google.com" || strings.HasSuffix(host, ".google.com") {
		return true
	}
	if domain == "" {
		return false
	}
	path := strings.TrimRight(rest, "/")
	return path == domain || strings.HasSuffix(path, "/"+domain)
}

// spTargetsGoogle returns the identifier of a service provider that
// targets Google ("" when none does).
func spTargetsGoogle(in idpapi.SPInput, domain string) string {
	for _, v := range append([]string{in.EntityID}, in.ACSURLs...) {
		if googleTarget(v, domain) {
			return v
		}
	}
	return ""
}

// clientTargetsGoogle returns the redirect URI of an OIDC client that
// targets Google ("" when none does).
func clientTargetsGoogle(in idpapi.ClientInput, domain string) string {
	for _, v := range append(append([]string{}, in.RedirectURIs...), in.PostLogoutURIs...) {
		if googleTarget(v, domain) {
			return v
		}
	}
	return ""
}

// p3Hit is one conductor-idp application that targets Google.
type p3Hit struct {
	Kind    string // "saml" or "oidc"
	Name    string
	ID      string // entity ID or client ID
	Match   string // the identifier or URL that matched
	Enabled bool
}

// p3Result is the outcome of one P3 check.
type p3Result struct {
	// Off: conductor has no [idp] section, so no application can be
	// registered from here; the check passes and the page says so.
	Off bool
	// Err is set when conductor-idp could not be asked: the check fails
	// (closed).
	Err  string
	Hits []p3Hit
}

// OK reports whether the check passed.
func (r p3Result) OK() bool { return r.Err == "" && len(r.Hits) == 0 }

// summary is the audit text of a check (names and identifiers only).
func (r p3Result) summary() string {
	switch {
	case r.Err != "":
		return "P3 check failed: conductor-idp could not be asked"
	case len(r.Hits) > 0:
		var names []string
		for _, h := range r.Hits {
			names = append(names, h.Kind+" "+h.ID)
		}
		return "P3 check failed: conductor-idp serves Google: " + strings.Join(names, ", ")
	case r.Off:
		return "P3 check passed: the single sign-on section is off"
	}
	return "P3 check passed"
}

// p3Check lists conductor-idp's applications and returns those that
// target Google for domain.
func (s *Server) p3Check(ctx context.Context, rc *reqCtx, domain string) p3Result {
	if s.idp == nil {
		return p3Result{Off: true}
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	var out p3Result
	var sps []idpapi.SP
	if err := s.idpCall(ctx, rc, idpapi.OpSPList, nil, &sps); err != nil {
		out.Err = s.idpErr(rc, err)
		return out
	}
	var clients []idpapi.Client
	if err := s.idpCall(ctx, rc, idpapi.OpClientList, nil, &clients); err != nil {
		out.Err = s.idpErr(rc, err)
		return out
	}
	for _, sp := range sps {
		if m := spTargetsGoogle(sp.SPInput, domain); m != "" {
			out.Hits = append(out.Hits, p3Hit{Kind: "saml", Name: sp.Name, ID: sp.EntityID, Match: m, Enabled: sp.Enabled})
		}
	}
	for _, c := range clients {
		if m := clientTargetsGoogle(c.ClientInput, domain); m != "" {
			out.Hits = append(out.Hits, p3Hit{Kind: "oidc", Name: c.Name, ID: c.ID, Match: m, Enabled: c.Enabled})
		}
	}
	return out
}

// p3Error turns a failed check into the error of a refused action: the
// first application named, or the reason the check could not run.
func p3Error(r p3Result) error {
	if r.Err != "" {
		return &gfError{key: "gf.p3.unverified", args: []any{r.Err}}
	}
	if len(r.Hits) > 0 {
		return &gfError{key: "gf.p3.refused", args: []any{r.Hits[0].Name, r.Hits[0].Match}}
	}
	return nil
}

// gfError is a refusal of the Google-first section with its message.
type gfError struct {
	key  string
	args []any
}

func (e *gfError) Error() string { return "web: google-first: " + e.key }

// ssoGoogleFirstCheck is the other direction of P3: the Single sign-on
// section asks it before registering or changing an application. It
// returns the refusal (nil: allowed). The settings are read fresh from
// conductor-sync; when they cannot be read, an application that targets
// google.com is refused (the Google domain is then unknown).
func (s *Server) ssoGoogleFirstCheck(ctx context.Context, rc *reqCtx, sp *idpapi.SPInput, client *idpapi.ClientInput, preset string) error {
	if s.sync == nil {
		return nil
	}
	match := func(domain string) string {
		switch {
		case sp != nil:
			if m := spTargetsGoogle(*sp, domain); m != "" {
				return m
			}
		case client != nil:
			if m := clientTargetsGoogle(*client, domain); m != "" {
				return m
			}
		}
		if preset == googlePreset {
			return "Google Workspace"
		}
		return ""
	}
	gf, err := s.googleFirst(ctx, rc, true)
	if err != nil {
		if m := match(""); m != "" {
			return &gfError{key: "sso.err.google_first_unverified", args: []any{m}}
		}
		return nil
	}
	if !gf.Enabled {
		return nil
	}
	if m := match(gf.GoogleDomain); m != "" {
		return &gfError{key: "sso.err.google_first", args: []any{m}}
	}
	return nil
}

// googleFirstOf returns the section of settings (never nil).
func googleFirstOf(st syncapi.Settings) syncapi.GoogleFirstSettings {
	if st.GoogleFirst == nil {
		return syncapi.GoogleFirstSettings{}
	}
	gf := *st.GoogleFirst
	gf.Scopes = append([]syncapi.G2AScope(nil), gf.Scopes...)
	return gf
}
