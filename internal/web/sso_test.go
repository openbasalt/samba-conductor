package web

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

// fakeIDP answers conductor-idp's management API from memory.
type fakeIDP struct {
	mu       sync.Mutex
	calls    []idpapi.Request
	clients  map[string]idpapi.Client
	sps      map[string]idpapi.SP
	settings idpapi.SettingsView
	rotated  []idpapi.KeysRotateParams
	fail     map[idpapi.Op]*idpapi.Error
	n        int
	// branding is what branding.update stored; brandingAssets its images.
	branding       idpapi.BrandingView
	brandingAssets []idpapi.BrandingAsset
}

func newFakeIDP() *fakeIDP {
	return &fakeIDP{clients: map[string]idpapi.Client{}, sps: map[string]idpapi.SP{}, fail: map[idpapi.Op]*idpapi.Error{},
		settings: idpapi.SettingsView{Settings: idpapi.Settings{SessionIdleMinutes: 60, SessionAbsoluteHours: 8, MFAPolicy: "optional",
			ConsentText: map[string]string{}}, Defaults: idpapi.Settings{SessionIdleMinutes: 60, SessionAbsoluteHours: 8, MFAPolicy: "optional"},
			MFABackend: "conductor", MFAPolicyShared: true}}
}

func (f *fakeIDP) Call(_ context.Context, req idpapi.Request) (idpapi.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := req.Decode()
	if err != nil {
		return idpapi.Response{}, err
	}
	f.calls = append(f.calls, req)
	if e := f.fail[req.Op]; e != nil {
		return idpapi.ErrorResponse(req.ID, e), e
	}
	fail := func(code idpapi.ErrorCode, msg string, details ...string) (idpapi.Response, error) {
		e := &idpapi.Error{Code: code, Message: msg, Details: details}
		return idpapi.ErrorResponse(req.ID, e), e
	}
	var out any
	switch req.Op {
	case idpapi.OpStatus:
		out = idpapi.Status{Version: "test", Protocol: 1, Issuer: "https://idp.lab.test", DiscoveryURL: "https://idp.lab.test/.well-known/openid-configuration",
			SAMLEnabled: true, SAMLMetadataURL: "https://idp.lab.test/saml/metadata", SAMLSSOURL: "https://idp.lab.test/saml/sso",
			SAMLSLOURL: "https://idp.lab.test/saml/slo", MFABackend: "conductor", Clients: len(f.clients), SPs: len(f.sps), DirectoryOK: true}
	case idpapi.OpClientList:
		var l []idpapi.Client
		for _, c := range f.clients {
			l = append(l, c)
		}
		out = l
	case idpapi.OpClientGet:
		c, ok := f.clients[p.(*idpapi.ClientRef).ID]
		if !ok {
			return fail(idpapi.CodeNotFound, "not found")
		}
		out = c
	case idpapi.OpClientPreview:
		q := p.(*idpapi.ClientPreviewParams)
		if q.Input != nil && len(q.Input.RedirectURIs) == 0 {
			return fail(idpapi.CodeInvalid, "the registration is not valid", "at least one redirect URI is required")
		}
		out = idpapi.Preview{User: q.Username, Allowed: true, Values: []idpapi.Value{{Name: "email", Values: []string{q.Username + "@lab.test"}}}}
	case idpapi.OpClientCreate:
		f.n++
		in := p.(*idpapi.ClientCreateParams).Input
		c := idpapi.Client{ID: "cidp_test" + string(rune('0'+f.n)), ClientInput: in, Enabled: true, HasSecret: in.Kind == "confidential"}
		f.clients[c.ID] = c
		out = idpapi.ClientSecret{Client: c, Secret: "cidp_cs_supersecret"}
	case idpapi.OpClientUpdate:
		q := p.(*idpapi.ClientUpdateParams)
		c := f.clients[q.ID]
		c.ClientInput = q.Input
		f.clients[q.ID] = c
		out = c
	case idpapi.OpClientRotate:
		c := f.clients[p.(*idpapi.ClientRef).ID]
		out = idpapi.ClientSecret{Client: c, Secret: "cidp_cs_rotated"}
	case idpapi.OpClientEnable:
		q := p.(*idpapi.ClientEnableParams)
		c := f.clients[q.ID]
		c.Enabled = q.Enabled
		f.clients[q.ID] = c
		out = c
	case idpapi.OpClientDelete:
		delete(f.clients, p.(*idpapi.ClientRef).ID)
		out = struct{}{}
	case idpapi.OpSPList:
		var l []idpapi.SP
		for _, s := range f.sps {
			l = append(l, s)
		}
		out = l
	case idpapi.OpSPGet:
		s, ok := f.sps[p.(*idpapi.SPRef).EntityID]
		if !ok {
			return fail(idpapi.CodeNotFound, "not found")
		}
		out = s
	case idpapi.OpSPMetadata:
		out = idpapi.SPDraft{Input: idpapi.SPInput{EntityID: "https://sp.lab.test/saml/metadata", ACSURLs: []string{"https://sp.lab.test/saml/acs"},
			NameIDFormat: idpapi.NameIDFormats[0], NameIDSource: "email", SLOURL: "https://sp.lab.test/saml/slo", SLOBinding: idpapi.SLOBindings[0],
			SigningCert: []byte("DER-SIGNING"), Attributes: []idpapi.Attribute{}, Groups: []string{}}, Warnings: []string{"no_encryption_cert"}}
	case idpapi.OpSPPreview:
		q := p.(*idpapi.SPPreviewParams)
		out = idpapi.Preview{User: q.Username, Allowed: true, NameIDFormat: idpapi.NameIDFormats[0], NameID: q.Username + "@lab.test", Values: []idpapi.Value{}}
	case idpapi.OpSPCreate:
		in := p.(*idpapi.SPCreateParams).Input
		s := idpapi.SP{SPInput: in, Enabled: true}
		f.sps[in.EntityID] = s
		out = s
	case idpapi.OpKeysList:
		out = idpapi.Keys{SAMLEnabled: true, RotateDays: 90, OverlapHours: 48, NextOIDCRotation: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			OIDC: []idpapi.Key{{ID: "k-oidc-1", Purpose: "oidc", Alg: "ES256", Signing: true}},
			SAML: []idpapi.Key{{ID: "k-saml-1", Purpose: "saml", Alg: "RS256", Signing: true, Cert: &idpapi.Cert{Subject: "CN=idp.lab.test", SHA256: "AA:BB"}}}}
	case idpapi.OpKeysRotate:
		f.rotated = append(f.rotated, *p.(*idpapi.KeysRotateParams))
		out = idpapi.KeyRotated{ID: "k-new"}
	case idpapi.OpKeysCert:
		out = idpapi.CertPEM{ID: "k-saml-1", PEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}
	case idpapi.OpSettingsGet:
		out = f.settings
	case idpapi.OpSettingsUpdate:
		q := p.(*idpapi.SettingsUpdateParams)
		if q.BaseVersion != f.settings.Version {
			return fail(idpapi.CodeConflict, "changed since it was read")
		}
		f.settings.Version++
		f.settings.Settings = q.Settings
		out = f.settings
	case idpapi.OpBrandingGet:
		out = f.branding
	case idpapi.OpBrandingUpdate:
		q := p.(*idpapi.BrandingUpdateParams)
		f.branding = idpapi.BrandingView{Version: q.Version, Branding: q.Branding, UpdatedBy: "conductor", UpdatedAt: time.Now().UTC()}
		f.brandingAssets = q.Assets
		out = f.branding
	case idpapi.OpActivity:
		out = idpapi.Activity{SignIns: 5, Failures: 2, Lockouts: 1, Apps: []idpapi.AppActivity{{Kind: "oidc", ID: "cidp_x", Name: "Grafana", SignIns: 4, Users: 2}},
			Recent: []idpapi.AuditEvent{{ID: 3, Action: "signin.failure", Actor: "bob", Result: "denied"}}}
	case idpapi.OpAuditList:
		out = idpapi.AuditPage{Events: []idpapi.AuditEvent{{ID: 9, Action: "oidc.authorize", Actor: "alice", Target: "cidp_x", Result: "ok"}}}
	case idpapi.OpAuditVerify:
		out = idpapi.AuditVerify{Rows: 9}
	default:
		return fail(idpapi.CodeBadRequest, "unexpected")
	}
	return idpapi.OKResponse(req.ID, out)
}

func (f *fakeIDP) last(op idpapi.Op) *idpapi.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i].Op == op {
			return &f.calls[i]
		}
	}
	return nil
}

func ssoHarness(t *testing.T) (*harness, *fakeIDP) {
	h := newHarness(t)
	fi := newFakeIDP()
	h.s.idp = fi
	return h, fi
}

// confirmWith submits a pending operation with the password and a code.
func (h *harness) confirmWith(t *testing.T, tok, loc string, secret []byte) *http.Response {
	t.Helper()
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("not a confirmation: %q", loc)
	}
	// A TOTP step is accepted once: each confirmation uses the next one.
	h.now = h.now.Add(30 * time.Second)
	w := h.do("POST", loc, tok, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	return w.Result()
}

func TestSSOOverviewAndAccess(t *testing.T) {
	h, fi := ssoHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	w := h.do("GET", "/admin/sso", admin, nil)
	body := w.Body.String()
	for _, want := range []string{`data-e2e="nav-group-sso"`, `data-e2e="sso-text-issuer"`, "https://idp.lab.test/saml/metadata",
		`data-e2e="sso-text-signins"`, `data-e2e="sso-link-new"`, `data-e2e="sso-top-app-cidp-x"`} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if r := fi.last(idpapi.OpStatus); r == nil || r.Actor.User != "lab.admin" || r.Actor.IP != "192.0.2.10" {
		t.Fatalf("actor %+v", r)
	}
	for _, who := range []string{"auditor.user", "helpdesk.user", "normal.user"} {
		tok := h.session(t, who, stageFull, true)
		for _, p := range []string{"/admin/sso", "/admin/sso/oidc", "/admin/sso/saml", "/admin/sso/keys", "/admin/sso/policy", "/admin/sso/activity", "/admin/sso/new"} {
			if w := h.do("GET", p, tok, nil); w.Code != http.StatusForbidden {
				t.Errorf("%s GET %s: %d", who, p, w.Code)
			}
		}
	}
	h.s.idp = nil
	if body := h.do("GET", "/admin/sso", admin, nil).Body.String(); !strings.Contains(body, "sso-card-disabled") || strings.Contains(body, `data-e2e="nav-group-sso"`) {
		t.Fatal("disabled view")
	}
	h.s.idp = fi
	fi.fail[idpapi.OpStatus] = &idpapi.Error{Code: idpapi.CodeUnavailable, Message: "dial unix: no such file"}
	if body := h.do("GET", "/admin/sso", admin, nil).Body.String(); !strings.Contains(body, "form-text-error") || strings.Contains(body, "no such file") {
		t.Fatal("unavailable view")
	}
}

var secretRefRE = regexp.MustCompile(`^/admin/sso/secret/[A-Za-z0-9_-]+$`)

func TestSSOClientCreateReviewConfirmSecretOnce(t *testing.T) {
	h, fi := ssoHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	if body := h.do("GET", "/admin/sso/oidc/new", admin, nil).Body.String(); !strings.Contains(body, `data-e2e="sso-form-client"`) {
		t.Fatal("new form")
	}
	group := testDomain + "-1500"
	form := url.Values{"name": {"Grafana"}, "kind": {"confidential"}, "redirect_uris": {"https://grafana.lab.test/login/generic_oauth"},
		"scopes": {"profile", "email", "groups"}, "groups_claim": {"names"}, "add_group": {group}}
	// Picking a group keeps it in a hidden field.
	body := h.do("POST", "/admin/sso/oidc/form", admin, form).Body.String()
	if !strings.Contains(body, `name="group" value="`+group+`"`) {
		t.Fatalf("picked group lost:\n%s", body)
	}
	form.Del("add_group")
	form.Set("group", group)
	// Validation errors come back on the form, with details.
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("redirect_uris", "")
	bad.Set("action", "review")
	if w := h.do("POST", "/admin/sso/oidc/form", admin, bad); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "redirect URI is required") {
		t.Fatalf("invalid: %d", w.Code)
	}
	// Preview for a user.
	form.Set("action", "preview")
	form.Set("preview_user", "normal.user")
	if body := h.do("POST", "/admin/sso/oidc/form", admin, form).Body.String(); !strings.Contains(body, `data-e2e="sso-card-preview"`) || !strings.Contains(body, "normal.user@lab.test") {
		t.Fatal("preview")
	}
	// Review: a confirmation with re-authentication; nothing created yet.
	form.Set("action", "review")
	w := h.do("POST", "/admin/sso/oidc/form", admin, form)
	loc := w.Header().Get("Location")
	if fi.last(idpapi.OpClientCreate) != nil {
		t.Fatal("created before confirmation")
	}
	cp := h.do("GET", loc, admin, nil).Body.String()
	for _, want := range []string{"conductor-idp client.create", "https://grafana.lab.test/login/generic_oauth", group, "confirm-text-reauth"} {
		if !strings.Contains(cp, want) {
			t.Fatalf("confirm page lacks %q:\n%s", want, cp)
		}
	}
	res := h.confirmWith(t, admin, loc, secret)
	sloc := res.Header.Get("Location")
	if !secretRefRE.MatchString(sloc) {
		t.Fatalf("after confirm: %d %q", res.StatusCode, sloc)
	}
	var cp2 idpapi.ClientCreateParams
	_ = json.Unmarshal(fi.last(idpapi.OpClientCreate).Params, &cp2)
	if cp2.Input.Groups[0] != group || cp2.Input.GroupsClaim != "names" || fi.last(idpapi.OpClientCreate).Actor.User != "lab.admin" {
		t.Fatalf("create params %+v", cp2)
	}
	// The secret is shown once.
	page := h.do("GET", sloc, admin, nil)
	if !strings.Contains(page.Body.String(), "cidp_cs_supersecret") || page.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("secret page")
	}
	if w := h.do("GET", sloc, admin, nil); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "cidp_cs_supersecret") {
		t.Fatal("secret shown twice")
	}
	// The audit log names the operation, never the secret.
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "sso.client_create"}, 0, 10)
	if len(evs) != 1 || evs[0].Result != store.ResultOK || !strings.Contains(evs[0].Detail, "[re-authenticated]") {
		t.Fatalf("audit %+v", evs)
	}
	if strings.Contains(h.auditText(t), "cidp_cs_supersecret") {
		t.Fatal("secret in the audit log")
	}
}

func TestSSOClientRotateToggleDelete(t *testing.T) {
	h, fi := ssoHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	fi.clients["cidp_a"] = idpapi.Client{ID: "cidp_a", ClientInput: idpapi.ClientInput{Name: "App", Kind: "confidential",
		RedirectURIs: []string{"https://app.lab.test/cb"}, GroupsClaim: "none"}, Enabled: true, HasSecret: true}
	page := h.do("GET", "/admin/sso/oidc/cidp_a?preview_user=normal.user", admin, nil).Body.String()
	for _, want := range []string{`data-e2e="sso-btn-client-rotate"`, `data-e2e="sso-card-preview"`, "https://idp.lab.test/.well-known/openid-configuration"} {
		if !strings.Contains(page, want) {
			t.Fatalf("client page lacks %q", want)
		}
	}
	loc := h.do("POST", "/admin/sso/oidc/cidp_a/rotate", admin, nil).Header().Get("Location")
	res := h.confirmWith(t, admin, loc, secret)
	if body := h.do("GET", res.Header.Get("Location"), admin, nil).Body.String(); !strings.Contains(body, "cidp_cs_rotated") {
		t.Fatal("rotated secret not shown")
	}
	loc = h.do("POST", "/admin/sso/oidc/cidp_a/enabled", admin, url.Values{"enabled": {"0"}}).Header().Get("Location")
	h.confirmWith(t, admin, loc, secret)
	if fi.clients["cidp_a"].Enabled {
		t.Fatal("not disabled")
	}
	// A wrong typed confirmation is refused before any preview.
	if w := h.do("POST", "/admin/sso/oidc/cidp_a/delete", admin, url.Values{"confirm": {"App"}}); w.Header().Get("Location") != "/admin/sso/oidc/cidp_a" {
		t.Fatalf("mismatch: %q", w.Header().Get("Location"))
	}
	loc = h.do("POST", "/admin/sso/oidc/cidp_a/delete", admin, url.Values{"confirm": {"cidp_a"}}).Header().Get("Location")
	if res := h.confirmWith(t, admin, loc, secret); res.Header.Get("Location") != "/admin/sso/oidc" {
		t.Fatalf("after delete: %q", res.Header.Get("Location"))
	}
	if _, ok := fi.clients["cidp_a"]; ok {
		t.Fatal("not deleted")
	}
}

func TestSSOSAMLImportAndCreate(t *testing.T) {
	h, fi := ssoHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	if body := h.do("GET", "/admin/sso/saml/new", admin, nil).Body.String(); !strings.Contains(body, `data-e2e="sso-form-sp-import"`) {
		t.Fatal("import form")
	}
	w := h.postMultipartForm(t, "/admin/sso/saml/import", admin, url.Values{"url": {"https://sp.lab.test/saml/metadata"}}, "", "", nil)
	body := w.Body.String()
	signB64 := base64.StdEncoding.EncodeToString([]byte("DER-SIGNING"))
	for _, want := range []string{`name="sign_cert" value="` + signB64 + `"`, `value="https://sp.lab.test/saml/slo"`, `data-e2e="sso-warning-no-encryption-cert"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("imported form lacks %q:\n%s", want, body)
		}
	}
	var mp idpapi.SPMetadataParams
	_ = json.Unmarshal(fi.last(idpapi.OpSPMetadata).Params, &mp)
	if mp.URL != "https://sp.lab.test/saml/metadata" {
		t.Fatalf("metadata params %+v", mp)
	}
	form := url.Values{"name": {"Example"}, "entity_id": {"https://sp.lab.test/saml/metadata"}, "acs_urls": {"https://sp.lab.test/saml/acs"},
		"nameid_format": {idpapi.NameIDFormats[0]}, "nameid_source": {"email"}, "attributes": {"mail=email\ngroups=groups"},
		"slo_url": {"https://sp.lab.test/saml/slo"}, "slo_binding": {idpapi.SLOBindings[0]}, "sign_cert": {signB64}, "allow_all": {"1"}, "action": {"review"}}
	loc := h.do("POST", "/admin/sso/saml/form", admin, form).Header().Get("Location")
	cp := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(cp, "confirm-text-warning") || !strings.Contains(cp, "single_logout: https://sp.lab.test/saml/slo") {
		t.Fatalf("confirm page:\n%s", cp)
	}
	res := h.confirmWith(t, admin, loc, secret)
	if !strings.HasPrefix(res.Header.Get("Location"), "/admin/sso/saml/sp?id=") {
		t.Fatalf("after confirm %q", res.Header.Get("Location"))
	}
	var sc idpapi.SPCreateParams
	_ = json.Unmarshal(fi.last(idpapi.OpSPCreate).Params, &sc)
	if string(sc.Input.SigningCert) != "DER-SIGNING" || len(sc.Input.Attributes) != 2 || !sc.Input.AllowAllUsers {
		t.Fatalf("create params %+v", sc.Input)
	}
	// Bad attribute lines stay on the form.
	form.Set("attributes", "no equals sign")
	if w := h.do("POST", "/admin/sso/saml/form", admin, form); w.Code != http.StatusBadRequest {
		t.Fatalf("bad attributes: %d", w.Code)
	}
	// The SP page shows the IdP's values; a Google SP gets the Admin
	// console's labels.
	fi.sps["google.com/a/lab.test"] = idpapi.SP{SPInput: idpapi.SPInput{EntityID: "google.com/a/lab.test", Name: "Google",
		ACSURLs: []string{"https://www.google.com/a/lab.test/acs"}, NameIDFormat: idpapi.NameIDFormats[0], NameIDSource: "email"}, Enabled: true}
	if body := h.do("GET", "/admin/sso/saml/sp?id=google.com%2Fa%2Flab.test", admin, nil).Body.String(); !strings.Contains(body, `data-e2e="sso-text-google-signin"`) {
		t.Fatal("Google values")
	}
}

func TestSSOPresetsKeysPolicyActivity(t *testing.T) {
	h, fi := ssoHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	if body := h.do("GET", "/admin/sso/new", admin, nil).Body.String(); !strings.Contains(body, `data-e2e="sso-preset-google-workspace"`) {
		t.Fatal("presets")
	}
	if body := h.do("GET", "/admin/sso/new/grafana", admin, nil).Body.String(); !strings.Contains(body, `data-e2e="sso-input-preset-base-url"`) {
		t.Fatal("preset questions")
	}
	body := h.do("POST", "/admin/sso/new/grafana", admin, url.Values{"base_url": {"https://grafana.lab.test"}}).Body.String()
	if !strings.Contains(body, "https://grafana.lab.test/login/generic_oauth") || !strings.Contains(body, `data-e2e="sso-text-preset"`) {
		t.Fatalf("preset form:\n%s", body)
	}
	if w := h.do("POST", "/admin/sso/new/grafana", admin, url.Values{"base_url": {"http://grafana"}}); w.Code != http.StatusBadRequest {
		t.Fatal("bad preset answer accepted")
	}
	body = h.do("POST", "/admin/sso/new/google-workspace", admin, url.Values{"domain": {"example.com"}}).Body.String()
	if !strings.Contains(body, "https://www.google.com/a/example.com/acs") {
		t.Fatal("Google preset")
	}
	// Keys: an emergency SAML rotation needs the confirmation.
	if body := h.do("GET", "/admin/sso/keys", admin, nil).Body.String(); !strings.Contains(body, `data-e2e="sso-btn-rotate-saml-now"`) {
		t.Fatal("keys page")
	}
	loc := h.do("POST", "/admin/sso/keys/rotate", admin, url.Values{"purpose": {"saml"}, "immediate": {"1"}}).Header().Get("Location")
	h.confirmWith(t, admin, loc, secret)
	if len(fi.rotated) != 1 || !fi.rotated[0].Immediate {
		t.Fatalf("rotated %+v", fi.rotated)
	}
	if w := h.do("POST", "/admin/sso/keys/rotate", admin, url.Values{"purpose": {"oidc"}, "immediate": {"1"}}); w.Code != http.StatusBadRequest {
		t.Fatal("immediate OIDC accepted")
	}
	if w := h.do("GET", "/admin/sso/keys/saml.pem", admin, nil); w.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Fatal("certificate download")
	}
	// Policy: shared 2FA shown; sessions and consent saved with the version.
	page := h.do("GET", "/admin/sso/policy", admin, nil).Body.String()
	if !strings.Contains(page, `data-e2e="sso-text-mfa-shared"`) {
		t.Fatal("policy page")
	}
	loc = h.do("POST", "/admin/sso/policy", admin, url.Values{"session_idle_minutes": {"30"}, "session_absolute_hours": {"4"},
		"consent_en": {"Data stays here."}, "mfa_policy": {"optional"}}).Header().Get("Location")
	h.confirmWith(t, admin, loc, secret)
	if fi.settings.Version != 1 || fi.settings.Settings.SessionIdleMinutes != 30 || fi.settings.Settings.ConsentText["en"] != "Data stays here." {
		t.Fatalf("settings %+v", fi.settings)
	}
	if w := h.do("POST", "/admin/sso/policy", admin, url.Values{"session_idle_minutes": {"0"}, "session_absolute_hours": {"4"}}); w.Code != http.StatusBadRequest {
		t.Fatal("invalid policy accepted")
	}
	// Activity.
	act := h.do("GET", "/admin/sso/activity?days=30&verify=1&action=oidc.", admin, nil).Body.String()
	for _, want := range []string{`data-e2e="sso-activity-app-cidp-x"`, `data-e2e="sso-alert-chain-ok"`, `data-e2e="sso-audit-9"`} {
		if !strings.Contains(act, want) {
			t.Fatalf("activity lacks %q", want)
		}
	}
	var ap idpapi.ActivityParams
	_ = json.Unmarshal(fi.last(idpapi.OpActivity).Params, &ap)
	if ap.Days != 30 {
		t.Fatalf("days %d", ap.Days)
	}
}

// ---- the 2FA socket ----

func mfaReq(op, user string, groups ...string) idpapi.MFARequest {
	u := testDomain + "-" + map[string]string{"normal.user": "1101", "lab.admin": "1104"}[user]
	return idpapi.MFARequest{V: idpapi.MFAProtocolVersion, Op: op, UserSID: u, User: user, Groups: groups}
}

func TestMFASocketAnswers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	secret := h.enrollTOTP(t, "lab.admin")
	// Status: conductor's policy from the groups.
	a := h.s.answerMFA(ctx, mfaReq(idpapi.MFAOpStatus, "lab.admin", testDomain+"-513", domainAdmins))
	if !a.Enrolled || !a.TOTP || !a.Required || a.Error != "" {
		t.Fatalf("admin status %+v", a)
	}
	a = h.s.answerMFA(ctx, mfaReq(idpapi.MFAOpStatus, "normal.user", testDomain+"-513"))
	if a.Enrolled || a.Required || a.Policy != "optional" {
		t.Fatalf("user status %+v", a)
	}
	// Verify: a right code once, the same step not twice.
	req := mfaReq(idpapi.MFAOpVerify, "lab.admin", domainAdmins)
	req.Code = totp.Code(secret, totp.Step(h.now))
	if a := h.s.answerMFA(ctx, req); !a.OK {
		t.Fatalf("verify %+v", a)
	}
	if a := h.s.answerMFA(ctx, req); a.OK {
		t.Fatal("replayed code accepted")
	}
	// Wrong codes hit the per-user limit, and every attempt is audited.
	req.Code = "000000"
	for i := 0; i < 10; i++ {
		h.s.answerMFA(ctx, req)
	}
	if a := h.s.answerMFA(ctx, req); a.Error != idpapi.MFAErrRateLimited {
		t.Fatalf("no rate limit: %+v", a)
	}
	evs, _, _ := h.st.ListAudit(ctx, store.AuditFilter{Action: "idp.mfa_verify"}, 0, 50)
	if len(evs) < 3 || evs[len(evs)-1].Result != store.ResultOK || evs[0].Target != "lab.admin" {
		t.Fatalf("audit %+v", evs[:1])
	}
	// Bad requests and keys without WebAuthn.
	bad := mfaReq(idpapi.MFAOpVerify, "lab.admin")
	bad.V = 1
	if a := h.s.answerMFA(ctx, bad); a.Error != idpapi.MFAErrVersion {
		t.Fatalf("version: %+v", a)
	}
	if a := h.s.answerMFA(ctx, mfaReq(idpapi.MFAOpKeyBegin, "lab.admin")); a.Error != idpapi.MFAErrNoKeys {
		t.Fatalf("keys: %+v", a)
	}
}

func TestMFASocketKeyRequiredRefusesTOTP(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.WebAuthn.RPID, c.WebAuthn.AdminRequired = "lab.test", true
		c.WebAuthn.Origins = []string{"https://conductor.lab.test:8443", "https://idp.lab.test:9443"}
	})
	ctx := context.Background()
	secret := h.enrollTOTP(t, "lab.admin")
	st := h.s.answerMFA(ctx, mfaReq(idpapi.MFAOpStatus, "lab.admin", domainAdmins))
	if !st.KeyRequired {
		t.Fatalf("status %+v", st)
	}
	req := mfaReq(idpapi.MFAOpVerify, "lab.admin", domainAdmins)
	req.Code = totp.Code(secret, totp.Step(h.now))
	if a := h.s.answerMFA(ctx, req); a.Error != idpapi.MFAErrKeyRequired || a.OK {
		t.Fatalf("TOTP accepted for a key-only admin: %+v", a)
	}
	// No key registered: key.begin says so.
	if a := h.s.answerMFA(ctx, mfaReq(idpapi.MFAOpKeyBegin, "lab.admin", domainAdmins)); a.Error != idpapi.MFAErrNoKeys {
		t.Fatalf("begin %+v", a)
	}
	// A ceremony that does not exist is refused.
	fin := mfaReq(idpapi.MFAOpKeyFinish, "lab.admin", domainAdmins)
	fin.Ceremony, fin.Response = "abcdefghijklmnopqrstuvwxyz012345", "{}"
	if a := h.s.answerMFA(ctx, fin); a.Error != idpapi.MFAErrCeremony {
		t.Fatalf("finish %+v", a)
	}
}

func TestMFASocketPeerCheck(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "mfa.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	peer := 4242
	h.s.mfaPeerCred = func(*net.UnixConn) (int, error) { mu.Lock(); defer mu.Unlock(); return peer, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = h.s.ServeMFA(ctx, ln, []int{1001}); close(done) }()
	ask := func() (idpapi.MFAAnswer, error) {
		c, err := net.Dial("unix", path)
		if err != nil {
			return idpapi.MFAAnswer{}, err
		}
		defer func() { _ = c.Close() }()
		_ = json.NewEncoder(c).Encode(mfaReq(idpapi.MFAOpStatus, "normal.user", testDomain+"-513"))
		line, err := bufio.NewReader(c).ReadBytes('\n')
		var a idpapi.MFAAnswer
		if err == nil {
			err = json.Unmarshal(line, &a)
		}
		return a, err
	}
	if _, err := ask(); err == nil {
		t.Fatal("a peer that is not allowed got an answer")
	}
	mu.Lock()
	peer = 1001
	mu.Unlock()
	if a, err := ask(); err != nil || a.V != idpapi.MFAProtocolVersion || a.Policy != "optional" {
		t.Fatalf("allowed peer: %+v %v", a, err)
	}
	cancel()
	<-done
}

func TestWellKnownWebAuthn(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.WebAuthn.RPID = "lab.test"
		c.WebAuthn.RelatedOrigins = []string{"https://login.example.org"}
	})
	w := h.do("GET", "/.well-known/webauthn", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "https://login.example.org") {
		t.Fatalf("well-known: %d %s", w.Code, w.Body.String())
	}
	if w := newHarness(t).do("GET", "/.well-known/webauthn", "", nil); w.Code != http.StatusNotFound {
		t.Fatal("served without related origins")
	}
}
