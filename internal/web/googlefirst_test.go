package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

// gfFakeSync adds the Google-first operations to fakeSync: one recorded
// g2a plan (answered by g2a.plan, runs.list and run.get, two operations
// per page so the merge of pages is exercised) and the confirmations.
type gfFakeSync struct {
	*fakeSync
	mu        sync.Mutex
	plan      syncapi.G2APlan
	status    string
	results   []syncapi.G2AOpResult
	planned   []syncapi.G2APlanParams
	confirms  []syncapi.G2AConfirmParams
	invalid   []string
	newerRuns []syncapi.Run
}

func (g *gfFakeSync) Call(ctx context.Context, req syncapi.Request) (syncapi.Response, error) {
	g.fakeSync.mu.Lock()
	e := g.fakeSync.fail[req.Op]
	g.fakeSync.mu.Unlock()
	if e != nil {
		return g.fakeSync.Call(ctx, req)
	}
	p, err := req.Decode()
	if err != nil {
		return syncapi.Response{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	var out any
	switch req.Op {
	case syncapi.OpG2APlan:
		g.planned = append(g.planned, *p.(*syncapi.G2APlanParams))
		g.status = syncapi.StatusPlanned
		g.results = nil
		out = g.plan
	case syncapi.OpG2AConfirm:
		c := *p.(*syncapi.G2AConfirmParams)
		g.confirms = append(g.confirms, c)
		res := syncapi.G2AConfirmResult{RunID: c.RunID, Status: syncapi.StatusApplied}
		for _, r := range c.Results {
			switch r.Status {
			case syncapi.G2AOpDone:
				res.Done++
			case syncapi.G2AOpFailed:
				res.Failed++
			default:
				res.Skipped++
			}
		}
		if res.Failed+res.Skipped > 0 {
			res.Status = syncapi.StatusPartial
		}
		g.status, g.results = res.Status, c.Results
		out = res
	case syncapi.OpRunsList:
		runs := append([]syncapi.Run{}, g.newerRuns...)
		runs = append(runs, syncapi.Run{ID: 1, Action: "apply", Status: "applied"})
		if g.plan.RunID > 0 {
			runs = append(runs[:len(g.newerRuns)], syncapi.Run{ID: g.plan.RunID, Action: syncapi.RunActionG2A, Status: g.status,
				Actor: "conductor:lab.admin", Digest: g.plan.Digest}, syncapi.Run{ID: 1, Action: "apply", Status: "applied"})
		}
		out = syncapi.RunsList{Runs: runs, Total: len(runs)}
	case syncapi.OpRunGet:
		q := p.(*syncapi.RunGetParams)
		if q.ID != g.plan.RunID {
			if slices.ContainsFunc(g.newerRuns, func(r syncapi.Run) bool { return r.ID == q.ID }) {
				out = syncapi.RunDetail{Run: syncapi.Run{ID: q.ID, Action: syncapi.RunActionG2A, Status: syncapi.StatusPlanned},
					G2A: &syncapi.G2APlan{RunID: q.ID, Digest: strings.Repeat("cd", 32)}}
				break
			}
			e := &syncapi.Error{Code: syncapi.CodeNotFound, Message: "no run"}
			return syncapi.ErrorResponse(req.ID, e), e
		}
		limit := min(q.Limit, 2)
		if limit == 0 {
			limit = 2
		}
		page := g.plan
		page.Scopes = nil
		idx, total, taken := 0, 0, 0
		for _, sc := range g.plan.Scopes {
			ps := sc
			ps.Ops = []syncapi.G2AOp{}
			for _, o := range sc.Ops {
				total++
				if idx >= q.Offset && taken < limit {
					ps.Ops = append(ps.Ops, o)
					taken++
				}
				idx++
			}
			page.Scopes = append(page.Scopes, ps)
		}
		out = syncapi.RunDetail{Run: syncapi.Run{ID: g.plan.RunID, Action: syncapi.RunActionG2A, Status: g.status, Actor: "conductor:lab.admin"},
			HasPlan: true, Digest: g.plan.Digest, G2A: &page, OpsMatching: total, G2AResults: g.results, NotApply: "g2a"}
	case syncapi.OpConfigValidate:
		if len(g.invalid) > 0 {
			out = syncapi.ConfigValidateResult{Valid: false, Errors: g.invalid}
			break
		}
		return g.fakeSync.Call(ctx, req)
	default:
		return g.fakeSync.Call(ctx, req)
	}
	return syncapi.OKResponse(req.ID, out)
}

func (g *gfFakeSync) setGF(gf *syncapi.GoogleFirstSettings) {
	g.fakeSync.mu.Lock()
	defer g.fakeSync.mu.Unlock()
	g.fakeSync.cfg.Settings.GoogleFirst = gf
}

// fakeApplier records the operations it is asked to run.
type fakeApplier struct {
	mu    sync.Mutex
	prov  *fakeProv
	calls []string
	fail  map[int]error
}

func (f *fakeApplier) do(kind string, op syncapi.G2AOp) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("%s:%d", kind, op.Seq))
	return f.fail[op.Seq]
}

func (f *fakeApplier) Update(_ context.Context, _ provapi.Actor, _ string, op syncapi.G2AOp) error {
	return f.do("update", op)
}
func (f *fakeApplier) Rename(_ context.Context, _ provapi.Actor, _ string, op syncapi.G2AOp) error {
	return f.do("rename", op)
}
func (f *fakeApplier) Reenable(_ context.Context, _ provapi.Actor, _ string, op syncapi.G2AOp) error {
	return f.do("reenable", op)
}
func (f *fakeApplier) Disable(_ context.Context, _ provapi.Actor, _ string, op syncapi.G2AOp) error {
	return f.do("disable", op)
}
func (f *fakeApplier) Create(_ context.Context, _ provapi.Actor, _ string, op syncapi.G2AOp) (g2aCreated, error) {
	if err := f.do("create", op); err != nil {
		return g2aCreated{}, err
	}
	sidv := fmt.Sprintf("%s-%d", testDomain, 1300+op.Seq)
	f.prov.mu.Lock()
	f.prov.users[sidv] = &provapi.UserResult{SID: sidv, SAM: op.SAM, DN: op.DN, Mail: g2aMail(op), InScope: true,
		PrivilegedReasons: []string{}, PendingTokens: []provapi.PendingToken{}}
	f.prov.mu.Unlock()
	return g2aCreated{SID: sidv, ObjectGUID: "00112233-4455-6677-8899-aabbccddee" + fmt.Sprintf("%02d", op.Seq)}, nil
}

func (f *fakeApplier) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.calls...)
}

const (
	gfManagedOU = "OU=People,OU=Google,DC=lab,DC=test"
	gfDigest    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func gfSettings(mode string) *syncapi.GoogleFirstSettings {
	l := gfDefaultLimits()
	return &syncapi.GoogleFirstSettings{Enabled: true, GoogleDomain: "example.com", Scopes: []syncapi.G2AScope{{Name: "people", Mode: mode,
		ManagedOU: gfManagedOU, GroupsOU: "OU=Groups," + gfManagedOU, QuarantineOU: "OU=Quarantine," + gfManagedOU,
		OrgUnits: []string{"/Staff"}, SubOrgUnits: true, Fields: []string{"title", "phone_work"}, Limits: &l},
		{Name: "contractors", Mode: syncapi.G2AModeApply, ManagedOU: "OU=Contractors,OU=Google,DC=lab,DC=test",
			GroupsOU: "OU=Groups,OU=Contractors,OU=Google,DC=lab,DC=test", QuarantineOU: "OU=Quarantine,OU=Contractors,OU=Google,DC=lab,DC=test",
			OrgUnits: []string{"/Contractors"}, Limits: &l}}}
}

// gfPlan is a plan with every kind in scope people (in the order
// conductor-sync emits them) and a blocked scope contractors.
func gfPlan(mode string) syncapi.G2APlan {
	dn := func(sam string) string { return "CN=" + sam + "," + gfManagedOU }
	return syncapi.G2APlan{RunID: 42, Digest: gfDigest, GoogleDomain: "example.com", Scopes: []syncapi.G2AScopePlan{
		{Name: "people", Mode: mode, SourceSize: 10, Managed: 8, Ops: []syncapi.G2AOp{
			{Seq: 0, Kind: syncapi.G2AUserUpdate, GoogleID: "g1", SAM: "ana.lima", DN: dn("ana.lima"), Reason: syncapi.G2AReasonADDrift,
				Marker: "google-first:g1", Changes: []syncapi.G2AChange{{Field: "title", Before: "Boss", After: "Analyst"}}},
			{Seq: 1, Kind: syncapi.G2AUserRename, GoogleID: "g2", SAM: "bia.reis", DN: dn("bia.reis"), Reason: syncapi.G2AReasonPrimaryAddress,
				Marker: "google-first:g2", Changes: []syncapi.G2AChange{{Field: "mail", Before: "bia@example.com", After: "beatriz@example.com"}}},
			{Seq: 2, Kind: syncapi.G2AUserReenable, GoogleID: "g3", SAM: "caio.dias", DN: "CN=caio.dias,OU=Quarantine," + gfManagedOU,
				Reason: syncapi.G2AReasonActive, Marker: "google-first:g3", MoveTo: gfManagedOU, Enable: true},
			{Seq: 3, Kind: syncapi.G2AUserCreate, GoogleID: "g4", SAM: "davi.melo", DN: dn("Davi Melo"), Reason: syncapi.G2AReasonNew,
				Marker: "google-first:g4", ParentOU: gfManagedOU, Invite: true,
				Changes: []syncapi.G2AChange{{Field: "sAMAccountName", After: "davi.melo"}, {Field: "mail", After: "davi@example.com"}}},
			{Seq: 4, Kind: syncapi.G2AUserDisable, GoogleID: "g5", SAM: "eva.cruz", DN: dn("eva.cruz"), Reason: syncapi.G2AReasonSuspended,
				Marker: "google-first:g5", MoveTo: "OU=Quarantine," + gfManagedOU, Disable: true},
		},
			Skipped: []syncapi.G2ASkipped{{GoogleID: "g9", SAM: "root.admin", DN: dn("root.admin"), Reason: syncapi.G2ASkipPrivileged,
				Detail: []string{"member of Domain Admins"}}, {GoogleID: "g8", Reason: syncapi.G2ASkipNoFreeLogon}},
			Limits: []syncapi.LimitRow{{Limit: "max_creates", Value: 1, Max: 20}}},
		{Name: "contractors", Mode: syncapi.G2AModeApply, Blocked: true, SourceSize: 300, Managed: 3, Ops: []syncapi.G2AOp{
			{Seq: 5, Kind: syncapi.G2AUserCreate, GoogleID: "c1", SAM: "c1", DN: "CN=c1,OU=Contractors,OU=Google,DC=lab,DC=test", Reason: syncapi.G2AReasonNew}},
			Limits: []syncapi.LimitRow{{Limit: "max_creates", Value: 300, Max: 20, Exceeded: true}}},
	}}
}

type gfH struct {
	*pwHarness
	fs     *gfFakeSync
	idp    *fakeIDP
	ap     *fakeApplier
	secret []byte
	admin  string
}

func newGFHarness(t *testing.T, mode string) *gfH {
	t.Helper()
	h := newPWHarness(t)
	fs := &gfFakeSync{fakeSync: newFakeSync(h.now), plan: gfPlan(mode)}
	fs.cfg.Settings.GoogleFirst = gfSettings(mode)
	h.s.sync = fs
	idp := newFakeIDP()
	h.s.idp = idp
	ap := &fakeApplier{prov: h.prov, fail: map[int]error{}}
	h.s.g2a = ap
	secret := h.enrollTOTP(t, "lab.admin")
	return &gfH{pwHarness: h, fs: fs, idp: idp, ap: ap, secret: secret, admin: h.session(t, "lab.admin", stageFull, true)}
}

// confirm answers a confirmation page with the password and a fresh code.
func (h *gfH) confirm(t *testing.T, loc string) *httptest.ResponseRecorder {
	t.Helper()
	h.now = h.now.Add(31 * time.Second)
	return h.do("POST", loc, h.admin, url.Values{"password": {"pw"}, "code": {totp.Code(h.secret, totp.Step(h.now))}})
}

func (h *gfH) audits(t *testing.T, action string) []store.AuditEvent {
	t.Helper()
	evs, _, err := h.st.ListAudit(context.Background(), store.AuditFilter{Action: action}, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func (h *gfH) addGoogleSP() {
	h.idp.sps["google.com/a/example.com"] = idpapi.SP{SPInput: idpapi.SPInput{EntityID: "google.com/a/example.com",
		Name: "Google Workspace (example.com)", ACSURLs: []string{"https://www.google.com/a/example.com/acs"}}, Enabled: true}
}

func TestGoogleTarget(t *testing.T) {
	for _, c := range []struct {
		v    string
		want bool
	}{
		{"google.com/a/example.com", true},
		{"https://www.google.com/a/example.com/acs", true},
		{"https://accounts.google.com/samlrp/03abc123", true},
		{"https://user@accounts.google.com:443/x", true},
		{"HTTPS://WWW.GOOGLE.COM./a/x", true},
		{"https://example.com", true},
		{"https://proxy.example.net/sso/example.com/", true},
		{"https://cloud.example.com/apps/user_oidc/code", false},
		{"https://grafana.example.com", false},
		{"https://evilgoogle.com/a/x", false},
		{"https://google.com.evil.test/x", false},
		{"", false},
	} {
		if got := googleTarget(c.v, "example.com"); got != c.want {
			t.Errorf("googleTarget(%q) = %v", c.v, got)
		}
	}
	if googleTarget("https://example.com", "") {
		t.Error("no domain: only google.com counts")
	}
	if spTargetsGoogle(idpapi.SPInput{EntityID: "https://sp.lab.test", ACSURLs: []string{"https://accounts.google.com/samlrp/acs?rpid=1"}}, "") == "" {
		t.Error("an ACS URL at google.com targets Google")
	}
	if clientTargetsGoogle(idpapi.ClientInput{RedirectURIs: []string{"https://app.lab.test/cb"}, PostLogoutURIs: []string{"https://accounts.google.com/logout"}}, "") == "" {
		t.Error("a post-logout URI at google.com targets Google")
	}
}

func TestGoogleFirstSectionAvailability(t *testing.T) {
	h := newHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	h.s.sync = newFakeSync(h.now)
	body := h.do("GET", "/admin/google-first", admin, nil).Body.String()
	if !strings.Contains(body, `data-e2e="gf-card-disabled"`) || !strings.Contains(body, `data-e2e="gf-text-missing-provisioner"`) ||
		strings.Contains(body, `data-e2e="nav-link-google-first"`) {
		t.Fatalf("section without the provisioner:\n%s", body)
	}
	for _, p := range []string{"/admin/google-first/runs/42", "/admin/google-first/new-scope", "/admin/google-first/scopes/people"} {
		if b := h.do("GET", p, admin, nil).Body.String(); !strings.Contains(b, "gf-card-disabled") {
			t.Errorf("%s without the provisioner", p)
		}
	}
	for _, p := range []string{"/admin/google-first/plan", "/admin/google-first/settings", "/admin/google-first/runs/42/apply"} {
		if b := h.do("POST", p, admin, url.Values{}).Body.String(); !strings.Contains(b, "gf-card-disabled") {
			t.Errorf("POST %s without the provisioner", p)
		}
	}
	g := newGFHarness(t, syncapi.G2AModeDryRun)
	body = g.do("GET", "/admin/google-first", g.admin, nil).Body.String()
	for _, want := range []string{`data-e2e="nav-link-google-first"`, `data-e2e="gf-text-state"`, `data-e2e="gf-scope-people"`,
		`data-e2e="gf-p3-ok"`, `data-e2e="gf-text-what-admins-can-do"`, `data-e2e="gf-btn-plan"`, `data-e2e="gf-link-run-42"`} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %s", want)
		}
	}
	// Helpdesk and auditors never reach it.
	for _, who := range []string{"helpdesk.user", "auditor.user"} {
		tok := g.session(t, who, stageFull, true)
		if w := g.do("GET", "/admin/google-first", tok, nil); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", who, w.Code)
		}
	}
	// conductor-idp off: the check passes and says so.
	g.s.idp = nil
	if b := g.do("GET", "/admin/google-first", g.admin, nil).Body.String(); !strings.Contains(b, `data-e2e="gf-p3-off"`) {
		t.Fatal("idp off not shown")
	}
	// conductor-sync unreachable: an error, not a crash.
	g.fs.fail[syncapi.OpConfigGet] = &syncapi.Error{Code: syncapi.CodeUnavailable, Message: "down"}
	if b := g.do("GET", "/admin/google-first", g.admin, nil).Body.String(); !strings.Contains(b, "form-text-error") {
		t.Fatal("unreachable sync")
	}
}

func TestGoogleFirstEnableRefusedWhileIDPServesGoogle(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeDryRun)
	gf := gfSettings(syncapi.G2AModeDryRun)
	gf.Enabled = false
	h.fs.setGF(gf)
	h.addGoogleSP()
	form := url.Values{"enabled": {"1"}, "google_domain": {"Example.com"}}
	w := h.do("POST", "/admin/google-first/settings", h.admin, form)
	if w.Header().Get("Location") != "/admin/google-first" || h.fs.updated != nil {
		t.Fatalf("enablement with a Google SP: %d %q", w.Code, w.Header().Get("Location"))
	}
	body := h.do("GET", "/admin/google-first", h.admin, nil).Body.String()
	if !strings.Contains(body, "Google Workspace (example.com)") || !strings.Contains(body, `data-e2e="gf-p3-refused"`) {
		t.Fatalf("refusal not shown:\n%s", body)
	}
	if evs := h.audits(t, "g2a.p3_refused"); len(evs) != 1 || evs[0].Result != store.ResultDenied {
		t.Fatalf("audit %+v", evs)
	}
	// A disabled registration counts too.
	sp := h.idp.sps["google.com/a/example.com"]
	sp.Enabled = false
	h.idp.sps[sp.EntityID] = sp
	if w := h.do("POST", "/admin/google-first/settings", h.admin, form); strings.HasPrefix(w.Header().Get("Location"), "/confirm/") {
		t.Fatal("a disabled Google SP did not block")
	}
	// An OIDC client redirecting to Google blocks too.
	delete(h.idp.sps, sp.EntityID)
	h.idp.clients["c1"] = idpapi.Client{ID: "c1", ClientInput: idpapi.ClientInput{Name: "Google login", RedirectURIs: []string{"https://accounts.google.com/oauth2/cb"}}}
	if w := h.do("POST", "/admin/google-first/settings", h.admin, form); strings.HasPrefix(w.Header().Get("Location"), "/confirm/") {
		t.Fatal("a Google OIDC client did not block")
	}
	delete(h.idp.clients, "c1")
	// conductor-idp unreachable: refused (closed).
	h.idp.fail[idpapi.OpSPList] = &idpapi.Error{Code: idpapi.CodeUnavailable, Message: "down"}
	if w := h.do("POST", "/admin/google-first/settings", h.admin, form); strings.HasPrefix(w.Header().Get("Location"), "/confirm/") {
		t.Fatal("unverified check passed")
	}
	delete(h.idp.fail, idpapi.OpSPList)
	// Nothing serves Google: a preview that says what Google admins can do.
	w = h.do("POST", "/admin/google-first/settings", h.admin, form)
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("propose: %q", loc)
	}
	cp := h.do("GET", loc, h.admin, nil).Body.String()
	if !strings.Contains(cp, "confirm-text-warning") || !strings.Contains(cp, "google_first.enabled") || !strings.Contains(cp, "confirm-text-reauth") {
		t.Fatalf("confirm page:\n%s", cp)
	}
	// A Google SP registered between the preview and the confirmation.
	h.addGoogleSP()
	h.confirm(t, loc)
	if h.fs.updated != nil {
		t.Fatal("saved although conductor-idp serves Google now")
	}
	delete(h.idp.sps, "google.com/a/example.com")
	loc = h.do("POST", "/admin/google-first/settings", h.admin, form).Header().Get("Location")
	h.confirm(t, loc)
	u := h.fs.updated
	if u == nil || u.Settings.GoogleFirst == nil || !u.Settings.GoogleFirst.Enabled || u.Settings.GoogleFirst.GoogleDomain != "example.com" ||
		len(u.Settings.GoogleFirst.Scopes) != 2 || u.BaseVersion != 2 {
		t.Fatalf("update %+v", u)
	}
	if evs := h.audits(t, "google_first.enable"); len(evs) == 0 || evs[0].Result != store.ResultOK || !strings.Contains(evs[0].Detail, "[re-authenticated]") {
		t.Fatalf("audit %+v", evs)
	}
	// Turning it on needs a domain.
	h.fs.updated = nil
	if w := h.do("POST", "/admin/google-first/settings", h.admin, url.Values{"enabled": {"1"}}); strings.HasPrefix(w.Header().Get("Location"), "/confirm/") {
		t.Fatal("enabled without a domain")
	}
	// Off needs no P3 check, even with a Google SP.
	h.addGoogleSP()
	if w := h.do("POST", "/admin/google-first/settings", h.admin, url.Values{"google_domain": {"example.com"}}); !strings.HasPrefix(w.Header().Get("Location"), "/confirm/") &&
		w.Header().Get("Location") != "/admin/google-first" {
		t.Fatalf("turning off: %q", w.Header().Get("Location"))
	}
}

func TestSSORefusesGoogleWhileGoogleFirst(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeDryRun)
	spForm := func(entity, acs, preset string) url.Values {
		v := url.Values{"entity_id": {entity}, "name": {"App"}, "acs_urls": {acs}, "nameid_format": {idpapi.NameIDFormats[0]},
			"nameid_source": {"email"}, "allow_all": {"1"}, "action": {"review"}}
		if preset != "" {
			v.Set("preset", preset)
		}
		return v
	}
	w := h.do("POST", "/admin/sso/saml/form", h.admin, spForm("google.com/a/example.com", "https://www.google.com/a/example.com/acs", "google-workspace"))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "form-text-error") {
		t.Fatalf("Google SP accepted: %d", w.Code)
	}
	if evs := h.audits(t, "sso.sp_create"); len(evs) != 1 || evs[0].Result != store.ResultDenied {
		t.Fatalf("audit %+v", evs)
	}
	// The preset counts even with another entity ID.
	if w := h.do("POST", "/admin/sso/saml/form", h.admin, spForm("https://sp.lab.test/meta", "https://sp.lab.test/acs", "google-workspace")); w.Code != http.StatusConflict {
		t.Fatalf("preset accepted: %d", w.Code)
	}
	// An OIDC client redirecting to Google.
	cf := url.Values{"name": {"G"}, "kind": {"confidential"}, "redirect_uris": {"https://accounts.google.com/cb"}, "scopes": {"profile"},
		"groups_claim": {"none"}, "allow_all": {"1"}, "action": {"review"}}
	if w := h.do("POST", "/admin/sso/oidc/form", h.admin, cf); w.Code != http.StatusConflict {
		t.Fatalf("Google client accepted: %d", w.Code)
	}
	// Any other application is fine.
	w = h.do("POST", "/admin/sso/saml/form", h.admin, spForm("https://cloud.example.com/saml", "https://cloud.example.com/acs", ""))
	if !strings.HasPrefix(w.Header().Get("Location"), "/confirm/") {
		t.Fatalf("other SP refused: %d", w.Code)
	}
	// The mode turned on between the preview and the confirmation of a
	// Google registration made while it was off.
	gf := gfSettings(syncapi.G2AModeDryRun)
	gf.Enabled = false
	h.fs.setGF(gf)
	w = h.do("POST", "/admin/sso/saml/form", h.admin, spForm("google.com/a/example.com", "https://www.google.com/a/example.com/acs", ""))
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("mode off: Google SP refused: %d", w.Code)
	}
	h.fs.setGF(gfSettings(syncapi.G2AModeDryRun))
	h.confirm(t, loc)
	if _, ok := h.idp.sps["google.com/a/example.com"]; ok {
		t.Fatal("created at confirmation while the mode is on")
	}
	// Settings unreadable: a google.com target is refused, others pass.
	h.fs.fail[syncapi.OpConfigGet] = &syncapi.Error{Code: syncapi.CodeUnavailable, Message: "down"}
	if w := h.do("POST", "/admin/sso/saml/form", h.admin, spForm("https://accounts.google.com/samlrp/1", "https://accounts.google.com/samlrp/acs", "")); w.Code != http.StatusConflict {
		t.Fatalf("unverified Google SP accepted: %d", w.Code)
	}
	if w := h.do("POST", "/admin/sso/saml/form", h.admin, spForm("https://sp2.lab.test/meta", "https://sp2.lab.test/acs", "")); !strings.HasPrefix(w.Header().Get("Location"), "/confirm/") {
		t.Fatalf("unverified other SP refused: %d", w.Code)
	}
	// Without the sync section there is nothing to check.
	h.s.sync = nil
	if w := h.do("POST", "/admin/sso/saml/form", h.admin, spForm("google.com/a/example.com", "https://www.google.com/a/example.com/acs", "")); !strings.HasPrefix(w.Header().Get("Location"), "/confirm/") {
		t.Fatalf("no sync section: %d", w.Code)
	}
}

func scopeForm(name string) url.Values {
	return url.Values{"name": {name}, "managed_ou": {"OU=Sales,OU=Google,DC=lab,DC=test"}, "groups_ou": {"OU=Groups,OU=Sales,OU=Google,DC=lab,DC=test"},
		"quarantine_ou": {"OU=Quarantine,OU=Sales,OU=Google,DC=lab,DC=test"}, "org_units": {"/Sales\n/Sales/North\n"}, "sub_org_units": {"1"},
		"member_of": {""}, "fields": {"title", "phone_mobile", "bogus"}, "logon_template": {"{g}{family}"},
		"max_creates": {"10"}, "max_disables": {"2"}, "max_reenables": {"10"}, "max_updates": {"30"}, "max_renames": {"3"},
		"max_touched_percent": {"15.5"}, "min_source_size": {"1"}, "max_source_drop_percent": {"20"}}
}

func TestGoogleFirstScopes(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeApply)
	if body := h.do("GET", "/admin/google-first/new-scope", h.admin, nil).Body.String(); !strings.Contains(body, `data-e2e="gf-input-managed-ou"`) ||
		!strings.Contains(body, `value="20"`) {
		t.Fatal("new scope form")
	}
	if body := h.do("GET", "/admin/google-first/scopes/people", h.admin, nil).Body.String(); !strings.Contains(body, gfManagedOU) ||
		!strings.Contains(body, `data-e2e="gf-text-scope-name"`) {
		t.Fatal("edit form")
	}
	if w := h.do("GET", "/admin/google-first/scopes/nope", h.admin, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown scope: %d", w.Code)
	}
	// Invalid input stays on the form.
	bad := scopeForm("sales")
	bad.Set("max_creates", "many")
	if w := h.do("POST", "/admin/google-first/scopes", h.admin, bad); w.Code != http.StatusBadRequest {
		t.Fatalf("bad number: %d", w.Code)
	}
	if w := h.do("POST", "/admin/google-first/scopes", h.admin, scopeForm("Sales Team")); w.Code != http.StatusBadRequest {
		t.Fatalf("bad name: %d", w.Code)
	}
	if w := h.do("POST", "/admin/google-first/scopes", h.admin, scopeForm("people")); w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate: %d", w.Code)
	}
	h.fs.invalid = []string{"google_first.scopes[sales].managed_ou overlaps source.user_bases"}
	if w := h.do("POST", "/admin/google-first/scopes", h.admin, scopeForm("sales")); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "overlaps") {
		t.Fatalf("validation: %d", w.Code)
	}
	h.fs.invalid = nil
	// Add: dry-run, limits and fields as typed (unknown fields dropped).
	loc := h.do("POST", "/admin/google-first/scopes", h.admin, scopeForm("sales")).Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("add: %q", loc)
	}
	h.confirm(t, loc)
	u := h.fs.updated
	if u == nil || len(u.Settings.GoogleFirst.Scopes) != 3 {
		t.Fatalf("update %+v", u)
	}
	sc := u.Settings.GoogleFirst.Scopes[2]
	if sc.Name != "sales" || sc.Mode != syncapi.G2AModeDryRun || len(sc.OrgUnits) != 2 || !sc.SubOrgUnits || fmt.Sprint(sc.Fields) != "[title phone_mobile]" ||
		sc.Limits == nil || sc.Limits.MaxCreates != 10 || sc.Limits.MaxTouchedPercent != 15.5 || sc.LogonTemplate != "{g}{family}" {
		t.Fatalf("scope %+v %+v", sc, sc.Limits)
	}
	// Editing what an apply scope selects puts it back in dry-run.
	h.fs.updated = nil
	edit := scopeForm("people")
	edit.Set("edit", "1")
	loc = h.do("POST", "/admin/google-first/scopes", h.admin, edit).Header().Get("Location")
	if cp := h.do("GET", loc, h.admin, nil).Body.String(); !strings.Contains(cp, "confirm-text-warning") {
		t.Fatal("no warning about dry-run")
	}
	h.confirm(t, loc)
	if p := h.fs.updated.Settings.GoogleFirst.Scopes[0]; p.Mode != syncapi.G2AModeDryRun || p.ManagedOU != "OU=Sales,OU=Google,DC=lab,DC=test" {
		t.Fatalf("edited scope %+v", p)
	}
	// Changing only the limits keeps apply.
	h.fs.updated = nil
	sel := scopeFormFrom(gfSettings(syncapi.G2AModeApply).Scopes[0], true)
	lim := url.Values{"edit": {"1"}, "name": {"people"}, "managed_ou": {sel.ManagedOU}, "groups_ou": {sel.GroupsOU}, "quarantine_ou": {sel.QuarantineOU},
		"org_units": {sel.OrgUnitsText}, "sub_org_units": {"1"}, "fields": sel.Fields, "max_creates": {"5"}, "max_disables": {"5"}, "max_reenables": {"20"},
		"max_updates": {"50"}, "max_renames": {"5"}, "max_touched_percent": {"20"}, "min_source_size": {"1"}, "max_source_drop_percent": {"20"}}
	loc = h.do("POST", "/admin/google-first/scopes", h.admin, lim).Header().Get("Location")
	h.confirm(t, loc)
	if p := h.fs.updated.Settings.GoogleFirst.Scopes[0]; p.Mode != syncapi.G2AModeApply || p.Limits.MaxCreates != 5 {
		t.Fatalf("limits only %+v", p)
	}
	// Remove: typed name, then the confirmation.
	h.fs.updated = nil
	if w := h.do("POST", "/admin/google-first/scopes/people/remove", h.admin, url.Values{"confirm": {"peopl"}}); w.Header().Get("Location") != "/admin/google-first" {
		t.Fatal("wrong typed name")
	}
	loc = h.do("POST", "/admin/google-first/scopes/people/remove", h.admin, url.Values{"confirm": {"people"}}).Header().Get("Location")
	h.confirm(t, loc)
	if s := h.fs.updated.Settings.GoogleFirst.Scopes; len(s) != 1 || s[0].Name != "contractors" {
		t.Fatalf("after remove %+v", s)
	}
	if evs := h.audits(t, "google_first.scope_remove"); len(evs) != 2 || evs[1].Result != store.ResultDenied {
		t.Fatalf("remove audit %+v", evs)
	}
}

func TestGoogleFirstPlanPage(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeDryRun)
	// P3 is checked before any plan is requested.
	h.addGoogleSP()
	if w := h.do("POST", "/admin/google-first/plan", h.admin, url.Values{"scope": {"people"}}); w.Header().Get("Location") != "/admin/google-first" || len(h.fs.planned) != 0 {
		t.Fatal("plan requested while conductor-idp serves Google")
	}
	delete(h.idp.sps, "google.com/a/example.com")
	// Off: no plan.
	gf := gfSettings(syncapi.G2AModeDryRun)
	gf.Enabled = false
	h.fs.setGF(gf)
	if h.do("POST", "/admin/google-first/plan", h.admin, nil); len(h.fs.planned) != 0 {
		t.Fatal("plan while off")
	}
	h.fs.setGF(gfSettings(syncapi.G2AModeDryRun))
	if w := h.do("POST", "/admin/google-first/plan", h.admin, url.Values{"scope": {"Bad Name"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad scope: %d", w.Code)
	}
	w := h.do("POST", "/admin/google-first/plan", h.admin, url.Values{"scope": {"people"}})
	if w.Header().Get("Location") != "/admin/google-first/runs/42" || len(h.fs.planned) != 1 {
		t.Fatalf("plan: %q", w.Header().Get("Location"))
	}
	if p := h.fs.planned[0]; p.Scope != "people" || !slices.Contains(p.RoleGroupSIDs, helpdeskSID) || !slices.Contains(p.RoleGroupSIDs, auditorSID) {
		t.Fatalf("plan params %+v", p)
	}
	if evs := h.audits(t, "g2a.plan"); len(evs) != 1 || !strings.Contains(evs[0].Detail, "privileged accounts skipped: 1") ||
		!strings.Contains(evs[0].Detail, "ad.user.create=1") {
		t.Fatalf("plan audit %+v", evs)
	}
	if evs := h.audits(t, "g2a.skip.privileged"); len(evs) != 1 || !strings.Contains(evs[0].Target, "root.admin") ||
		!strings.Contains(evs[0].Detail, "Domain Admins") {
		t.Fatalf("privileged skip audit %+v", evs)
	}
	body := h.do("GET", "/admin/google-first/runs/42", h.admin, nil).Body.String()
	for _, want := range []string{`data-e2e="gf-plan-scope-people"`, `data-e2e="gf-plan-kind-people-ad-user-create"`,
		`data-e2e="gf-plan-kind-people-ad-user-disable"`, `data-e2e="gf-plan-op-4"`, `data-e2e="gf-plan-skip-privileged-root-admin"`,
		`data-e2e="gf-plan-limit-exceeded-contractors-max-creates"`, `data-e2e="gf-plan-blocked-contractors"`, `data-e2e="gf-p3-ok"`,
		`data-e2e="gf-plan-form-mode-people"`, "people 01234567", `data-e2e="gf-plan-not-applicable"`, `data-e2e="gf-plan-preview-only-people"`,
		"beatriz@example.com", `data-e2e="gf-plan-skips-people"`} {
		if !strings.Contains(body, want) {
			t.Errorf("plan page lacks %s", want)
		}
	}
	// Kinds in apply order: updates first, disables last.
	if strings.Index(body, "gf-plan-kind-people-ad-user-update") > strings.Index(body, "gf-plan-kind-people-ad-user-disable") {
		t.Error("kinds out of order")
	}
	if strings.Contains(body, `data-e2e="gf-plan-form-apply"`) {
		t.Error("apply offered for a dry-run scope")
	}
	if w := h.do("GET", "/admin/google-first/runs/7", h.admin, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown run: %d", w.Code)
	}
	// conductor-sync refuses (selection error): shown, audited.
	h.fs.fail[syncapi.OpG2APlan] = &syncapi.Error{Code: syncapi.CodeInvalid, Message: "the Google selection stops the read", Details: []string{"empty-selection: /Staff"}}
	h.do("POST", "/admin/google-first/plan", h.admin, nil)
	if evs := h.audits(t, "g2a.plan"); len(evs) != 2 || evs[0].Result != store.ResultFailed || !strings.Contains(evs[0].Detail, "empty-selection") {
		t.Fatalf("failed plan audit %+v", evs)
	}
}

func TestGoogleFirstModeGate(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeDryRun)
	h.fs.status = syncapi.StatusPlanned
	back := "/admin/google-first/runs/42"
	post := func(form url.Values) string {
		return h.do("POST", "/admin/google-first/scopes/people/mode", h.admin, form).Header().Get("Location")
	}
	if loc := post(url.Values{"mode": {"apply"}, "run": {"42"}, "confirm": {"people 0123456"}}); loc != back {
		t.Fatalf("short confirmation: %q", loc)
	}
	if loc := post(url.Values{"mode": {"apply"}, "run": {"42"}, "confirm": {"people " + strings.Repeat("f", 8)}}); loc != back {
		t.Fatalf("wrong digest: %q", loc)
	}
	if w := h.do("POST", "/admin/google-first/scopes/people/mode", h.admin, url.Values{"mode": {"apply"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("no run: %d", w.Code)
	}
	if w := h.do("POST", "/admin/google-first/scopes/people/mode", h.admin, url.Values{"mode": {"yolo"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad mode: %d", w.Code)
	}
	// A newer plan exists: the reviewed one is not the latest.
	h.fs.newerRuns = []syncapi.Run{{ID: 43, Action: syncapi.RunActionG2A, Status: syncapi.StatusPlanned}}
	if loc := post(url.Values{"mode": {"apply"}, "run": {"42"}, "confirm": {"people 01234567"}}); loc != back {
		t.Fatalf("not latest: %q", loc)
	}
	h.fs.newerRuns = nil
	if evs := h.audits(t, "google_first.mode"); len(evs) != 3 || evs[0].Result != store.ResultDenied {
		t.Fatalf("refusals audited %+v", evs)
	}
	if h.fs.updated != nil {
		t.Fatal("saved without the gate")
	}
	loc := post(url.Values{"mode": {"apply"}, "run": {"42"}, "confirm": {"people 01234567"}})
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("gate passed: %q", loc)
	}
	cp := h.do("GET", loc, h.admin, nil).Body.String()
	if !strings.Contains(cp, "reviewed plan: run 42") || !strings.Contains(cp, "confirm-text-reauth") {
		t.Fatalf("confirm page:\n%s", cp)
	}
	if w := h.do("POST", loc, h.admin, url.Values{"password": {"pw"}, "code": {"000000"}}); w.Code != http.StatusUnauthorized || h.fs.updated != nil {
		t.Fatalf("without the second factor: %d", w.Code)
	}
	h.confirm(t, loc)
	if p := h.fs.updated.Settings.GoogleFirst.Scopes[0]; p.Mode != syncapi.G2AModeApply {
		t.Fatalf("mode %+v", p)
	}
	// Back to dry-run: the confirmation only.
	h.fs.setGF(gfSettings(syncapi.G2AModeApply))
	h.fs.updated = nil
	loc = post(url.Values{"mode": {"dry-run"}})
	h.confirm(t, loc)
	if p := h.fs.updated.Settings.GoogleFirst.Scopes[0]; p.Mode != syncapi.G2AModeDryRun {
		t.Fatalf("mode %+v", p)
	}
	// Mode already set: nothing proposed.
	if loc := post(url.Values{"mode": {"apply"}, "run": {"42"}, "confirm": {"people 01234567"}}); loc != "/admin/google-first" {
		t.Fatalf("no change: %q", loc)
	}
}

func TestGoogleFirstApply(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeApply)
	h.fs.status = syncapi.StatusPlanned
	back := "/admin/google-first/runs/42"
	body := h.do("GET", back, h.admin, nil).Body.String()
	if !strings.Contains(body, `data-e2e="gf-plan-form-apply"`) || !strings.Contains(body, `data-e2e="gf-plan-applies-people"`) ||
		!strings.Contains(body, `data-e2e="gf-run-applicable">5<`) {
		t.Fatalf("apply not offered:\n%s", body)
	}
	apply := func(confirm, digest string) string {
		return h.do("POST", back+"/apply", h.admin, url.Values{"digest": {digest}, "confirm": {confirm}}).Header().Get("Location")
	}
	if loc := apply("0123456", gfDigest); loc != back {
		t.Fatalf("wrong prefix: %q", loc)
	}
	if loc := apply("01234567", strings.Repeat("0", 64)); loc != back {
		t.Fatalf("stale digest: %q", loc)
	}
	loc := apply("01234567", gfDigest)
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("propose: %q", loc)
	}
	cp := h.do("GET", loc, h.admin, nil).Body.String()
	if !strings.Contains(cp, "scope people: ad.user.update=1 ad.user.rename=1 ad.user.reenable=1 ad.user.create=1 ad.user.disable=1") ||
		!strings.Contains(cp, "scope contractors: not applied (limits exceeded)") || !strings.Contains(cp, "confirm-text-reauth") {
		t.Fatalf("confirm page:\n%s", cp)
	}
	if len(h.ap.called()) != 0 {
		t.Fatal("applied before the confirmation")
	}
	h.ap.fail[0] = &provapi.Error{Code: provapi.CodeConflict, Message: "title changed in AD"}
	w := h.confirm(t, loc)
	if w.Header().Get("Location") != back {
		t.Fatalf("after apply: %q", w.Header().Get("Location"))
	}
	if got := fmt.Sprint(h.ap.called()); got != "[update:0 rename:1 reenable:2 create:3 disable:4]" {
		t.Fatalf("order %s", got)
	}
	if len(h.fs.confirms) != 1 {
		t.Fatal("not confirmed")
	}
	c := h.fs.confirms[0]
	if c.RunID != 42 || c.Digest != gfDigest || c.Actor != "lab.admin" || len(c.Results) != 5 {
		t.Fatalf("confirm %+v", c)
	}
	st := map[int]syncapi.G2AOpResult{}
	for _, r := range c.Results {
		st[r.Seq] = r
	}
	if st[0].Status != syncapi.G2AOpFailed || !strings.Contains(st[0].Error, "conflict") || st[3].Status != syncapi.G2AOpDone ||
		st[3].SID != testDomain+"-1303" || st[3].ObjectGUID == "" || st[4].Status != syncapi.G2AOpDone {
		t.Fatalf("results %+v", c.Results)
	}
	for _, a := range []string{"g2a.apply.ad.user.update", "g2a.apply.ad.user.create", "g2a.apply.ad.user.disable", "g2a.confirm", "g2a.apply"} {
		if len(h.audits(t, a)) == 0 {
			t.Errorf("no audit %s", a)
		}
	}
	if evs := h.audits(t, "g2a.apply.ad.user.update"); evs[0].Result != store.ResultFailed || !strings.Contains(evs[0].Detail, `title: "Boss" -> "Analyst"`) ||
		!strings.Contains(evs[0].Detail, "digest "+gfDigest) {
		t.Fatalf("update audit %+v", evs[0])
	}
	// The account created got its invitation.
	if inv := h.mailsOf(t, "invitation"); len(inv) != 1 || inv[0].To != "davi@example.com" {
		t.Fatalf("invitations %+v", inv)
	}
	if evs := h.audits(t, "invite.issued"); len(evs) != 1 || evs[0].Result != store.ResultOK {
		t.Fatalf("invite audit %+v", evs)
	}
	// The plan is closed now: no second apply.
	if loc := apply("01234567", gfDigest); loc != back {
		t.Fatalf("second apply: %q", loc)
	}
	if body := h.do("GET", back, h.admin, nil).Body.String(); !strings.Contains(body, `data-e2e="gf-plan-op-status-3"`) ||
		strings.Contains(body, `data-e2e="gf-plan-form-apply"`) {
		t.Fatal("results not shown")
	}
}

func TestGoogleFirstApplyStopsAndRefusals(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeApply)
	h.fs.status = syncapi.StatusPlanned
	back := "/admin/google-first/runs/42"
	form := func() url.Values { return url.Values{"digest": {gfDigest}, "confirm": {"01234567"}} }
	// The provisioner at its ceiling: the rest is not attempted.
	h.ap.fail[1] = &provapi.Error{Code: provapi.CodeRateLimited, Message: "ceiling"}
	loc := h.do("POST", back+"/apply", h.admin, form()).Header().Get("Location")
	h.confirm(t, loc)
	if got := fmt.Sprint(h.ap.called()); got != "[update:0 rename:1]" {
		t.Fatalf("calls %s", got)
	}
	c := h.fs.confirms[0]
	if len(c.Results) != 5 || c.Results[2].Status != syncapi.G2AOpSkipped || !strings.Contains(c.Results[4].Error, "rate_limited") {
		t.Fatalf("results %+v", c.Results)
	}
	// P3 fails between the preview and the confirmation: nothing runs.
	h2 := newGFHarness(t, syncapi.G2AModeApply)
	h2.fs.status = syncapi.StatusPlanned
	loc = h2.do("POST", back+"/apply", h2.admin, form()).Header().Get("Location")
	h2.addGoogleSP()
	h2.confirm(t, loc)
	if len(h2.ap.called()) != 0 || len(h2.fs.confirms) != 0 {
		t.Fatal("applied while conductor-idp serves Google")
	}
	// Scope switched to dry-run after the preview: nothing to apply.
	delete(h2.idp.sps, "google.com/a/example.com")
	loc = h2.do("POST", back+"/apply", h2.admin, form()).Header().Get("Location")
	h2.fs.setGF(gfSettings(syncapi.G2AModeDryRun))
	h2.confirm(t, loc)
	if len(h2.ap.called()) != 0 {
		t.Fatal("applied a scope now in dry-run")
	}
	// Refusals before any proposal.
	if w := h2.do("POST", back+"/apply", h2.admin, form()); w.Header().Get("Location") != back {
		t.Fatalf("dry-run scope: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	h2.fs.setGF(gfSettings(syncapi.G2AModeApply))
	h2.addGoogleSP()
	if loc := h2.do("POST", back+"/apply", h2.admin, form()).Header().Get("Location"); loc != back {
		t.Fatalf("P3: %q", loc)
	}
	delete(h2.idp.sps, "google.com/a/example.com")
	h2.fs.newerRuns = []syncapi.Run{{ID: 43, Action: syncapi.RunActionG2A, Status: syncapi.StatusPlanned}}
	if loc := h2.do("POST", back+"/apply", h2.admin, form()).Header().Get("Location"); loc != back {
		t.Fatalf("not latest: %q", loc)
	}
	h2.fs.newerRuns = nil
	h2.s.g2a = nil
	if loc := h2.do("POST", back+"/apply", h2.admin, form()).Header().Get("Location"); loc != back {
		t.Fatalf("no applier: %q", loc)
	}
	if body := h2.do("GET", back, h2.admin, nil).Body.String(); !strings.Contains(body, `data-e2e="gf-plan-not-applicable"`) {
		t.Fatal("unsupported not shown")
	}
	if evs := h2.audits(t, "g2a.apply"); len(evs) < 3 {
		t.Fatalf("refusals not audited: %d", len(evs))
	}
}

func TestGoogleFirstApplyWithoutMail(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeApply)
	h.fs.status = syncapi.StatusPlanned
	h.s.mailq = nil
	loc := h.do("POST", "/admin/google-first/runs/42/apply", h.admin, url.Values{"digest": {gfDigest}, "confirm": {"01234567"}}).Header().Get("Location")
	if cp := h.do("GET", loc, h.admin, nil).Body.String(); !strings.Contains(cp, "get no invitation") {
		t.Fatalf("no warning about invitations:\n%s", cp)
	}
	h.confirm(t, loc)
	if evs := h.audits(t, "invite.skipped"); len(evs) != 1 {
		t.Fatalf("skipped invitation not audited %+v", evs)
	}
	if len(h.fs.confirms) != 1 || h.fs.confirms[0].Results[3].Status != syncapi.G2AOpDone {
		t.Fatal("create not reported")
	}
}

func TestGoogleFirstConfirmFailure(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeApply)
	h.fs.status = syncapi.StatusPlanned
	loc := h.do("POST", "/admin/google-first/runs/42/apply", h.admin, url.Values{"digest": {gfDigest}, "confirm": {"01234567"}}).Header().Get("Location")
	h.fs.fail[syncapi.OpG2AConfirm] = &syncapi.Error{Code: syncapi.CodeConflict, Message: "closed"}
	h.confirm(t, loc)
	if len(h.ap.called()) != 5 {
		t.Fatal("operations not run")
	}
	if evs := h.audits(t, "g2a.confirm"); len(evs) != 1 || evs[0].Result != store.ResultFailed {
		t.Fatalf("confirm audit %+v", evs)
	}
	if evs := h.audits(t, "g2a.apply"); len(evs) == 0 || evs[0].Result != store.ResultFailed {
		t.Fatalf("apply audit %+v", evs)
	}
}

func TestGFApplyOrderAndHelpers(t *testing.T) {
	pl := gfPlan(syncapi.G2AModeApply)
	// Scope order and Seq do not decide: the kind does.
	pl.Scopes[1].Blocked = false
	pl.Scopes[1].Ops = append(pl.Scopes[1].Ops, syncapi.G2AOp{Seq: 6, Kind: syncapi.G2AUserUpdate})
	gf := *gfSettings(syncapi.G2AModeApply)
	var seqs []int
	for _, o := range gfApplyOps(&pl, gf) {
		seqs = append(seqs, o.Op.Seq)
	}
	if fmt.Sprint(seqs) != "[0 6 1 2 3 5 4]" {
		t.Fatalf("order %v", seqs)
	}
	gf.Enabled = false
	if len(gfApplyOps(&pl, gf)) != 0 {
		t.Fatal("applied while off")
	}
	if modeConfirmation("people", gfDigest) != "people 01234567" || applyConfirmation(gfDigest) != "01234567" || applyConfirmation("ab") != "ab" {
		t.Fatal("confirmations")
	}
	if !g2aStops(errProvisionerOff) || !g2aStops(context.DeadlineExceeded) || !g2aStops(&provapi.Error{Code: provapi.CodeUnavailable}) ||
		g2aStops(&provapi.Error{Code: provapi.CodeConflict}) {
		t.Fatal("stops")
	}
	long := func(k string, a ...any) string { return strings.Repeat("x", 3000) }
	if len(g2aErrText(long, &provapi.Error{Code: provapi.CodeConflict})) != 512 {
		t.Fatal("error text not bounded")
	}
	for _, c := range []struct {
		sp   syncapi.G2AScopePlan
		want string
	}{
		{syncapi.G2AScopePlan{Name: "people", Blocked: true}, "limits exceeded"},
		{syncapi.G2AScopePlan{Name: "people", Mode: "dry-run"}, "dry-run in the plan"},
		{syncapi.G2AScopePlan{Name: "gone", Mode: "apply"}, "removed since the plan"},
		{syncapi.G2AScopePlan{Name: "people", Mode: "apply"}, "dry-run now"},
	} {
		if got := gfWhyNot(c.sp, *gfSettings(syncapi.G2AModeDryRun)); got != c.want {
			t.Errorf("gfWhyNot %+v = %q", c.sp, got)
		}
	}
	s := &Server{}
	s.roleSIDs.helpdesk = []sid.SID{sid.MustParse(helpdeskSID), sid.MustParse(helpdeskSID)}
	s.roleSIDs.auditor = []sid.SID{sid.MustParse(auditorSID)}
	if fmt.Sprint(s.roleGroupSIDs()) != "["+helpdeskSID+" "+auditorSID+"]" {
		t.Fatalf("role groups %v", s.roleGroupSIDs())
	}
}

func TestManagedByGoogle(t *testing.T) {
	gf := *gfSettings(syncapi.G2AModeApply)
	dn := "CN=ana.lima," + gfManagedOU
	if m := gfManagedOf("", dn, gf, true); m.Managed || m.Owns("mail") {
		t.Fatal("no marker")
	}
	if m := gfManagedOf("something-else", dn, gf, true); m.Managed {
		t.Fatal("other marker")
	}
	m := gfManagedOf("google-first:g1", dn, gf, true)
	if !m.Managed || m.Scope != "people" || m.GoogleID != "g1" || !m.Owns("mail") || !m.Owns("givenName") || !m.Owns("title") ||
		!m.Owns("telephoneNumber") || m.Owns("department") || m.Owns("mobile") || m.Owns("description") {
		t.Fatalf("managed %+v", m)
	}
	// In the quarantine OU (below the managed OU): still managed.
	if m := gfManagedOf("google-first:g1", "CN=x,OU=Quarantine,"+gfManagedOU, gf, true); m.Scope != "people" {
		t.Fatal("quarantine")
	}
	// No scope contains it: AD-managed again.
	if m := gfManagedOf("google-first:g1", "CN=x,OU=Elsewhere,DC=lab,DC=test", gf, true); m.Managed || !m.Orphan || m.GoogleID != "g1" {
		t.Fatalf("orphan %+v", m)
	}
	// Settings unknown: every field Google may own is read only.
	if m := gfManagedOf("google-first:g1", "CN=x,OU=Elsewhere,DC=lab,DC=test", gf, false); !m.Managed || !m.Unverified || !m.Owns("mobile") ||
		!m.Owns("employeeID") || m.Owns("description") {
		t.Fatalf("unverified %+v", m)
	}
	if got := gfRefused(m, []string{"description", "mail", "title"}); fmt.Sprint(got) != "[mail title]" {
		t.Fatalf("refused %v", got)
	}
	u := ad.User{DisplayName: "Ana Lima", Mail: "ana@example.com", Title: "Analyst", Description: "x"}
	in := map[string]string{"display_name": "Ana Lima", "email": "other@example.com", "title": clearValue, "description": "new", "mobile": ""}
	if got := gfBulkRefused(m, in, u); fmt.Sprint(got) != "[email title]" {
		t.Fatalf("bulk refused %v", got)
	}
	if got := gfBulkRefused(gfManaged{}, in, u); len(got) != 0 {
		t.Fatal("unmanaged refused")
	}
	// changedAttrs: only fields present and different.
	r := httptest.NewRequest("POST", "/", nil)
	r.PostForm = url.Values{"mail": {"ana@example.com"}, "title": {"Boss"}, "mobile": {"123"}}
	rc := &reqCtx{r: r}
	if got := changedAttrs(rc, adminFields, u); fmt.Sprint(got) != "[title mobile]" {
		t.Fatalf("changed %v", got)
	}
	views := gfFieldViews(adminFields, u, m)
	for _, v := range views {
		if v.Managed != m.Owns(v.Attr) {
			t.Errorf("view %s managed=%v", v.Attr, v.Managed)
		}
	}
}

func TestManagedSettingsCache(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeApply)
	sess := h.s.sess.get(context.Background(), h.admin)
	rc := &reqCtx{s: h.s, sess: sess, ip: "192.0.2.10", r: httptest.NewRequest("GET", "/", nil)}
	ctx := context.Background()
	before := h.fs.count(syncapi.OpConfigGet)
	for range 3 {
		if m := h.s.gfManagedFor(ctx, rc, "google-first:g1", "CN=a,"+gfManagedOU); m.Scope != "people" {
			t.Fatalf("managed %+v", m)
		}
	}
	if n := h.fs.count(syncapi.OpConfigGet) - before; n != 1 {
		t.Fatalf("config.get %d times", n)
	}
	// Unmarked accounts never ask.
	h.s.gfManagedFor(ctx, rc, "", "CN=a,"+gfManagedOU)
	if n := h.fs.count(syncapi.OpConfigGet) - before; n != 1 {
		t.Fatal("unmarked account read the settings")
	}
	// After the TTL, and after a save, the settings are read again.
	h.now = h.now.Add(gfCacheTTL + time.Second)
	h.s.gfManagedFor(ctx, rc, "google-first:g1", "CN=a,"+gfManagedOU)
	h.s.gfForget()
	h.s.gfManagedFor(ctx, rc, "google-first:g1", "CN=a,"+gfManagedOU)
	if n := h.fs.count(syncapi.OpConfigGet) - before; n != 3 {
		t.Fatalf("config.get %d times", n)
	}
	// Unreachable: fail closed.
	h.s.gfForget()
	h.fs.fail[syncapi.OpConfigGet] = &syncapi.Error{Code: syncapi.CodeUnavailable, Message: "down"}
	if m := h.s.gfManagedFor(ctx, rc, "google-first:g1", "CN=a,"+gfManagedOU); !m.Unverified || !m.Owns("mobile") {
		t.Fatalf("unverified %+v", m)
	}
}

// TestManagedTemplates renders the pages that show Google-owned fields
// (they need AD to be reached through their handlers).
func TestManagedTemplates(t *testing.T) {
	h := newGFHarness(t, syncapi.G2AModeApply)
	sess := h.s.sess.get(context.Background(), h.admin)
	m := gfManagedOf("google-first:g1", "CN=a,"+gfManagedOU, *gfSettings(syncapi.G2AModeApply), true)
	u := ad.User{SAMAccountName: "ana.lima", DisplayName: "Ana Lima", Mail: "ana@example.com", Title: "Analyst", Description: "desc"}
	render := func(page string, d map[string]any) string {
		w := httptest.NewRecorder()
		rc := &reqCtx{s: h.s, sess: sess, w: w, r: httptest.NewRequest("GET", "/admin/users/x/edit", nil), lang: "en", roles: Roles{Admin: true}}
		rc.render(http.StatusOK, page, d)
		return w.Body.String()
	}
	body := render("user_edit", map[string]any{"U": u, "Fields": gfFieldViews(adminFields, u, m), "Google": m})
	for _, want := range []string{`data-e2e="gf-managed-note"`, `data-e2e="user-edit-managed-mail"`, `value="ana@example.com" readonly`,
		`data-e2e="user-edit-managed-title"`} {
		if !strings.Contains(body, want) {
			t.Errorf("edit page lacks %s", want)
		}
	}
	if strings.Contains(body, `data-e2e="user-edit-managed-description"`) {
		t.Error("description marked")
	}
	body = render("me_edit", map[string]any{"U": u, "Fields": gfFieldViews(selfFields, u, m), "Google": m})
	if !strings.Contains(body, `data-e2e="me-edit-managed-telephonenumber"`) || strings.Contains(body, `data-e2e="me-edit-managed-mobile"`) {
		t.Errorf("self edit page:\n%s", body)
	}
	body = render("user", map[string]any{"U": u, "Fields": gfFieldViews(adminFields, u, m), "Google": m})
	if !strings.Contains(body, `data-e2e="user-text-google-id">g1<`) || !strings.Contains(body, "people") || !strings.Contains(body, `data-e2e="user-managed-mail"`) {
		t.Errorf("user page lacks the Google ID or scope")
	}
	plain := render("user_edit", map[string]any{"U": u, "Fields": gfFieldViews(adminFields, u, gfManaged{}), "Google": gfManaged{}})
	if strings.Contains(plain, "readonly") || strings.Contains(plain, "gf-managed-note") {
		t.Error("unmanaged account shown read only")
	}
}

// provCalls records what provApplier sends.
type provCalls struct {
	ops    []string
	params []any
	fail   map[provapi.Op]error
}

func (p *provCalls) call(_ context.Context, _ provapi.Actor, op provapi.Op, params provapi.Params, out any) error {
	p.ops = append(p.ops, string(op))
	p.params = append(p.params, params)
	if err := params.Validate(); err != nil {
		return err
	}
	if err := p.fail[op]; err != nil {
		return err
	}
	if r, ok := out.(*provapi.UserCreateResult); ok {
		r.SID, r.ObjectGUID = testDomain+"-1400", "00112233-4455-6677-8899-aabbccddeeff"
	}
	return nil
}

func TestProvApplier(t *testing.T) {
	pc := &provCalls{fail: map[provapi.Op]error{}}
	a := provApplier{call: pc.call}
	ctx := context.Background()
	sidv := testDomain + "-1500"
	upd := syncapi.G2AOp{Seq: 7, Kind: syncapi.G2AUserRename, SID: sidv, Marker: "google-first:g2",
		Changes: []syncapi.G2AChange{{Field: "mail", Before: "a@example.com", After: "b@example.com"},
			{Field: "proxyAddresses", Before: "", After: "smtp:a@example.com"}}}
	if err := a.Rename(ctx, provapi.Actor{User: "lab.admin"}, "g2a run 42", upd); err != nil {
		t.Fatal(err)
	}
	up := pc.params[0].(*provapi.UserUpdateParams)
	if up.SID != sidv || up.Marker != "google-first:g2" || up.Reference != "g2a run 42 op 7" || len(up.Changes) != 2 || up.Changes[1].Attr != "proxyAddresses" {
		t.Fatalf("update %+v", up)
	}
	// Disable: set_enabled false, then the move to quarantine.
	pc.ops, pc.params = nil, nil
	dis := syncapi.G2AOp{Seq: 8, SID: sidv, Marker: "google-first:g5", Disable: true, MoveTo: "OU=Quarantine," + gfManagedOU}
	if err := a.Disable(ctx, provapi.Actor{User: "lab.admin"}, "g2a run 42", dis); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(pc.ops) != "[user.set_enabled user.move]" || pc.params[0].(*provapi.UserSetEnabledParams).Enabled ||
		pc.params[1].(*provapi.UserMoveParams).ToOU != dis.MoveTo {
		t.Fatalf("disable %v", pc.ops)
	}
	// Already disabled: only the move.
	pc.ops = nil
	dis.Disable = false
	_ = a.Disable(ctx, provapi.Actor{User: "lab.admin"}, "r", dis)
	if fmt.Sprint(pc.ops) != "[user.move]" {
		t.Fatalf("move only %v", pc.ops)
	}
	// Re-enable: the move back, then set_enabled true; a failed move stops.
	pc.ops, pc.params = nil, nil
	re := syncapi.G2AOp{Seq: 9, SID: sidv, Marker: "google-first:g3", Enable: true, MoveTo: gfManagedOU}
	if err := a.Reenable(ctx, provapi.Actor{User: "lab.admin"}, "r", re); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(pc.ops) != "[user.move user.set_enabled]" || !pc.params[1].(*provapi.UserSetEnabledParams).Enabled {
		t.Fatalf("reenable %v", pc.ops)
	}
	pc.ops = nil
	pc.fail[provapi.OpUserMove] = &provapi.Error{Code: provapi.CodeOutOfScope}
	if err := a.Reenable(ctx, provapi.Actor{User: "lab.admin"}, "r", re); err == nil || fmt.Sprint(pc.ops) != "[user.move]" {
		t.Fatalf("failed move: %v %v", err, pc.ops)
	}
	pc.ops = nil
	if err := a.Disable(ctx, provapi.Actor{}, "r", syncapi.G2AOp{Disable: true, SID: sidv, Marker: "google-first:g5", MoveTo: "OU=Q," + gfManagedOU}); err == nil ||
		fmt.Sprint(pc.ops) != "[user.set_enabled user.move]" {
		t.Fatalf("disable then failed move: %v", pc.ops)
	}
	delete(pc.fail, provapi.OpUserMove)
	// Create: the changes become the create parameters.
	pc.ops, pc.params = nil, nil
	cr := gfPlan(syncapi.G2AModeApply).Scopes[0].Ops[3]
	cr.Changes = append(cr.Changes, syncapi.G2AChange{Field: "userPrincipalName", After: "davi.melo@lab.test"}, syncapi.G2AChange{Field: "cn", After: "Davi Melo"},
		syncapi.G2AChange{Field: "givenName", After: "Davi"}, syncapi.G2AChange{Field: "sn", After: "Melo"}, syncapi.G2AChange{Field: "displayName", After: "Davi Melo"},
		syncapi.G2AChange{Field: "title", After: "Engineer"}, syncapi.G2AChange{Field: "mobile", After: ""})
	got, err := a.Create(ctx, provapi.Actor{User: "lab.admin"}, "g2a run 42", cr)
	if err != nil {
		t.Fatal(err)
	}
	cp := pc.params[0].(*provapi.UserCreateParams)
	if got.SID != testDomain+"-1400" || cp.ScopeOU != gfManagedOU || cp.SAM != "davi.melo" || cp.UPN != "davi.melo@lab.test" || cp.CN != "Davi Melo" ||
		cp.Mail != "davi@example.com" || cp.GivenName != "Davi" || cp.Sn != "Melo" || cp.DisplayName != "Davi Melo" || cp.Marker != "google-first:g4" ||
		fmt.Sprint(cp.Fields) != "map[title:Engineer]" || cp.Reference != "g2a run 42 op 3" {
		t.Fatalf("create %+v", cp)
	}
	// Incomplete operations never reach the provisioner.
	pc.ops = nil
	for _, err := range []error{
		a.Update(ctx, provapi.Actor{}, "r", syncapi.G2AOp{Marker: "google-first:x"}),
		a.Disable(ctx, provapi.Actor{}, "r", syncapi.G2AOp{Disable: true}),
		a.Reenable(ctx, provapi.Actor{}, "r", syncapi.G2AOp{Enable: true}),
	} {
		if !errors.Is(err, errG2AOp) {
			t.Errorf("incomplete op: %v", err)
		}
	}
	if _, err := a.Create(ctx, provapi.Actor{}, "r", syncapi.G2AOp{SAM: "x"}); !errors.Is(err, errG2AOp) || len(pc.ops) != 0 {
		t.Fatal("create without an OU")
	}
}

func TestG2AErrorMessages(t *testing.T) {
	h := newHarness(t)
	tr := func(k string, a ...any) string { return h.s.cat.T("en", k, a...) }
	for _, c := range []struct {
		err  error
		want string
	}{
		{&provapi.Error{Code: provapi.CodeExists, Kinds: []string{"sam", "mail"}}, "exists: Already exists in AD: sam, mail."},
		{&provapi.Error{Code: provapi.CodeConflict, Kinds: []string{"title"}}, "conflict: Changed in AD since the plan: title."},
		{&provapi.Error{Code: provapi.CodeMarkerMismatch}, "marker_mismatch: The AD account is not linked"},
		{&provapi.Error{Code: provapi.CodeSchemaMissing}, "schema_missing: The AD schema has no attribute"},
		{&provapi.Error{Code: provapi.CodePrivileged, Kinds: []string{"admin-count"}}, "privileged: The account holds privileged rights (admin-count)"},
		{&provapi.Error{Code: provapi.CodeRateLimited}, "rate_limited: conductor-provisioner's hourly limit"},
		{errG2AOp, "error: The plan operation lacks"},
	} {
		if got := g2aErrText(tr, c.err); !strings.HasPrefix(got, c.want) {
			t.Errorf("%v: %q", c.err, got)
		}
	}
	// The section's applier is the provisioner's when it is on.
	h2 := newHarness(t, func(c *config.Config) { c.Provisioner = config.Provisioner{Enabled: true, Socket: "/run/x.sock"} })
	s, err := New(Deps{Config: h2.s.cfg, Store: h2.st, Backend: h2.backend, MFABox: h2.s.box, Provisioner: newFakeProv(time.Now), Logger: h2.s.log})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.g2a.(provApplier); !ok {
		t.Fatal("no provisioner applier")
	}
}
