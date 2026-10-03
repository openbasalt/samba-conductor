package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/samba-conductor/conductor-files/filesapi"
	"github.com/samba-conductor/conductor/internal/store"
	"github.com/samba-conductor/conductor/internal/totp"
)

const (
	fakeAgentPin = "sha256:AgentAgentAgentAgentAgentAgentAgentAgentAge"
	fakeCondPin  = "sha256:CondCondCondCondCondCondCondCondCondCondCon"
	engSID       = testDomain + "-4105"
)

// fakeFiles answers like a conductor-files agent.
type fakeFiles struct {
	mu        sync.Mutex
	calls     []filesapi.Request
	addrs     []string
	transport error
	fail      map[filesapi.Op]*filesapi.Error
	plan      filesapi.Plan
}

func newFakeFiles() *fakeFiles {
	return &fakeFiles{fail: map[filesapi.Op]*filesapi.Error{}, plan: filesapi.Plan{Kind: "create", Name: "eng", Path: "/srv/shares/eng", CreateDir: true,
		Section:  "[eng]\n\tpath = /srv/shares/eng\n\tconductor-files:managed = yes\n",
		ShareACL: filesapi.ACLChange{After: []filesapi.ACE{{Type: "allow", SID: engSID, Name: `LAB\Engineering`, Mask: 0x1301ff, Rights: "CHANGE"}}, Changed: true},
		NTACL: filesapi.ACLChange{Before: []filesapi.ACE{{Type: "allow", SID: "S-1-1-0", Name: "Everyone", Mask: 0x1200a9, Rights: "read"}},
			After: []filesapi.ACE{{Type: "allow", SID: engSID, Name: `LAB\Engineering`, Mask: 0x1301bf, Flags: "OICI", Rights: "modify"}}, Changed: true},
		Commands: []string{"# create the folder /srv/shares/eng", "/usr/bin/net conf import /var/lib/conductor-files/import/eng.conf eng"},
		Warnings: []filesapi.Warning{{Code: filesapi.WarnInsideShare, Arg: "data"}},
		Digest:   strings.Repeat("d", 64)}}
}

func (f *fakeFiles) Pin() string  { return fakeCondPin }
func (f *fakeFiles) Name() string { return "dc1.lab.test" }

func (f *fakeFiles) Call(_ context.Context, addr, pin string, req filesapi.Request) (filesapi.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := req.Decode()
	if err != nil {
		return filesapi.Response{}, err
	}
	if f.transport != nil {
		return filesapi.Response{}, f.transport
	}
	if pin != fakeAgentPin {
		return filesapi.Response{}, &filesapi.PinMismatchError{Want: pin, Got: fakeAgentPin}
	}
	f.calls = append(f.calls, req)
	f.addrs = append(f.addrs, addr)
	if e := f.fail[req.Op]; e != nil {
		return filesapi.ErrorResponse(req.ID, e), nil
	}
	var out any
	switch req.Op {
	case filesapi.OpEnroll:
		out = filesapi.EnrollResult{Hostname: "fs1.lab.test", AgentPin: fakeAgentPin, Version: "test"}
	case filesapi.OpUnenroll:
		out = map[string]bool{"removed": true}
	case filesapi.OpStatus:
		out = filesapi.Status{Hostname: "fs1.lab.test", Version: "test", SambaVersion: "4.22.11", Domain: "LAB", Realm: "LAB.TEST",
			DomainSID: testDomain, Roots: []string{"/srv/shares"}, Checks: []filesapi.Check{{Name: "member_not_dc", OK: true}}}
	case filesapi.OpSharesList:
		out = []filesapi.ShareSummary{{Name: "eng", Path: "/srv/shares/eng", Source: "registry", Managed: true, Browseable: true},
			{Name: "legacy", Path: "/srv/legacy", Source: "smb.conf"}}
	case filesapi.OpShareGet:
		name := p.(*filesapi.ShareNameParams).Name
		d := filesapi.ShareDetail{ShareSummary: filesapi.ShareSummary{Name: name, Path: "/srv/shares/" + name, Source: "registry", Managed: name == "eng", Browseable: true},
			ShareACL: []filesapi.ACE{{Type: "allow", SID: engSID, Name: `LAB\Engineering`, Mask: 0x1301ff, Rights: "CHANGE"}},
			NTACL:    []filesapi.ACE{{Type: "allow", SID: engSID, Name: `LAB\Engineering`, Mask: 0x1301bf, Flags: "OICI", Rights: "modify"}}}
		if name == "eng" {
			d.Spec = &filesapi.ShareSpec{Name: "eng", Path: "/srv/shares/eng", Browseable: true, Access: []filesapi.Grant{{SID: engSID, Level: "modify", Name: `LAB\Engineering`}}}
		}
		out = d
	case filesapi.OpDirsList:
		out = filesapi.DirList{Path: "/srv/shares", Root: "/srv/shares", Roots: []string{"/srv/shares"}, CanCreate: true,
			Entries: []filesapi.DirEntry{{Name: "data", Path: "/srv/shares/data", Usable: true}, {Name: "eng", Path: "/srv/shares/eng", Share: "eng", Usable: true}}}
	case filesapi.OpSharePlan:
		out = f.plan
	case filesapi.OpShareApply:
		if p.(*filesapi.SharePlanParams).Digest != f.plan.Digest {
			return filesapi.ErrorResponse(req.ID, &filesapi.Error{Code: filesapi.CodeConflict, Message: "changed"}), nil
		}
		out = filesapi.ApplyResult{Digest: f.plan.Digest, Steps: f.plan.Commands}
	case filesapi.OpShareRemovePlan:
		out = filesapi.Plan{Kind: "remove", Name: "eng", Path: "/srv/shares/eng", SectionBefore: "[eng]\n", Commands: []string{"sharesec eng --delete"}, Digest: strings.Repeat("e", 64),
			Warnings: []filesapi.Warning{{Code: filesapi.WarnFolderKept, Arg: "/srv/shares/eng"}}}
	case filesapi.OpShareRemove:
		out = filesapi.ApplyResult{}
	case filesapi.OpSessionsList:
		out = filesapi.Sessions{Sessions: []filesapi.Session{{User: `LAB\user0001`, Machine: "10.93.0.11", Protocol: "SMB3_11"}},
			Connections: []filesapi.TreeConnect{{Share: "eng", Machine: "10.93.0.11"}}, Files: []filesapi.OpenFile{}}
	default:
		return filesapi.Response{}, errors.New("unexpected op " + string(req.Op))
	}
	return filesapi.OKResponse(req.ID, out)
}

func (f *fakeFiles) last(op filesapi.Op) *filesapi.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i].Op == op {
			return &f.calls[i]
		}
	}
	return nil
}

func filesHarness(t *testing.T) (*harness, *fakeFiles, store.FileServer) {
	h := newHarness(t)
	ff := newFakeFiles()
	h.s.files = ff
	srv := store.FileServer{ID: "srv-0000000001", Name: "fs1.lab.test", Address: "fs1.lab.test:7443", AgentPin: fakeAgentPin, EnrolledAt: h.now, EnrolledBy: "lab.admin"}
	if err := h.st.AddFileServer(context.Background(), srv); err != nil {
		t.Fatal(err)
	}
	return h, ff, srv
}

func TestFilesAccessAndPages(t *testing.T) {
	h, ff, srv := filesHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	body := h.do("GET", "/admin/files", admin, nil).Body.String()
	for _, want := range []string{`data-e2e="files-row-fs1-lab-test"`, `data-e2e="files-badge-ready"`, `data-e2e="nav-link-files"`, fakeCondPin, `data-e2e="files-link-new"`} {
		if !strings.Contains(body, want) {
			t.Errorf("list lacks %q", want)
		}
	}
	if r := ff.last(filesapi.OpStatus); r == nil || r.Actor.User != "lab.admin" || r.Actor.IP == "" {
		t.Fatalf("status actor %+v", r)
	}
	page := h.do("GET", "/admin/files/"+srv.ID, admin, nil).Body.String()
	for _, want := range []string{`data-e2e="files-share-row-eng"`, `data-e2e="files-share-row-legacy"`, `data-e2e="files-btn-remove-server"`, fakeAgentPin} {
		if !strings.Contains(page, want) {
			t.Errorf("server page lacks %q", want)
		}
	}
	share := h.do("GET", "/admin/files/"+srv.ID+"/shares/eng", admin, nil).Body.String()
	if !strings.Contains(share, `data-e2e="files-link-edit-share"`) || !strings.Contains(share, "Modify") || !strings.Contains(share, `\\fs1.lab.test\eng`) {
		t.Fatalf("share page:\n%s", share)
	}
	legacy := h.do("GET", "/admin/files/"+srv.ID+"/shares/legacy", admin, nil).Body.String()
	if !strings.Contains(legacy, `data-e2e="files-share-unmanaged"`) || strings.Contains(legacy, "files-link-edit-share") {
		t.Fatal("an unmanaged share must be read-only")
	}
	if s := h.do("GET", "/admin/files/"+srv.ID+"/sessions", admin, nil).Body.String(); !strings.Contains(s, `data-e2e="files-session-row-lab-user0001"`) {
		t.Fatal("sessions page")
	}
	// Auditors read, never write; helpdesk sees nothing.
	aud := h.session(t, "auditor.user", stageFull, true)
	for _, p := range []string{"/admin/files", "/admin/files/" + srv.ID, "/admin/files/" + srv.ID + "/shares/eng", "/admin/files/" + srv.ID + "/sessions"} {
		if w := h.do("GET", p, aud, nil); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "files-link-new") || strings.Contains(w.Body.String(), "files-btn-remove") {
			t.Errorf("auditor GET %s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/admin/files/new", "/admin/files/" + srv.ID + "/new-share", "/admin/files/" + srv.ID + "/wizard"} {
		if w := h.do("GET", p, aud, nil); w.Code != http.StatusForbidden {
			t.Errorf("auditor GET %s: %d", p, w.Code)
		}
	}
	hd := h.session(t, "helpdesk.user", stageFull, true)
	if w := h.do("GET", "/admin/files", hd, nil); w.Code != http.StatusForbidden {
		t.Errorf("helpdesk: %d", w.Code)
	}
	if strings.Contains(h.do("GET", "/me", hd, nil).Body.String(), "nav-link-files") {
		t.Error("helpdesk sees the navigation entry")
	}
	// Unknown server and bad names: 404.
	for _, p := range []string{"/admin/files/nope", "/admin/files/srv-9999999999", "/admin/files/" + srv.ID + "/shares/a%2Fb"} {
		if w := h.do("GET", p, admin, nil); w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d", p, w.Code)
		}
	}
	// Unreachable agent: a badge, no crash.
	h.s.forgetStatus(srv.ID)
	ff.transport = errors.New("dial tcp 10.93.0.20:7443: connect: connection refused")
	if b := h.do("GET", "/admin/files", admin, nil).Body.String(); !strings.Contains(b, `data-e2e="files-badge-unreachable"`) || strings.Contains(b, "connection refused") {
		t.Fatal("unreachable view")
	}
	// Disabled section.
	h.s.files = nil
	if b := h.do("GET", "/admin/files", admin, nil).Body.String(); !strings.Contains(b, "files-card-disabled") || strings.Contains(b, `data-e2e="nav-link-files"`) {
		t.Fatal("disabled view")
	}
}

func TestFilesEnroll(t *testing.T) {
	h := newHarness(t)
	ff := newFakeFiles()
	h.s.files = ff
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	if b := h.do("GET", "/admin/files/new", admin, nil).Body.String(); !strings.Contains(b, fakeCondPin) || !strings.Contains(b, "conductor-files enroll-code") {
		t.Fatal("new page")
	}
	token := strings.Repeat("T", 43)
	code := filesapi.FormatEnrollmentCode(token, fakeAgentPin)
	for _, bad := range []url.Values{{"address": {"fs1 two"}, "code": {code}}, {"address": {"fs1.lab.test"}, "code": {"nonsense"}}} {
		if w := h.do("POST", "/admin/files/new", admin, bad); w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("bad input %v: %d", bad, w.Code)
		}
	}
	w := h.do("POST", "/admin/files/new", admin, url.Values{"address": {"fs1.lab.test"}, "code": {"  " + code + " "}})
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("propose: %d %q", w.Code, loc)
	}
	cp := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(cp, "address: fs1.lab.test:7443") || !strings.Contains(cp, fakeAgentPin) || !strings.Contains(cp, "confirm-text-reauth") || strings.Contains(cp, token) {
		t.Fatalf("enroll preview (the token must not be shown):\n%s", cp)
	}
	if w := h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {"000000"}}); w.Code != http.StatusUnauthorized || ff.last(filesapi.OpEnroll) != nil {
		t.Fatalf("without the second factor: %d", w.Code)
	}
	w = h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	r := ff.last(filesapi.OpEnroll)
	if r == nil || r.Actor.User != "lab.admin" {
		t.Fatalf("enroll call %+v", r)
	}
	var ep filesapi.EnrollParams
	_ = json.Unmarshal(r.Params, &ep)
	if ep.Token != token || ep.Name != "dc1.lab.test" {
		t.Fatalf("enroll params %+v", ep)
	}
	servers, _ := h.st.FileServers(context.Background())
	if len(servers) != 1 || servers[0].Address != "fs1.lab.test:7443" || servers[0].AgentPin != fakeAgentPin || servers[0].Name != "fs1.lab.test" {
		t.Fatalf("stored %+v", servers)
	}
	if w.Header().Get("Location") != "/admin/files/"+servers[0].ID {
		t.Fatalf("after enroll: %q", w.Header().Get("Location"))
	}
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "files.enroll"}, 0, 10)
	if len(evs) != 2 || evs[0].Result != store.ResultOK || !strings.Contains(evs[0].Detail, "[re-authenticated]") {
		t.Fatalf("audit %+v", evs)
	}
	// The same address again is refused.
	if w := h.do("POST", "/admin/files/new", admin, url.Values{"address": {"fs1.lab.test:7443"}, "code": {code}}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate: %d", w.Code)
	}
}

func TestFilesShareWizard(t *testing.T) {
	h, ff, srv := filesHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	base := "/admin/files/" + srv.ID
	if w := h.do("GET", base+"/wizard", admin, nil); w.Header().Get("Location") != base {
		t.Fatalf("wizard without a draft: %q", w.Header().Get("Location"))
	}
	if w := h.do("GET", base+"/new-share", admin, nil); w.Header().Get("Location") != base+"/wizard?step=folder" {
		t.Fatalf("new share: %q", w.Header().Get("Location"))
	}
	page := h.do("GET", base+"/wizard?step=folder", admin, nil).Body.String()
	if !strings.Contains(page, `data-e2e="files-wizard-radio-data"`) || strings.Contains(page, `data-e2e="files-wizard-radio-eng"`) || !strings.Contains(page, "files-wizard-input-newdir") {
		t.Fatalf("folder step:\n%s", page)
	}
	// Bad name, bad folder name.
	h.do("POST", base+"/wizard", admin, url.Values{"action": {"folder"}, "name": {"bad/name"}, "newdir": {"x"}})
	h.do("POST", base+"/wizard", admin, url.Values{"action": {"folder"}, "name": {"eng"}, "newdir": {"a/b"}})
	if dr := h.s.sess.get(context.Background(), admin).filesDraft; dr.Spec.Name == "bad/name" || dr.Spec.Path != "" {
		t.Fatalf("invalid input reached the draft: %+v", dr.Spec)
	}
	w := h.do("POST", base+"/wizard", admin, url.Values{"action": {"folder"}, "name": {"eng"}, "comment": {"Engineering"}, "newdir": {"eng-new"}})
	if w.Header().Get("Location") != base+"/wizard?step=access" {
		t.Fatalf("folder → %q", w.Header().Get("Location"))
	}
	h.do("POST", base+"/wizard", admin, url.Values{"action": {"add"}, "sid": {engSID}, "level": {"read"}, "name": {"Engineering"}})
	h.do("POST", base+"/wizard", admin, url.Values{"action": {"level"}, "sid": {engSID}, "level": {"modify"}})
	h.do("POST", base+"/wizard", admin, url.Values{"action": {"add"}, "sid": {"S-1-5-32-544"}, "level": {"full"}})
	dr := h.s.sess.get(context.Background(), admin).filesDraft
	if dr.Spec.Path != "/srv/shares/eng-new" || !dr.Spec.CreateDir || len(dr.Spec.Access) != 1 || dr.Spec.Access[0].Level != "modify" {
		t.Fatalf("draft %+v", dr.Spec)
	}
	if b := h.do("GET", base+"/wizard?step=options", admin, nil).Body.String(); !strings.Contains(b, `data-e2e="files-wizard-check-shadow"`) {
		t.Fatal("options step")
	}
	w = h.do("POST", base+"/wizard", admin, url.Values{"action": {"options"}, "browseable": {"1"}, "recycle": {"1"}, "go": {"plan"}})
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("plan: %d %q", w.Code, loc)
	}
	var pp filesapi.SharePlanParams
	_ = json.Unmarshal(ff.last(filesapi.OpSharePlan).Params, &pp)
	if !pp.Create || !pp.Spec.RecycleBin || pp.Spec.Path != "/srv/shares/eng-new" || pp.Digest != "" {
		t.Fatalf("plan params %+v", pp)
	}
	cp := h.do("GET", loc, admin, nil).Body.String()
	for _, want := range []string{`data-e2e="files-plan"`, `data-e2e="files-diff-nt-add-s-1-5-21-1-2-3-4105"`, `data-e2e="files-diff-nt-del-s-1-1-0"`,
		"net conf import", "digest: " + ff.plan.Digest, "inside the folder of share data", "confirm-text-reauth"} {
		if !strings.Contains(cp, want) {
			t.Errorf("confirm page lacks %q", want)
		}
	}
	if w := h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {"000000"}}); w.Code != http.StatusUnauthorized || ff.last(filesapi.OpShareApply) != nil {
		t.Fatalf("without the second factor: %d", w.Code)
	}
	w = h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	if w.Header().Get("Location") != base+"/shares/eng" {
		t.Fatalf("after apply: %q", w.Header().Get("Location"))
	}
	var ap filesapi.SharePlanParams
	_ = json.Unmarshal(ff.last(filesapi.OpShareApply).Params, &ap)
	if ap.Digest != ff.plan.Digest || !ap.Create || ap.Spec.Name != "eng" {
		t.Fatalf("apply params %+v", ap)
	}
	if h.s.sess.get(context.Background(), admin).filesDraft != nil {
		t.Fatal("the draft must be cleared")
	}
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "files.share_create"}, 0, 10)
	if len(evs) < 1 || evs[0].Result != store.ResultOK || !strings.Contains(evs[0].Detail, "net conf import") || evs[0].Target != "fs1.lab.test/eng" {
		t.Fatalf("audit %+v", evs)
	}

	// Edit starts from the share's spec; an agent refusal is shown with its details.
	if w := h.do("GET", base+"/shares/eng/edit", admin, nil); w.Header().Get("Location") != base+"/wizard?step=access" {
		t.Fatalf("edit: %q", w.Header().Get("Location"))
	}
	if dr := h.s.sess.get(context.Background(), admin).filesDraft; dr.Create || dr.Spec.Name != "eng" || len(dr.Spec.Access) != 1 {
		t.Fatalf("edit draft %+v", dr)
	}
	if w := h.do("GET", base+"/shares/legacy/edit", admin, nil); w.Header().Get("Location") != base+"/shares/legacy" {
		t.Fatal("an unmanaged share must not open in the wizard")
	}
	ff.fail[filesapi.OpSharePlan] = &filesapi.Error{Code: filesapi.CodeInvalid, Message: "invalid", Details: []string{"path: a parent directory is writable by others"}}
	w = h.do("POST", base+"/wizard/plan", admin, nil)
	if w.Header().Get("Location") != base+"/wizard?step=options" {
		t.Fatalf("refused plan: %q", w.Header().Get("Location"))
	}
	if b := h.do("GET", base+"/wizard?step=options", admin, nil).Body.String(); !strings.Contains(b, "a parent directory is writable by others") {
		t.Fatal("the agent's details must be shown")
	}
	// A conflict at apply time (state changed) is reported, nothing else runs.
	delete(ff.fail, filesapi.OpSharePlan)
	loc = h.do("POST", base+"/wizard/plan", admin, nil).Header().Get("Location")
	ff.plan.Digest = strings.Repeat("f", 64)
	h.now = h.now.Add(31 * 1e9)
	w = h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	if w.Header().Get("Location") != base+"/wizard?step=options" {
		t.Fatalf("conflict: %q", w.Header().Get("Location"))
	}
	if b := h.do("GET", base+"/wizard?step=options", admin, nil).Body.String(); !strings.Contains(b, "changed since you reviewed it") {
		t.Fatal("conflict message")
	}
	// Discard.
	if w := h.do("POST", base+"/wizard/discard", admin, nil); w.Header().Get("Location") != base || h.s.sess.get(context.Background(), admin).filesDraft != nil {
		t.Fatal("discard")
	}
}

func TestFilesRemove(t *testing.T) {
	h, ff, srv := filesHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	base := "/admin/files/" + srv.ID
	loc := h.do("POST", base+"/shares/eng/remove", admin, nil).Header().Get("Location")
	cp := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(cp, "sharesec eng --delete") || !strings.Contains(cp, "/srv/shares/eng and its files are kept") {
		t.Fatalf("remove preview:\n%s", cp)
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	var rp filesapi.ShareNameParams
	_ = json.Unmarshal(ff.last(filesapi.OpShareRemove).Params, &rp)
	if rp.Name != "eng" || rp.Digest != strings.Repeat("e", 64) {
		t.Fatalf("remove params %+v", rp)
	}
	// Removing the server: the agent is told; if it cannot be reached the
	// server is still forgotten and the page says how to revoke locally.
	ff.fail[filesapi.OpUnenroll] = &filesapi.Error{Code: filesapi.CodeFailed, Message: "x"}
	h.now = h.now.Add(31 * 1e9)
	loc = h.do("POST", base+"/remove", admin, nil).Header().Get("Location")
	w := h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	if w.Header().Get("Location") != "/admin/files" {
		t.Fatalf("after remove: %q", w.Header().Get("Location"))
	}
	if b := h.do("GET", "/admin/files", admin, nil).Body.String(); !strings.Contains(b, "trust remove "+fakeCondPin) || !strings.Contains(b, "files-card-empty") {
		t.Fatalf("after remove:\n%s", b)
	}
	if _, err := h.st.FileServer(context.Background(), srv.ID); err == nil {
		t.Fatal("the server must be forgotten")
	}
}
