//go:build lab

// End-to-end test of "Import from Google Workspace" against a real Samba
// AD and a real `conductor-sync serve` whose Google is the fake Directory
// API (conductor-sync's tools/fakegws), never a real tenant. It drives the
// web handlers with a real Kerberos credential of a Domain Admin: the read
// of the import plan through the management API socket, the job built with
// real LDAP lookups, the apply row by row, and the idempotent re-run.
//
//	AD_LAB_REALM, AD_LAB_DNS (DNS servers), AD_LAB_CA (CA PEM path),
//	AD_LAB_ADMIN_USER / AD_LAB_ADMIN_PASSWORD (a Domain Admin),
//	IMPORT_LAB_SOCKET (conductor-sync's API socket; this process's UID must
//	be allowed), IMPORT_LAB_USERS_OU and IMPORT_LAB_GROUPS_OU (created, with
//	their parents, when missing).
//
// The Google side must hold the company seeded by the run script
// (accounts @acme.example in /Vendas, /TI and /TI/Infra, groups
// @groups.acme.example). Objects are created, never deleted: use new OUs
// for every run, or expect the re-run behaviour.
package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/directory"
	"github.com/openbasalt/samba-conductor/internal/secret"
	"github.com/openbasalt/samba-conductor/internal/store"
)

func importLabEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s not set", name)
	}
	return v
}

// socketSync calls conductor-sync's API socket.
type socketSync struct{ path string }

func (s socketSync) Call(ctx context.Context, req syncapi.Request) (syncapi.Response, error) {
	return syncapi.Call(ctx, s.path, req)
}

func TestLabImportFromGoogle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cfg := config.Default()
	cfg.Domain.Realm = importLabEnv(t, "AD_LAB_REALM")
	cfg.Domain.DNSServers = strings.Split(importLabEnv(t, "AD_LAB_DNS"), ",")
	cfg.Domain.CAFile = importLabEnv(t, "AD_LAB_CA")
	cfg.Server.TLSCert, cfg.Server.TLSKey = "/x/cert.pem", "/x/key.pem"
	cfg.RateLimit.PerIPPerMinute = 1000
	usersOU, groupsOU := importLabEnv(t, "IMPORT_LAB_USERS_OU"), importLabEnv(t, "IMPORT_LAB_GROUPS_OU")
	dir, err := directory.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	box, _ := secret.NewRandom()
	s, err := New(Deps{Config: cfg, Store: st, Backend: dir, MFABox: box, Sync: socketSync{importLabEnv(t, "IMPORT_LAB_SOCKET")},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	admin := strings.ToLower(importLabEnv(t, "AD_LAB_ADMIN_USER"))
	cred, err := dir.SignIn(ctx, admin, importLabEnv(t, "AD_LAB_ADMIN_PASSWORD"))
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	id, groups, err := s.identify(ctx, cred, admin)
	if err != nil {
		t.Fatal(err)
	}
	sess := &Session{sam: admin, dn: id.DN, userSID: id.SID, displayName: id.DisplayName, stage: stageFull, cred: cred, mfaVerified: true,
		roles: s.roleSIDs.resolve(id.SID, groups), rolesAt: time.Now(), groupSIDs: groups}
	if !sess.roles.Admin {
		t.Fatalf("%s is not an administrator", admin)
	}
	tok, err := s.sess.create(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{s: s, st: st, now: time.Now()}

	conn, err := dir.Connect(ctx, cred)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// ensureOU creates an OU and its missing parents (below the domain).
	var ensureOU func(dn string)
	ensureOU = func(dn string) {
		if _, err := conn.Get(ctx, dn, "objectClass"); err == nil || escape.EqualDN(dn, conn.BaseDN()) {
			return
		}
		parent, name, err := escape.ParentDN(dn)
		if err != nil {
			t.Fatal(err)
		}
		ensureOU(parent)
		op, err := ad.CreateOU(ad.NewOU{ParentDN: parent, Name: name, Description: "Import from Google Workspace (end-to-end test)"})
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Apply(ctx, op); err != nil {
			t.Fatalf("create %s: %v", dn, err)
		}
	}
	ensureOU(usersOU)
	ensureOU(groupsOU)
	// An AD account that already has a Google address: never changed, used
	// as a member of the imported group.
	pre := "CN=Fabio Preexisting," + usersOU
	if _, err := conn.Get(ctx, pre, "objectClass"); err != nil {
		op, _ := ad.CreateUser(ad.NewUser{ParentDN: usersOU, CN: "Fabio Preexisting", SAMAccountName: "fabio.preexist",
			UserPrincipalName: "fabio.preexist@" + strings.ToLower(cfg.Domain.Realm), Mail: "fabio.import@acme.example"})
		if err := conn.Apply(ctx, op); err != nil {
			t.Fatalf("pre-existing user: %v", err)
		}
	}

	form := func(maxRun int) url.Values {
		return url.Values{"org_units": {"/Vendas\n/TI"}, "sub_org_units": {"1"}, "groups": {"1"}, "skip_empty_groups": {"1"},
			"user_ou": {usersOU}, "group_ou": {groupsOU}, "fallback": {"{given}.{family}"}, "enabled": {"1"}, "max_users": {"100"},
			"max_run": {itoa(maxRun)}}
	}
	// runJob builds a job from a fresh read and applies it as the
	// administrator (re-authentication is covered by the bulk tests).
	runJob := func(maxRun int) (map[string]store.BulkRow, *bulkJob) {
		t.Helper()
		f := form(maxRun)
		f.Set("step", "read")
		if w := h.do("POST", "/admin/sync/import", tok, f); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "import-row-user-ana-import-acme-example") {
			t.Fatalf("read: %d\n%s", w.Code, w.Body.String())
		}
		f.Set("step", "build")
		w := h.do("POST", "/admin/sync/import", tok, f)
		loc := w.Header().Get("Location")
		if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/admin/bulk/") {
			t.Fatalf("build: %d %s\n%s", w.Code, loc, w.Body.String())
		}
		jobID := strings.TrimPrefix(loc, "/admin/bulk/")
		job := s.jobs.get(jobID)
		if job == nil || !job.Reauth {
			t.Fatalf("job %s: %+v (an import must require re-authentication)", jobID, job)
		}
		page := h.do("GET", loc, tok, nil).Body.String()
		if strings.Contains(page, "changetype: add") && !strings.Contains(page, "unicodePwd: &lt;redacted&gt;") {
			t.Fatal("a create preview shows no redacted password")
		}
		job.mu.Lock()
		job.Reauth = false
		job.mu.Unlock()
		if w := h.do("POST", loc+"/apply", tok, nil); w.Code != http.StatusSeeOther {
			t.Fatalf("apply: %d", w.Code)
		}
		s.bgJobs.Wait()
		rows, err := st.BulkRows(ctx, jobID)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]store.BulkRow{}
		for _, r := range rows {
			out[r.Label] = r
			t.Logf("job %s row %d %s: %s %s", jobID, r.No, r.Label, r.Status, r.Error)
		}
		if job.passwordsLeft {
			t.Fatal("an import must not offer generated passwords")
		}
		return out, job
	}

	// Run 1: a limit of 4 objects.
	rows, _ := runJob(4)
	created := 0
	for _, r := range rows {
		if r.Status == store.RowOK {
			created++
		}
		if r.Status == store.RowFailed {
			t.Errorf("row %s failed: %s", r.Label, r.Error)
		}
	}
	if created != 4 || !strings.Contains(rows["fabio.import@acme.example"].Error, "fabio.preexist") {
		t.Fatalf("run 1 created %d: %+v", created, rows)
	}
	// Run 2: the rest.
	rows, _ = runJob(50)
	for _, r := range rows {
		if r.Status == store.RowFailed {
			t.Errorf("row %s failed: %s", r.Label, r.Error)
		}
	}
	// Run 3: nothing left to do.
	rows, _ = runJob(50)
	for _, r := range rows {
		if r.Status != store.RowSkipped {
			t.Errorf("run 3 row %s: %s %s", r.Label, r.Status, r.Error)
		}
	}

	// The AD objects.
	users := map[string]ad.User{}
	for u, err := range conn.Users(ctx, usersOU, nil) {
		if err != nil {
			t.Fatal(err)
		}
		users[strings.ToLower(u.Mail)] = u
	}
	ana := users["ana.import@acme.example"]
	if ana.SAMAccountName != "ana.import" || ana.Title != "Gerente" || ana.Department != "Vendas" || ana.TelephoneNumber != "+55 11 5555-0101" ||
		ana.Mobile != "+55 11 99999-0101" || !ana.MustChangePassword() || !ana.Enabled() || ana.GivenName != "Ana" || ana.Surname != "Importada" {
		t.Errorf("ana: %+v", ana)
	}
	if e, err := conn.Get(ctx, ana.DN, "employeeID"); err != nil || e.GetAttributeValue("employeeID") != "E-101" {
		t.Errorf("ana employeeID: %v", err)
	}
	for mail, sam := range map[string]string{"normal.user@acme.example": "normal.imported",
		"maria.eduarda.conceicao.import@acme.example": "mariaeduarda.import", "diego.import@acme.example": "diego.import"} {
		if users[mail].SAMAccountName != sam {
			t.Errorf("%s: logon %q, want %q", mail, users[mail].SAMAccountName, sam)
		}
	}
	for _, left := range []string{"elisa.import@acme.example", "chefe.import@acme.example"} {
		if _, ok := users[left]; ok {
			t.Errorf("%s was imported (suspended and administrators are left out by default)", left)
		}
	}
	if len(users) != 7 {
		t.Errorf("%d users in the OU, want 6 imported and the pre-existing one", len(users))
	}
	groupMembers := func(mail string) (ad.Group, []string) {
		for g, err := range conn.Groups(ctx, groupsOU, escape.Eq("mail", mail)) {
			if err != nil {
				t.Fatal(err)
			}
			m, err := conn.GroupMembers(ctx, g.DN)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, dn := range m {
				names = append(names, rdnOf(dn))
			}
			return g, names
		}
		t.Fatalf("no group %s", mail)
		return ad.Group{}, nil
	}
	if g, m := groupMembers("vendas@groups.acme.example"); g.Name != "Vendas" || g.Description != "Equipe comercial" || len(m) != 3 ||
		!strings.Contains(strings.Join(m, ","), "Fabio Preexisting") {
		t.Errorf("vendas: %+v %v", g, m)
	}
	if _, m := groupMembers("all@groups.acme.example"); len(m) != 2 {
		t.Errorf("all (nested vendas and ti): %v", m)
	}
	if _, m := groupMembers("ti@groups.acme.example"); len(m) != 3 {
		t.Errorf("ti (carla, normal, nested infra): %v", m)
	}
	evs, _, _ := st.ListAudit(ctx, store.AuditFilter{Action: "bulk." + importKind}, 0, 100)
	if len(evs) == 0 || evs[0].ActorName != admin || strings.Contains(evs[0].Detail, "unicodePwd:: ") {
		t.Errorf("per-row audit: %+v", evs)
	}
	if reads, _, _ := st.ListAudit(ctx, store.AuditFilter{Action: "sync.import.read"}, 0, 10); len(reads) != 6 {
		t.Errorf("read audit: %d", len(reads))
	}
}
