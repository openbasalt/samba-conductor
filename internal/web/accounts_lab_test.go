//go:build lab

// End-to-end test of "Connected accounts" against a real Samba AD and a
// real `conductor-sync serve` whose Google is the fake Directory API
// (conductor-sync's tools/fakegws), never a real tenant. Regular users sign
// in with Kerberos; the web handlers drive account.status, account.activate
// and account.set_password through the API socket, and the fake confirms
// that the password a user was shown is the one the account has.
//
//	AD_LAB_REALM, AD_LAB_DNS (DNS servers), AD_LAB_CA (CA PEM path),
//	ACCOUNTS_LAB_PEOPLE_OU (the sync's user base; its first two users by
//	logon name, with a mail, that sign in with the password are used), ACCOUNTS_LAB_USER_PASSWORD (their
//	password, also the one of normal.user, a user outside that base), ACCOUNTS_LAB_SOCKET (conductor-sync's API socket; this
//	process's UID must be allowed), ACCOUNTS_LAB_FAKE (fakegws base URL)
//	and ACCOUNTS_LAB_FAKE_CA (its certificate), ACCOUNTS_LAB_SCAN_DIR (a
//	directory with conductor-sync's state, logs and request log, searched
//	for the passwords afterwards).
//
// conductor-sync must run with mode = "apply", [self_service] activation =
// "self-service" and policy.adopt = "email", against a fresh fake.
package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"html"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// fakeAPI calls fakegws's test controls.
type fakeAPI struct {
	base string
	hc   *http.Client
}

func (f fakeAPI) post(t *testing.T, path string, body, out any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := f.hc.Post(f.base+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %s", path, resp.Status)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
}

func (f fakeAPI) matches(t *testing.T, user, pw string) bool {
	t.Helper()
	var r struct {
		Match bool `json:"match"`
	}
	f.post(t, "/_fake/password-check", map[string]string{"user": user, "password": pw}, &r)
	return r.Match
}

// fakeUser reads one account from /_fake/state.
func (f fakeAPI) fakeUser(t *testing.T, email string) map[string]any {
	t.Helper()
	resp, err := f.hc.Get(f.base + "/_fake/state")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	for _, u := range st.Users {
		if strings.EqualFold(u["primaryEmail"].(string), email) {
			return u
		}
	}
	return nil
}

func (f fakeAPI) writes(t *testing.T) []map[string]any {
	t.Helper()
	resp, err := f.hc.Get(f.base + "/_fake/writes")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

var secretValueRE = regexp.MustCompile(`id="new-password" type="text" class="secret" value="([^"]+)"`)

func TestLabConnectedAccounts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cfg := config.Default()
	cfg.Domain.Realm = importLabEnv(t, "AD_LAB_REALM")
	cfg.Domain.DNSServers = strings.Split(importLabEnv(t, "AD_LAB_DNS"), ",")
	cfg.Domain.CAFile = importLabEnv(t, "AD_LAB_CA")
	cfg.Server.TLSCert, cfg.Server.TLSKey = "/x/cert.pem", "/x/key.pem"
	cfg.RateLimit.PerIPPerMinute = 1000
	peopleOU, userPW := importLabEnv(t, "ACCOUNTS_LAB_PEOPLE_OU"), importLabEnv(t, "ACCOUNTS_LAB_USER_PASSWORD")
	sock, scanDir := importLabEnv(t, "ACCOUNTS_LAB_SOCKET"), importLabEnv(t, "ACCOUNTS_LAB_SCAN_DIR")
	caPEM, err := os.ReadFile(importLabEnv(t, "ACCOUNTS_LAB_FAKE_CA"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	fake := fakeAPI{base: importLabEnv(t, "ACCOUNTS_LAB_FAKE"), hc: &http.Client{Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}

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
	s, err := New(Deps{Config: cfg, Store: st, Backend: dir, MFABox: box, Sync: socketSync{sock},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{s: s, st: st, now: time.Now()}

	// Two users of the sync's user base (by logon name), signed in for
	// real; the session passed a second factor just now.
	type person struct{ sam, mail, tok, sid string }
	var people []person
	trySignin := func(sam string) (person, error) {
		cred, err := dir.SignIn(ctx, sam, userPW)
		if err != nil {
			return person{}, err
		}
		id, groups, err := s.identify(ctx, cred, sam)
		if err != nil {
			t.Fatal(err)
		}
		sess := &Session{sam: sam, dn: id.DN, userSID: id.SID, displayName: id.DisplayName, stage: stageFull, cred: cred, mfaVerified: true,
			mfaAt: time.Now(), roles: s.roleSIDs.resolve(id.SID, groups), rolesAt: time.Now(), groupSIDs: groups}
		tok, err := s.sess.create(ctx, sess)
		if err != nil {
			t.Fatal(err)
		}
		return person{sam: sam, tok: tok, sid: id.SID.String()}, nil
	}
	signin := func(sam string) person {
		p, err := trySignin(sam)
		if err != nil {
			t.Fatalf("sign-in %s: %v", sam, err)
		}
		return p
	}
	{
		// normal.user is outside the sync's user base: not eligible.
		first := signin("normal.user")
		if page := h.do("GET", "/me/accounts", first.tok, nil).Body.String(); !strings.Contains(page, "not in the scope") || strings.Contains(page, "accounts-btn-") {
			t.Fatalf("normal.user: %s", page)
		}
		conn, err := dir.Connect(ctx, s.sess.byID[hashToken(first.tok)].cred)
		if err != nil {
			t.Fatal(err)
		}
		es, err := conn.SearchAll(ctx, ad.SearchRequest{BaseDN: peopleOU, Filter: escape.And(escape.Eq("objectClass", "user"), escape.Present("mail")),
			Attributes: []string{"sAMAccountName", "mail"}})
		_ = conn.Close()
		if err != nil || len(es) < 2 {
			t.Fatalf("people: %v (%d)", err, len(es))
		}
		sort.Slice(es, func(i, j int) bool {
			return es[i].GetAttributeValue("sAMAccountName") < es[j].GetAttributeValue("sAMAccountName")
		})
		// The first two that sign in with the shared password (other tests
		// may have left accounts with their own passwords in the base).
		for _, e := range es {
			if len(people) == 2 {
				break
			}
			sam := e.GetAttributeValue("sAMAccountName")
			if strings.HasPrefix(sam, "adopt.") || strings.HasPrefix(sam, "teste.") {
				continue // accounts of other tests, with passwords of their own
			}
			p, err := trySignin(sam)
			if err != nil {
				continue
			}
			p.mail = strings.ToLower(sam) + "@" + strings.ToLower(cfg.Domain.Realm)
			people = append(people, p)
		}
		if len(people) != 2 {
			t.Fatal("no two users of the base sign in with the shared password")
		}
	}
	a, b := people[0], people[1]
	t.Logf("users %s and %s", a.sam, b.sam)
	// b's address already exists in Google: the sync adopts it.
	fake.post(t, "/_fake/seed", map[string]any{"users": []map[string]any{{"primaryEmail": b.mail,
		"name": map[string]any{"givenName": "Pre", "familyName": "Existing"}}}}, nil)

	// confirm runs an action through its confirmation and returns where it
	// ended.
	confirm := func(tok, path string, form url.Values) string {
		t.Helper()
		w := h.do("POST", path, tok, form)
		loc := w.Header().Get("Location")
		if !strings.HasPrefix(loc, "/confirm/") {
			t.Fatalf("%s: %d %q", path, w.Code, loc)
		}
		if cp := h.do("GET", loc, tok, nil).Body.String(); strings.Contains(cp, "confirm-text-reauth") {
			t.Fatal("step-up asked for a fresh second factor")
		}
		start := time.Now()
		w = h.do("POST", loc, tok, nil)
		t.Logf("%s confirmed in %s", path, time.Since(start).Round(time.Millisecond))
		return w.Header().Get("Location")
	}
	shown := func(tok, loc string) string {
		t.Helper()
		if !strings.HasPrefix(loc, "/me/accounts/secret/") {
			t.Fatalf("no password page: %q (flash: %s)", loc, h.do("GET", "/me/accounts", tok, nil).Body.String())
		}
		m := secretValueRE.FindStringSubmatch(h.do("GET", loc, tok, nil).Body.String())
		if m == nil {
			t.Fatal("password not on the page")
		}
		if w := h.do("GET", loc, tok, nil); w.Code != http.StatusNotFound {
			t.Fatalf("password page shown twice: %d", w.Code)
		}
		return html.UnescapeString(m[1])
	}

	// 1. a activates: the account is created with the password shown.
	page := h.do("GET", "/me/accounts", a.tok, nil).Body.String()
	if !strings.Contains(page, `data-e2e="accounts-btn-activate-google"`) || !strings.Contains(page, a.mail) {
		t.Fatalf("a before activation: %s", page)
	}
	pw1 := shown(a.tok, confirm(a.tok, "/me/accounts/google/activate", url.Values{"mode": {"generate"}}))
	if !fake.matches(t, a.mail, pw1) {
		t.Fatal("the password shown is not the account's")
	}
	if u := fake.fakeUser(t, a.mail); u == nil || u["changePasswordAtNextLogin"] != false || u["orgUnitPath"] != "/Staff" {
		t.Fatalf("a's account %+v", u)
	}
	page = h.do("GET", "/me/accounts", a.tok, nil).Body.String()
	if !strings.Contains(page, `data-e2e="accounts-btn-password-google"`) || !strings.Contains(page, "Created by the sync") {
		t.Fatalf("a after activation: %s", page)
	}

	// 2. a sets a new password.
	pw2 := shown(a.tok, confirm(a.tok, "/me/accounts/google/password", url.Values{"mode": {"generate"}}))
	if pw2 == pw1 || !fake.matches(t, a.mail, pw2) || fake.matches(t, a.mail, pw1) {
		t.Fatal("the reset did not replace the password")
	}

	// 3. b: an existing account, linked by the next run, not activated.
	page = h.do("GET", "/me/accounts", b.tok, nil).Body.String()
	if strings.Contains(page, "accounts-btn-") || !strings.Contains(page, "the next sync links it to you") {
		t.Fatalf("b before the run: %s", page)
	}
	adminActor := syncapi.Actor{User: "lab.e2e", SID: "S-1-5-21-1-2-3-500", Session: "labsession", IP: "127.0.0.1"}
	call := func(op syncapi.Op, p syncapi.Params, out any) {
		t.Helper()
		req, err := syncapi.NewRequest("lab-"+strings.ReplaceAll(string(op), ".", "-")+"-"+itoa(int(time.Now().UnixNano()%1e9)), op, adminActor, p)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := syncapi.Call(ctx, sock, req)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if out != nil {
			if err := syncapi.DecodeResult(resp, out); err != nil {
				t.Fatal(err)
			}
		}
	}
	waitRun := func(id string) int64 {
		for range 600 {
			var j syncapi.Job
			call(syncapi.OpJobGet, syncapi.JobGetParams{ID: id}, &j)
			if j.State != syncapi.JobRunning {
				return j.RunID
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("job did not finish")
		return 0
	}
	var js syncapi.JobStarted
	call(syncapi.OpPlanStart, nil, &js)
	var rd syncapi.RunDetail
	call(syncapi.OpRunGet, syncapi.RunGetParams{ID: waitRun(js.Job.ID), Limit: 500}, &rd)
	pending := 0
	for _, w := range rd.Warnings {
		if w.Code == "pending-activation" {
			pending++
		}
	}
	t.Logf("plan: %v; %d pending activations", rd.Counts, pending)
	if rd.Counts["user.create"] != 0 || rd.Counts["user.adopt"] != 1 || pending == 0 {
		t.Fatalf("plan %v", rd.Counts)
	}
	call(syncapi.OpApplyStart, syncapi.ApplyStartParams{RunID: rd.Run.ID, Digest: rd.Digest, OverrideLimits: rd.Override}, &js)
	waitRun(js.Job.ID)
	page = h.do("GET", "/me/accounts", b.tok, nil).Body.String()
	if strings.Contains(page, "accounts-btn-") || !strings.Contains(page, "existed before the sync") {
		t.Fatalf("b after adoption: %s", page)
	}
	w := h.do("POST", "/me/accounts/google/password", b.tok, url.Values{"mode": {"generate"}})
	if w.Header().Get("Location") != "/me/accounts" {
		t.Fatalf("reset of an adopted account: %d %q", w.Code, w.Header().Get("Location"))
	}

	// 4. Only a's create and a's reset carried a password; nothing anywhere
	// keeps one.
	for _, wr := range fake.writes(t) {
		fields, _ := json.Marshal(wr["fields"])
		if !strings.Contains(string(fields), `"password"`) {
			continue
		}
		t.Logf("password write: %v %v %v", wr["method"], wr["path"], wr["fields"])
		if wr["method"] == "POST" && wr["path"] == "/users" {
			continue
		}
		if wr["method"] == "PATCH" && string(fields) == `["changePasswordAtNextLogin","password"]` {
			continue
		}
		t.Fatalf("unexpected password write %+v", wr)
	}
	if strings.Contains(h.auditText(t), pw1) || strings.Contains(h.auditText(t), pw2) {
		t.Fatal("a password is in conductor's audit")
	}
	scanned := 0
	_ = filepath.WalkDir(scanDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		scanned++
		for _, pw := range []string{pw1, pw2} {
			if bytes.Contains(b, []byte(pw)) {
				t.Errorf("a password is in %s", p)
			}
		}
		return nil
	})
	t.Logf("scanned %d files of conductor-sync's state and logs: no password", scanned)
}
