package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

// Secret values that must never reach a page, the audit or the log.
const (
	testBindPW  = "New-Bind-Password-5d1e"
	testHookKey = "hook-secret-0123456789abcdef"
)

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Lab Test Root CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// connForm is the connection form as the page renders it for the fake's
// settings, with overrides.
func connFormValues(over map[string]string) url.Values {
	v := url.Values{"realm": {"LAB.TEST"}, "auth": {"kerberos"}, "dcs": {"dc1.lab.test"}, "preferred": {""}, "dns_servers": {""},
		"bind_user": {"svc.sync"}, "ca_pem": {""}, "admin_subject": {"admin@example.com"}, "customer": {"my_customer"},
		"requests_per_second": {"5"}, "max_retries": {"6"}, "timeout": {"1m0s"}, "webhook_url": {""}}
	for k, val := range over {
		v.Set(k, val)
	}
	return v
}

// postMultipartForm sends fields and one file.
func (h *harness) postMultipartForm(t *testing.T, path, tok string, fields url.Values, fileField, filename string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf", h.csrfOf(tok))
	for k, vals := range fields {
		for _, v := range vals {
			_ = mw.WriteField(k, v)
		}
	}
	if fileField != "" {
		fw, _ := mw.CreateFormFile(fileField, filename)
		_, _ = fw.Write(content)
	}
	_ = mw.Close()
	r := httptest.NewRequest("POST", "https://"+testHost+path, &buf)
	r.RemoteAddr = "192.0.2.10:40000"
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	w := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(w, r)
	return w
}

// auditText concatenates every audit detail and target.
func (h *harness) auditText(t *testing.T) string {
	t.Helper()
	evs, _, err := h.st.ListAudit(context.Background(), store.AuditFilter{}, 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range evs {
		b.WriteString(e.Action + " " + e.Target + " " + e.Detail + "\n")
	}
	return b.String()
}

func TestSyncConnectionPageAndAccess(t *testing.T) {
	h, _ := syncHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	w := h.do("GET", syncConnURL, admin, nil)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	for _, want := range []string{`data-e2e="sync-conn-input-realm"`, `value="LAB.TEST"`, `data-e2e="sync-conn-secret-ad-bind-password"`,
		`data-e2e="sync-conn-btn-remove-google-service-account-key"`, `data-e2e="sync-conn-text-marker"`, "conductor-sync</code>",
		`data-e2e="sync-config-tab-connection" aria-current="page"`, "/etc/conductor-sync/domain-ca.pem", `data-e2e="sync-conn-btn-test"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// A secret from a credential file cannot be removed here; an absent one neither.
	if strings.Contains(body, `sync-conn-btn-remove-ad-bind-password`) || strings.Contains(body, `sync-conn-btn-remove-alert-webhook-secret`) {
		t.Error("remove offered for a secret that is not stored")
	}
	// The settings page links to it and offers the rollback of older versions.
	cp := h.do("GET", "/admin/sync/config", admin, nil).Body.String()
	if !strings.Contains(cp, `data-e2e="sync-config-link-connection"`) || !strings.Contains(cp, `data-e2e="sync-config-secrets"`) {
		t.Error("settings page lacks the connection summary")
	}
	for _, who := range []string{"auditor.user", "helpdesk.user"} {
		tok := h.session(t, who, stageFull, true)
		if w := h.do("GET", syncConnURL, tok, nil); w.Code != http.StatusForbidden {
			t.Errorf("%s GET: %d", who, w.Code)
		}
		for _, p := range []string{syncConnURL, "/admin/sync/config/marker", "/admin/sync/config/secret", "/admin/sync/config/rollback"} {
			if w := h.do("POST", p, tok, url.Values{"name": {syncapi.SecretADBindPassword}, "action": {"remove"}}); w.Code != http.StatusForbidden {
				t.Errorf("%s POST %s: %d", who, p, w.Code)
			}
		}
		if w := h.do("GET", "/admin/sync/config/rollback?version=1", tok, nil); w.Code != http.StatusForbidden {
			t.Errorf("%s GET rollback: %d", who, w.Code)
		}
	}
}

func TestSyncConnectionTestThenSave(t *testing.T) {
	h, fs := syncHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	post := func(over map[string]string, goVal string) string {
		t.Helper()
		v := connFormValues(over)
		v.Set("go", goVal)
		w := h.do("POST", syncConnURL, admin, v)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("post %s: %d", goVal, w.Code)
		}
		return w.Header().Get("Location")
	}
	two := map[string]string{"dcs": "dc1.lab.test\ndc2.lab.test", "preferred": "dc2.lab.test", "comment": "second DC"}
	// Saving an untested AD change is refused.
	if loc := post(two, "save"); loc != syncConnURL || fs.updated != nil {
		t.Fatalf("untested save: %q", loc)
	}
	page := h.do("GET", syncConnURL, admin, nil).Body.String()
	if !strings.Contains(page, `data-e2e="flash-error"`) || !strings.Contains(page, `data-e2e="sync-conn-draft-changes"`) ||
		!strings.Contains(page, "connection.ad.dcs") || !strings.Contains(page, `data-e2e="sync-conn-test-needed"`) {
		t.Fatalf("draft page:\n%s", page)
	}
	// Test, then save the tested draft: preview, re-authentication.
	if loc := post(two, "test"); loc != syncConnURL+"#test" {
		t.Fatalf("test: %q", loc)
	}
	if r := fs.last(syncapi.OpConnectionTest); r == nil || !strings.Contains(string(r.Params), "dc2.lab.test") {
		t.Fatal("the test did not use the draft")
	}
	if page := h.do("GET", syncConnURL, admin, nil).Body.String(); !strings.Contains(page, `data-e2e="sync-conn-test-ad-ok"`) || strings.Contains(page, "sync-conn-test-outdated") {
		t.Fatal("test result not shown")
	}
	// A change after the test needs a new test.
	if loc := post(map[string]string{"dcs": "dc1.lab.test\ndc3.lab.test"}, "save"); loc != syncConnURL || fs.updated != nil {
		t.Fatalf("save after an untested change: %q", loc)
	}
	post(two, "test")
	loc := post(two, "save")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("save: %q", loc)
	}
	cp := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(cp, "connection.ad.dcs") || !strings.Contains(cp, "confirm-text-reauth") || !strings.Contains(cp, "confirm-text-warning") {
		t.Fatalf("confirm page:\n%s", cp)
	}
	if w := h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {"000000"}}); w.Code != http.StatusUnauthorized || fs.updated != nil {
		t.Fatal("saved without the second factor")
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	u := fs.updated
	if u == nil || u.BaseVersion != 2 || u.Settings.Connection == nil || strings.Join(u.Settings.Connection.AD.DCs, ",") != "dc1.lab.test,dc2.lab.test" ||
		u.Settings.Connection.Marker != "conductor-sync" || len(u.Settings.Scope.IncludeGroups) != 1 || u.ADPassword != "" || u.Comment != "second DC" {
		t.Fatalf("update %+v", u)
	}
	if sess := h.s.sess.get(context.Background(), admin); sess.syncConn != nil {
		t.Fatal("draft kept after the save")
	}
}

func TestSyncConnectionNewBindAccount(t *testing.T) {
	h, fs := syncHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	over := map[string]string{"bind_user": "svc.sync2", "new_password": testBindPW}
	v := connFormValues(over)
	v.Set("go", "test")
	h.do("POST", syncConnURL, admin, v)
	if fs.testPW != testBindPW {
		t.Fatal("the test did not use the new password")
	}
	page := h.do("GET", syncConnURL, admin, nil).Body.String()
	if strings.Contains(page, testBindPW) || !strings.Contains(page, `data-e2e="sync-conn-draft-password"`) {
		t.Fatal("draft page shows the password or misses its note")
	}
	// The test failed: the save is refused.
	fs.adTestFail = true
	v = connFormValues(map[string]string{"bind_user": "svc.sync2"})
	v.Set("go", "test")
	h.do("POST", syncConnURL, admin, v)
	v.Set("go", "save")
	if w := h.do("POST", syncConnURL, admin, v); w.Header().Get("Location") != syncConnURL {
		t.Fatal("saved after a failed test")
	}
	fs.adTestFail = false
	v.Set("go", "test")
	h.do("POST", syncConnURL, admin, v) // the draft keeps the password entered before
	v.Set("go", "save")
	loc := h.do("POST", syncConnURL, admin, v).Header().Get("Location")
	cp := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(cp, "secret ad_bind_password: replaced") || strings.Contains(cp, testBindPW) {
		t.Fatalf("confirm page:\n%s", cp)
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	if fs.updated == nil || fs.updated.ADPassword != testBindPW || fs.updated.Settings.Connection.AD.BindUser != "svc.sync2" {
		t.Fatalf("update %+v", fs.updated)
	}
	if strings.Contains(h.auditText(t), testBindPW) {
		t.Fatal("the audit has the password")
	}
}

func TestSyncConnectionCAUpload(t *testing.T) {
	h, _ := syncHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	v := connFormValues(nil)
	v.Set("go", "test")
	if w := h.postMultipartForm(t, syncConnURL, admin, v, "ca_upload", "ca.pem", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")); w.Header().Get("Location") != syncConnURL {
		t.Fatal("a private key accepted as CA")
	}
	if sess := h.s.sess.get(context.Background(), admin); sess.syncConn != nil {
		t.Fatal("a draft was made from a refused upload")
	}
	ca := testCAPEM(t)
	h.postMultipartForm(t, syncConnURL, admin, v, "ca_upload", "ca.pem", ca)
	page := h.do("GET", syncConnURL, admin, nil).Body.String()
	if !strings.Contains(page, "CN=Lab Test Root CA") || !strings.Contains(page, `data-e2e="sync-conn-ca-list"`) || !strings.Contains(page, "connection.ad.ca_pem") {
		t.Fatalf("CA not in the draft:\n%s", page)
	}
	// Back to the host's CA file.
	v.Set("ca_use_file", "1")
	h.do("POST", syncConnURL, admin, v)
	if sess := h.s.sess.get(context.Background(), admin); sess.syncConn.S.Connection.AD.CAPEM != "" {
		t.Fatal("ca_use_file kept the inline CA")
	}
	// Discard.
	h.do("POST", syncConnURL, admin, url.Values{"go": {"discard"}})
	if sess := h.s.sess.get(context.Background(), admin); sess.syncConn != nil {
		t.Fatal("draft not discarded")
	}
}

func TestSyncMarkerChange(t *testing.T) {
	h, fs := syncHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	for _, typed := range []string{"", "change marker to conductor-sync", "yes"} {
		w := h.do("POST", "/admin/sync/config/marker", admin, url.Values{"marker": {"conductor-sync-b"}, "confirm": {typed}})
		if w.Header().Get("Location") != syncConnURL+"#marker" {
			t.Fatalf("typed %q: %q", typed, w.Header().Get("Location"))
		}
	}
	if !strings.Contains(h.auditText(t), "typed confirmation did not match") {
		t.Fatal("refusal not audited")
	}
	w := h.do("POST", "/admin/sync/config/marker", admin, url.Values{"marker": {"conductor-sync-b"}, "confirm": {"change marker to conductor-sync-b"}})
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("propose: %q", loc)
	}
	cp := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(cp, "confirm-text-warning") || !strings.Contains(cp, "connection.marker: conductor-sync -&gt; conductor-sync-b") {
		t.Fatalf("confirm page:\n%s", cp)
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	if fs.updated == nil || fs.updated.Settings.Connection.Marker != "conductor-sync-b" || fs.updated.MarkerConfirmation != "change marker to conductor-sync-b" {
		t.Fatalf("update %+v", fs.updated)
	}
}

func TestSyncSecretsWriteOnly(t *testing.T) {
	h, fs := syncHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	// A fresh time step per confirmation (a code is accepted once).
	code := func() string { h.now = h.now.Add(totp.Period); return totp.Code(secret, totp.Step(h.now)) }
	back := syncConnURL + "#secrets"
	// The bind password: AD refuses it, nothing is proposed.
	fs.adTestFail = true
	w := h.do("POST", "/admin/sync/config/secret", admin, url.Values{"name": {syncapi.SecretADBindPassword}, "action": {"replace"}, "value": {testBindPW}})
	if w.Header().Get("Location") != back || fs.testPW != testBindPW {
		t.Fatalf("refused password: %q", w.Header().Get("Location"))
	}
	fs.adTestFail = false
	w = h.do("POST", "/admin/sync/config/secret", admin, url.Values{"name": {syncapi.SecretADBindPassword}, "action": {"replace"}, "value": {testBindPW}})
	loc := w.Header().Get("Location")
	cp := h.do("GET", loc, admin, nil).Body.String()
	if !strings.HasPrefix(loc, "/confirm/") || strings.Contains(cp, testBindPW) || !strings.Contains(cp, "name: ad_bind_password") {
		t.Fatalf("confirm page:\n%s", cp)
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {code()}})
	if fs.secrets[syncapi.SecretADBindPassword] != testBindPW {
		t.Fatal("password not sent")
	}
	// The webhook secret: too short, then set.
	if w := h.do("POST", "/admin/sync/config/secret", admin, url.Values{"name": {syncapi.SecretWebhookSecret}, "action": {"replace"}, "value": {"short"}}); w.Header().Get("Location") != back {
		t.Fatal("short webhook secret proposed")
	}
	loc = h.do("POST", "/admin/sync/config/secret", admin, url.Values{"name": {syncapi.SecretWebhookSecret}, "action": {"replace"}, "value": {testHookKey}}).Header().Get("Location")
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {code()}})
	if fs.secrets[syncapi.SecretWebhookSecret] != testHookKey {
		t.Fatal("webhook secret not sent")
	}
	// Remove: only a stored secret; the Google key (stored) with a warning.
	if w := h.do("POST", "/admin/sync/config/secret", admin, url.Values{"name": {syncapi.SecretADBindPassword}, "action": {"remove"}}); w.Header().Get("Location") != back {
		t.Fatal("removal of a credential-file secret proposed")
	}
	loc = h.do("POST", "/admin/sync/config/secret", admin, url.Values{"name": {syncapi.SecretGoogleKey}, "action": {"remove"}}).Header().Get("Location")
	if cp := h.do("GET", loc, admin, nil).Body.String(); !strings.Contains(cp, "confirm-text-warning") {
		t.Fatal("no warning on the key removal")
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {code()}})
	if len(fs.removed) != 1 || fs.removed[0] != syncapi.SecretGoogleKey {
		t.Fatalf("removed %v", fs.removed)
	}
	// Unknown names and the key through the generic form are refused.
	for _, form := range []url.Values{{"name": {"shadow"}, "action": {"replace"}, "value": {"x"}},
		{"name": {syncapi.SecretGoogleKey}, "action": {"replace"}, "value": {"{}"}}} {
		if w := h.do("POST", "/admin/sync/config/secret", admin, form); w.Code != http.StatusBadRequest {
			t.Fatalf("form %v: %d", form, w.Code)
		}
	}
	// The key replaced from the connection page returns there.
	key := []byte(`{"type":"service_account","client_email":"new@project.iam.gserviceaccount.com","private_key_id":"k3","private_key":"-----BEGIN PRIVATE KEY-----\nKEYMATERIAL\n-----END PRIVATE KEY-----\n"}`)
	loc = h.postMultipartForm(t, "/admin/sync/setup/key", admin, url.Values{"from": {"connection"}}, "key", "k.json", key).Header().Get("Location")
	w = h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {code()}})
	if w.Header().Get("Location") != back {
		t.Fatalf("key replace back: %q", w.Header().Get("Location"))
	}
	audit := h.auditText(t)
	for _, v := range []string{testBindPW, testHookKey, "KEYMATERIAL"} {
		if strings.Contains(audit, v) {
			t.Fatal("a secret value is in the audit")
		}
	}
	if !strings.Contains(audit, "sync.secret_set ad_bind_password") || !strings.Contains(audit, "sync.secret_remove google_service_account_key") {
		t.Fatalf("audit:\n%s", audit)
	}
	// No page shows a value.
	if page := h.do("GET", syncConnURL, admin, nil).Body.String(); strings.Contains(page, testBindPW) || strings.Contains(page, testHookKey) {
		t.Fatal("a page shows a secret")
	}
}

func TestSyncRollback(t *testing.T) {
	h, fs := syncHarness(t)
	secret := h.enrollTOTP(t, "lab.admin")
	admin := h.session(t, "lab.admin", stageFull, true)
	old := fs.cfg.Settings
	oc := *old.Connection
	oc.Marker = "conductor-sync-old"
	oc.AD.DCs = []string{"dc9.lab.test"}
	old.Connection = &oc
	old.Mode = "dry-run"
	fs.versions[1] = old
	cp := h.do("GET", "/admin/sync/config", admin, nil).Body.String()
	if !strings.Contains(cp, `data-e2e="sync-config-history-2"`) || strings.Contains(cp, `sync-config-link-rollback-2"`) {
		t.Fatal("rollback offered for the current version")
	}
	if w := h.do("GET", "/admin/sync/config/rollback?version=7", admin, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown version: %d", w.Code)
	}
	page := h.do("GET", "/admin/sync/config/rollback?version=1", admin, nil).Body.String()
	for _, want := range []string{`data-e2e="sync-rollback-changes"`, "connection.marker", "connection.ad.dcs", `data-e2e="sync-rollback-marker-warning"`,
		`data-e2e="sync-rollback-secrets"`, "change marker to conductor-sync-old"} {
		if !strings.Contains(page, want) {
			t.Errorf("rollback page lacks %q", want)
		}
	}
	if w := h.do("POST", "/admin/sync/config/rollback", admin, url.Values{"version": {"1"}, "confirm": {"change marker to conductor-sync"}}); w.Header().Get("Location") != "/admin/sync/config/rollback?version=1" {
		t.Fatal("rollback across a marker change without its confirmation")
	}
	loc := h.do("POST", "/admin/sync/config/rollback", admin, url.Values{"version": {"1"}, "confirm": {"change marker to conductor-sync-old"}, "comment": {"undo"}}).Header().Get("Location")
	if !strings.HasPrefix(loc, "/confirm/") {
		t.Fatalf("propose: %q", loc)
	}
	conf := h.do("GET", loc, admin, nil).Body.String()
	if !strings.Contains(conf, "config.rollback") || !strings.Contains(conf, "version: 1") || !strings.Contains(conf, "confirm-text-warning") {
		t.Fatalf("confirm page:\n%s", conf)
	}
	h.do("POST", loc, admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}})
	r := fs.rollback
	if r == nil || r.Version != 1 || r.BaseVersion != 2 || r.MarkerConfirmation != "change marker to conductor-sync-old" || r.Comment != "undo" {
		t.Fatalf("rollback %+v", r)
	}
}
