package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

func withWebAuthn(c *config.Config) {
	c.WebAuthn.RPID = testHost
	c.WebAuthn.Origins = []string{"https://" + testHost}
}

var scriptTagRE = regexp.MustCompile(`<script src="/static/webauthn\.js\?v=[^"]*" nonce="([^"]+)" integrity="(sha256-[^"]+)" defer></script>`)

// TestCSPScriptOnlyOnSecondFactorPages renders every GET page as an actor
// that reaches it and checks: the script and a nonce in the CSP only on
// the second-factor routes, script-src 'none' and no <script> anywhere
// else.
func TestCSPScriptOnlyOnSecondFactorPages(t *testing.T) {
	h := newHarness(t, withWebAuthn)
	scripted := 0
	for _, rt := range h.s.routes {
		if rt.method != "GET" {
			continue
		}
		var tok string
		switch {
		case rt.perm == PermPublic:
		case rt.perm == PermPreAuth:
			tok = h.session(t, "lab.admin", rt.stages[0], false)
		default:
			tok = h.session(t, "lab.admin", stageFull, true)
			h.s.sess.byID[hashToken(tok)].keyOK = true
		}
		w := h.do("GET", concretePath(rt.pattern), tok, nil)
		csp := w.Header().Get("Content-Security-Policy")
		body := w.Body.String()
		m := scriptTagRE.FindStringSubmatch(body)
		if rt.script {
			scripted++
			if !strings.Contains(csp, "script-src 'nonce-") || strings.Contains(csp, "script-src 'none'") {
				t.Errorf("%s: CSP %q", rt.pattern, csp)
				continue
			}
			if w.Header().Get("Content-Type") == "text/html; charset=utf-8" {
				if m == nil || !strings.Contains(csp, "'nonce-"+m[1]+"'") || m[2] != h.s.scriptSRI {
					t.Errorf("%s: script tag/nonce/SRI mismatch (status %d)", rt.pattern, w.Code)
				}
			}
			if !strings.Contains(csp, "connect-src 'none'") {
				t.Errorf("%s: the script page may connect: %q", rt.pattern, csp)
			}
		} else {
			if !strings.Contains(csp, "script-src 'none'") {
				t.Errorf("%s: CSP allows scripts: %q", rt.pattern, csp)
			}
			if strings.Contains(body, "<script") {
				t.Errorf("%s: <script> in a page that must be script-free", rt.pattern)
			}
		}
		if strings.Contains(body, " style=") || strings.Contains(body, "onclick") || strings.Contains(body, "javascript:") {
			t.Errorf("%s: inline style or handler", rt.pattern)
		}
	}
	if scripted != 9 {
		t.Fatalf("script routes: %d (the second-factor pages, those of the link pages, and the generated password page only)", scripted)
	}
	// The script itself matches its SRI hash and makes no requests.
	w := h.do("GET", "/static/webauthn.js", "", nil)
	sum := sha256.Sum256(w.Body.Bytes())
	if "sha256-"+base64.StdEncoding.EncodeToString(sum[:]) != h.s.scriptSRI {
		t.Fatal("SRI hash does not match the served script")
	}
	for _, bad := range []string{"fetch(", "XMLHttpRequest", "eval(", "innerHTML", "new Function"} {
		if strings.Contains(w.Body.String(), bad) {
			t.Errorf("webauthn.js uses %s", bad)
		}
	}
}

// softKey is a software WebAuthn authenticator (ES256, "none" attestation).
type softKey struct {
	priv  *ecdsa.PrivateKey
	id    []byte
	count uint32
	rpID  string
}

func newSoftKey(t *testing.T, rpID string) *softKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &softKey{priv: priv, id: id, rpID: rpID}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (k *softKey) clientData(t *testing.T, typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": "https://" + k.rpID, "crossOrigin": false})
	return b
}

func (k *softKey) authData(attested bool) []byte {
	h := sha256.Sum256([]byte(k.rpID))
	k.count++
	flags := byte(0x05) // UP | UV
	if attested {
		flags |= 0x40
	}
	b := append(h[:], flags)
	b = binary.BigEndian.AppendUint32(b, k.count)
	if attested {
		x, y := k.priv.X.FillBytes(make([]byte, 32)), k.priv.Y.FillBytes(make([]byte, 32))
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		b = append(b, make([]byte, 16)...) // AAGUID
		b = binary.BigEndian.AppendUint16(b, uint16(len(k.id)))
		b = append(b, k.id...)
		b = append(b, cose...)
	}
	return b
}

// register answers creation options with an attestation response.
func (k *softKey) register(t *testing.T, optionsJSON string) string {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(optionsJSON), &o); err != nil {
		t.Fatal(err)
	}
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(true)})
	resp, _ := json.Marshal(map[string]any{"id": b64u(k.id), "rawId": b64u(k.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u(k.clientData(t, "webauthn.create", o.PublicKey.Challenge)),
			"attestationObject": b64u(att), "transports": []string{"usb"}}, "clientExtensionResults": map[string]any{}})
	return string(resp)
}

// assert answers request options with an assertion response.
func (k *softKey) assert(t *testing.T, optionsJSON string) string {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(optionsJSON), &o); err != nil {
		t.Fatal(err)
	}
	cd := k.clientData(t, "webauthn.get", o.PublicKey.Challenge)
	ad := k.authData(false)
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte(nil), ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := json.Marshal(map[string]any{"id": b64u(k.id), "rawId": b64u(k.id), "type": "public-key",
		"response":               map[string]any{"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig)},
		"clientExtensionResults": map[string]any{}})
	return string(resp)
}

var optionsRE = regexp.MustCompile(`data-options="([^"]+)"`)

func pageOptions(t *testing.T, body string) string {
	t.Helper()
	m := optionsRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no WebAuthn options on the page")
	}
	return html.UnescapeString(m[1])
}

// TestWebAuthnEnrollAndSignIn: an administrator enrolls a security key
// through a one-time link (no TOTP), signs in with it, and a replayed or
// foreign assertion is refused. With admin_required, TOTP is refused.
func TestWebAuthnEnrollAndSignIn(t *testing.T) {
	h := newHarness(t, withWebAuthn, func(c *config.Config) { c.WebAuthn.AdminRequired = true })
	ctx := context.Background()
	tok, hash := NewEnrollLinkToken()
	if err := h.st.CreateEnrollLink(ctx, hash, "lab.admin", "test", enrollLinkTTL); err != nil {
		t.Fatal(err)
	}
	w := h.signin(t, "lab.admin", "pw", tok)
	if w.Header().Get("Location") != "/signin/enroll" {
		t.Fatalf("enroll: %d %q", w.Code, w.Header().Get("Location"))
	}
	sess := sessionFrom(w)
	page := h.do("GET", "/signin/enroll", sess, nil)
	if !strings.Contains(page.Body.String(), `data-e2e="enroll-text-key-only"`) || strings.Contains(page.Body.String(), "enroll-text-secret") {
		t.Fatal("key-only enrollment still offers TOTP")
	}
	// TOTP enrollment is refused when keys are required.
	if w := h.do("POST", "/signin/enroll", sess, url.Values{"code": {"123456"}}); w.Code != http.StatusForbidden {
		t.Fatalf("TOTP enrollment for a key-only admin: %d", w.Code)
	}
	key := newSoftKey(t, testHost)
	resp := key.register(t, pageOptions(t, page.Body.String()))
	// A missing name is refused, and the ceremony is single use.
	if w := h.do("POST", "/signin/enroll/key", sess, url.Values{"name": {""}, "response": {resp}}); w.Code != http.StatusBadRequest {
		t.Fatalf("no name: %d", w.Code)
	}
	page = h.do("GET", "/signin/enroll", sess, nil)
	resp = key.register(t, pageOptions(t, page.Body.String()))
	w = h.do("POST", "/signin/enroll/key", sess, url.Values{"name": {"Desk key"}, "response": {resp}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/me/recovery-codes" {
		t.Fatalf("register: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	full := sessionFrom(w)
	if h.s.sess.get(ctx, sess) != nil {
		t.Fatal("session not rotated after enrollment")
	}
	if ok, _ := h.st.ValidEnrollLink(ctx, hash, "lab.admin"); ok {
		t.Fatal("enrollment link still valid")
	}
	if codes := codeRE.FindAllStringSubmatch(h.do("GET", "/me/recovery-codes", full, nil).Body.String(), -1); len(codes) == 0 {
		t.Fatal("no recovery codes after a key-only enrollment")
	}
	if w := h.do("GET", "/admin/users", full, nil); w.Code == http.StatusSeeOther {
		t.Fatalf("admin page after key enrollment: %d %q", w.Code, w.Header().Get("Location"))
	}
	h.do("POST", "/signout", full, nil)

	// Sign in again: second factor with the key.
	w = h.signin(t, "lab.admin", "pw", "")
	if w.Header().Get("Location") != "/signin/2fa" {
		t.Fatalf("sign-in: %q", w.Header().Get("Location"))
	}
	sess = sessionFrom(w)
	// A TOTP-looking code is refused for a key-only administrator.
	if w := h.do("POST", "/signin/2fa", sess, url.Values{"code": {"123456"}}); w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Body.String(), "security key") {
		t.Fatalf("TOTP for a key-only admin: %d", w.Code)
	}
	// Another authenticator's assertion fails.
	other := newSoftKey(t, testHost)
	page = h.do("GET", "/signin/2fa", sess, nil)
	if w := h.do("POST", "/signin/2fa/key", sess, url.Values{"response": {other.assert(t, pageOptions(t, page.Body.String()))}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("foreign key: %d", w.Code)
	}
	page = h.do("GET", "/signin/2fa", sess, nil)
	good := key.assert(t, pageOptions(t, page.Body.String()))
	w = h.do("POST", "/signin/2fa/key", sess, url.Values{"response": {good}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin" {
		t.Fatalf("key sign-in: %d %q", w.Code, w.Header().Get("Location"))
	}
	full = sessionFrom(w)
	// The same assertion cannot be replayed (challenge used, counter).
	w2 := h.signin(t, "lab.admin", "pw", "")
	s2 := sessionFrom(w2)
	h.do("GET", "/signin/2fa", s2, nil)
	if w := h.do("POST", "/signin/2fa/key", s2, url.Values{"response": {good}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed assertion: %d", w.Code)
	}
	rows, _ := h.st.WebAuthnCredentials(ctx, h.s.sess.byID[hashToken(full)].userSID.String())
	if len(rows) != 1 || rows[0].Name != "Desk key" || rows[0].LastUsedAt.IsZero() {
		t.Fatalf("stored credential %+v", rows)
	}
	// The security page lists the key and offers registration (script page).
	sec := h.do("GET", "/me/security", full, nil)
	if !strings.Contains(sec.Body.String(), `data-e2e="security-row-key-desk-key"`) || !scriptTagRE.MatchString(sec.Body.String()) {
		t.Fatal("security page")
	}
	// The last key of a key-only administrator cannot be removed.
	if w := h.do("POST", "/me/2fa/keys/"+rows[0].ID+"/remove", full, url.Values{"password": {"pw"}, "code": {"x"}}); w.Code != http.StatusForbidden {
		t.Fatalf("remove last key: %d", w.Code)
	}
	evs, _, _ := h.st.ListAudit(ctx, store.AuditFilter{Action: "mfa."}, 0, 100)
	if len(evs) < 4 {
		t.Fatalf("2FA events audited: %d", len(evs))
	}
}

func TestParseCSV(t *testing.T) {
	head := strings.Join(createColumns, ",")
	rows, errs := parseCSV([]byte("\xef\xbb\xbf"+head+"\r\njdoe,John,Doe,,,,Lab/People,,yes,yes\r\n,,,,,,,,,\r\n"), createColumns, 10)
	if len(errs) != 0 || len(rows) != 1 || rows[0]["username"] != "jdoe" || rows[0]["_line"] != "2" {
		t.Fatalf("%v %v", rows, errs)
	}
	for name, data := range map[string]string{
		"wrong header":   "user,first\r\n",
		"shifted header": strings.Join(updateColumns, ",") + "\r\n",
		"missing field":  head + "\r\njdoe,John\r\n",
		"control char":   head + "\r\njd\x01oe,John,Doe,,,,Lab,,yes,yes\r\n",
		"not UTF-8":      head + "\r\n\xff\xfe,,,,,,,,,\r\n",
	} {
		if _, errs := parseCSV([]byte(data), createColumns, 10); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	many := head + "\r\n" + strings.Repeat("a,b,c,,,,Lab,,yes,yes\r\n", 3)
	if _, errs := parseCSV([]byte(many), createColumns, 2); len(errs) == 0 {
		t.Error("row limit not enforced")
	}
}

func TestNewPasswordComplexity(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		p := newPassword()
		if len(p) != 20 || !strings.ContainsAny(p, "ABCDEFGHJKLMNPQRSTUVWXYZ") || !strings.ContainsAny(p, "abcdefghijkmnopqrstuvwxyz") ||
			!strings.ContainsAny(p, "23456789") || !strings.ContainsAny(p, "!#%+-=?@") || seen[p] {
			t.Fatalf("weak or repeated password %q", p)
		}
		seen[p] = true
	}
}

func TestCSVCellNeutralizesFormulas(t *testing.T) {
	for in, want := range map[string]string{"=1+1": "'=1+1", "+x": "'+x", "-2": "'-2", "@SUM": "'@SUM", "jdoe": "jdoe", "": ""} {
		if got := csvCell(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestZoneNameFromNetwork(t *testing.T) {
	for in, want := range map[string]string{"10.93.0.0/24": "0.93.10.in-addr.arpa", "192.168.0.0/16": "168.192.in-addr.arpa",
		"10.0.0.0/8": "10.in-addr.arpa", "2001:db8::/32": "8.b.d.0.1.0.0.2.ip6.arpa"} {
		if got, err := zoneNameFromNetwork(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"10.0.0.0/20", "x", "2001:db8::/33"} {
		if _, err := zoneNameFromNetwork(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// TestSelectedActionPermissions: the selection route is open to helpdesk,
// but each action checks its own permission before touching AD.
func TestSelectedActionPermissions(t *testing.T) {
	h := newHarness(t)
	helpdesk := h.session(t, "helpdesk.user", stageFull, true)
	sel := url.Values{"sel": {"00112233-4455-6677-8899-aabbccddeeff"}, "back": {"/admin/users"}}
	for _, a := range []string{"move", "group_add", "group_remove", "delete"} {
		f := url.Values{"action": {a}}
		for k, v := range sel {
			f[k] = v
		}
		if w := h.do("POST", "/admin/users/selected", helpdesk, f); w.Code != http.StatusForbidden {
			t.Errorf("helpdesk %s: %d", a, w.Code)
		}
	}
	if w := h.do("POST", "/admin/users/selected", helpdesk, url.Values{"action": {"format-c"}, "sel": sel["sel"]}); w.Code != http.StatusBadRequest {
		t.Errorf("unknown action: %d", w.Code)
	}
	w := h.do("POST", "/admin/users/selected", helpdesk, url.Values{"action": {"unlock"}, "back": {"https://evil.example/"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/users" {
		t.Errorf("no selection / foreign back: %d %q", w.Code, w.Header().Get("Location"))
	}
	auditor := h.session(t, "auditor.user", stageFull, true)
	if w := h.do("POST", "/admin/users/selected", auditor, url.Values{"action": {"unlock"}, "sel": sel["sel"]}); w.Code != http.StatusForbidden {
		t.Errorf("auditor: %d", w.Code)
	}
}

// TestBulkJobLifecycle runs a job against a backend that cannot reach AD:
// only its owner sees it, applying it reports every row as failed (never
// silently), every row is audited, and the report is stored.
func TestBulkJobLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	admin := h.session(t, "lab.admin", stageFull, true)
	sess := h.s.sess.byID[hashToken(admin)]
	var rows []*bulkRow
	var stored []store.BulkRow
	for i, dn := range []string{"CN=a,OU=People,DC=lab,DC=test", "CN=b,OU=People,DC=lab,DC=test"} {
		op, _ := ad.UnlockUser(dn)
		if i == 1 {
			// One row is written on every DC: each DC is reported.
			op, _ = ad.UnlockUserOnDCs(dn, []string{"dc1.test", "dc2.test"})
		}
		r := &bulkRow{No: i + 1, Label: rdnOf(dn), Target: dn, Input: map[string]string{"guid": "x"}, ops: []*ad.Operation{op},
			Preview: rowPreview([]*ad.Operation{op}), Status: store.RowPending}
		rows = append(rows, r)
		stored = append(stored, store.BulkRow{No: r.No, Label: r.Label, Target: dn, Input: "{}", Preview: r.Preview})
	}
	job := &bulkJob{ID: strings.Repeat("j", 22), Kind: "selected-unlock", ownerSID: sess.userSID.String(), owner: "lab.admin",
		session: sess.hash, perm: PermUsersHelpdesk, Rows: rows, Status: store.JobPreviewed, created: h.now}
	if err := h.st.CreateBulkJob(ctx, store.BulkJob{ID: job.ID, Kind: job.Kind, OwnerSID: job.ownerSID, OwnerName: job.owner}, stored); err != nil {
		t.Fatal(err)
	}
	h.s.jobs.put(job, h.now)
	helpdesk := h.session(t, "helpdesk.user", stageFull, true)
	if w := h.do("GET", "/admin/bulk/"+job.ID, helpdesk, nil); w.Code != http.StatusNotFound {
		t.Fatalf("someone else's job: %d", w.Code)
	}
	w := h.do("GET", "/admin/bulk/"+job.ID, admin, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `data-e2e="job-btn-apply"`) || !strings.Contains(w.Body.String(), "lockoutTime: 0") {
		t.Fatalf("preview page: %d", w.Code)
	}
	if w := h.do("POST", "/admin/bulk/"+job.ID+"/apply", admin, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d", w.Code)
	}
	h.s.bgJobs.Wait()
	got, _ := h.st.GetBulkJob(ctx, job.ID)
	counts, _ := h.st.RowCounts(ctx, job.ID)
	if got.Status != store.JobDone || counts[store.RowFailed] != 2 {
		t.Fatalf("after the run: %+v %v", got, counts)
	}
	if w := h.do("POST", "/admin/bulk/"+job.ID+"/apply", admin, nil); w.Code != http.StatusConflict {
		t.Fatalf("second apply: %d", w.Code)
	}
	evs, _, _ := h.st.ListAudit(ctx, store.AuditFilter{Action: "bulk.selected-unlock"}, 0, 10)
	if len(evs) != 2 || evs[0].Result != store.ResultFailed {
		t.Fatalf("row audit: %+v", evs)
	}
	perDC := false
	for _, e := range evs {
		if strings.Contains(e.Detail, "# per DC: dc1.test: failed; dc2.test: failed") {
			perDC = true
		}
	}
	if !perDC {
		t.Fatalf("the per-DC outcome is not in the audit: %+v", evs)
	}
	rep := h.do("GET", "/admin/bulk/"+job.ID+"/report.csv", admin, nil)
	if !strings.Contains(rep.Body.String(), "dc1.test, dc2.test") {
		t.Fatalf("report lacks the failed DCs:\n%s", rep.Body.String())
	}
	if !strings.Contains(rep.Body.String(), "row,label,target,status,error") || strings.Count(rep.Body.String(), ",failed,") != 2 {
		t.Fatalf("report:\n%s", rep.Body.String())
	}
	// A restart marks running jobs interrupted.
	_ = h.st.SetBulkJobStatus(ctx, job.ID, store.JobRunning)
	if err := h.s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.st.GetBulkJob(ctx, job.ID); got.Status != store.JobInterrupted {
		t.Fatalf("after restart: %s", got.Status)
	}
}

// TestSidebarFollowsRoles: the grouped sidebar shows only what the role can
// use, a group with nothing usable is left out, and the footer entries are
// there for everyone.
func TestSidebarFollowsRoles(t *testing.T) {
	h := newHarness(t)
	has := func(body, id string) bool { return strings.Contains(body, `data-e2e="`+id+`"`) }
	admin := h.do("GET", "/me/security", h.session(t, "lab.admin", stageFull, true), nil).Body.String()
	for _, id := range []string{"nav-group-overview", "nav-group-directory", "nav-group-policies", "nav-group-network",
		"nav-group-operations", "nav-group-audit", "nav-group-account", "nav-link-dns", "nav-link-bulk", "nav-link-security", "nav-btn-signout", "nav-btn-menu"} {
		if !has(admin, id) {
			t.Errorf("admin sidebar lacks %s", id)
		}
	}
	if !strings.Contains(admin, `data-e2e="nav-link-security" aria-current="page"`) {
		t.Error("the current page is not marked")
	}
	help := h.do("GET", "/me/security", h.session(t, "helpdesk.user", stageFull, true), nil).Body.String()
	for _, id := range []string{"nav-group-network", "nav-group-policies", "nav-group-audit", "nav-group-overview", "nav-link-bulk", "nav-link-groups"} {
		if has(help, id) {
			t.Errorf("helpdesk sidebar has %s", id)
		}
	}
	for _, id := range []string{"nav-group-directory", "nav-link-users", "nav-group-operations", "nav-link-lockouts", "nav-link-me", "nav-btn-signout"} {
		if !has(help, id) {
			t.Errorf("helpdesk sidebar lacks %s", id)
		}
	}
	if has(help, "nav-link-bulk") || has(help, "nav-link-health") == false {
		t.Error("helpdesk operations group")
	}
}

// TestBulkJobReauthSecondFactors: a job that needs re-authentication asks
// for the same second factors as any other confirmation: an authenticator
// code (or a recovery code) and, when the policy requires a security key
// for administrators, the key or a recovery code only.
func TestBulkJobReauthSecondFactors(t *testing.T) {
	newJob := func(t *testing.T, h *harness, admin string) *bulkJob {
		t.Helper()
		sess := h.s.sess.byID[hashToken(admin)]
		dn := "CN=a,OU=People,DC=lab,DC=test"
		op, _ := ad.UnlockUser(dn)
		r := &bulkRow{No: 1, Label: "a", Target: dn, Input: map[string]string{"guid": "x"}, ops: []*ad.Operation{op},
			Preview: rowPreview([]*ad.Operation{op}), Status: store.RowPending}
		job := &bulkJob{ID: strings.Repeat("k", 22), Kind: importKind, ownerSID: sess.userSID.String(), owner: "lab.admin",
			session: sess.hash, perm: PermUsersHelpdesk, Reauth: true, Rows: []*bulkRow{r}, Status: store.JobPreviewed, created: h.now}
		if err := h.st.CreateBulkJob(context.Background(), store.BulkJob{ID: job.ID, Kind: job.Kind, OwnerSID: job.ownerSID, OwnerName: job.owner},
			[]store.BulkRow{{No: 1, Label: "a", Target: dn, Input: "{}", Preview: r.Preview}}); err != nil {
			t.Fatal(err)
		}
		h.s.jobs.put(job, h.now)
		return job
	}

	h := newHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	secret := h.enrollTOTP(t, "lab.admin")
	job := newJob(t, h, admin)
	body := h.do("GET", "/admin/bulk/"+job.ID+"?lang=en", admin, nil).Body.String()
	if !strings.Contains(body, "a code from your authenticator (or a recovery code)") || !strings.Contains(body, "Authentication code") ||
		strings.Contains(body, "re-authentication with a security key") {
		t.Fatalf("job page asks for a key or recovery code only: %s", body)
	}
	// Without a code nothing runs.
	if w := h.do("POST", "/admin/bulk/"+job.ID+"/apply", admin, url.Values{"password": {"pw"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("apply without code: %d", w.Code)
	}
	if got, _ := h.st.GetBulkJob(context.Background(), job.ID); got.Status != store.JobPreviewed {
		t.Fatalf("applied without a second factor: %s", got.Status)
	}
	// An authenticator code is accepted.
	h.now = h.now.Add(30 * time.Second)
	if w := h.do("POST", "/admin/bulk/"+job.ID+"/apply", admin, url.Values{"password": {"pw"}, "code": {totp.Code(secret, totp.Step(h.now))}}); w.Code != http.StatusSeeOther {
		t.Fatalf("apply with code: %d", w.Code)
	}
	h.s.bgJobs.Wait()
	if got, _ := h.st.GetBulkJob(context.Background(), job.ID); got.Status != store.JobDone {
		t.Fatalf("a TOTP code was not accepted: %s", got.Status)
	}

	// Policy: security keys required for administrators.
	h = newHarness(t, withWebAuthn, func(c *config.Config) { c.WebAuthn.AdminRequired = true })
	admin = h.session(t, "lab.admin", stageFull, true)
	h.s.sess.byID[hashToken(admin)].keyOK = true // signed in with a key
	job = newJob(t, h, admin)
	body = h.do("GET", "/admin/bulk/"+job.ID+"?lang=en", admin, nil).Body.String()
	if !strings.Contains(body, "re-authentication with a security key") || !strings.Contains(body, "Recovery code") {
		t.Fatalf("key policy not shown: %s", body)
	}
}
