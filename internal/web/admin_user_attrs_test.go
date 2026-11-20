package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor/internal/config"
)

func TestAttributesPermission(t *testing.T) {
	if !(Roles{Admin: true}).Has(PermUsersAttrs) || !(Roles{Auditor: true}).Has(PermUsersAttrs) {
		t.Error("admin and auditor must see the Attributes tab")
	}
	if (Roles{Helpdesk: true}).Has(PermUsersAttrs) {
		t.Error("helpdesk must not see the Attributes tab")
	}
	if (Roles{Auditor: true}).Has(PermUsersWrite) {
		t.Error("auditor may not edit")
	}
}

// renderAs renders a page with the given roles.
func renderAs(t *testing.T, h *harness, roles Roles, page string, d map[string]any) string {
	t.Helper()
	tok := h.session(t, "lab.admin", stageFull, true)
	sess := h.s.sess.get(context.Background(), tok)
	w := httptest.NewRecorder()
	rc := &reqCtx{s: h.s, sess: sess, w: w, r: httptest.NewRequest("GET", "/admin/users/x", nil), lang: "en", roles: roles}
	rc.render(http.StatusOK, page, d)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d", page, w.Code)
	}
	return w.Body.String()
}

func TestAttributesTemplates(t *testing.T) {
	h := newHarness(t)
	g, _ := sid.ParseGUID("00112233-4455-6677-8899-aabbccddeeff")
	u := ad.User{SAMAccountName: "ana", DisplayName: "Ana", GUID: g, DN: "CN=Ana,DC=lab,DC=test"}
	raw := ad.RawEntry{DN: u.DN, Attributes: []ad.RawAttribute{
		{Name: "cn", Values: []ad.RawValue{{Text: "Ana", Len: 3}}},
		{Name: "description", Values: []ad.RawValue{{Binary: true, Len: 11}}},
		{Name: "info", Values: []ad.RawValue{{Text: "<script>x</script>", Len: 2000, Truncated: true}}},
		{Name: "otherMailbox", Values: []ad.RawValue{{Text: "a@x.test", Len: 8}}, More: 7},
		{Name: "unicodePwd", Hidden: true},
	}}
	body := renderAs(t, h, Roles{Auditor: true}, "user_attrs", map[string]any{"U": u, "Raw": raw, "Edit": false})
	for _, want := range []string{`data-e2e="user-tabs"`, `data-e2e="user-tab-attributes" aria-current="page"`, `data-e2e="attrs-row-cn"`,
		`data-e2e="attrs-hidden-unicodepwd"`, "binary value, 11 bytes", "and 7 more", "(cut, 2000 bytes in all)", "&lt;script&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("attributes page lacks %s", want)
		}
	}
	if strings.Contains(body, "attrs-link-edit") || strings.Contains(body, "<script>x") {
		t.Error("edit link without the flag, or unescaped value")
	}
	body = renderAs(t, h, Roles{Admin: true}, "user_attrs", map[string]any{"U": u, "Raw": raw, "Edit": true})
	if !strings.Contains(body, `href="/admin/users/00112233-4455-6677-8899-aabbccddeeff/attributes/edit" data-e2e="attrs-link-edit"`) {
		t.Error("edit link missing")
	}

	// The overview shows the tabs only to roles that may open them.
	d := map[string]any{"U": u, "Fields": gfFieldViews(adminFields, u, gfManaged{})}
	if b := renderAs(t, h, Roles{Admin: true}, "user", d); !strings.Contains(b, `data-e2e="user-tab-overview" aria-current="page"`) {
		t.Error("admin overview without tabs")
	}
	if b := renderAs(t, h, Roles{Helpdesk: true}, "user", d); strings.Contains(b, "user-tab-attributes") {
		t.Error("helpdesk sees the Attributes tab")
	}

	fields := attrFields(map[string][]string{"loginShell": {"/bin/bash"}, "otherMailbox": {"a@x.test", "b@x.test"}}, gfManaged{},
		map[string]string{"uidNumber": "Enter a number from 1000 to 2147483647."})
	body = renderAs(t, h, Roles{Admin: true}, "user_attrs_edit", map[string]any{"U": u, "Fields": fields, "Error": "Some values are invalid."})
	for _, want := range []string{`data-e2e="attrs-input-loginshell"`, `value="/bin/bash"`, `data-e2e="attrs-input-othermailbox">a@x.test` + "\nb@x.test<",
		`data-e2e="attrs-error-uidnumber"`, `inputmode="numeric"`, `data-e2e="attrs-btn-preview"`, `data-e2e="attrs-link-cancel"`,
		`data-e2e="form-text-error"`, "Login shell"} {
		if !strings.Contains(body, want) {
			t.Errorf("edit page lacks %s", want)
		}
	}
}

func TestAttributesFromForm(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader(url.Values{
		"loginShell": {" /bin/zsh "}, "gecos": {""}, "otherMailbox": {"a@x.test\r\n\r\n b@x.test \n"},
		"userAccountControl": {"514"}, "description": {"x"}, "unicodePwd": {"y"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	rc := &reqCtx{r: r}
	cur := map[string][]string{"uidNumber": {"10001"}, "gecos": {"Ana"}}
	got := attrsFromForm(rc, cur)
	if len(got) != len(ad.EditableUserAttributes()) {
		t.Fatalf("names outside the allowlist read: %v", got)
	}
	for _, n := range []string{"userAccountControl", "description", "unicodePwd"} {
		if _, ok := got[n]; ok {
			t.Errorf("%s read from the form", n)
		}
	}
	if v := got["loginShell"]; len(v) != 1 || v[0] != "/bin/zsh" {
		t.Errorf("loginShell %q", v)
	}
	if v := got["gecos"]; len(v) != 0 {
		t.Errorf("empty field must remove: %q", v)
	}
	if v := got["uidNumber"]; len(v) != 1 || v[0] != "10001" {
		t.Errorf("absent field must keep the current value: %q", v)
	}
	if v := got["otherMailbox"]; len(v) != 2 || v[0] != "a@x.test" || v[1] != "b@x.test" {
		t.Errorf("otherMailbox %q", v)
	}
}

func TestAttributesEditorOffAnswers404(t *testing.T) {
	h := newHarness(t)
	admin := h.session(t, "lab.admin", stageFull, true)
	path := "/admin/users/00112233-4455-6677-8899-aabbccddeeff/attributes/edit"
	if w := h.do("GET", path, admin, nil); w.Code != http.StatusNotFound {
		t.Errorf("GET with the editor off: %d", w.Code)
	}
	if w := h.do("POST", path, admin, url.Values{"loginShell": {"/bin/sh"}}); w.Code != http.StatusNotFound {
		t.Errorf("POST with the editor off: %d", w.Code)
	}
	if n := len(h.s.sess.byID[hashToken(admin)].pending); n != 0 {
		t.Errorf("%d operations proposed with the editor off", n)
	}
	// With the flag on, a helpdesk session is still refused by the guard.
	on := newHarness(t, func(c *config.Config) { c.UI.AdvancedAttributeEdit = true })
	hd := on.session(t, "helpdesk.user", stageFull, true)
	if w := on.do("POST", path, hd, url.Values{"loginShell": {"/bin/sh"}}); w.Code != http.StatusForbidden {
		t.Errorf("helpdesk POST: %d", w.Code)
	}
	if w := on.do("GET", "/admin/users/00112233-4455-6677-8899-aabbccddeeff/attributes", hd, nil); w.Code != http.StatusForbidden {
		t.Errorf("helpdesk GET attributes: %d", w.Code)
	}
}
