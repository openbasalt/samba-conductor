package web

import (
	"context"
	"fmt"
	"html"
	"iter"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
)

const fakeBase = "DC=lab,DC=test"

// fakeDir is an in-memory directory for the list pages. It honours the
// search base and subtree scope; it does not evaluate filters (the tests
// check the compiled filter of the recorded request instead).
type fakeDir struct {
	mu         sync.Mutex
	ous        []ad.OU
	containers []string
	objects    map[string][]*ldap.Entry // "user", "group", "computer"
	reqs       []ad.SearchRequest
}

func (f *fakeDir) BaseDN() string { return fakeBase }

func (f *fakeDir) Get(_ context.Context, dn string, _ ...string) (*ldap.Entry, error) {
	for _, c := range f.containers {
		if escape.EqualDN(c, dn) {
			cn := strings.TrimPrefix(strings.SplitN(c, ",", 2)[0], "CN=")
			return ldap.NewEntry(c, map[string][]string{"cn": {cn}}), nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ad.ErrNotFound, dn)
}

func (f *fakeDir) OUs(context.Context, string, escape.Filter) iter.Seq2[ad.OU, error] {
	return func(yield func(ad.OU, error) bool) {
		for _, o := range f.ous {
			if !yield(o, nil) {
				return
			}
		}
	}
}

func (f *fakeDir) SearchWindow(_ context.Context, req ad.SearchRequest, skip, n int) ([]*ldap.Entry, bool, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	filter := escape.MustCompile(req.Filter)
	kind := "user"
	switch {
	case strings.Contains(filter, "(objectClass=computer)"):
		kind = "computer"
	case strings.Contains(filter, "(objectClass=group)"):
		kind = "group"
	}
	base := req.BaseDN
	if base == "" {
		base = fakeBase
	}
	pb, err := ldap.ParseDN(base)
	if err != nil {
		return nil, false, err
	}
	var in []*ldap.Entry
	for _, e := range f.objects[kind] {
		pe, _ := ldap.ParseDN(e.DN)
		if pb.AncestorOfFold(pe) {
			in = append(in, e)
		}
	}
	if skip >= len(in) {
		return nil, false, nil
	}
	end := min(skip+n, len(in))
	return in[skip:end], end < len(in), nil
}

func (f *fakeDir) last() ad.SearchRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[len(f.reqs)-1]
}

const (
	ouStaff = "OU=Staff," + fakeBase
	ouSales = "OU=Sales,OU=Staff," + fakeBase
	ouOps   = "OU=Ops," + fakeBase
	cnUsers = "CN=Users," + fakeBase
	cnComps = "CN=Computers," + fakeBase
)

func fakeUser(sam, parent string) *ldap.Entry {
	return ldap.NewEntry("CN="+sam+","+parent, map[string][]string{"sAMAccountName": {sam}, "userAccountControl": {"512"}})
}

func newFakeDir() *fakeDir {
	return &fakeDir{
		ous: []ad.OU{
			{DN: ouStaff, Name: "Staff"},
			{DN: ouSales, Name: "Sales"},
			{DN: ouOps, Name: "Ops"},
		},
		containers: []string{cnUsers, cnComps},
		objects: map[string][]*ldap.Entry{
			"user": {fakeUser("alice", ouStaff), fakeUser("bob", ouSales), fakeUser("carol", ouOps), fakeUser("administrator", cnUsers)},
			"group": {
				ldap.NewEntry("CN=staff-all,"+ouStaff, map[string][]string{"cn": {"staff-all"}, "sAMAccountName": {"staff-all"}}),
				ldap.NewEntry("CN=sales-team,"+ouSales, map[string][]string{"cn": {"sales-team"}, "sAMAccountName": {"sales-team"}}),
				ldap.NewEntry("CN=Domain Admins,"+cnUsers, map[string][]string{"cn": {"Domain Admins"}, "sAMAccountName": {"Domain Admins"}}),
			},
			"computer": {
				ldap.NewEntry("CN=WS1,"+ouSales, map[string][]string{"cn": {"WS1"}, "sAMAccountName": {"WS1$"}}),
				ldap.NewEntry("CN=WS2,"+cnComps, map[string][]string{"cn": {"WS2"}, "sAMAccountName": {"WS2$"}}),
			},
		},
	}
}

func listHarness(t *testing.T) (*harness, *fakeDir, string) {
	t.Helper()
	h := newHarness(t)
	d := newFakeDir()
	h.s.listDir = d
	return h, d, h.session(t, "lab.admin", stageFull, true)
}

func getList(t *testing.T, h *harness, tok, path string) string {
	t.Helper()
	w := h.do("GET", path, tok, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
	}
	return w.Body.String()
}

func rowsIn(body, prefix string, names ...string) map[string]bool {
	got := map[string]bool{}
	for _, n := range names {
		got[n] = strings.Contains(body, `data-e2e="`+prefix+`-row-`+e2eID(n)+`"`)
	}
	return got
}

func wantRows(t *testing.T, body, prefix string, want map[string]bool) {
	t.Helper()
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	got := rowsIn(body, prefix, names...)
	for n, w := range want {
		if got[n] != w {
			t.Errorf("%s row %q shown=%v, want %v", prefix, n, got[n], w)
		}
	}
}

func TestListScopeEntireDomainByDefault(t *testing.T) {
	h, d, tok := listHarness(t)
	body := getList(t, h, tok, "/admin/users")
	if d.last().BaseDN != "" {
		t.Fatalf("base %q, want the domain default", d.last().BaseDN)
	}
	wantRows(t, body, "users", map[string]bool{"alice": true, "bob": true, "carol": true, "administrator": true})
	if !strings.Contains(body, `data-e2e="users-select-ou"`) || strings.Contains(body, "users-text-ou-unavailable") {
		t.Fatal("picker missing or a fallback notice without ?ou=")
	}
	// The tree: OUs and CN=Users, children indented under their parent.
	i := strings.Index(body, `data-e2e="users-select-ou"`)
	sel := body[i : i+strings.Index(body[i:], "</select>")]
	order := []string{">Ops<", ">Staff<", ">" + scopeIndent + "Sales<", ">Users<"}
	pos := 0
	for _, o := range order {
		j := strings.Index(sel[pos:], o)
		if j < 0 {
			t.Fatalf("option %q missing or out of order in %s", o, sel)
		}
		pos += j
	}
	if strings.Contains(sel, ">Computers<") {
		t.Error("CN=Computers offered on the Users page")
	}
}

func TestListScopeValidOU(t *testing.T) {
	h, d, tok := listHarness(t)
	body := getList(t, h, tok, "/admin/users?ou="+url.QueryEscape(ouOps))
	if d.last().BaseDN != ouOps || d.last().Scope != ad.ScopeSubtree {
		t.Fatalf("request %+v", d.last())
	}
	wantRows(t, body, "users", map[string]bool{"carol": true, "alice": false, "bob": false, "administrator": false})
	if !strings.Contains(body, `value="`+html.EscapeString(ouOps)+`" selected`) {
		t.Error("chosen OU not selected in the picker")
	}

	// A default container is selectable too.
	body = getList(t, h, tok, "/admin/users?ou="+url.QueryEscape(cnUsers))
	wantRows(t, body, "users", map[string]bool{"administrator": true, "alice": false})
}

func TestListScopeNestedOU(t *testing.T) {
	h, d, tok := listHarness(t)
	// Case and spacing differences still match; the directory's spelling is used.
	body := getList(t, h, tok, "/admin/users?ou="+url.QueryEscape(" ou=staff, dc=LAB,dc=test "))
	if d.last().BaseDN != ouStaff {
		t.Fatalf("base %q, want %q", d.last().BaseDN, ouStaff)
	}
	wantRows(t, body, "users", map[string]bool{"alice": true, "bob": true, "carol": false, "administrator": false})

	body = getList(t, h, tok, "/admin/groups?ou="+url.QueryEscape(ouStaff))
	wantRows(t, body, "groups", map[string]bool{"staff-all": true, "sales-team": true, "Domain Admins": false})

	body = getList(t, h, tok, "/admin/computers?ou="+url.QueryEscape(ouStaff))
	wantRows(t, body, "computers", map[string]bool{"WS1$": true, "WS2$": false})
	body = getList(t, h, tok, "/admin/computers?ou="+url.QueryEscape(cnComps))
	wantRows(t, body, "computers", map[string]bool{"WS1$": false, "WS2$": true})
}

func TestListScopeRejectsOtherDNs(t *testing.T) {
	h, d, tok := listHarness(t)
	for _, bad := range []string{
		"OU=Staff,DC=other,DC=test",           // another domain
		"DC=test",                             // above the base
		fakeBase,                              // the base itself (that is "entire domain")
		"CN=alice," + ouStaff,                 // an object, not a container
		"OU=Ghost," + fakeBase,                // does not exist
		"CN=Computers," + fakeBase + "x",      // not below the base
		"OU=Staff)(objectClass=*," + fakeBase, // filter syntax: just an unknown DN
		"((((",                                // not a DN
		strings.Repeat("OU=a,", 600) + fakeBase,
	} {
		for _, page := range []string{"users", "groups", "computers"} {
			body := getList(t, h, tok, "/admin/"+page+"?ou="+url.QueryEscape(bad))
			if d.last().BaseDN != "" {
				t.Fatalf("%s with %q searched below %q", page, bad, d.last().BaseDN)
			}
			if !strings.Contains(body, `data-e2e="`+page+`-text-ou-unavailable"`) {
				t.Errorf("%s with %q: no fallback notice", page, bad)
			}
			if strings.Contains(body, `" selected>`) && strings.Contains(body, page+"-select-ou") {
				i := strings.Index(body, page+"-select-ou")
				if sel := body[i : i+strings.Index(body[i:], "</select>")]; strings.Contains(sel, "selected") {
					t.Errorf("%s with %q: an option is selected", page, bad)
				}
			}
		}
	}
	// CN=Computers is not offered (nor accepted) on the Users page.
	getList(t, h, tok, "/admin/users?ou="+url.QueryEscape(cnComps))
	if d.last().BaseDN != "" {
		t.Fatal("CN=Computers accepted on the Users page")
	}
}

func TestListScopeWithTextFilter(t *testing.T) {
	h, d, tok := listHarness(t)
	getList(t, h, tok, "/admin/users?q=al&status=enabled&ou="+url.QueryEscape(ouStaff))
	req := d.last()
	f := escape.MustCompile(req.Filter)
	if req.BaseDN != ouStaff || !strings.Contains(f, "(sAMAccountName=al*)") || !strings.Contains(f, "userAccountControl") {
		t.Fatalf("base %q filter %s", req.BaseDN, f)
	}
	// The OU never reaches the filter.
	if strings.Contains(strings.ToLower(f), "staff") {
		t.Fatalf("OU in the filter: %s", f)
	}
	getList(t, h, tok, "/admin/computers?q=ws&ou="+url.QueryEscape(ouSales))
	if req := d.last(); req.BaseDN != ouSales || !strings.Contains(escape.MustCompile(req.Filter), "(dNSHostName=ws*)") {
		t.Fatalf("computers request %+v", req)
	}
	getList(t, h, tok, "/admin/groups?q=sa&ou="+url.QueryEscape(ouStaff))
	if req := d.last(); req.BaseDN != ouStaff || !strings.Contains(escape.MustCompile(req.Filter), "(cn=sa*)") {
		t.Fatalf("groups request %+v", req)
	}
}

func TestListScopePagination(t *testing.T) {
	h, d, tok := listHarness(t)
	var many []*ldap.Entry
	for i := range pageSize + 10 {
		many = append(many, fakeUser(fmt.Sprintf("sales%02d", i), ouSales))
	}
	d.objects["user"] = append(d.objects["user"], many...)
	q := "/admin/users?q=s&ou=" + url.QueryEscape(ouStaff)
	body := getList(t, h, tok, q)
	// alice, bob and 60 sales users: page 1 is full; the next link keeps
	// ou and q (the fake does not apply q).
	i := strings.Index(body, `data-e2e="pager-link-next"`)
	if i < 0 {
		t.Fatal("no next page link")
	}
	start := strings.LastIndex(body[:i], `href="`) + len(`href="`)
	link := html.UnescapeString(body[start : start+strings.Index(body[start:], `"`)])
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("ou") != ouStaff || u.Query().Get("q") != "s" || u.Query().Get("page") != "2" {
		t.Fatalf("next link %q", link)
	}
	body = getList(t, h, tok, "/admin/users"+link)
	if d.last().BaseDN != ouStaff {
		t.Fatalf("page 2 base %q", d.last().BaseDN)
	}
	if n := strings.Count(body, `data-e2e="users-row-`); n != 12 {
		t.Fatalf("page 2 rows %d, want 12", n)
	}
	if strings.Contains(body, `data-e2e="pager-link-next"`) {
		t.Fatal("next link on the last page")
	}
	wantRows(t, body, "users", map[string]bool{"carol": false, "administrator": false})
}

func TestScopeMatchParsesDNs(t *testing.T) {
	sc := ouScope{Options: []scopeOption{{DN: `OU=A\,B,` + fakeBase}}}
	if dn, ok := sc.match(`ou=a\2cb,dc=lab,dc=test`, fakeBase); !ok || dn != `OU=A\,B,`+fakeBase {
		t.Fatalf("escaped comma: %q %v", dn, ok)
	}
	if _, ok := sc.match(`OU=A,OU=B,`+fakeBase, fakeBase); ok {
		t.Fatal("a different DN matched")
	}
}
