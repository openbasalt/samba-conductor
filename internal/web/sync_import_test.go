package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/i18n"
	"github.com/openbasalt/samba-conductor/internal/store"
)

func TestLogonNames(t *testing.T) {
	for in, want := range map[string]string{
		"João da Silva":         "joaodasilva",
		"Ana-Maria.Ñandú":       "ana-maria.nandu",
		"..x..y--":              "x.y",
		"Ærøskøbing Straße":     "aeroskobingstrasse",
		"averyveryverylongname": "averyveryverylongnam",
	} {
		if got := logonName(in, maxUserSAM); got != want {
			t.Errorf("logonName(%q) = %q, want %q", in, got, want)
		}
	}
	for tmpl, ok := range map[string]bool{"{given}.{family}": true, "{g}{family}": true, "{local}-ext": true, "plain": false,
		"{given} {family}": false, "{GIVEN}": false, "{given}@x": false, "": false} {
		if validFallback(tmpl) != ok {
			t.Errorf("validFallback(%q) = %v", tmpl, !ok)
		}
	}
	if got := renderFallback("{given}.{family}", "José", "da Conceição", "x@example.com"); got != "jose.conceicao" {
		t.Errorf("fallback %q", got)
	}
	if got := renderFallback("{g}{f}", "José", "da Conceição", "x@example.com"); got != "jc" {
		t.Errorf("fallback initials %q", got)
	}
	// The local part is used as is when valid; otherwise the fallback.
	if got := userSAMCandidates("{given}.{family}", "Ana", "Souza", "Ana.Souza@example.com"); strings.Join(got, ",") != "ana.souza" {
		t.Errorf("candidates %v", got)
	}
	if got := userSAMCandidates("{given}.{family}", "Ana", "Souza", "ana+sales@example.com"); strings.Join(got, ",") != "ana.souza" {
		t.Errorf("invalid local part: %v", got)
	}
	if got := userSAMCandidates("{g}{family}", "Ana", "Souza", "ana.maria.de.souza.lima@example.com"); strings.Join(got, ",") != "asouza" {
		t.Errorf("too long local part: %v", got)
	}
}

func importT(key string, args ...any) string {
	c, err := i18n.Load()
	if err != nil {
		panic(err)
	}
	return c.T("en", key, args...)
}

const (
	usersOU  = "OU=People,DC=lab,DC=test"
	groupsOU = "OU=Google Groups,DC=lab,DC=test"
)

func testImportOptions() importOptions {
	return importOptions{UserOU: usersOU, GroupOU: groupsOU, Enabled: true, Fallback: defaultFallback, Max: 50}
}

func testLookup() *importLookup {
	return &importLookup{Realm: "lab.test",
		UsersByMail: map[string]*adRef{"bruno@example.com": {DN: "CN=Bruno Costa," + usersOU, SAM: "bcosta"},
			"dup@example.com": {Several: true}},
		GroupsByMail: map[string]*adRef{
			"it@example.com":     {DN: "CN=IT," + groupsOU, SAM: "it", Members: map[string]bool{escape.NormalizeDN("CN=Bruno Costa," + usersOU): true}},
			"admins@example.com": {DN: "CN=Domain Admins,CN=Users,DC=lab,DC=test", SAM: "Domain Admins", Protected: true}},
		SAMTaken: map[string]bool{"carla": true},
		CNTaken:  map[string]bool{cnKey(usersOU, "Dora Lima"): true},
	}
}

func rowsByLabel(rows []*bulkRow) map[string]*bulkRow {
	out := map[string]*bulkRow{}
	for _, r := range rows {
		out[r.Label] = r
	}
	return out
}

// TestImportRows: the AD side of an import decides, per object, a create
// (with the Google address as mail, a hidden random password and a forced
// change), a skip with its reason (same address already in AD, no free
// logon name, the run's limit), and group members limited to the users the
// job creates or finds by address.
func TestImportRows(t *testing.T) {
	users := []importUserIn{
		{Email: "ana@example.com", Given: "Ana", Family: "Ribeiro", Title: "Manager", Department: "Sales", EmployeeID: "E1",
			PhoneWork: "+55 11 5555-0001", PhoneMobile: "+55 11 99999-0001"},
		{Email: "bruno@example.com", Given: "Bruno", Family: "Costa"},
		{Email: "carla@example.com", Given: "Carla", Family: "Dias"},
		{Email: "dora@example.com", Given: "Dora", Family: "Lima", Suspended: true},
		{Email: "dup@example.com", Given: "Dup", Family: "Licate"},
		{Email: "ana@example.com", Given: "Ana", Family: "Ribeiro"},
	}
	groups := []importGroupIn{
		{Email: "sales@example.com", Name: "Sales", Description: "Sales team", Users: []string{"ana@example.com", "bruno@example.com", "nobody@example.com"},
			Groups: []string{"it@example.com"}},
		{Email: "it@example.com", Name: "IT", Users: []string{"bruno@example.com", "carla@example.com"}},
		{Email: "admins@example.com", Name: "Admins", Users: []string{"ana@example.com"}},
	}
	var passwords []string
	pw := func() string {
		p := newPasswordLen(32)
		passwords = append(passwords, p)
		return p
	}
	rows, errs := importPlanRows(importT, testImportOptions(), users, groups, testLookup(), pw)
	if len(errs) > 0 {
		t.Fatalf("errors %+v", errs)
	}
	by := rowsByLabel(rows)
	ana := by["ana@example.com"]
	if ana == nil || len(ana.ops) != 1 || ana.password != "" || ana.Target != "CN=Ana Ribeiro,"+usersOU {
		t.Fatalf("ana %+v", ana)
	}
	for _, want := range []string{"sAMAccountName: ana", "userPrincipalName: ana@lab.test", "mail: ana@example.com", "title: Manager",
		"department: Sales", "employeeID: E1", "telephoneNumber: +55 11 5555-0001", "mobile: +55 11 99999-0001",
		"unicodePwd: <redacted>", "pwdLastSet: 0", "userAccountControl: 512", "displayName: Ana Ribeiro"} {
		if !strings.Contains(ana.Preview, want) {
			t.Errorf("ana preview lacks %q:\n%s", want, ana.Preview)
		}
	}
	for _, p := range passwords {
		for _, r := range rows {
			if strings.Contains(r.Preview, p) || strings.Contains(r.Note, p) {
				t.Fatal("a generated password is visible")
			}
		}
	}
	if b := by["bruno@example.com"]; len(b.ops) != 0 || !strings.Contains(b.Note, "bcosta") {
		t.Fatalf("an AD account with the address must be left alone: %+v", b)
	}
	// carla's local part is taken: the fallback is used.
	if c := by["carla@example.com"]; len(c.ops) != 1 || !strings.Contains(c.Preview, "sAMAccountName: carla.dias") {
		t.Fatalf("carla %+v", c)
	}
	// dora: suspended in Google -> created disabled; the name is taken in
	// the OU -> "(logon)" suffix.
	if d := by["dora@example.com"]; len(d.ops) != 1 || !strings.Contains(d.Preview, "userAccountControl: 514") ||
		d.Target != "CN=Dora Lima (dora),"+usersOU {
		t.Fatalf("dora %+v\n%s", d, d.Preview)
	}
	if d := by["dup@example.com"]; len(d.ops) != 0 || !strings.Contains(d.Note, "Several") {
		t.Fatalf("dup %+v", d)
	}
	sales := by["sales@example.com"]
	if sales == nil || len(sales.ops) != 3 || !strings.Contains(sales.Preview, "mail: sales@example.com") ||
		!strings.Contains(sales.Preview, "member: CN=Ana Ribeiro,"+usersOU) || !strings.Contains(sales.Preview, "member: CN=Bruno Costa,"+usersOU) {
		t.Fatalf("sales %+v\n%s", sales, sales.Preview)
	}
	// An existing group with the address receives only the missing
	// members; a privileged one is never changed.
	it := by["it@example.com"]
	if len(it.ops) != 1 || !strings.Contains(it.Preview, "member: CN=Carla Dias,"+usersOU) || strings.Contains(it.Preview, "changetype: add") {
		t.Fatalf("it %+v\n%s", it, it.Preview)
	}
	if a := by["admins@example.com"]; len(a.ops) != 0 || !strings.Contains(a.Note, "privileged") {
		t.Fatalf("protected group %+v", a)
	}
	nest := rows[len(rows)-1]
	if nest.Input["type"] != importNest || !strings.Contains(nest.Preview, "member: CN=IT,"+groupsOU) || nest.Target != "CN=Sales,"+groupsOU {
		t.Fatalf("nested row %+v", nest)
	}
	if len(rows) != 5+3+1 {
		t.Fatalf("%d rows (the duplicate address must appear once)", len(rows))
	}

	// The run's limit: only the first object is created; the rest are
	// reported, and the next run continues.
	opt := testImportOptions()
	opt.Max = 1
	rows, _ = importPlanRows(importT, opt, users, groups, testLookup(), pw)
	by = rowsByLabel(rows)
	if len(by["ana@example.com"].ops) != 1 || len(by["carla@example.com"].ops) != 0 || !strings.Contains(by["carla@example.com"].Note, "limit of 1") ||
		!strings.Contains(by["sales@example.com"].Note, "limit") {
		t.Fatalf("limit: %+v", by)
	}
	// Disabled accounts on request.
	opt = testImportOptions()
	opt.Enabled = false
	rows, _ = importPlanRows(importT, opt, users[:1], nil, testLookup(), pw)
	if !strings.Contains(rows[0].Preview, "userAccountControl: 514") || !strings.Contains(rows[0].Preview, "pwdLastSet: 0") {
		t.Fatalf("disabled:\n%s", rows[0].Preview)
	}
	// A missing OU stops the job before anything is built.
	look := testLookup()
	look.UserOUMissing = true
	if _, errs := importPlanRows(importT, testImportOptions(), users, nil, look, pw); len(errs) != 1 {
		t.Fatal("a missing OU must be an error")
	}
}

// TestImportInputsRoundTrip: a plan becomes job inputs that decode back
// (the retry of failed rows rebuilds from them).
func TestImportInputsRoundTrip(t *testing.T) {
	plan := &syncapi.ImportPlan{Users: []syncapi.ImportUser{{Email: "ana@example.com", GivenName: "Ana", FamilyName: "Ribeiro", Title: "Manager",
		Suspended: true}}, Groups: []syncapi.ImportGroup{{Email: "sales@example.com", Name: "Sales", Users: []string{"ana@example.com"},
		Groups: []string{"it@example.com"}}}}
	inputs := importInputs(plan, testImportOptions())
	opt, users, groups, err := decodeImportInputs(inputs)
	if err != nil || opt != testImportOptions() || len(users) != 1 || !users[0].Suspended || users[0].Title != "Manager" ||
		len(groups) != 1 || groups[0].Users[0] != "ana@example.com" || groups[0].Groups[0] != "it@example.com" {
		t.Fatalf("round trip: %v %+v %+v %+v", err, opt, users, groups)
	}
	inputs[1]["opt_max"] = "7"
	if _, _, _, err := decodeImportInputs(inputs); err == nil {
		t.Fatal("rows with different options must be refused")
	}
}

// TestSyncImportPages: administrators only; the read goes to
// conductor-sync as the signed-in administrator with the form's filters,
// is audited, and the plan and the sync configuration warnings are shown.
func TestSyncImportPages(t *testing.T) {
	h, fs := syncHarness(t)
	fs.importPlan = syncapi.ImportPlan{UsersRead: 3, GroupsRead: 1, Users: []syncapi.ImportUser{{Email: "ana@example.com", GivenName: "Ana",
		FamilyName: "Ribeiro", OrgUnit: "/Sales", Aliases: []string{"ana.r@example.com"}}, {Email: "x@other.example", OrgUnit: "/",
		Warnings: []string{syncapi.ImportWarnDomain}}}, Groups: []syncapi.ImportGroup{{Email: "sales@example.com", Name: "Sales",
		Users: []string{"ana@example.com"}, LeftOut: 2}}, SkippedCounts: map[string]int{syncapi.ImportSkipSuspended: 1},
		Skipped:  []syncapi.ImportSkip{{Kind: "user", Email: "bruno@example.com", Reason: syncapi.ImportSkipSuspended}},
		OrgUnits: []syncapi.ImportOrgUnit{{Path: "/Sales", Users: 2}}}
	helpdesk := h.session(t, "helpdesk.user", stageFull, true)
	if w := h.do("GET", "/admin/sync/import", helpdesk, nil); w.Code != http.StatusForbidden {
		t.Fatalf("helpdesk: %d", w.Code)
	}
	admin := h.session(t, "lab.admin", stageFull, true)
	w := h.do("GET", "/admin/sync/import", admin, nil)
	body := w.Body.String()
	// The fake sync's policy does not adopt and its template is
	// {sAMAccountName}@: both are warned about.
	for _, want := range []string{`data-e2e="import-form"`, `data-e2e="import-btn-read"`, `data-e2e="sync-tab-import"`,
		"policy adopt is not", "does not use {mail}", `value="OU=People,DC=lab,DC=test"`} {
		if !strings.Contains(body, want) {
			t.Errorf("form page lacks %q", want)
		}
	}
	if strings.Contains(body, `data-e2e="import-btn-build"`) {
		t.Error("the build button is shown before a read")
	}
	form := url.Values{"step": {"read"}, "org_units": {"/Sales\n/IT"}, "sub_org_units": {"1"}, "member_of": {"Staff@Example.com"},
		"groups": {"1"}, "skip_empty_groups": {"1"}, "user_ou": {usersOU}, "group_ou": {groupsOU}, "fallback": {"{given}.{family}"},
		"enabled": {"1"}, "max_users": {"100"}, "max_run": {"20"}}
	w = h.do("POST", "/admin/sync/import", admin, form)
	body = w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("read: %d", w.Code)
	}
	for _, want := range []string{`data-e2e="import-row-user-ana-example-com"`, `data-e2e="import-row-group-sales-example-com"`,
		`data-e2e="import-btn-build"`, "domain not synced", "1 users, 0 groups, 2 others left out", `data-e2e="import-text-skipped-suspended"`} {
		if !strings.Contains(body, want) {
			t.Errorf("plan page lacks %q", want)
		}
	}
	req := fs.last(syncapi.OpImportPlan)
	if req == nil || req.Actor.User != "lab.admin" {
		t.Fatalf("import.plan request %+v", req)
	}
	p, _ := req.Decode()
	ip := p.(*syncapi.ImportPlanParams)
	if strings.Join(ip.OrgUnits, ",") != "/Sales,/IT" || !ip.SubOrgUnits || ip.MemberOf[0] != "staff@example.com" || !ip.Groups ||
		!ip.SkipEmptyGroups || ip.MaxUsers != 100 || ip.IncludeAdmins || ip.IncludeSuspended {
		t.Fatalf("params %+v", ip)
	}
	evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "sync.import.read"}, 0, 10)
	if len(evs) != 1 || evs[0].Result != store.ResultOK {
		t.Fatalf("audit %+v", evs)
	}
	// Invalid choices never reach conductor-sync.
	n := fs.count(syncapi.OpImportPlan)
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("fallback", "{given} {family}")
	if w := h.do("POST", "/admin/sync/import", admin, bad); w.Code != http.StatusBadRequest || fs.count(syncapi.OpImportPlan) != n {
		t.Fatalf("bad fallback: %d", w.Code)
	}
	bad.Set("fallback", "{given}.{family}")
	bad.Set("user_ou", "OU=Elsewhere,DC=other,DC=test")
	if w := h.do("POST", "/admin/sync/import", admin, bad); w.Code != http.StatusBadRequest || fs.count(syncapi.OpImportPlan) != n {
		t.Fatalf("bad OU: %d", w.Code)
	}
	// A failed read is shown and audited.
	fs.fail[syncapi.OpImportPlan] = &syncapi.Error{Code: syncapi.CodeInvalid, Message: "a group named in the filters does not exist in Google"}
	if w := h.do("POST", "/admin/sync/import", admin, form); !strings.Contains(w.Body.String(), "does not exist in Google") {
		t.Fatalf("failed read: %s", w.Body.String())
	}
	if evs, _, _ := h.st.ListAudit(context.Background(), store.AuditFilter{Action: "sync.import.read"}, 0, 10); len(evs) != 2 || evs[0].Result != store.ResultFailed {
		t.Fatalf("audit of the failure %+v", evs)
	}
}
