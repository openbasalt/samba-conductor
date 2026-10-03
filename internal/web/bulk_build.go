package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
)

// CSV templates. The header must match exactly (same names, same order):
// a strict template catches a shifted column before anything is written.
var (
	createColumns = []string{"username", "first_name", "last_name", "display_name", "email", "description", "ou", "groups",
		"must_change_password", "enabled"}
	updateColumns = []string{"username", "display_name", "email", "description", "title", "department", "company",
		"telephone", "mobile", "office", "enabled", "ou", "add_groups", "remove_groups"}
)

// clearValue in an update cell removes the attribute; an empty cell
// leaves it unchanged.
const clearValue = "(clear)"

// maxUpload bounds a CSV upload (1,000 rows fit easily).
const maxUpload = 4 << 20

func newCSVWriter(w io.Writer) *csv.Writer { return csv.NewWriter(w) }

// parseCSV reads an upload with the exact header want and returns one map
// per data row. Errors carry the (1-based, header = 1) line number.
func parseCSV(data []byte, want []string, maxRows int) ([]map[string]string, []rowError) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // UTF-8 BOM from spreadsheets
	if !utf8.Valid(data) {
		return nil, []rowError{{Msg: "the file is not UTF-8 text"}}
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = len(want)
	r.ReuseRecord = false
	header, err := r.Read()
	if err != nil {
		return nil, []rowError{{No: 1, Msg: "header: " + csvErr(err)}}
	}
	for i := range header {
		header[i] = strings.TrimSpace(header[i])
	}
	if strings.Join(header, ",") != strings.Join(want, ",") {
		return nil, []rowError{{No: 1, Msg: "the header must be exactly: " + strings.Join(want, ",")}}
	}
	var out []map[string]string
	var errs []rowError
	line := 1
	for {
		rec, err := r.Read()
		line++
		if err == io.EOF {
			break
		}
		if err != nil {
			errs = append(errs, rowError{No: line, Msg: csvErr(err)})
			if len(errs) > 50 {
				break
			}
			continue
		}
		if len(out) >= maxRows {
			return nil, []rowError{{No: line, Msg: fmt.Sprintf("more than %d rows", maxRows)}}
		}
		row := map[string]string{"_line": fmt.Sprint(line)}
		empty := true
		for i, c := range want {
			v := strings.TrimSpace(rec[i])
			if len(v) > 1024 || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 }) {
				errs = append(errs, rowError{No: line, Msg: c + ": value too long or with control characters"})
			}
			if v != "" {
				empty = false
			}
			row[c] = v
		}
		if !empty {
			out = append(out, row)
		}
	}
	return out, errs
}

func csvErr(err error) string {
	var pe *csv.ParseError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// yesNo parses a yes/no cell ("" = def).
func yesNo(v string, def bool) (bool, bool) {
	switch strings.ToLower(v) {
	case "":
		return def, true
	case "yes", "y", "true", "1", "sim", "s":
		return true, true
	case "no", "n", "false", "0", "nao", "não":
		return false, true
	}
	return false, false
}

// ouResolver resolves an OU cell: a DN, or a path as the pickers show it
// ("Lab / People / Sales" or "Lab/People/Sales").
type ouResolver struct {
	byKey map[string]string
	base  string
}

func newOUResolver(ctx context.Context, conn *ad.Conn) (*ouResolver, error) {
	opts, err := ouOptions(ctx, conn)
	if err != nil {
		return nil, err
	}
	r := &ouResolver{byKey: map[string]string{}, base: conn.BaseDN()}
	for _, o := range opts {
		r.byKey[strings.ToLower(o.DN)] = o.DN
		r.byKey[normPath(o.Label)] = o.DN
	}
	return r, nil
}

func normPath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(parts[i]))
	}
	return strings.Join(parts, "/")
}

func (r *ouResolver) resolve(v string) (string, bool) {
	if dn, ok := r.byKey[strings.ToLower(v)]; ok {
		return dn, true
	}
	dn, ok := r.byKey[normPath(v)]
	return dn, ok
}

// groupCache resolves group names once per job.
type groupCache struct {
	conn  *ad.Conn
	ctx   context.Context
	found map[string]*ad.Group
}

func (g *groupCache) get(name string) (*ad.Group, bool) {
	key := strings.ToLower(name)
	if grp, ok := g.found[key]; ok {
		return grp, grp != nil
	}
	grp, err := g.conn.FindGroup(g.ctx, name)
	if err != nil {
		g.found[key] = nil
		return nil, false
	}
	g.found[key] = &grp
	return &grp, true
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ";") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// existingUsers looks up which usernames exist, 100 per search.
func existingUsers(ctx context.Context, conn *ad.Conn, names []string) (map[string]ad.User, error) {
	out := map[string]ad.User{}
	for i := 0; i < len(names); i += 100 {
		batch := names[i:min(i+100, len(names))]
		ors := make([]escape.Filter, len(batch))
		for j, n := range batch {
			ors[j] = escape.Eq("sAMAccountName", n)
		}
		for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: andFilters(userFilter, escape.Or(ors...)), Attributes: ad.UserAttributes}) {
			if err != nil {
				return nil, err
			}
			u := ad.UserFromEntry(e)
			out[strings.ToLower(u.SAMAccountName)] = u
		}
	}
	return out, nil
}

func lineOf(in map[string]string, i int) int {
	var n int
	if _, err := fmt.Sscan(in["_line"], &n); err == nil {
		return n
	}
	return i + 1
}

// buildImportCreate validates create rows and builds, per row, the user
// add (with a generated password) and its group memberships.
func (s *Server) buildImportCreate(ctx context.Context, rc *reqCtx, conn *ad.Conn, inputs []map[string]string) ([]*bulkRow, []rowError, bool, error) {
	ous, err := newOUResolver(ctx, conn)
	if err != nil {
		return nil, nil, false, err
	}
	groups := &groupCache{conn: conn, ctx: ctx, found: map[string]*ad.Group{}}
	var names []string
	for _, in := range inputs {
		names = append(names, in["username"])
	}
	existing, err := existingUsers(ctx, conn, names)
	if err != nil {
		return nil, nil, false, err
	}
	realm := strings.ToLower(s.backend.Realm())
	seen := map[string]bool{}
	var rows []*bulkRow
	var errs []rowError
	reauth := false
	for i, in := range inputs {
		line := lineOf(in, i)
		sam := in["username"]
		bad := func(msg string) { errs = append(errs, rowError{No: line, Label: sam, Msg: msg}) }
		if sam == "" {
			bad(rc.T("bulk.err.username"))
			continue
		}
		if seen[strings.ToLower(sam)] {
			bad(rc.T("bulk.err.duplicate"))
			continue
		}
		seen[strings.ToLower(sam)] = true
		if _, ok := existing[strings.ToLower(sam)]; ok {
			bad(rc.T("bulk.err.exists"))
			continue
		}
		parent, ok := ous.resolve(in["ou"])
		if !ok {
			bad(rc.T("bulk.err.ou", in["ou"]))
			continue
		}
		mustChange, ok1 := yesNo(in["must_change_password"], true)
		enabled, ok2 := yesNo(in["enabled"], true)
		if !ok1 || !ok2 {
			bad(rc.T("bulk.err.yes_no"))
			continue
		}
		cn := in["display_name"]
		if cn == "" {
			cn = strings.TrimSpace(in["first_name"] + " " + in["last_name"])
		}
		if cn == "" {
			cn = sam
		}
		pw := newPassword()
		op, err := ad.CreateUser(ad.NewUser{ParentDN: parent, CN: cn, SAMAccountName: sam, UserPrincipalName: sam + "@" + realm,
			GivenName: in["first_name"], Surname: in["last_name"], DisplayName: in["display_name"], Mail: in["email"],
			Description: in["description"], Password: pw, MustChangePassword: mustChange, Disabled: !enabled})
		if err != nil {
			bad(rc.T("bulk.err.invalid_user"))
			continue
		}
		userDN := op.Preview().Changes[0].DN
		ops := []*ad.Operation{op}
		failed := false
		for _, gname := range splitList(in["groups"]) {
			grp, ok := groups.get(gname)
			if !ok {
				bad(rc.T("bulk.err.group", gname))
				failed = true
				break
			}
			if s.roleSIDs.isProtectedGroup(grp.SID) {
				reauth = true
			}
			gop, err := ad.AddGroupMember(grp.DN, userDN)
			if err != nil {
				bad(err.Error())
				failed = true
				break
			}
			ops = append(ops, gop)
		}
		if failed {
			continue
		}
		in := cloneInput(in)
		rows = append(rows, &bulkRow{No: line, Label: sam, Target: userDN, Input: in, ops: ops, Preview: rowPreview(ops), password: pw})
	}
	return rows, sortedErrors(errs), reauth, nil
}

func cloneInput(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// updateField maps an update column to the UserUpdate field.
var updateFields = []struct {
	col string
	get func(ad.User) string
	set func(*ad.UserUpdate, *string)
}{
	{"display_name", func(u ad.User) string { return u.DisplayName }, func(x *ad.UserUpdate, v *string) { x.DisplayName = v }},
	{"email", func(u ad.User) string { return u.Mail }, func(x *ad.UserUpdate, v *string) { x.Mail = v }},
	{"description", func(u ad.User) string { return u.Description }, func(x *ad.UserUpdate, v *string) { x.Description = v }},
	{"title", func(u ad.User) string { return u.Title }, func(x *ad.UserUpdate, v *string) { x.Title = v }},
	{"department", func(u ad.User) string { return u.Department }, func(x *ad.UserUpdate, v *string) { x.Department = v }},
	{"company", func(u ad.User) string { return u.Company }, func(x *ad.UserUpdate, v *string) { x.Company = v }},
	{"telephone", func(u ad.User) string { return u.TelephoneNumber }, func(x *ad.UserUpdate, v *string) { x.TelephoneNumber = v }},
	{"mobile", func(u ad.User) string { return u.Mobile }, func(x *ad.UserUpdate, v *string) { x.Mobile = v }},
	{"office", func(u ad.User) string { return u.Office }, func(x *ad.UserUpdate, v *string) { x.Office = v }},
}

// buildImportUpdate validates update rows and builds per row: attribute
// replace, enable/disable, group changes, then the move (last, since it
// changes the DN).
func (s *Server) buildImportUpdate(ctx context.Context, rc *reqCtx, conn *ad.Conn, inputs []map[string]string) ([]*bulkRow, []rowError, bool, error) {
	ous, err := newOUResolver(ctx, conn)
	if err != nil {
		return nil, nil, false, err
	}
	groups := &groupCache{conn: conn, ctx: ctx, found: map[string]*ad.Group{}}
	var names []string
	for _, in := range inputs {
		names = append(names, in["username"])
	}
	existing, err := existingUsers(ctx, conn, names)
	if err != nil {
		return nil, nil, false, err
	}
	seen := map[string]bool{}
	var rows []*bulkRow
	var errs []rowError
	reauth := false
	for i, in := range inputs {
		line := lineOf(in, i)
		sam := in["username"]
		bad := func(msg string) { errs = append(errs, rowError{No: line, Label: sam, Msg: msg}) }
		u, ok := existing[strings.ToLower(sam)]
		if !ok {
			bad(rc.T("bulk.err.no_user"))
			continue
		}
		if seen[strings.ToLower(sam)] {
			bad(rc.T("bulk.err.duplicate"))
			continue
		}
		seen[strings.ToLower(sam)] = true
		protected, err := s.accountProtected(ctx, conn, u.DN, u.SID)
		if err != nil {
			return nil, nil, false, err
		}
		if protected {
			reauth = true
		}
		var ops []*ad.Operation
		var upd ad.UserUpdate
		n := 0
		for _, f := range updateFields {
			v := in[f.col]
			if v == "" {
				continue
			}
			if v == clearValue {
				v = ""
			}
			if v == f.get(u) {
				continue
			}
			val := v
			f.set(&upd, &val)
			n++
		}
		if n > 0 {
			op, err := ad.UpdateUser(u.DN, upd)
			if err != nil {
				bad(rc.T("bulk.err.invalid_user"))
				continue
			}
			ops = append(ops, op)
		}
		if in["enabled"] != "" {
			en, ok := yesNo(in["enabled"], true)
			if !ok {
				bad(rc.T("bulk.err.yes_no"))
				continue
			}
			if !en && rc.isSelf(u) {
				bad(rc.T("err.self_target"))
				continue
			}
			if op, err := ad.SetUserEnabled(u, en); err == nil {
				ops = append(ops, op)
			} else if !errors.Is(err, ad.ErrNoChange) {
				bad(err.Error())
				continue
			}
		}
		failed := false
		member := map[string]bool{}
		for _, dn := range u.MemberOf {
			member[strings.ToLower(dn)] = true
		}
		for _, gc := range []struct {
			col string
			add bool
		}{{"add_groups", true}, {"remove_groups", false}} {
			col, add := gc.col, gc.add
			for _, gname := range splitList(in[col]) {
				grp, ok := groups.get(gname)
				if !ok {
					bad(rc.T("bulk.err.group", gname))
					failed = true
					break
				}
				if member[strings.ToLower(grp.DN)] == add {
					continue // already in that state
				}
				if s.roleSIDs.isProtectedGroup(grp.SID) {
					reauth = true
				}
				var op *ad.Operation
				if add {
					op, err = ad.AddGroupMember(grp.DN, u.DN)
				} else {
					op, err = ad.RemoveGroupMember(grp.DN, u.DN)
				}
				if err != nil {
					bad(err.Error())
					failed = true
					break
				}
				ops = append(ops, op)
			}
		}
		if failed {
			continue
		}
		if in["ou"] != "" {
			parent, ok := ous.resolve(in["ou"])
			if !ok {
				bad(rc.T("bulk.err.ou", in["ou"]))
				continue
			}
			cur, _, _ := escape.ParentDN(u.DN)
			if !escape.EqualDN(cur, parent) {
				op, err := ad.MoveObject(u.DN, parent)
				if err != nil {
					bad(err.Error())
					continue
				}
				ops = append(ops, op)
			}
		}
		rows = append(rows, &bulkRow{No: line, Label: u.SAMAccountName, Target: u.DN, Input: cloneInput(in), ops: ops, Preview: rowPreview(ops)})
	}
	return rows, sortedErrors(errs), reauth, nil
}

// ---- actions on selected accounts ----

var selectedActions = []string{"enable", "disable", "unlock", "reset", "move", "group_add", "group_remove", "delete"}

// selectedPerm is the permission an action on selected accounts needs.
func selectedPerm(action string) Perm {
	switch action {
	case "enable", "disable", "unlock", "reset":
		return PermUsersHelpdesk
	}
	return PermUsersWrite
}

// buildSelected builds one row per selected account. Inputs hold the
// account's GUID and the action's parameters.
func (s *Server) buildSelected(ctx context.Context, rc *reqCtx, conn *ad.Conn, action string, inputs []map[string]string) ([]*bulkRow, []rowError, bool, error) {
	var rows []*bulkRow
	var errs []rowError
	reauth := false
	seen := map[string]bool{}
	var groupDN string
	var groupProtected bool
	var unlockHosts []string
	for i, in := range inputs {
		no := i + 1
		u, err := userByGUIDString(ctx, conn, in["guid"])
		if err != nil {
			errs = append(errs, rowError{No: no, Label: in["guid"], Msg: rc.T("bulk.err.no_user")})
			continue
		}
		bad := func(msg string) { errs = append(errs, rowError{No: no, Label: u.SAMAccountName, Msg: msg}) }
		if seen[u.GUID.String()] {
			continue
		}
		seen[u.GUID.String()] = true
		protected, err := s.accountProtected(ctx, conn, u.DN, u.SID)
		if err != nil {
			return nil, nil, false, err
		}
		if protected && !rc.roles.Admin {
			bad(rc.T("err.protected"))
			continue
		}
		if protected {
			reauth = true
		}
		var ops []*ad.Operation
		var pw string
		switch action {
		case "enable", "disable":
			if action == "disable" && rc.isSelf(u) {
				bad(rc.T("err.self_target"))
				continue
			}
			op, err := ad.SetUserEnabled(u, action == "enable")
			if err != nil && !errors.Is(err, ad.ErrNoChange) {
				bad(err.Error())
				continue
			}
			if op != nil {
				ops = append(ops, op)
			}
		case "unlock":
			// The lockout may exist on one DC only (it replicates with a
			// delay), so the row is always written on every DC.
			{
				if unlockHosts == nil {
					if unlockHosts, err = writableDCHosts(ctx, conn); err != nil {
						return nil, nil, false, err
					}
				}
				op, err := ad.UnlockUserOnDCs(u.DN, unlockHosts)
				if err != nil {
					bad(err.Error())
					continue
				}
				ops = append(ops, op)
			}
		case "reset":
			pw = newPassword()
			op, err := ad.ResetPassword(u.DN, pw, in["must_change"] != "0")
			if err != nil {
				bad(err.Error())
				continue
			}
			ops = append(ops, op)
		case "move":
			if !validParent(in["parent"], conn.BaseDN()) {
				bad(rc.T("form.invalid_parent"))
				continue
			}
			cur, _, _ := escape.ParentDN(u.DN)
			if !escape.EqualDN(cur, in["parent"]) {
				op, err := ad.MoveObject(u.DN, in["parent"])
				if err != nil {
					bad(err.Error())
					continue
				}
				ops = append(ops, op)
			}
		case "group_add", "group_remove":
			if groupDN == "" {
				grp, err := conn.FindGroup(ctx, in["group"])
				if err != nil {
					return nil, []rowError{{Msg: rc.T("user.groups.not_found")}}, false, nil
				}
				groupDN, groupProtected = grp.DN, s.roleSIDs.isProtectedGroup(grp.SID)
			}
			if groupProtected {
				reauth = true
			}
			member := false
			for _, dn := range u.MemberOf {
				if escape.EqualDN(dn, groupDN) {
					member = true
				}
			}
			if member != (action == "group_add") {
				var op *ad.Operation
				if action == "group_add" {
					op, err = ad.AddGroupMember(groupDN, u.DN)
				} else {
					op, err = ad.RemoveGroupMember(groupDN, u.DN)
				}
				if err != nil {
					bad(err.Error())
					continue
				}
				ops = append(ops, op)
			}
		case "delete":
			if rc.isSelf(u) {
				bad(rc.T("err.self_target"))
				continue
			}
			op, err := ad.DeleteObject(u.DN)
			if err != nil {
				bad(err.Error())
				continue
			}
			ops = append(ops, op)
		default:
			return nil, []rowError{{Msg: rc.T("form.invalid")}}, false, nil
		}
		rows = append(rows, &bulkRow{No: no, Label: u.SAMAccountName, Target: u.DN, Input: cloneInput(in), ops: ops,
			Preview: rowPreview(ops), password: pw})
	}
	return rows, sortedErrors(errs), reauth, nil
}

// handleSelected starts an action on the accounts selected in a list:
// first the parameters (and the typed confirmation of a delete), then the
// job with its full preview.
func (s *Server) handleSelected(rc *reqCtx) {
	action := rc.form("action")
	sel := rc.r.PostForm["sel"]
	back := rc.form("back")
	if !strings.HasPrefix(back, "/admin/") || strings.HasPrefix(back, "//") {
		back = "/admin/users"
	}
	if !contains(selectedActions, action) {
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	if len(sel) == 0 {
		rc.flashErr("sel.err.none")
		rc.redirect(back)
		return
	}
	if !rc.roles.Has(selectedPerm(action)) {
		s.audit(rc.ctx(), rc, "access.denied", "selected-"+action, "requires "+string(selectedPerm(action)), "denied")
		rc.errorPage(http.StatusForbidden, "err.forbidden")
		return
	}
	params := map[string]string{"parent": rc.form("parent"), "group": rc.form("group"), "must_change": rc.form("must_change")}
	ready := rc.form("step") == "go"
	switch action {
	case "move":
		ready = ready && params["parent"] != ""
	case "group_add", "group_remove":
		ready = ready && params["group"] != ""
	case "delete":
		ready = ready && rc.form("confirm") == itoa(len(sel))
	case "reset":
		if params["must_change"] == "" {
			params["must_change"] = "0"
		}
	}
	if !ready {
		rc.view(func(ctx context.Context, conn *ad.Conn) error {
			var opts []ouOption
			if action == "move" {
				var err error
				if opts, err = ouOptions(ctx, conn); err != nil {
					return err
				}
			}
			var names []string
			for _, g := range sel {
				if u, err := userByGUIDString(ctx, conn, g); err == nil {
					names = append(names, u.SAMAccountName)
				}
			}
			d := map[string]any{"Action": action, "Sel": sel, "Names": names, "Back": back, "OUs": opts, "Count": len(sel)}
			if rc.form("step") == "go" {
				d["Error"] = rc.T("sel.err.params")
			}
			rc.render(http.StatusOK, "selected", d)
			return nil
		})
		return
	}
	inputs := make([]map[string]string, 0, len(sel))
	for _, g := range sel {
		in := map[string]string{"guid": g}
		for k, v := range params {
			if v != "" {
				in[k] = v
			}
		}
		inputs = append(inputs, in)
	}
	s.createJob(rc, "selected-"+action, rc.T("sel.action."+action), inputs, func(errs []rowError) {
		rc.render(http.StatusBadRequest, "bulk_errors", map[string]any{"Errors": errs, "Back": back})
	})
}

// handleBulkUpload reads a CSV upload and makes a job of it.
func (s *Server) handleBulkUpload(rc *reqCtx) {
	kind := rc.form("kind")
	var cols []string
	switch kind {
	case "import-create":
		cols = createColumns
	case "import-update":
		cols = updateColumns
	default:
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	f, _, err := rc.r.FormFile("file")
	if err != nil {
		rc.flashErr("bulk.err.file")
		rc.redirect("/admin/bulk")
		return
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxUpload+1))
	if err != nil || len(data) > maxUpload {
		rc.flashErr("bulk.err.file")
		rc.redirect("/admin/bulk")
		return
	}
	fail := func(errs []rowError) {
		s.audit(rc.ctx(), rc, "bulk.rejected", kind, fmt.Sprintf("%d invalid rows", len(errs)), "failed")
		rc.render(http.StatusBadRequest, "bulk_errors", map[string]any{"Errors": errs, "Back": "/admin/bulk"})
	}
	inputs, errs := parseCSV(data, cols, s.cfg.Bulk.MaxRows)
	if len(errs) > 0 {
		fail(errs)
		return
	}
	s.createJob(rc, kind, rc.T("bulk.kind."+kind), inputs, fail)
}

// handleBulkTemplate serves the CSV header of an import kind.
func (s *Server) handleBulkTemplate(rc *reqCtx) {
	var cols []string
	switch rc.r.PathValue("kind") {
	case "create.csv":
		cols = createColumns
	case "update.csv":
		cols = updateColumns
	default:
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	rc.w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	rc.w.Header().Set("Content-Disposition", `attachment; filename="conductor-`+rc.r.PathValue("kind")+`"`)
	_, _ = io.WriteString(rc.w, strings.Join(cols, ",")+"\r\n")
}
