package web

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
)

// Import from Google Workspace: the AD side. conductor-sync reads the
// Google directory (read-only) and returns an import plan; conductor turns
// it into a bulk job of kind importKind whose rows create the AD users and
// groups with the administrator's own credentials, after a full preview,
// re-authentication and a per-row audit, like a CSV import.
//
// Rules (docs/import-from-google.md):
//   - mail of a new user or group = the Google primary address, so the sync
//     later adopts the Google account by address (policy.adopt = "email");
//   - an AD account or group that already has the address is never changed
//     (a group only receives the missing members of the plan), so running
//     the import again creates only what is missing;
//   - users get a random password nobody knows (never shown, never stored)
//     and must change it at next logon; the administrator sets the initial
//     password when onboarding each person (Reset password);
//   - nothing is ever deleted, and nothing is sent to Google.

// importKind is the bulk job kind of an import from Google ("import-" makes
// the apply require re-authentication, as for CSV imports).
const importKind = "import-google"

// Row types of an import job (the "type" input).
const (
	importUser  = "user"
	importGroup = "group"
	// importNest adds imported groups as members of imported groups, after
	// every group exists.
	importNest = "nest"
)

// defaultFallback renders a logon name when the address's local part
// cannot be one (too long, invalid characters) or is taken.
const defaultFallback = "{given}.{family}"

// maxUserSAM and maxGroupSAM bound sAMAccountName (users: the pre-Windows
// 2000 limit of 20 characters; groups as the ad library allows).
const (
	maxUserSAM  = 20
	maxGroupSAM = 64
	maxCN       = 64
)

// importOptions are the AD choices of an import (the same on every row).
type importOptions struct {
	UserOU   string
	GroupOU  string
	Enabled  bool
	Fallback string
	Max      int
}

func (o importOptions) put(in map[string]string) {
	in["opt_user_ou"], in["opt_group_ou"], in["opt_fallback"], in["opt_max"] = o.UserOU, o.GroupOU, o.Fallback, strconv.Itoa(o.Max)
	in["opt_enabled"] = "0"
	if o.Enabled {
		in["opt_enabled"] = "1"
	}
}

func importOptionsOf(in map[string]string) importOptions {
	max, _ := strconv.Atoi(in["opt_max"])
	return importOptions{UserOU: in["opt_user_ou"], GroupOU: in["opt_group_ou"], Enabled: in["opt_enabled"] == "1",
		Fallback: in["opt_fallback"], Max: max}
}

// validFallback checks a logon name template: at least one placeholder,
// only known placeholders, and only characters a logon name may hold.
func validFallback(tmpl string) bool {
	if tmpl == "" || len(tmpl) > 64 {
		return false
	}
	rest := tmpl
	placeholders := 0
	for _, p := range []string{"{given}", "{family}", "{g}", "{f}", "{local}"} {
		placeholders += strings.Count(rest, p)
		rest = strings.ReplaceAll(rest, p, "")
	}
	if placeholders == 0 {
		return false
	}
	for _, r := range rest {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// foldTable maps the accented Latin letters names commonly carry to ASCII.
var foldTable = map[rune]string{
	'à': "a", 'á': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a", 'ā': "a", 'ă': "a", 'ą': "a",
	'ç': "c", 'ć': "c", 'č': "c", 'ď': "d", 'đ': "d",
	'è': "e", 'é': "e", 'ê': "e", 'ë': "e", 'ē': "e", 'ė': "e", 'ę': "e", 'ě': "e",
	'ì': "i", 'í': "i", 'î': "i", 'ï': "i", 'ī': "i", 'į': "i", 'ı': "i",
	'ñ': "n", 'ń': "n", 'ň': "n", 'ł': "l", 'ľ': "l",
	'ò': "o", 'ó': "o", 'ô': "o", 'õ': "o", 'ö': "o", 'ø': "o", 'ō': "o", 'ő': "o",
	'ř': "r", 'ś': "s", 'š': "s", 'ş': "s", 'ť': "t", 'ţ': "t",
	'ù': "u", 'ú': "u", 'û': "u", 'ü': "u", 'ū': "u", 'ů': "u", 'ű': "u", 'ų': "u",
	'ý': "y", 'ÿ': "y", 'ź': "z", 'ż': "z", 'ž': "z",
	'ß': "ss", 'æ': "ae", 'œ': "oe", 'þ': "th", 'ð': "d",
}

// logonName folds text into a logon name: lower-case ASCII letters,
// digits, '.', '-' and '_'; other characters are dropped (spaces become
// nothing), repeated dots collapse, leading and trailing dots and hyphens
// go, and the result is cut to max characters.
func logonName(s string, max int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			if f, ok := foldTable[r]; ok {
				b.WriteString(f)
			}
		}
	}
	out := b.String()
	for strings.Contains(out, "..") {
		out = strings.ReplaceAll(out, "..", ".")
	}
	out = strings.Trim(out, ".-")
	if len(out) > max {
		out = strings.TrimRight(out[:max], ".-")
	}
	return out
}

// validLogon reports whether s may be used as is as a sAMAccountName
// (the ad library's rules, plus no spaces in derived names).
func validLogon(s string, max int) bool {
	if s == "" || utf8.RuneCountInString(s) > max || strings.HasSuffix(s, ".") {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool {
		return r < 0x21 || r == 0x7f || strings.ContainsRune(`"/\[]:;|=,+*?<>@`, r) || unicode.IsSpace(r)
	})
}

func localPart(email string) string {
	if i := strings.LastIndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

func firstLetter(s string) string {
	for _, r := range logonName(s, 64) {
		return string(r)
	}
	return ""
}

// renderFallback renders the fallback template for a user.
func renderFallback(tmpl, given, family, email string) string {
	r := strings.NewReplacer("{given}", logonName(given, 64), "{family}", logonName(lastWord(family), 64),
		"{g}", firstLetter(given), "{f}", firstLetter(lastWord(family)), "{local}", logonName(localPart(email), 64))
	return logonName(r.Replace(tmpl), maxUserSAM)
}

// lastWord is the last word of a family name ("da Silva" -> "Silva").
func lastWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

// userSAMCandidates are the logon names tried for a user, in order: the
// local part of the address when it is a valid logon name as is (lower
// case), then the fallback.
func userSAMCandidates(fallback, given, family, email string) []string {
	var out []string
	if lp := strings.ToLower(localPart(email)); validLogon(lp, maxUserSAM) {
		out = append(out, lp)
	}
	if fb := renderFallback(fallback, given, family, email); validLogon(fb, maxUserSAM) && !contains(out, fb) {
		out = append(out, fb)
	}
	return out
}

// groupSAMCandidates: the local part of the group address, then the name.
func groupSAMCandidates(email, name string) []string {
	var out []string
	if lp := strings.ToLower(localPart(email)); validLogon(lp, maxGroupSAM) {
		out = append(out, lp)
	}
	if n := logonName(name, maxGroupSAM); validLogon(n, maxGroupSAM) && !contains(out, n) {
		out = append(out, n)
	}
	return out
}

// cutRunes cuts s to n characters.
func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return strings.TrimSpace(string([]rune(s)[:n]))
}

// importUserIn and importGroupIn are the decoded inputs of the rows.
type importUserIn struct {
	in                                                                          map[string]string
	Email, Given, Family, Title, Department, EmployeeID, PhoneWork, PhoneMobile string
	Suspended                                                                   bool
}

type importGroupIn struct {
	in                       map[string]string
	Email, Name, Description string
	Users, Groups            []string
}

// adRef is an existing AD object found by address.
type adRef struct {
	DN, SAM string
	// Several: more than one AD object has the address.
	Several bool
	// Protected: a privileged group (never changed by an import).
	Protected bool
	// Members of a group (normalized DNs).
	Members map[string]bool
}

// importLookup is what AD already holds, read before the rows are built.
type importLookup struct {
	Realm          string
	UsersByMail    map[string]*adRef
	GroupsByMail   map[string]*adRef
	SAMTaken       map[string]bool // lower-case sAMAccountName of any object
	CNTaken        map[string]bool // cnKey(parent, cn)
	UserOUMissing  bool
	GroupOUMissing bool
}

func cnKey(parent, cn string) string { return escape.NormalizeDN(parent) + "|" + strings.ToLower(cn) }

// importPlanRows decides every row of an import job from the inputs and
// what AD holds. Conflicts and limits are rows without operations, with a
// note saying why (they are reported, never stop the job); only unusable
// options (an OU that does not exist) are errors. newPassword makes the
// random password of each new user (nobody ever sees it).
func importPlanRows(t func(string, ...any) string, opt importOptions, users []importUserIn, groups []importGroupIn, look *importLookup,
	newPassword func() string) ([]*bulkRow, []rowError) {
	if look.UserOUMissing && len(users) > 0 {
		return nil, []rowError{{Msg: t("import.err.user_ou", opt.UserOU)}}
	}
	if look.GroupOUMissing && len(groups) > 0 {
		return nil, []rowError{{Msg: t("import.err.group_ou", opt.GroupOU)}}
	}
	var rows []*bulkRow
	created := 0
	taken := map[string]bool{}
	for k := range look.SAMTaken {
		taken[k] = true
	}
	cnUsed := map[string]bool{}
	for k := range look.CNTaken {
		cnUsed[k] = true
	}
	// Address -> DN of the AD objects the plan's memberships may use:
	// existing (found by address) or created in this job.
	userDN, groupDN := map[string]string{}, map[string]string{}
	add := func(r *bulkRow) {
		r.No = len(rows) + 1
		rows = append(rows, r)
	}
	pickCN := func(parent, cn, sam string) (string, bool) {
		cn = cutRunes(strings.TrimSpace(cn), maxCN)
		if cn == "" {
			cn = sam
		}
		if !cnUsed[cnKey(parent, cn)] {
			return cn, true
		}
		suffix := " (" + sam + ")"
		alt := cutRunes(cn, maxCN-utf8.RuneCountInString(suffix)) + suffix
		return alt, !cnUsed[cnKey(parent, alt)]
	}
	pickSAM := func(cands []string) string {
		for _, c := range cands {
			if !taken[strings.ToLower(c)] {
				return c
			}
		}
		return ""
	}
	seenUser := map[string]bool{}
	for _, u := range users {
		if seenUser[u.Email] {
			continue
		}
		seenUser[u.Email] = true
		row := &bulkRow{Label: u.Email, Input: cloneInput(u.in)}
		if ex := look.UsersByMail[u.Email]; ex != nil {
			if ex.Several {
				row.Note = t("import.note.several", u.Email)
			} else {
				row.Note, row.Target = t("import.note.user_exists", ex.SAM), ex.DN
				userDN[u.Email] = ex.DN
			}
			add(row)
			continue
		}
		cands := userSAMCandidates(opt.Fallback, u.Given, u.Family, u.Email)
		sam := pickSAM(cands)
		if sam == "" {
			row.Note = t("import.note.no_logon", strings.Join(cands, ", "))
			add(row)
			continue
		}
		display := strings.TrimSpace(u.Given + " " + u.Family)
		cn, ok := pickCN(opt.UserOU, display, sam)
		if !ok {
			row.Note = t("import.note.cn_taken", cn)
			add(row)
			continue
		}
		if opt.Max > 0 && created >= opt.Max {
			row.Note = t("import.note.limit", opt.Max)
			add(row)
			continue
		}
		op, err := ad.CreateUser(ad.NewUser{ParentDN: opt.UserOU, CN: cn, SAMAccountName: sam, UserPrincipalName: sam + "@" + look.Realm,
			GivenName: cutRunes(u.Given, 64), Surname: cutRunes(u.Family, 64), DisplayName: cutRunes(display, 256), Mail: u.Email,
			Title: cutRunes(u.Title, 128), Department: cutRunes(u.Department, 64), TelephoneNumber: cutRunes(u.PhoneWork, 64),
			Mobile: cutRunes(u.PhoneMobile, 64), EmployeeID: cutRunes(u.EmployeeID, 16), Password: newPassword(),
			MustChangePassword: true, Disabled: !opt.Enabled || u.Suspended})
		if err != nil {
			row.Note = t("import.note.invalid", err.Error())
			add(row)
			continue
		}
		created++
		taken[strings.ToLower(sam)] = true
		cnUsed[cnKey(opt.UserOU, cn)] = true
		row.ops = []*ad.Operation{op}
		row.Target = op.Preview().Changes[0].DN
		row.Preview = rowPreview(row.ops)
		userDN[u.Email] = row.Target
		add(row)
	}

	// Groups: create (or complete) each one with its user members.
	seenGroup := map[string]bool{}
	var nests []importGroupIn
	for _, g := range groups {
		if seenGroup[g.Email] {
			continue
		}
		seenGroup[g.Email] = true
		row := &bulkRow{Label: g.Email, Input: cloneInput(g.in)}
		var ops []*ad.Operation
		var members map[string]bool
		dn := ""
		if ex := look.GroupsByMail[g.Email]; ex != nil {
			switch {
			case ex.Several:
				row.Note = t("import.note.several", g.Email)
			case ex.Protected:
				row.Note, row.Target = t("import.note.group_protected", ex.SAM), ex.DN
			default:
				dn, members, row.Target = ex.DN, ex.Members, ex.DN
				groupDN[g.Email] = ex.DN
			}
			if dn == "" {
				add(row)
				continue
			}
		} else {
			sam := pickSAM(groupSAMCandidates(g.Email, g.Name))
			if sam == "" {
				row.Note = t("import.note.no_logon", strings.Join(groupSAMCandidates(g.Email, g.Name), ", "))
				add(row)
				continue
			}
			name := g.Name
			if strings.TrimSpace(name) == "" {
				name = localPart(g.Email)
			}
			cn, ok := pickCN(opt.GroupOU, name, sam)
			if !ok {
				row.Note = t("import.note.cn_taken", cn)
				add(row)
				continue
			}
			if opt.Max > 0 && created >= opt.Max {
				row.Note = t("import.note.limit", opt.Max)
				add(row)
				continue
			}
			op, err := ad.CreateGroup(ad.NewGroup{ParentDN: opt.GroupOU, Name: cn, SAMAccountName: sam,
				Description: cutRunes(g.Description, 1024), Mail: g.Email})
			if err != nil {
				row.Note = t("import.note.invalid", err.Error())
				add(row)
				continue
			}
			created++
			taken[strings.ToLower(sam)] = true
			cnUsed[cnKey(opt.GroupOU, cn)] = true
			dn = op.Preview().Changes[0].DN
			ops = append(ops, op)
			row.Target = dn
			groupDN[g.Email] = dn
		}
		for _, m := range g.Users {
			mdn, ok := userDN[m]
			if !ok || members[escape.NormalizeDN(mdn)] {
				continue
			}
			op, err := ad.AddGroupMember(dn, mdn)
			if err == nil {
				ops = append(ops, op)
			}
		}
		if len(ops) == 0 {
			row.Note = t("import.note.group_complete", look.GroupsByMail[g.Email].SAM)
		}
		row.ops, row.Preview = ops, rowPreview(ops)
		add(row)
		if len(g.Groups) > 0 {
			nests = append(nests, g)
		}
	}
	// Nested groups, once every group of the job exists.
	for _, g := range nests {
		parent, ok := groupDN[g.Email]
		if !ok {
			continue
		}
		var members map[string]bool
		if ex := look.GroupsByMail[g.Email]; ex != nil {
			members = ex.Members
		}
		var ops []*ad.Operation
		for _, child := range g.Groups {
			cdn, ok := groupDN[child]
			if !ok || members[escape.NormalizeDN(cdn)] || escape.EqualDN(cdn, parent) {
				continue
			}
			if op, err := ad.AddGroupMember(parent, cdn); err == nil {
				ops = append(ops, op)
			}
		}
		if len(ops) == 0 {
			continue
		}
		in := cloneInput(g.in)
		in["type"] = importNest
		add(&bulkRow{Label: t("import.label.nested", g.Email), Target: parent, Input: in, ops: ops, Preview: rowPreview(ops)})
	}
	return rows, nil
}

// decodeImportInputs splits the inputs of an import job into users and
// groups (a nested-groups row is its group again: the group row of a retry
// only adds what is missing).
func decodeImportInputs(inputs []map[string]string) (importOptions, []importUserIn, []importGroupIn, error) {
	if len(inputs) == 0 {
		return importOptions{}, nil, nil, errors.New("no rows")
	}
	opt := importOptionsOf(inputs[0])
	var users []importUserIn
	var groups []importGroupIn
	for _, in := range inputs {
		if importOptionsOf(in) != opt {
			return opt, nil, nil, errors.New("rows with different options")
		}
		email := strings.ToLower(strings.TrimSpace(in["email"]))
		if email == "" || !strings.Contains(email, "@") {
			return opt, nil, nil, fmt.Errorf("a row without an address")
		}
		switch in["type"] {
		case importUser:
			users = append(users, importUserIn{in: in, Email: email, Given: in["given"], Family: in["family"], Title: in["title"],
				Department: in["department"], EmployeeID: in["employee_id"], PhoneWork: in["phone_work"], PhoneMobile: in["phone_mobile"],
				Suspended: in["suspended"] == "1"})
		case importGroup, importNest:
			groups = append(groups, importGroupIn{in: in, Email: email, Name: in["name"], Description: in["description"],
				Users: splitList(strings.ToLower(in["users"])), Groups: splitList(strings.ToLower(in["groups"]))})
		default:
			return opt, nil, nil, fmt.Errorf("unknown row type %q", in["type"])
		}
	}
	return opt, users, groups, nil
}

// buildImportGoogle is the job builder of importKind (first preview and
// retries alike).
func (s *Server) buildImportGoogle(ctx context.Context, rc *reqCtx, conn *ad.Conn, inputs []map[string]string) ([]*bulkRow, []rowError, bool, error) {
	opt, users, groups, err := decodeImportInputs(inputs)
	if err != nil {
		return nil, []rowError{{Msg: rc.T("form.invalid") + " " + err.Error()}}, false, nil
	}
	if (len(users) > 0 && !validParent(opt.UserOU, conn.BaseDN())) || (len(groups) > 0 && !validParent(opt.GroupOU, conn.BaseDN())) ||
		!validFallback(opt.Fallback) {
		return nil, []rowError{{Msg: rc.T("form.invalid_parent")}}, false, nil
	}
	look, err := s.importLookup(ctx, conn, opt, users, groups)
	if err != nil {
		return nil, nil, false, err
	}
	rows, errs := importPlanRows(rc.T, opt, users, groups, look, func() string { return newPasswordLen(32) })
	return rows, errs, true, nil
}

// importLookup reads what the rows depend on: whether the OUs exist, the
// AD users and groups that already have the addresses, the logon names
// and the names (CN) in the target OUs already in use.
func (s *Server) importLookup(ctx context.Context, conn *ad.Conn, opt importOptions, users []importUserIn, groups []importGroupIn) (*importLookup, error) {
	look := &importLookup{Realm: strings.ToLower(s.backend.Realm()), UsersByMail: map[string]*adRef{}, GroupsByMail: map[string]*adRef{},
		SAMTaken: map[string]bool{}, CNTaken: map[string]bool{}}
	exists := func(dn string) (bool, error) {
		_, err := conn.Get(ctx, dn, "objectClass")
		if errors.Is(err, ad.ErrNotFound) {
			return false, nil
		}
		return err == nil, err
	}
	var err error
	if len(users) > 0 {
		ok, err := exists(opt.UserOU)
		if err != nil {
			return nil, err
		}
		look.UserOUMissing = !ok
	}
	if len(groups) > 0 {
		ok, err := exists(opt.GroupOU)
		if err != nil {
			return nil, err
		}
		look.GroupOUMissing = !ok
	}
	var userMails, groupMails, sams []string
	var userCNs, groupCNs []string
	// Every name a row may pick: the plain name, its "(logon)" variants
	// and the logon names themselves (used when there is no name).
	cnVariants := func(name string, cands []string) []string {
		name = cutRunes(strings.TrimSpace(name), maxCN)
		out := append([]string{name}, cands...)
		for _, c := range cands {
			base := name
			if base == "" {
				base = c
			}
			suffix := " (" + c + ")"
			out = append(out, cutRunes(base, maxCN-utf8.RuneCountInString(suffix))+suffix)
		}
		return out
	}
	for _, u := range users {
		userMails = append(userMails, u.Email)
		cands := userSAMCandidates(opt.Fallback, u.Given, u.Family, u.Email)
		sams = append(sams, cands...)
		userCNs = append(userCNs, cnVariants(u.Given+" "+u.Family, cands)...)
	}
	for _, g := range groups {
		groupMails = append(groupMails, g.Email)
		cands := groupSAMCandidates(g.Email, g.Name)
		sams = append(sams, cands...)
		name := g.Name
		if strings.TrimSpace(name) == "" {
			name = localPart(g.Email)
		}
		groupCNs = append(groupCNs, cnVariants(name, cands)...)
	}
	if look.UsersByMail, err = s.objectsByMail(ctx, conn, userFilter, userMails, false); err != nil {
		return nil, err
	}
	if look.GroupsByMail, err = s.objectsByMail(ctx, conn, groupFilter, groupMails, true); err != nil {
		return nil, err
	}
	if look.SAMTaken, err = takenSAMs(ctx, conn, sams); err != nil {
		return nil, err
	}
	for _, x := range []struct {
		parent string
		names  []string
	}{{opt.UserOU, userCNs}, {opt.GroupOU, groupCNs}} {
		if x.parent == "" || len(x.names) == 0 {
			continue
		}
		if err := takenCNs(ctx, conn, x.parent, x.names, look.CNTaken); err != nil {
			return nil, err
		}
	}
	return look, nil
}

// batches calls fn with up to 100 distinct values at a time.
func batches(values []string, fn func([]string) error) error {
	seen := map[string]bool{}
	var uniq []string
	for _, v := range values {
		if k := strings.ToLower(v); v != "" && !seen[k] {
			seen[k] = true
			uniq = append(uniq, v)
		}
	}
	sort.Strings(uniq)
	for i := 0; i < len(uniq); i += 100 {
		if err := fn(uniq[i:min(i+100, len(uniq))]); err != nil {
			return err
		}
	}
	return nil
}

// objectsByMail finds users or groups by address: mail, userPrincipalName
// and the SMTP entries of proxyAddresses. For groups it also reads the
// members and whether the group is privileged.
func (s *Server) objectsByMail(ctx context.Context, conn *ad.Conn, class escape.Filter, mails []string, group bool) (map[string]*adRef, error) {
	out := map[string]*adRef{}
	err := batches(mails, func(batch []string) error {
		var ors []escape.Filter
		for _, m := range batch {
			ors = append(ors, escape.Eq("mail", m), escape.Eq("userPrincipalName", m), escape.Eq("proxyAddresses", "smtp:"+m))
		}
		want := map[string]bool{}
		for _, m := range batch {
			want[strings.ToLower(m)] = true
		}
		for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: escape.And(class, escape.Or(ors...)),
			Attributes: []string{"distinguishedName", "sAMAccountName", "mail", "userPrincipalName", "proxyAddresses", "objectSid"}}) {
			if err != nil {
				return err
			}
			addrs := map[string]bool{strings.ToLower(e.GetAttributeValue("mail")): true, strings.ToLower(e.GetAttributeValue("userPrincipalName")): true}
			for _, p := range e.GetAttributeValues("proxyAddresses") {
				if lp := strings.ToLower(p); strings.HasPrefix(lp, "smtp:") {
					addrs[strings.TrimPrefix(lp, "smtp:")] = true
				}
			}
			for a := range addrs {
				if !want[a] {
					continue
				}
				if prev := out[a]; prev != nil && !escape.EqualDN(prev.DN, e.DN) {
					prev.Several = true
					continue
				}
				ref := &adRef{DN: e.DN, SAM: e.GetAttributeValue("sAMAccountName")}
				if group {
					g := ad.GroupFromEntry(e)
					ref.Protected = s.roleSIDs.isProtectedGroup(g.SID)
				}
				out[a] = ref
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if group {
		for _, ref := range out {
			if ref.Several || ref.Protected {
				continue
			}
			members, err := conn.GroupMembers(ctx, ref.DN)
			if err != nil {
				return nil, err
			}
			ref.Members = map[string]bool{}
			for _, m := range members {
				ref.Members[escape.NormalizeDN(m)] = true
			}
		}
	}
	return out, nil
}

// takenSAMs returns which of the names are a sAMAccountName of any object
// (users, groups and computers share the namespace).
func takenSAMs(ctx context.Context, conn *ad.Conn, names []string) (map[string]bool, error) {
	out := map[string]bool{}
	err := batches(names, func(batch []string) error {
		ors := make([]escape.Filter, len(batch))
		for i, n := range batch {
			ors[i] = escape.Eq("sAMAccountName", n)
		}
		for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: escape.Or(ors...), Attributes: []string{"sAMAccountName"}}) {
			if err != nil {
				return err
			}
			out[strings.ToLower(e.GetAttributeValue("sAMAccountName"))] = true
		}
		return nil
	})
	return out, err
}

// takenCNs marks which of the names already exist directly below parent.
func takenCNs(ctx context.Context, conn *ad.Conn, parent string, names []string, out map[string]bool) error {
	return batches(names, func(batch []string) error {
		ors := make([]escape.Filter, len(batch))
		for i, n := range batch {
			ors[i] = escape.Eq("cn", n)
		}
		for e, err := range conn.Search(ctx, ad.SearchRequest{BaseDN: parent, Scope: ad.ScopeOneLevel, Filter: escape.Or(ors...),
			Attributes: []string{"cn"}}) {
			if err != nil {
				return err
			}
			out[cnKey(parent, e.GetAttributeValue("cn"))] = true
		}
		return nil
	})
}
