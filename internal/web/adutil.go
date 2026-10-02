package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/escape"
	"github.com/samba-conductor/ad/sid"
	"github.com/samba-conductor/conductor/internal/directory"
)

// Object class filters (the ad package keeps its own unexported).
var (
	userFilter     = escape.And(escape.Eq("objectCategory", "person"), escape.Eq("objectClass", "user"))
	groupFilter    = escape.Eq("objectClass", "group")
	ouFilter       = escape.Eq("objectClass", "organizationalUnit")
	computerFilter = escape.Eq("objectClass", "computer")
)

// pageSize of server-side paginated lists.
const pageSize = 50

// withConn runs fn on a connection bound as the signed-in user.
func (rc *reqCtx) withConn(ctx context.Context, fn func(*ad.Conn) error) error {
	rc.sess.mu.Lock()
	cred := rc.sess.cred
	rc.sess.mu.Unlock()
	if cred == nil {
		return directory.ErrCredentialClosed
	}
	conn, err := rc.s.backend.Connect(ctx, cred)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return fn(conn)
}

// view runs a read-only page body with a connection and a request timeout;
// errors become a friendly page (or the sign-in page when the ticket is gone).
func (rc *reqCtx) view(fn func(ctx context.Context, conn *ad.Conn) error) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	err := rc.withConn(ctx, func(conn *ad.Conn) error { return fn(ctx, conn) })
	if err == nil {
		return
	}
	rc.failed(err)
}

// failed renders the error of a request that could not complete.
func (rc *reqCtx) failed(err error) {
	if errors.Is(err, directory.ErrCredentialClosed) || errors.Is(err, ad.ErrSessionClosed) {
		rc.s.sess.destroy(rc.ctx(), rc.sess)
		clearCookie(rc.w, sessionCookie)
		rc.redirectSignin("expired")
		return
	}
	if errors.Is(err, errNotFoundPage) || errors.Is(err, ad.ErrNotFound) {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	key := rc.s.adErrorKey(err)
	rc.s.log.Warn("request failed", "path", rc.r.URL.Path, "user", rc.sess.sam, "err", err)
	status := http.StatusBadGateway
	if key == "err.ad.access_denied" || key == "err.protected" {
		status = http.StatusForbidden
	}
	rc.errorPage(status, key)
}

var errNotFoundPage = errors.New("web: not found")

func isNotAllowedOnNonLeaf(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultNotAllowedOnNonLeaf)
}

// guidParam parses the {guid} path value.
func (rc *reqCtx) guidParam() (sid.GUID, error) {
	g, err := sid.ParseGUID(rc.r.PathValue("guid"))
	if err != nil {
		return g, errNotFoundPage
	}
	return g, nil
}

func byGUID(g sid.GUID) escape.Filter { return escape.EqBytes("objectGUID", g.Bytes()) }

func userByGUID(ctx context.Context, conn *ad.Conn, g sid.GUID) (ad.User, error) {
	for u, err := range conn.Users(ctx, "", byGUID(g)) {
		return u, err
	}
	return ad.User{}, errNotFoundPage
}

func groupByGUID(ctx context.Context, conn *ad.Conn, g sid.GUID) (ad.Group, error) {
	for x, err := range conn.Groups(ctx, "", byGUID(g)) {
		return x, err
	}
	return ad.Group{}, errNotFoundPage
}

func ouByGUID(ctx context.Context, conn *ad.Conn, g sid.GUID) (ad.OU, error) {
	for x, err := range conn.OUs(ctx, "", byGUID(g)) {
		return x, err
	}
	return ad.OU{}, errNotFoundPage
}

func computerByGUID(ctx context.Context, conn *ad.Conn, g sid.GUID) (ad.Computer, error) {
	for x, err := range conn.Computers(ctx, "", byGUID(g)) {
		return x, err
	}
	return ad.Computer{}, errNotFoundPage
}

// ouOption is one entry of an OU picker.
type ouOption struct {
	DN    string
	Label string // path from the domain root, e.g. "Lab / People / Sales"
}

// maxOUOptions bounds the picker; larger domains type the DN instead.
const maxOUOptions = 2000

// ouOptions lists OUs (and the default Users/Computers containers) for
// pickers, ordered by path.
func ouOptions(ctx context.Context, conn *ad.Conn) ([]ouOption, error) {
	base := conn.BaseDN()
	opts := []ouOption{{DN: "CN=Users," + base, Label: "Users"}, {DN: "CN=Computers," + base, Label: "Computers"}}
	n := 0
	for o, err := range conn.OUs(ctx, "", nil) {
		if err != nil {
			return nil, err
		}
		n++
		if n > maxOUOptions {
			break
		}
		opts = append(opts, ouOption{DN: o.DN, Label: ouPath(o.DN, base)})
	}
	sort.Slice(opts, func(i, j int) bool { return strings.ToLower(opts[i].Label) < strings.ToLower(opts[j].Label) })
	return opts, nil
}

// ouPath renders a DN below base as "A / B / C" from the top.
func ouPath(dn, base string) string {
	var parts []string
	cur := dn
	for cur != "" && !escape.EqualDN(cur, base) {
		parent, v, err := escape.ParentDN(cur)
		if err != nil {
			break
		}
		parts = append([]string{v}, parts...)
		cur = parent
	}
	return strings.Join(parts, " / ")
}

// validParent checks that a DN chosen in a picker is a container below the
// domain (the DC still enforces rights).
func validParent(dn, base string) bool {
	if _, err := escape.ParseDN(dn); err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(dn), ","+strings.ToLower(base)) || escape.EqualDN(dn, base)
}

// accountProtected reports whether an account (user or computer) belongs to
// a privileged group, directly, nested or by primary group.
func (s *Server) accountProtected(ctx context.Context, conn *ad.Conn, dn string, account sid.SID) (bool, error) {
	groups, err := directory.GroupSIDs(ctx, conn, dn)
	if err != nil {
		return true, err
	}
	return s.roleSIDs.isProtectedMember(account, groups), nil
}

// pageParam reads ?page= (1-based).
func (rc *reqCtx) pageParam() int {
	p, _ := strconv.Atoi(rc.r.URL.Query().Get("page"))
	if p < 1 || p > 10000 {
		return 1
	}
	return p
}

// searchFilter builds the text search over the usual naming attributes.
func searchFilter(q string, attrs ...string) escape.Filter {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil
	}
	parts := make([]escape.Filter, len(attrs))
	for i, a := range attrs {
		parts[i] = escape.Prefix(a, q)
	}
	return escape.Or(parts...)
}

func andFilters(fs ...escape.Filter) escape.Filter {
	var out []escape.Filter
	for _, f := range fs {
		if f != nil {
			out = append(out, f)
		}
	}
	if len(out) == 1 {
		return out[0]
	}
	return escape.And(out...)
}

// memberRef is a group member for display.
type memberRef struct {
	DN   string
	Name string
	Kind string // user, group, computer, other
	GUID string
}

// describeMembers resolves member DNs to names and kinds with one search
// per batch (OR of distinguishedName equality).
func describeMembers(ctx context.Context, conn *ad.Conn, dns []string) ([]memberRef, error) {
	out := make([]memberRef, 0, len(dns))
	byDN := map[string]memberRef{}
	for i := 0; i < len(dns); i += 100 {
		batch := dns[i:min(i+100, len(dns))]
		ors := make([]escape.Filter, len(batch))
		for j, dn := range batch {
			ors[j] = escape.Eq("distinguishedName", dn)
		}
		for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: escape.Or(ors...),
			Attributes: []string{"objectClass", "objectGUID", "cn", "sAMAccountName", "displayName"}}) {
			if err != nil {
				return nil, err
			}
			ref := memberRef{DN: e.DN, Name: e.GetAttributeValue("displayName"), Kind: "other"}
			if ref.Name == "" {
				ref.Name = e.GetAttributeValue("cn")
			}
			classes := e.GetAttributeValues("objectClass")
			switch {
			case contains(classes, "computer"):
				ref.Kind = "computer"
			case contains(classes, "group"):
				ref.Kind = "group"
			case contains(classes, "user"):
				ref.Kind = "user"
			}
			if g, err := sid.GUIDFromBytes(e.GetRawAttributeValue("objectGUID")); err == nil {
				ref.GUID = g.String()
			}
			byDN[strings.ToLower(e.DN)] = ref
		}
	}
	for _, dn := range dns {
		if ref, ok := byDN[strings.ToLower(dn)]; ok {
			out = append(out, ref)
		} else {
			_, v, _ := escape.ParentDN(dn)
			out = append(out, memberRef{DN: dn, Name: v, Kind: "other"})
		}
	}
	return out, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// objectBySAM finds a user, group or computer by sAMAccountName (a member
// to add to a group); computers may be typed without the trailing "$".
func objectBySAM(ctx context.Context, conn *ad.Conn, sam string) (string, error) {
	sam = strings.TrimSpace(sam)
	if sam == "" {
		return "", errNotFoundPage
	}
	f := escape.Or(escape.Eq("sAMAccountName", sam), escape.Eq("sAMAccountName", sam+"$"))
	entries, err := conn.SearchAll(ctx, ad.SearchRequest{Filter: f, Attributes: []string{"1.1"}, Limit: 2})
	if err != nil {
		return "", err
	}
	if len(entries) != 1 {
		return "", fmt.Errorf("%w: %q", ad.ErrNotFound, sam)
	}
	return entries[0].DN, nil
}
