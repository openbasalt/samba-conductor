package web

import (
	"context"
	"encoding/csv"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Lockouts across DCs and account health. Lockout state and bad-password
// counters are per DC (badPwdCount and badPasswordTime are not
// replicated; lockoutTime replicates with a delay), so the lockouts page
// asks every DC, each with the user's own credentials.

// healthAttrs are read for list rows (the constructed expiry time only for
// the password kinds, where it is needed).
var healthAttrs = append(append([]string(nil), userListAttrs...), "lastLogonTimestamp", "whenCreated", "badPwdCount", "badPasswordTime")

// lockDC is one DC's view of an account.
type lockDC struct {
	Host        string
	Seen        bool
	Locked      bool
	LockoutTime ad.FileTime
	BadPwdCount int
	BadTime     ad.FileTime
}

// lockRow is an account locked, or with failed attempts, on some DC.
type lockRow struct {
	User   ad.User
	Locked bool
	DCs    []lockDC
}

// maxLockRows bounds the accounts read per DC.
const maxLockRows = 500

func (s *Server) handleLockouts(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		dcs, err := conn.DomainControllers(ctx)
		if err != nil {
			return err
		}
		rc.sess.mu.Lock()
		cred := rc.sess.cred
		rc.sess.mu.Unlock()
		byDN := map[string]*lockRow{}
		var hosts []string
		unreachable := []string{}
		f := escape.And(userFilter, escape.Or(escape.GreaterOrEqual("lockoutTime", "1"), escape.GreaterOrEqual("badPwdCount", "1")))
		for i, dc := range dcs {
			host := dc.DNSHost
			hosts = append(hosts, host)
			dconn, err := s.backend.ConnectTo(ctx, cred, host)
			if err != nil {
				s.log.Warn("lockouts: DC unreachable", "dc", host, "err", err)
				unreachable = append(unreachable, host)
				continue
			}
			for e, err := range dconn.Search(ctx, ad.SearchRequest{Filter: f, Attributes: healthAttrs, Limit: maxLockRows}) {
				if err != nil {
					_ = dconn.Close()
					return err
				}
				u := ad.UserFromEntry(e)
				key := strings.ToLower(u.DN)
				row := byDN[key]
				if row == nil {
					row = &lockRow{User: u, DCs: make([]lockDC, len(dcs))}
					byDN[key] = row
				}
				row.DCs[i] = lockDC{Host: host, Seen: true, Locked: u.Locked(), LockoutTime: u.LockoutTime, BadPwdCount: u.BadPwdCount, BadTime: u.BadPasswordTime}
				if u.Locked() {
					row.Locked = true
					row.User = u
				}
			}
			_ = dconn.Close()
		}
		rows := make([]*lockRow, 0, len(byDN))
		for _, r := range byDN {
			for i := range r.DCs {
				r.DCs[i].Host = hosts[i]
			}
			rows = append(rows, r)
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Locked != rows[j].Locked {
				return rows[i].Locked
			}
			return strings.ToLower(rows[i].User.SAMAccountName) < strings.ToLower(rows[j].User.SAMAccountName)
		})
		rc.render(http.StatusOK, "lockouts", map[string]any{"Rows": rows, "Hosts": hosts, "Unreachable": unreachable,
			"CanAct": rc.roles.Has(PermUsersHelpdesk)})
		return nil
	})
}

// Health kinds.
var healthKinds = []string{"expiring", "expired", "never", "stale", "disabled"}

// maxHealthScan bounds the accounts examined for the password kinds (the
// expiry time is computed by the DC and cannot be filtered on).
const maxHealthScan = 20000

func healthParams(rc *reqCtx) (string, int) {
	q := rc.r.URL.Query()
	kind := q.Get("kind")
	if !contains(healthKinds, kind) {
		kind = "expiring"
	}
	days, err := strconv.Atoi(q.Get("days"))
	if err != nil || days < 1 || days > 3650 {
		days = map[string]int{"expiring": 14, "stale": 90}[kind]
	}
	return kind, days
}

var enabledFilter = escape.Not(escape.BitAnd("userAccountControl", uint32(ad.UACAccountDisable)))

// healthUsers returns the accounts of a kind: all of them (export, up to
// limit) or one page.
func (s *Server) healthUsers(ctx context.Context, conn *ad.Conn, kind string, days int, skip, n int) ([]ad.User, bool, error) {
	now := s.now()
	switch kind {
	case "never", "stale", "disabled":
		var f escape.Filter
		switch kind {
		case "never":
			f = andFilters(userFilter, enabledFilter, escape.Not(escape.Present("lastLogonTimestamp")))
		case "stale":
			f = andFilters(userFilter, enabledFilter, escape.Present("lastLogonTimestamp"),
				escape.LessOrEqual("lastLogonTimestamp", ad.FileTimeFrom(now.Add(-time.Duration(days)*24*time.Hour)).String()))
		default:
			f = andFilters(userFilter, escape.BitAnd("userAccountControl", uint32(ad.UACAccountDisable)))
		}
		entries, more, err := conn.SearchWindow(ctx, ad.SearchRequest{Filter: f, Attributes: healthAttrs, SortBy: "sAMAccountName"}, skip, n)
		if err != nil {
			return nil, false, err
		}
		out := make([]ad.User, len(entries))
		for i, e := range entries {
			out[i] = ad.UserFromEntry(e)
		}
		return out, more, nil
	}
	// expiring / expired: read the computed expiry of enabled accounts
	// whose password can expire.
	f := andFilters(userFilter, enabledFilter, escape.Not(escape.BitAnd("userAccountControl", uint32(ad.UACDontExpirePassword))))
	attrs := append(append([]string(nil), healthAttrs...), "msDS-UserPasswordExpiryTimeComputed")
	var match []ad.User
	scanned := 0
	for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: f, Attributes: attrs, SortBy: "sAMAccountName", Limit: maxHealthScan}) {
		if err != nil {
			return nil, false, err
		}
		scanned++
		u := ad.UserFromEntry(e)
		exp := u.PasswordExpires()
		mustChange := u.PwdLastSet == 0
		switch kind {
		case "expiring":
			if !exp.IsZero() && exp.After(now) && !exp.After(now.Add(time.Duration(days)*24*time.Hour)) {
				match = append(match, u)
			}
		case "expired":
			if mustChange || (!exp.IsZero() && !exp.After(now)) || u.PasswordExpired() {
				match = append(match, u)
			}
		}
	}
	if kind == "expiring" {
		sort.SliceStable(match, func(i, j int) bool { return match[i].PasswordExpires().Before(match[j].PasswordExpires()) })
	}
	if skip >= len(match) {
		return nil, false, nil
	}
	end := min(skip+n, len(match))
	return match[skip:end], end < len(match), nil
}

func (s *Server) handleHealth(rc *reqCtx) {
	kind, days := healthParams(rc)
	page := rc.pageParam()
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		users, more, err := s.healthUsers(ctx, conn, kind, days, (page-1)*pageSize, pageSize)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "health", map[string]any{"Users": users, "Kind": kind, "Days": days, "Kinds": healthKinds,
			"Page": page, "More": more, "CanAct": rc.roles.Has(PermUsersHelpdesk), "CanWrite": rc.roles.Has(PermUsersWrite)})
		return nil
	})
}

// maxExportRows bounds a CSV export.
const maxExportRows = 50000

// csvCell neutralizes values a spreadsheet would run as a formula.
func csvCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func csvTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Server) handleHealthExport(rc *reqCtx) {
	kind, days := healthParams(rc)
	ctx, cancel := context.WithTimeout(rc.ctx(), 5*requestTimeout)
	defer cancel()
	var users []ad.User
	err := rc.withConn(ctx, func(conn *ad.Conn) error {
		var err error
		users, _, err = s.healthUsers(ctx, conn, kind, days, 0, maxExportRows)
		return err
	})
	if err != nil {
		rc.failed(err)
		return
	}
	rc.w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	rc.w.Header().Set("Content-Disposition", `attachment; filename="conductor-health-`+kind+`-`+s.now().UTC().Format("20060102-150405")+`.csv"`)
	w := csv.NewWriter(rc.w)
	_ = w.Write([]string{"username", "display_name", "email", "dn", "enabled", "locked", "password_last_set", "password_expires", "last_logon", "created"})
	for _, u := range users {
		_ = w.Write([]string{csvCell(u.SAMAccountName), csvCell(u.DisplayName), csvCell(u.Mail), csvCell(u.DN),
			strconv.FormatBool(u.Enabled()), strconv.FormatBool(u.Locked()), csvTime(u.PwdLastSet.Time()),
			csvTime(u.PasswordExpires()), csvTime(u.LastLogon.Time()), csvTime(u.WhenCreated)})
	}
	w.Flush()
	s.audit(rc.ctx(), rc, "health.export", kind, "days="+strconv.Itoa(days)+" rows="+itoa(len(users)), store.ResultOK)
}
