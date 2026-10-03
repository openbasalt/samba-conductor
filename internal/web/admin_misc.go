package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/escape"
	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/conductor/internal/store"
)

// ---- dashboard ----

// stat is one dashboard counter.
type stat struct {
	Key   string
	Label string
	Value int
	Link  string
}

func (s *Server) handleDashboard(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		now := s.now()
		count := func(f escape.Filter) (int, error) { return conn.Count(ctx, ad.SearchRequest{Filter: f}) }
		var stats []stat
		for _, c := range []struct {
			key, link string
			f         escape.Filter
		}{
			{"users", "/admin/users", userFilter},
			{"users_disabled", "/admin/users?status=disabled", escape.And(userFilter, escape.BitAnd("userAccountControl", uint32(ad.UACAccountDisable)))},
			{"groups", "/admin/groups", groupFilter},
			{"computers", "/admin/computers", computerFilter},
			{"ous", "/admin/ous", ouFilter},
		} {
			n, err := count(c.f)
			if err != nil {
				return err
			}
			stats = append(stats, stat{Key: c.key, Label: rc.T("dashboard.stat." + c.key), Value: n, Link: c.link})
		}
		// Locked: lockoutTime set and the computed LOCKOUT bit still on.
		var locked []ad.User
		for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: escape.And(userFilter, escape.GreaterOrEqual("lockoutTime", "1")),
			Attributes: userListAttrs, SortBy: "sAMAccountName", Limit: 200}) {
			if err != nil {
				return err
			}
			if u := ad.UserFromEntry(e); u.Locked() {
				locked = append(locked, u)
			}
		}
		stats = append(stats, stat{Key: "users_locked", Label: rc.T("dashboard.stat.users_locked"), Value: len(locked), Link: "/admin/users?status=locked"})
		// Accounts expiring in the next 30 days.
		var expiring []ad.User
		lo, hi := ad.FileTimeFrom(now).String(), ad.FileTimeFrom(now.Add(30*24*time.Hour)).String()
		for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: escape.And(userFilter, escape.GreaterOrEqual("accountExpires", lo),
			escape.LessOrEqual("accountExpires", hi)), Attributes: userListAttrs, SortBy: "sAMAccountName", Limit: 50}) {
			if err != nil {
				return err
			}
			expiring = append(expiring, ad.UserFromEntry(e))
		}
		d := map[string]any{"Stats": stats, "Locked": locked, "Expiring": expiring, "Domain": conn.DNSDomain(),
			"Level": conn.DomainFunctionality(), "DC": conn.DC().Host}
		if rc.roles.Has(PermBackupRead) {
			// The banner uses the poller's cached status (no helper call per view).
			if st, ok := s.backups.get(); ok {
				d["BackupAlerts"] = s.backupAlerts(rc, st)
			}
		}
		if s.sync != nil && rc.roles.Has(PermSyncRead) {
			d["SyncCard"] = true
			if st, ok := s.syncDashboard(ctx, rc); ok {
				d["Sync"] = st
			}
		}
		if s.files != nil && rc.roles.Has(PermFilesRead) {
			d["FilesCard"] = true
			if total, ready, ok := s.filesDashboard(ctx, rc); ok {
				d["FilesTotal"], d["FilesReady"] = total, ready
			}
		}
		if rc.roles.Has(PermAuditRead) {
			recent, _, err := s.store.ListAudit(ctx, store.AuditFilter{}, 0, 10)
			if err == nil {
				d["Recent"] = recent
			}
		}
		rc.render(http.StatusOK, "dashboard", d)
		return nil
	})
}

// ---- audit ----

func auditFilterFrom(rc *reqCtx) (store.AuditFilter, map[string]string) {
	q := rc.r.URL.Query()
	f := store.AuditFilter{Actor: clipName(q.Get("actor")), Action: clipName(q.Get("action")), Target: clipName(q.Get("target"))}
	if r := q.Get("result"); r == store.ResultOK || r == store.ResultDenied || r == store.ResultFailed || r == store.ResultPending {
		f.Result = r
	}
	if t, err := time.Parse("2006-01-02", q.Get("since")); err == nil {
		f.Since = t
	}
	if t, err := time.Parse("2006-01-02", q.Get("until")); err == nil {
		f.Until = t.Add(24 * time.Hour)
	}
	vals := map[string]string{"actor": f.Actor, "action": f.Action, "target": f.Target, "result": f.Result,
		"since": q.Get("since"), "until": q.Get("until")}
	return f, vals
}

func (s *Server) handleAudit(rc *reqCtx) {
	f, vals := auditFilterFrom(rc)
	page := rc.pageParam()
	events, more, err := s.store.ListAudit(rc.ctx(), f, (page-1)*pageSize, pageSize)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.render(http.StatusOK, "audit", map[string]any{"Events": events, "F": vals, "Page": page, "More": more})
}

func (s *Server) handleAuditExport(rc *reqCtx) {
	f, _ := auditFilterFrom(rc)
	rc.w.Header().Set("Content-Type", "application/x-ndjson")
	rc.w.Header().Set("Content-Disposition", `attachment; filename="conductor-audit-`+s.now().UTC().Format("20060102-150405")+`.jsonl"`)
	n, err := s.store.ExportAudit(rc.ctx(), f, rc.w)
	if err != nil {
		s.log.Error("audit export", "err", err)
	}
	s.audit(rc.ctx(), rc, "audit.export", "", "rows="+itoa(n), store.ResultOK)
}

// ---- domain (through conductor-helper) ----

// helperCall runs one helper operation without parameters as the
// signed-in user and audits it.
func (s *Server) helperCall(ctx context.Context, rc *reqCtx, op helper.OpName, out any) error {
	return s.helperCallWith(ctx, rc, op, nil, out)
}

type helperErr string

func (e helperErr) Error() string { return string(e) }

const errHelperDisabled = helperErr("helper disabled")

func (s *Server) handleDomain(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	d := map[string]any{}
	var ping helper.PingResult
	if err := s.helperCall(ctx, rc, helper.OpPing, &ping); err != nil {
		s.log.Warn("helper unavailable", "err", err)
		d["Error"] = rc.T("domain.err.helper")
		rc.render(http.StatusOK, "domain", d)
		return
	}
	d["Ping"] = ping
	var level helper.DomainLevelResult
	if err := s.helperCall(ctx, rc, helper.OpDomainLevel, &level); err == nil {
		d["Level"] = level
	}
	var fsmo helper.FSMORolesResult
	if err := s.helperCall(ctx, rc, helper.OpFSMORoles, &fsmo); err == nil {
		for i := range fsmo.Roles {
			fsmo.Roles[i].Owner = ntdsServer(fsmo.Roles[i].Owner)
		}
		d["FSMO"] = fsmo.Roles
	}
	var dcs helper.DCListResult
	if err := s.helperCall(ctx, rc, helper.OpDCList, &dcs); err == nil {
		d["DCs"] = dcs.DCs
	}
	rc.render(http.StatusOK, "domain", d)
}

// ntdsServer turns "CN=NTDS Settings,CN=DC1,CN=Servers,…" into "DC1".
func ntdsServer(dn string) string {
	parts := strings.SplitN(dn, ",", 3)
	if len(parts) >= 2 && strings.HasPrefix(strings.ToUpper(parts[1]), "CN=") {
		return parts[1][3:]
	}
	return dn
}
