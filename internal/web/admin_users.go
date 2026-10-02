package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/escape"
	"github.com/samba-conductor/conductor/internal/store"
)

var userListAttrs = []string{"distinguishedName", "objectGUID", "objectSid", "sAMAccountName", "displayName", "mail",
	"userAccountControl", "msDS-User-Account-Control-Computed", "lockoutTime", "pwdLastSet", "accountExpires"}

func userStatusFilter(status string) escape.Filter {
	switch status {
	case "enabled":
		return escape.Not(escape.BitAnd("userAccountControl", uint32(ad.UACAccountDisable)))
	case "disabled":
		return escape.BitAnd("userAccountControl", uint32(ad.UACAccountDisable))
	case "locked":
		return escape.GreaterOrEqual("lockoutTime", "1")
	}
	return nil
}

func (s *Server) handleUsers(rc *reqCtx) {
	q := strings.TrimSpace(rc.r.URL.Query().Get("q"))
	status := rc.r.URL.Query().Get("status")
	page := rc.pageParam()
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		f := andFilters(userFilter, searchFilter(q, "sAMAccountName", "cn", "displayName", "mail", "givenName", "sn"), userStatusFilter(status))
		entries, more, err := conn.SearchWindow(ctx, ad.SearchRequest{Filter: f, Attributes: userListAttrs, SortBy: "sAMAccountName"},
			(page-1)*pageSize, pageSize)
		if err != nil {
			return err
		}
		users := make([]ad.User, 0, len(entries))
		for _, e := range entries {
			u := ad.UserFromEntry(e)
			if status == "locked" && !u.Locked() && u.LockoutTime.Time().IsZero() {
				continue
			}
			users = append(users, u)
		}
		rc.render(http.StatusOK, "users", map[string]any{"Users": users, "Q": q, "Status": status, "Page": page, "More": more,
			"From": (page-1)*pageSize + 1})
		return nil
	})
}

// userPage gathers what the user detail page shows.
func (s *Server) handleUser(rc *reqCtx) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		u, err := userByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		var groups []memberRef
		for grp, err := range conn.Groups(ctx, "", escape.Eq("member", u.DN)) {
			if err != nil {
				return err
			}
			groups = append(groups, memberRef{DN: grp.DN, Name: grp.Name, Kind: "group", GUID: grp.GUID.String()})
		}
		protected, perr := s.accountProtected(ctx, conn, u.DN, u.SID)
		if perr != nil {
			s.log.Warn("protection check", "dn", u.DN, "err", perr)
		}
		_, mfaErr := s.store.GetTOTP(ctx, u.SID.String())
		rc.sess.mu.Lock()
		link := rc.sess.issuedLink
		rc.sess.issuedLink = ""
		self := rc.sess.userSID.Equal(u.SID)
		rc.sess.mu.Unlock()
		rc.render(http.StatusOK, "user", map[string]any{"U": u, "Groups": groups, "Protected": protected,
			"MFA": mfaErr == nil, "Link": link, "Self": self, "Fields": fieldViews(adminFields, u)})
		return nil
	})
}

// userAction loads the user of the {guid} path, enforces the protected
// account rules, and proposes the operation built by build.
func (s *Server) userAction(rc *reqCtx, perm Perm, build func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error)) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		u, err := userByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		protected, err := s.accountProtected(ctx, conn, u.DN, u.SID)
		if err != nil {
			return err
		}
		if protected && !rc.roles.Admin {
			// Helpdesk never acts on privileged accounts (AD would refuse
			// most of it anyway through AdminSDHolder).
			s.audit(ctx, rc, "access.denied", u.DN, "protected account; requires admin", store.ResultDenied)
			rc.errorPage(http.StatusForbidden, "err.protected")
			return nil
		}
		p, err := build(ctx, conn, u)
		if err != nil {
			return err
		}
		if p == nil {
			return nil // build rendered a page itself
		}
		p.perm = perm
		if p.back == "" {
			p.back = "/admin/users/" + u.GUID.String()
		}
		if p.target == "" {
			p.target = u.DN
		}
		if protected {
			p.reauth = true
			p.warning = rc.T("confirm.warn.protected")
		}
		rc.propose(p)
		return nil
	})
}

func (s *Server) handleUserEnable(rc *reqCtx)  { s.userEnable(rc, true) }
func (s *Server) handleUserDisable(rc *reqCtx) { s.userEnable(rc, false) }

func (s *Server) userEnable(rc *reqCtx, enable bool) {
	s.userAction(rc, PermUsersHelpdesk, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		if !enable && rc.isSelf(u) {
			rc.errorPage(http.StatusBadRequest, "err.self_target")
			return nil, nil
		}
		op, err := ad.SetUserEnabled(u, enable)
		if err != nil {
			return nil, err
		}
		action, title, summary := "user.disable", rc.T("user.disable.title", u.SAMAccountName), rc.T("confirm.summary.disable", u.SAMAccountName)
		if enable {
			action, title, summary = "user.enable", rc.T("user.enable.title", u.SAMAccountName), rc.T("confirm.summary.enable", u.SAMAccountName)
		}
		return &pendingOp{action: action, op: op, title: title, summary: summary, done: rc.T("op.done")}, nil
	})
}

func (rc *reqCtx) isSelf(u ad.User) bool {
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	return rc.sess.userSID.Equal(u.SID)
}

func (s *Server) handleUserUnlock(rc *reqCtx) {
	s.userAction(rc, PermUsersHelpdesk, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		op, err := ad.UnlockUser(u.DN)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "user.unlock", op: op, title: rc.T("user.unlock.title", u.SAMAccountName),
			summary: rc.T("confirm.summary.unlock", u.SAMAccountName), done: rc.T("op.done")}, nil
	})
}

func (s *Server) handleUserResetPage(rc *reqCtx) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		u, err := userByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "user_reset", map[string]any{"U": u})
		return nil
	})
}

func (s *Server) handleUserReset(rc *reqCtx) {
	s.userAction(rc, PermUsersHelpdesk, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		pw, confirm := rc.rawForm("new"), rc.rawForm("confirm")
		if pw == "" || pw != confirm {
			key := "password.err.mismatch"
			if pw == "" {
				key = "password.err.required"
			}
			rc.render(http.StatusBadRequest, "user_reset", map[string]any{"U": u, "Error": rc.T(key)})
			return nil, nil
		}
		// Forcing a change at next sign-in is the default.
		mustChange := rc.form("must_change") == "1"
		op, err := ad.ResetPassword(u.DN, pw, mustChange)
		if err != nil {
			return nil, err
		}
		summary := rc.T("confirm.summary.reset", u.SAMAccountName)
		if mustChange {
			summary = rc.T("confirm.summary.reset_must_change", u.SAMAccountName)
		}
		return &pendingOp{action: "user.reset_password", op: op, title: rc.T("user.reset.title", u.SAMAccountName),
			summary: summary, done: rc.T("user.reset.done")}, nil
	})
}

func (s *Server) handleUserMovePage(rc *reqCtx) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		u, err := userByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		opts, err := ouOptions(ctx, conn)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "move", map[string]any{"Name": u.SAMAccountName, "DN": u.DN, "OUs": opts,
			"Action": "/admin/users/" + u.GUID.String() + "/move", "Back": "/admin/users/" + u.GUID.String(), "Ctx": "user"})
		return nil
	})
}

func (s *Server) handleUserMove(rc *reqCtx) {
	s.userAction(rc, PermUsersWrite, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		parent := rc.form("parent")
		if !validParent(parent, conn.BaseDN()) {
			return nil, ad.ErrNotFound
		}
		op, err := ad.MoveObject(u.DN, parent)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "user.move", op: op, title: rc.T("user.move.title", u.SAMAccountName),
			summary: rc.T("confirm.summary.move", parent), done: rc.T("op.done")}, nil
	})
}

func (s *Server) handleUserDelete(rc *reqCtx) {
	s.userAction(rc, PermUsersWrite, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		if rc.isSelf(u) {
			rc.errorPage(http.StatusBadRequest, "err.self_target")
			return nil, nil
		}
		op, err := ad.DeleteObject(u.DN)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "user.delete", op: op, title: rc.T("user.delete.title", u.SAMAccountName),
			summary: rc.T("confirm.summary.delete", u.SAMAccountName), warning: rc.T("confirm.warn.delete"), back: "/admin/users", done: rc.T("op.deleted")}, nil
	})
}

func (s *Server) handleUserEditPage(rc *reqCtx) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		u, err := userByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "user_edit", map[string]any{"U": u, "Fields": fieldViews(adminFields, u)})
		return nil
	})
}

func (s *Server) handleUserEdit(rc *reqCtx) {
	s.userAction(rc, PermUsersWrite, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		upd, n := updateFromForm(rc, adminFields, u)
		if n == 0 {
			rc.flashOK("form.no_change")
			rc.redirect("/admin/users/" + u.GUID.String())
			return nil, nil
		}
		op, err := ad.UpdateUser(u.DN, upd)
		if err != nil {
			rc.render(http.StatusBadRequest, "user_edit", map[string]any{"U": u, "Fields": fieldViews(adminFields, u), "Error": rc.T("form.invalid")})
			return nil, nil
		}
		return &pendingOp{action: "user.update", op: op, title: rc.T("user.edit.title", u.SAMAccountName),
			summary: rc.T("confirm.summary.update", n), done: rc.T("op.done")}, nil
	})
}

func (s *Server) handleUserGroupAdd(rc *reqCtx) {
	s.userAction(rc, PermUsersWrite, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		grp, err := conn.FindGroup(ctx, rc.form("group"))
		if err != nil {
			rc.flashErr("user.groups.not_found")
			rc.redirect("/admin/users/" + u.GUID.String())
			return nil, nil
		}
		op, err := ad.AddGroupMember(grp.DN, u.DN)
		if err != nil {
			return nil, err
		}
		p := &pendingOp{action: "group.add_member", target: grp.DN, op: op, title: rc.T("group.add.title", u.SAMAccountName, grp.Name),
			summary: rc.T("confirm.summary.member_add", u.SAMAccountName, grp.Name), done: rc.T("op.done")}
		if s.roleSIDs.isProtectedGroup(grp.SID) {
			p.reauth, p.warning = true, rc.T("confirm.warn.admin_group")
		}
		return p, nil
	})
}

func (s *Server) handleUserGroupRemove(rc *reqCtx) {
	s.userAction(rc, PermUsersWrite, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		gg, err := sidGUID(rc.form("group"))
		if err != nil {
			return nil, err
		}
		grp, err := groupByGUID(ctx, conn, gg)
		if err != nil {
			return nil, err
		}
		op, err := ad.RemoveGroupMember(grp.DN, u.DN)
		if err != nil {
			return nil, err
		}
		p := &pendingOp{action: "group.remove_member", target: grp.DN, op: op, title: rc.T("group.remove.title", u.SAMAccountName, grp.Name),
			summary: rc.T("confirm.summary.member_remove", u.SAMAccountName, grp.Name), done: rc.T("op.done")}
		if s.roleSIDs.isProtectedGroup(grp.SID) {
			p.reauth, p.warning = true, rc.T("confirm.warn.admin_group")
		}
		return p, nil
	})
}

func (s *Server) handleUserNewPage(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		opts, err := ouOptions(ctx, conn)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "user_new", map[string]any{"OUs": opts, "Realm": strings.ToLower(s.backend.Realm()),
			"F": map[string]string{"must_change": "1"}})
		return nil
	})
}

func (s *Server) handleUserNew(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		f := map[string]string{}
		for _, k := range []string{"parent", "given", "sn", "display", "sam", "mail", "description", "must_change", "disabled"} {
			f[k] = rc.form(k)
		}
		pw, confirm := rc.rawForm("password"), rc.rawForm("confirm")
		fail := func(key string) error {
			opts, err := ouOptions(ctx, conn)
			if err != nil {
				return err
			}
			rc.render(http.StatusBadRequest, "user_new", map[string]any{"OUs": opts, "Realm": strings.ToLower(s.backend.Realm()), "F": f, "Error": rc.T(key)})
			return nil
		}
		if !validParent(f["parent"], conn.BaseDN()) {
			return fail("form.invalid_parent")
		}
		if pw != confirm {
			return fail("password.err.mismatch")
		}
		cn := f["display"]
		if cn == "" {
			cn = strings.TrimSpace(f["given"] + " " + f["sn"])
		}
		if cn == "" {
			cn = f["sam"]
		}
		op, err := ad.CreateUser(ad.NewUser{ParentDN: f["parent"], CN: cn, SAMAccountName: f["sam"],
			UserPrincipalName: f["sam"] + "@" + strings.ToLower(s.backend.Realm()), GivenName: f["given"], Surname: f["sn"],
			DisplayName: f["display"], Mail: f["mail"], Description: f["description"], Password: pw,
			MustChangePassword: f["must_change"] == "1", Disabled: f["disabled"] == "1"})
		if err != nil {
			return fail("form.invalid")
		}
		rc.propose(&pendingOp{perm: PermUsersWrite, action: "user.create", target: op.Preview().Changes[0].DN, op: op,
			title: rc.T("user.new.title"), summary: rc.T("confirm.summary.create_user", f["sam"], ouPath(f["parent"], conn.BaseDN())), back: "/admin/users?q=" + url.QueryEscape(f["sam"]), done: rc.T("user.new.done")})
		return nil
	})
}

// ---- 2FA administration ----

func (s *Server) handleUserMFAReset(rc *reqCtx) {
	s.userAction(rc, PermMFAManage, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		target := u.SID.String()
		return &pendingOp{action: "mfa.reset", title: rc.T("user.mfa_reset.title", u.SAMAccountName),
			summary: rc.T("user.mfa_reset.summary"), preview: "remove the TOTP enrollment and recovery codes of " + u.SAMAccountName +
				" (" + target + ")\nend every conductor session of that user",
			run: func(ctx context.Context, rc *reqCtx) error {
				if err := s.store.DeleteTOTP(ctx, target); err != nil {
					return err
				}
				s.sess.destroyUser(ctx, target)
				return nil
			}, done: rc.T("user.mfa_reset.done")}, nil
	})
}

func (s *Server) handleUserEnrollLink(rc *reqCtx) {
	s.userAction(rc, PermMFAManage, func(ctx context.Context, conn *ad.Conn, u ad.User) (*pendingOp, error) {
		sam := strings.ToLower(u.SAMAccountName)
		host := rc.r.Host
		return &pendingOp{action: "mfa.enroll_link", title: rc.T("user.enroll_link.title", u.SAMAccountName),
			summary: rc.T("user.enroll_link.summary"), preview: "issue a one-time 2FA enrollment link for " + sam + ", valid 24 hours",
			run: func(ctx context.Context, rc *reqCtx) error {
				tok := newToken()
				if err := s.store.CreateEnrollLink(ctx, linkHash(tok), sam, rc.sess.sam, enrollLinkTTL); err != nil {
					return err
				}
				rc.sess.mu.Lock()
				rc.sess.issuedLink = "https://" + host + "/signin?enroll=" + tok
				rc.sess.mu.Unlock()
				return nil
			}, done: rc.T("user.enroll_link.done")}, nil
	})
}

func itoa(n int) string { return strconv.Itoa(n) }
