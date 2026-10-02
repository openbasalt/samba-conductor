package web

import (
	"context"
	"net/http"
	"strings"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/escape"
	"github.com/samba-conductor/ad/sid"
)

func sidGUID(s string) (sid.GUID, error) {
	g, err := sid.ParseGUID(strings.TrimSpace(s))
	if err != nil {
		return g, errNotFoundPage
	}
	return g, nil
}

func (s *Server) handleGroups(rc *reqCtx) {
	q := strings.TrimSpace(rc.r.URL.Query().Get("q"))
	page := rc.pageParam()
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		f := andFilters(groupFilter, searchFilter(q, "sAMAccountName", "cn", "description"))
		entries, more, err := conn.SearchWindow(ctx, ad.SearchRequest{Filter: f, Attributes: ad.GroupAttributes, SortBy: "cn"},
			(page-1)*pageSize, pageSize)
		if err != nil {
			return err
		}
		groups := make([]ad.Group, len(entries))
		for i, e := range entries {
			groups[i] = ad.GroupFromEntry(e)
		}
		rc.render(http.StatusOK, "groups", map[string]any{"Groups": groups, "Q": q, "Page": page, "More": more})
		return nil
	})
}

func (s *Server) handleGroup(rc *reqCtx) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	page := rc.pageParam()
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		grp, err := groupByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		members, err := conn.GroupMembers(ctx, grp.DN)
		if err != nil {
			return err
		}
		total := len(members)
		start := min((page-1)*pageSize, total)
		end := min(start+pageSize, total)
		refs, err := describeMembers(ctx, conn, members[start:end])
		if err != nil {
			return err
		}
		parents, err := describeMembers(ctx, conn, grp.MemberOf)
		if err != nil {
			return err
		}
		// Nested view: effective (transitive) user members.
		effective, err := conn.Count(ctx, ad.SearchRequest{Filter: escape.And(userFilter, escape.InChain("memberOf", grp.DN))})
		if err != nil {
			return err
		}
		var nested []memberRef
		for child, err := range conn.Groups(ctx, "", escape.Eq("memberOf", grp.DN)) {
			if err != nil {
				return err
			}
			nested = append(nested, memberRef{DN: child.DN, Name: child.Name, Kind: "group", GUID: child.GUID.String()})
		}
		rc.render(http.StatusOK, "group", map[string]any{"G": grp, "Members": refs, "Total": total, "Page": page,
			"More": end < total, "From": start + 1, "Parents": parents, "Nested": nested, "Effective": effective,
			"Protected": s.roleSIDs.isProtectedGroup(grp.SID)})
		return nil
	})
}

// groupAction loads the {guid} group and proposes the built operation;
// writes to administrator groups require re-authentication.
func (s *Server) groupAction(rc *reqCtx, build func(ctx context.Context, conn *ad.Conn, g ad.Group) (*pendingOp, error)) {
	gg, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		grp, err := groupByGUID(ctx, conn, gg)
		if err != nil {
			return err
		}
		p, err := build(ctx, conn, grp)
		if err != nil {
			return err
		}
		if p == nil {
			return nil
		}
		p.perm = PermDirWrite
		if p.target == "" {
			p.target = grp.DN
		}
		if p.back == "" {
			p.back = "/admin/groups/" + grp.GUID.String()
		}
		if s.roleSIDs.isProtectedGroup(grp.SID) {
			p.reauth, p.warning = true, rc.T("confirm.warn.admin_group")
		}
		rc.propose(p)
		return nil
	})
}

func (s *Server) handleGroupMemberAdd(rc *reqCtx) {
	s.groupAction(rc, func(ctx context.Context, conn *ad.Conn, g ad.Group) (*pendingOp, error) {
		memberDN, err := objectBySAM(ctx, conn, rc.form("member"))
		if err != nil {
			rc.flashErr("group.member_not_found")
			rc.redirect("/admin/groups/" + g.GUID.String())
			return nil, nil
		}
		op, err := ad.AddGroupMember(g.DN, memberDN)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "group.add_member", op: op, title: rc.T("group.add.title", rc.form("member"), g.Name),
			summary: op.Preview().Summary, done: rc.T("op.done")}, nil
	})
}

func (s *Server) handleGroupMemberRemove(rc *reqCtx) {
	s.groupAction(rc, func(ctx context.Context, conn *ad.Conn, g ad.Group) (*pendingOp, error) {
		memberDN := rc.form("member_dn")
		if _, err := escape.ParseDN(memberDN); err != nil {
			return nil, errNotFoundPage
		}
		op, err := ad.RemoveGroupMember(g.DN, memberDN)
		if err != nil {
			return nil, err
		}
		_, name, _ := escape.ParentDN(memberDN)
		return &pendingOp{action: "group.remove_member", op: op, title: rc.T("group.remove.title", name, g.Name),
			summary: op.Preview().Summary, done: rc.T("op.done")}, nil
	})
}

func (s *Server) handleGroupDelete(rc *reqCtx) {
	s.groupAction(rc, func(ctx context.Context, conn *ad.Conn, g ad.Group) (*pendingOp, error) {
		if rid, ok := g.SID.RID(); ok && rid < 1000 {
			// Built-in and well-known groups are never deleted here.
			rc.errorPage(http.StatusForbidden, "err.protected")
			return nil, nil
		}
		op, err := ad.DeleteObject(g.DN)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "group.delete", op: op, title: rc.T("group.delete.title", g.Name), summary: op.Preview().Summary,
			warning: rc.T("confirm.warn.delete"), back: "/admin/groups", done: rc.T("op.deleted")}, nil
	})
}

func (s *Server) handleGroupNewPage(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		opts, err := ouOptions(ctx, conn)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "group_new", map[string]any{"OUs": opts, "F": map[string]string{"scope": "global", "type": "security"}})
		return nil
	})
}

func (s *Server) handleGroupNew(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		f := map[string]string{}
		for _, k := range []string{"parent", "name", "sam", "description", "scope", "type"} {
			f[k] = rc.form(k)
		}
		fail := func(key string) error {
			opts, err := ouOptions(ctx, conn)
			if err != nil {
				return err
			}
			rc.render(http.StatusBadRequest, "group_new", map[string]any{"OUs": opts, "F": f, "Error": rc.T(key)})
			return nil
		}
		if !validParent(f["parent"], conn.BaseDN()) {
			return fail("form.invalid_parent")
		}
		scope := map[string]ad.GroupType{"global": ad.GroupTypeGlobal, "domainlocal": ad.GroupTypeDomainLocal, "universal": ad.GroupTypeUniversal}[f["scope"]]
		if scope == 0 {
			return fail("form.invalid")
		}
		op, err := ad.CreateGroup(ad.NewGroup{ParentDN: f["parent"], Name: f["name"], SAMAccountName: f["sam"],
			Description: f["description"], Scope: scope, Distribution: f["type"] == "distribution"})
		if err != nil {
			return fail("form.invalid")
		}
		rc.propose(&pendingOp{perm: PermDirWrite, action: "group.create", target: op.Preview().Changes[0].DN, op: op,
			title: rc.T("group.new.title"), summary: op.Preview().Summary, back: "/admin/groups?q=" + f["name"], done: rc.T("op.created")})
		return nil
	})
}
