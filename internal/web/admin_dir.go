package web

import (
	"context"
	"net/http"
	"sort"
	"strings"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
)

// ---- OUs ----

// ouNode is one node of the OU tree.
type ouNode struct {
	OU       ad.OU
	Children []*ouNode
	Depth    int
}

// flatten renders the tree depth-first (templates cannot recurse cheaply).
func flatten(nodes []*ouNode, depth int, out *[]*ouNode) {
	sort.Slice(nodes, func(i, j int) bool { return strings.ToLower(nodes[i].OU.Name) < strings.ToLower(nodes[j].OU.Name) })
	for _, n := range nodes {
		n.Depth = depth
		*out = append(*out, n)
		flatten(n.Children, depth+1, out)
	}
}

func (s *Server) handleOUs(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		byDN := map[string]*ouNode{}
		var all []*ouNode
		for o, err := range conn.OUs(ctx, "", nil) {
			if err != nil {
				return err
			}
			n := &ouNode{OU: o}
			byDN[strings.ToLower(o.DN)] = n
			all = append(all, n)
			if len(all) > maxOUOptions {
				break
			}
		}
		var roots []*ouNode
		for _, n := range all {
			parent, _, err := escape.ParentDN(n.OU.DN)
			if p, ok := byDN[strings.ToLower(parent)]; err == nil && ok {
				p.Children = append(p.Children, n)
			} else {
				roots = append(roots, n)
			}
		}
		var flat []*ouNode
		flatten(roots, 0, &flat)
		rc.render(http.StatusOK, "ous", map[string]any{"Nodes": flat, "Base": conn.BaseDN()})
		return nil
	})
}

// ouProtected: the Domain Controllers OU is never renamed, moved or deleted.
func ouProtected(o ad.OU, base string) bool {
	return escape.EqualDN(o.DN, "OU=Domain Controllers,"+base)
}

func (s *Server) handleOU(rc *reqCtx) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		o, err := ouByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		counts := map[string]int{}
		for name, f := range map[string]escape.Filter{"users": userFilter, "groups": groupFilter, "computers": computerFilter, "ous": ouFilter} {
			n, err := conn.Count(ctx, ad.SearchRequest{BaseDN: o.DN, Scope: ad.ScopeOneLevel, Filter: f})
			if err != nil {
				return err
			}
			counts[name] = n
		}
		children, err := conn.Count(ctx, ad.SearchRequest{BaseDN: o.DN, Scope: ad.ScopeOneLevel, Filter: escape.RawFilter("(objectClass=*)")})
		if err != nil {
			return err
		}
		opts, err := ouOptions(ctx, conn)
		if err != nil {
			return err
		}
		parent, _, _ := escape.ParentDN(o.DN)
		rc.render(http.StatusOK, "ou", map[string]any{"O": o, "Counts": counts, "Empty": children == 0, "OUs": opts,
			"Parent": parent, "Protected": ouProtected(o, conn.BaseDN()), "Path": ouPath(o.DN, conn.BaseDN())})
		return nil
	})
}

func (s *Server) ouAction(rc *reqCtx, build func(ctx context.Context, conn *ad.Conn, o ad.OU) (*pendingOp, error)) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		o, err := ouByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		if ouProtected(o, conn.BaseDN()) {
			rc.errorPage(http.StatusForbidden, "err.protected")
			return nil
		}
		p, err := build(ctx, conn, o)
		if err != nil {
			return err
		}
		if p == nil {
			return nil
		}
		p.perm = PermDirWrite
		if p.target == "" {
			p.target = o.DN
		}
		if p.back == "" {
			p.back = "/admin/ous/" + o.GUID.String()
		}
		rc.propose(p)
		return nil
	})
}

func (s *Server) handleOURename(rc *reqCtx) {
	s.ouAction(rc, func(ctx context.Context, conn *ad.Conn, o ad.OU) (*pendingOp, error) {
		op, err := ad.RenameObject(o.DN, rc.form("name"))
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "ou.rename", op: op, title: rc.T("ou.rename.title", o.Name), summary: rc.T("confirm.summary.rename", o.Name, rc.form("name")),
			back: "/admin/ous", done: rc.T("op.done")}, nil
	})
}

func (s *Server) handleOUMove(rc *reqCtx) {
	s.ouAction(rc, func(ctx context.Context, conn *ad.Conn, o ad.OU) (*pendingOp, error) {
		parent := rc.form("parent")
		if !validParent(parent, conn.BaseDN()) || strings.HasSuffix(strings.ToLower(parent), strings.ToLower(o.DN)) {
			// Not below itself.
			rc.flashErr("form.invalid_parent")
			rc.redirect("/admin/ous/" + o.GUID.String())
			return nil, nil
		}
		op, err := ad.MoveObject(o.DN, parent)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "ou.move", op: op, title: rc.T("ou.move.title", o.Name), summary: rc.T("confirm.summary.move", parent),
			done: rc.T("op.done")}, nil
	})
}

func (s *Server) handleOUDelete(rc *reqCtx) {
	s.ouAction(rc, func(ctx context.Context, conn *ad.Conn, o ad.OU) (*pendingOp, error) {
		op, err := ad.DeleteObject(o.DN)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "ou.delete", op: op, title: rc.T("ou.delete.title", o.Name), summary: rc.T("confirm.summary.delete", o.Name),
			warning: rc.T("ou.delete.warn"), back: "/admin/ous", done: rc.T("op.deleted")}, nil
	})
}

func (s *Server) handleOUNew(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		parent := rc.form("parent")
		if !validParent(parent, conn.BaseDN()) {
			rc.flashErr("form.invalid_parent")
			rc.redirect("/admin/ous")
			return nil
		}
		op, err := ad.CreateOU(ad.NewOU{ParentDN: parent, Name: rc.form("name"), Description: rc.form("description")})
		if err != nil {
			rc.flashErr("form.invalid")
			rc.redirect("/admin/ous")
			return nil
		}
		rc.propose(&pendingOp{perm: PermDirWrite, action: "ou.create", target: op.Preview().Changes[0].DN, op: op,
			title: rc.T("ou.new.title"), summary: rc.T("confirm.summary.create_ou", rc.form("name"), ouPathOrRoot(parent, conn.BaseDN())), back: "/admin/ous", done: rc.T("op.created")})
		return nil
	})
}

// ---- computers ----

func (s *Server) handleComputers(rc *reqCtx) {
	q := strings.TrimSpace(rc.r.URL.Query().Get("q"))
	page := rc.pageParam()
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		f := andFilters(computerFilter, searchFilter(q, "sAMAccountName", "cn", "dNSHostName"))
		entries, more, err := conn.SearchWindow(ctx, ad.SearchRequest{Filter: f, Attributes: ad.ComputerAttributes, SortBy: "cn"},
			(page-1)*pageSize, pageSize)
		if err != nil {
			return err
		}
		list := make([]ad.Computer, len(entries))
		for i, e := range entries {
			list[i] = ad.ComputerFromEntry(e)
		}
		rc.render(http.StatusOK, "computers", map[string]any{"Computers": list, "Q": q, "Page": page, "More": more})
		return nil
	})
}

func (s *Server) handleComputer(rc *reqCtx) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		c, err := computerByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		opts, err := ouOptions(ctx, conn)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "computer", map[string]any{"C": c, "OUs": opts, "Parent": parentOf(c.DN)})
		return nil
	})
}

func parentOf(dn string) string {
	p, _, _ := escape.ParentDN(dn)
	return p
}

func (s *Server) computerAction(rc *reqCtx, build func(ctx context.Context, conn *ad.Conn, c ad.Computer) (*pendingOp, error)) {
	g, err := rc.guidParam()
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		c, err := computerByGUID(ctx, conn, g)
		if err != nil {
			return err
		}
		if c.IsDomainController() {
			s.audit(ctx, rc, "access.denied", c.DN, "domain controller account", "denied")
			rc.errorPage(http.StatusForbidden, "err.protected")
			return nil
		}
		p, err := build(ctx, conn, c)
		if err != nil {
			return err
		}
		if p == nil {
			return nil
		}
		p.perm = PermDirWrite
		if p.target == "" {
			p.target = c.DN
		}
		if p.back == "" {
			p.back = "/admin/computers/" + c.GUID.String()
		}
		rc.propose(p)
		return nil
	})
}

func (s *Server) handleComputerEnable(rc *reqCtx)  { s.computerEnable(rc, true) }
func (s *Server) handleComputerDisable(rc *reqCtx) { s.computerEnable(rc, false) }

func (s *Server) computerEnable(rc *reqCtx, enable bool) {
	s.computerAction(rc, func(ctx context.Context, conn *ad.Conn, c ad.Computer) (*pendingOp, error) {
		op, err := ad.SetComputerEnabled(c, enable)
		if err != nil {
			return nil, err
		}
		action, key, sum := "computer.disable", "computer.disable.title", "confirm.summary.disable"
		if enable {
			action, key, sum = "computer.enable", "computer.enable.title", "confirm.summary.enable"
		}
		return &pendingOp{action: action, op: op, title: rc.T(key, c.SAMAccountName), summary: rc.T(sum, c.SAMAccountName), done: rc.T("op.done")}, nil
	})
}

func (s *Server) handleComputerMove(rc *reqCtx) {
	s.computerAction(rc, func(ctx context.Context, conn *ad.Conn, c ad.Computer) (*pendingOp, error) {
		parent := rc.form("parent")
		if !validParent(parent, conn.BaseDN()) {
			rc.flashErr("form.invalid_parent")
			rc.redirect("/admin/computers/" + c.GUID.String())
			return nil, nil
		}
		op, err := ad.MoveObject(c.DN, parent)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "computer.move", op: op, title: rc.T("computer.move.title", c.SAMAccountName),
			summary: rc.T("confirm.summary.move", parent), done: rc.T("op.done")}, nil
	})
}

func (s *Server) handleComputerDelete(rc *reqCtx) {
	s.computerAction(rc, func(ctx context.Context, conn *ad.Conn, c ad.Computer) (*pendingOp, error) {
		op, err := ad.DeleteObject(c.DN)
		if err != nil {
			return nil, err
		}
		return &pendingOp{action: "computer.delete", op: op, title: rc.T("computer.delete.title", c.SAMAccountName),
			summary: rc.T("confirm.summary.delete", c.SAMAccountName), warning: rc.T("confirm.warn.delete"), back: "/admin/computers", done: rc.T("op.deleted")}, nil
	})
}

// handleObject resolves a DN (from member lists) to its detail page.
func (s *Server) handleObject(rc *reqCtx) {
	dn := rc.r.URL.Query().Get("dn")
	if _, err := escape.ParseDN(dn); err != nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		e, err := conn.Get(ctx, dn, "objectClass", "objectGUID")
		if err != nil {
			return err
		}
		ref, err := describeMembers(ctx, conn, []string{e.DN})
		if err != nil || len(ref) != 1 || ref[0].GUID == "" {
			return errNotFoundPage
		}
		classes := e.GetAttributeValues("objectClass")
		switch {
		case contains(classes, "computer"):
			rc.redirect("/admin/computers/" + ref[0].GUID)
		case contains(classes, "group"):
			rc.redirect("/admin/groups/" + ref[0].GUID)
		case contains(classes, "user"):
			rc.redirect("/admin/users/" + ref[0].GUID)
		case contains(classes, "organizationalUnit"):
			rc.redirect("/admin/ous/" + ref[0].GUID)
		default:
			return errNotFoundPage
		}
		return nil
	})
}

// ouPathOrRoot is ouPath, or the domain's DNS-style name for the root.
func ouPathOrRoot(dn, base string) string {
	if p := ouPath(dn, base); p != "" {
		return p
	}
	return base
}
