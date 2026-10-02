package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/escape"
	"github.com/samba-conductor/ad/sambatool"
	"github.com/samba-conductor/conductor/internal/store"
)

// Group Policy: GPOs and where they are linked. Links, link flags, link
// order and block inheritance are LDAP writes on the container (gPLink,
// gPOptions) with the user's credentials. Creating and deleting a GPO also
// needs SYSVOL, so conductor runs samba-tool with the user's own Kerberos
// ticket (written to a private ccache file for the run). Editing the
// settings inside a GPO is out of scope (RSAT/GPMC).

// gpoParam parses the {id} path value: the GUID without braces.
func gpoParam(rc *reqCtx) (string, error) {
	id := "{" + strings.ToUpper(rc.r.PathValue("id")) + "}"
	if !ad.ValidGPOID(id) {
		return "", errNotFoundPage
	}
	return id, nil
}

func gpoLink(id string) string { return "/admin/gpo/" + strings.Trim(id, "{}") }

func containerLink(dn string) string { return "/admin/gpo/links?dn=" + url.QueryEscape(dn) }

// gpContainerOptions lists where a GPO can be linked: the domain and its OUs.
func gpContainerOptions(ctx context.Context, conn *ad.Conn) ([]ouOption, error) {
	opts := []ouOption{{DN: conn.BaseDN(), Label: conn.DNSDomain()}}
	n := 0
	for o, err := range conn.OUs(ctx, "", nil) {
		if err != nil {
			return nil, err
		}
		if n++; n > maxOUOptions {
			break
		}
		opts = append(opts, ouOption{DN: o.DN, Label: conn.DNSDomain() + " / " + ouPath(o.DN, conn.BaseDN())})
	}
	sort.Slice(opts[1:], func(i, j int) bool { return strings.ToLower(opts[1+i].Label) < strings.ToLower(opts[1+j].Label) })
	return opts, nil
}

// gpoView is a GPO with where it is linked.
type gpoView struct {
	G     ad.GPO
	Link  string
	Links []gpLinkView
}

type gpLinkView struct {
	Container ad.GPContainer
	Order     int
	Enabled   bool
	Enforced  bool
	Link      string
}

func linksOf(containers []ad.GPContainer, id string) []gpLinkView {
	var out []gpLinkView
	for _, gc := range containers {
		for i, l := range gc.Links {
			if strings.EqualFold(l.GPOID(), id) {
				out = append(out, gpLinkView{Container: gc, Order: ad.LinkOrder(i, len(gc.Links)), Enabled: l.Enabled(),
					Enforced: l.Enforced(), Link: containerLink(gc.DN)})
			}
		}
	}
	return out
}

func (s *Server) handleGPOs(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		gpos, err := conn.GPOs(ctx)
		if err != nil {
			return err
		}
		containers, err := conn.GPContainers(ctx)
		if err != nil {
			return err
		}
		views := make([]gpoView, 0, len(gpos))
		for _, g := range gpos {
			views = append(views, gpoView{G: g, Link: gpoLink(g.ID), Links: linksOf(containers, g.ID)})
		}
		type cview struct {
			C    ad.GPContainer
			Link string
		}
		var cs []cview
		for _, c := range containers {
			cs = append(cs, cview{C: c, Link: containerLink(c.DN)})
		}
		opts, err := gpContainerOptions(ctx, conn)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "gpos", map[string]any{"GPOs": views, "Containers": cs, "Options": opts})
		return nil
	})
}

func (s *Server) handleGPO(rc *reqCtx) {
	id, err := gpoParam(rc)
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		g, err := conn.GPOByID(ctx, id)
		if err != nil {
			return err
		}
		containers, err := conn.GPContainers(ctx)
		if err != nil {
			return err
		}
		opts, err := gpContainerOptions(ctx, conn)
		if err != nil {
			return err
		}
		links := linksOf(containers, id)
		rc.render(http.StatusOK, "gpo", map[string]any{"G": g, "Links": links, "Options": opts, "Link": gpoLink(id),
			"SysvolPath": `\\` + conn.DNSDomain() + `\SysVol\` + conn.DNSDomain() + `\Policies\` + g.ID})
		return nil
	})
}

// gpoRun prepares samba-tool for one GPO operation with the user's ticket:
// a private directory (inside conductor's own /tmp) holding the ccache,
// chosen now so the preview shows the exact command.
func (s *Server) gpoRunner() (*sambatool.Runner, string) {
	dir := filepath.Join(os.TempDir(), "conductor-gpo-"+newToken()[:16])
	return &sambatool.Runner{Binary: s.cfg.Tools.SambaTool, Credentials: sambatool.KerberosCCache{Path: filepath.Join(dir, "ccache")},
		Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "HOME=" + dir}}, dir
}

// withTicket writes the session's ticket for one samba-tool run and
// removes it afterwards.
func (rc *reqCtx) withTicket(dir string, fn func() error) error {
	rc.sess.mu.Lock()
	cred := rc.sess.cred
	rc.sess.mu.Unlock()
	if cred == nil {
		return errNoCredential
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := cred.WriteCCache(filepath.Join(dir, "ccache")); err != nil {
		return err
	}
	return fn()
}

var errNoCredential = errors.New("web: no credential")

func (s *Server) handleGPONewPage(rc *reqCtx) {
	rc.render(http.StatusOK, "gpo_new", map[string]any{})
}

func (s *Server) handleGPONew(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		name := rc.form("name")
		op := sambatool.GPOCreate{DisplayName: name, URL: "ldap://" + conn.DCHostName()}
		runner, dir := s.gpoRunner()
		cmd, err := sambatool.Preview(runner, op)
		if err != nil {
			rc.render(http.StatusBadRequest, "gpo_new", map[string]any{"Name": name, "Error": rc.T("gpo.err.name")})
			return nil
		}
		gpos, err := conn.GPOs(ctx)
		if err != nil {
			return err
		}
		for _, g := range gpos {
			if strings.EqualFold(g.DisplayName, name) {
				rc.render(http.StatusBadRequest, "gpo_new", map[string]any{"Name": name, "Error": rc.T("err.ad.exists")})
				return nil
			}
		}
		rc.propose(&pendingOp{perm: PermGPOWrite, action: "gpo.create", target: name,
			title: rc.T("gpo.new.title"), summary: rc.T("gpo.summary.create", name, conn.DCHostName()),
			preview: "# " + rc.T("gpo.preview.ticket") + "\n$ " + cmd + "\n# creates the groupPolicyContainer under " + conn.PoliciesDN() +
				"\n# and its folder in SYSVOL on " + conn.DCHostName(),
			run: func(ctx context.Context, rc *reqCtx) error {
				return rc.withTicket(dir, func() error {
					id, err := sambatool.Run(ctx, runner, op)
					if err != nil {
						return err
					}
					s.audit(ctx, rc, "gpo.created", id, "display name: "+name, store.ResultOK)
					rc.flashOK("gpo.new.created", name, id)
					return nil
				})
			}, back: "/admin/gpo", done: ""})
		return nil
	})
}

func (s *Server) handleGPODelete(rc *reqCtx) {
	id, err := gpoParam(rc)
	if err != nil {
		rc.failed(err)
		return
	}
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		g, err := conn.GPOByID(ctx, id)
		if err != nil {
			return err
		}
		if strings.EqualFold(g.ID, "{31B2F340-016D-11D2-945F-00C04FB984F9}") || strings.EqualFold(g.ID, "{6AC1786C-016F-11D2-945F-00C04FB984F9}") {
			// The Default Domain Policy and Default Domain Controllers Policy.
			rc.errorPage(http.StatusForbidden, "gpo.err.default")
			return nil
		}
		containers, err := conn.GPContainers(ctx)
		if err != nil {
			return err
		}
		if links := ad.LinksTo(containers, id); len(links) > 0 {
			rc.flashErr("gpo.err.linked", len(links))
			rc.redirect(gpoLink(id))
			return nil
		}
		op := sambatool.GPODelete{ID: g.ID, URL: "ldap://" + conn.DCHostName()}
		runner, dir := s.gpoRunner()
		cmd, err := sambatool.Preview(runner, op)
		if err != nil {
			return err
		}
		rc.propose(&pendingOp{perm: PermGPOWrite, action: "gpo.delete", target: g.DN, reauth: true,
			title: rc.T("gpo.delete.title", g.DisplayName), summary: rc.T("gpo.summary.delete", g.DisplayName, g.ID),
			warning: rc.T("confirm.warn.delete"),
			preview: "# " + rc.T("gpo.preview.ticket") + "\n$ " + cmd + "\n# deletes " + g.DN + "\n# and " + g.FileSysPath,
			run: func(ctx context.Context, rc *reqCtx) error {
				return rc.withTicket(dir, func() error {
					_, err := sambatool.Run(ctx, runner, op)
					return err
				})
			}, back: "/admin/gpo", done: rc.T("op.deleted")})
		return nil
	})
}

func (s *Server) handleGPOLinkTo(rc *reqCtx) {
	id, err := gpoParam(rc)
	if err != nil {
		rc.failed(err)
		return
	}
	s.gpLinkAction(rc, rc.form("dn"), id, ad.GPLinkAdd, gpoLink(id))
}

func (s *Server) handleGPContainer(rc *reqCtx) {
	dn := rc.r.URL.Query().Get("dn")
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		if !validParent(dn, conn.BaseDN()) {
			return errNotFoundPage
		}
		gc, err := conn.GPContainerByDN(ctx, dn)
		if err != nil {
			return err
		}
		gpos, err := conn.GPOs(ctx)
		if err != nil {
			return err
		}
		byID := map[string]ad.GPO{}
		for _, g := range gpos {
			byID[g.ID] = g
		}
		type linkRow struct {
			Order     int
			G         ad.GPO
			ID        string
			Enabled   bool
			Enforced  bool
			First     bool
			Last      bool
			GPOLink   string
			Dangling  bool
			LinkedDN  string
			ShortID   string
			StoredIdx int
		}
		var rows []linkRow
		n := len(gc.Links)
		// Show link order 1 (highest precedence, stored last) first.
		for i := n - 1; i >= 0; i-- {
			l := gc.Links[i]
			g, ok := byID[l.GPOID()]
			rows = append(rows, linkRow{Order: ad.LinkOrder(i, n), G: g, ID: l.GPOID(), Enabled: l.Enabled(), Enforced: l.Enforced(),
				First: i == n-1, Last: i == 0, GPOLink: gpoLink(l.GPOID()), Dangling: !ok, LinkedDN: l.GPODN, ShortID: strings.Trim(l.GPOID(), "{}")})
		}
		var unlinked []ad.GPO
		for _, g := range gpos {
			linked := false
			for _, l := range gc.Links {
				if strings.EqualFold(l.GPOID(), g.ID) {
					linked = true
				}
			}
			if !linked {
				unlinked = append(unlinked, g)
			}
		}
		name := gc.Name
		if gc.Kind == "ou" {
			name = ouPath(gc.DN, conn.BaseDN())
		}
		rc.render(http.StatusOK, "gp_container", map[string]any{"C": gc, "Name": name, "Rows": rows, "Unlinked": unlinked})
		return nil
	})
}

func (s *Server) handleGPContainerAction(rc *reqCtx) {
	dn, id := rc.form("dn"), "{"+strings.ToUpper(strings.Trim(rc.form("gpo"), "{}"))+"}"
	action := ad.GPLinkAction(rc.form("action"))
	switch action {
	case ad.GPLinkAdd, ad.GPLinkRemove, ad.GPLinkEnable, ad.GPLinkDisable, ad.GPLinkEnforce, ad.GPLinkUnforce, ad.GPLinkMoveUp, ad.GPLinkMoveDown:
	default:
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	s.gpLinkAction(rc, dn, id, action, containerLink(dn))
}

// gpLinkAction proposes one change to a container's links.
func (s *Server) gpLinkAction(rc *reqCtx, dn, id string, action ad.GPLinkAction, back string) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		if !validParent(dn, conn.BaseDN()) || !ad.ValidGPOID(id) {
			return errNotFoundPage
		}
		gc, err := conn.GPContainerByDN(ctx, dn)
		if err != nil {
			return err
		}
		g, err := conn.GPOByID(ctx, id)
		if err != nil && action != ad.GPLinkRemove {
			return err
		}
		if err != nil {
			// A link to a GPO that no longer exists can still be removed.
			for _, l := range gc.Links {
				if strings.EqualFold(l.GPOID(), id) {
					g = ad.GPO{ID: id, DN: l.GPODN, DisplayName: id}
				}
			}
		}
		op, err := ad.ChangeGPLink(gc, g, action)
		if err != nil {
			rc.flashErr(s.adErrorKey(err))
			rc.redirect(back)
			return nil
		}
		where := gc.Name
		if gc.Kind == "ou" {
			where = ouPath(gc.DN, conn.BaseDN())
		}
		rc.propose(&pendingOp{perm: PermGPOWrite, action: "gpo.link_" + string(action), target: gc.DN, op: op,
			title: rc.T("gpo.link.title", where), summary: rc.T("gpo.summary.link_"+string(action), g.DisplayName, where),
			back: back, done: rc.T("op.done")})
		return nil
	})
}

func (s *Server) handleGPInheritance(rc *reqCtx) {
	dn := rc.form("dn")
	block := rc.form("block") == "1"
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		if !validParent(dn, conn.BaseDN()) {
			return errNotFoundPage
		}
		gc, err := conn.GPContainerByDN(ctx, dn)
		if err != nil {
			return err
		}
		if escape.EqualDN(dn, conn.BaseDN()) {
			rc.errorPage(http.StatusBadRequest, "gpo.err.domain_inheritance")
			return nil
		}
		op, err := ad.SetBlockInheritance(gc, block)
		if err != nil {
			rc.flashErr(s.adErrorKey(err))
			rc.redirect(containerLink(dn))
			return nil
		}
		where := ouPath(gc.DN, conn.BaseDN())
		key := "gpo.summary.allow_inheritance"
		if block {
			key = "gpo.summary.block_inheritance"
		}
		rc.propose(&pendingOp{perm: PermGPOWrite, action: "gpo.inheritance", target: gc.DN, op: op,
			title: rc.T("gpo.inheritance.title", where), summary: rc.T(key, where), back: containerLink(dn), done: rc.T("op.done")})
		return nil
	})
}
