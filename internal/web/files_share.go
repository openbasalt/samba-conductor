package web

import (
	"context"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-files/filesapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// The share wizard edits a draft of a share spec held in the session (no
// JavaScript: every step is a form). The agent validates everything again
// when it plans; the plan is what the administrator confirms.

// filesDraft is a share being created or edited.
type filesDraft struct {
	ServerID string
	// Create: a new share (else Spec.Name is an existing managed share).
	Create bool
	Spec   filesapi.ShareSpec
	// Browse is the folder shown in the folder picker.
	Browse string
}

var filesSteps = []string{"folder", "access", "options"}

func wizardURL(srv store.FileServer, step string) string {
	return serverURL(srv) + "/wizard?step=" + step
}

// draftFor returns the session's draft for this server, or nil.
func (rc *reqCtx) filesDraftFor(srv store.FileServer) *filesDraft {
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	if d := rc.sess.filesDraft; d != nil && d.ServerID == srv.ID {
		return d
	}
	return nil
}

func (rc *reqCtx) setFilesDraft(d *filesDraft) {
	rc.sess.mu.Lock()
	rc.sess.filesDraft = d
	rc.sess.mu.Unlock()
}

func (s *Server) handleShareNew(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	rc.setFilesDraft(&filesDraft{ServerID: srv.ID, Create: true, Spec: filesapi.ShareSpec{Browseable: true}})
	rc.redirect(wizardURL(srv, "folder"))
}

func (s *Server) handleShareEdit(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	name, ok := shareName(rc)
	if !ok {
		return
	}
	ctx, cancel := filesTimeout(rc)
	defer cancel()
	var sd filesapi.ShareDetail
	if err := s.filesCall(ctx, rc, srv, filesapi.OpShareGet, filesapi.ShareNameParams{Name: name}, &sd); err != nil {
		rc.sess.addFlash("error", s.filesErr(rc, err))
		rc.redirect(serverURL(srv))
		return
	}
	if !sd.Managed || sd.Spec == nil {
		rc.flashErr("files.share.not_managed")
		rc.redirect(shareURL(srv, name))
		return
	}
	rc.setFilesDraft(&filesDraft{ServerID: srv.ID, Spec: *sd.Spec, Browse: path.Dir(sd.Spec.Path)})
	rc.redirect(wizardURL(srv, "access"))
}

func (s *Server) handleShareWizard(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	dr := rc.filesDraftFor(srv)
	if dr == nil {
		rc.flashErr("files.wizard.expired")
		rc.redirect(serverURL(srv))
		return
	}
	step := rc.r.URL.Query().Get("step")
	if !slices.Contains(filesSteps, step) {
		step = filesSteps[0]
	}
	ctx, cancel := filesTimeout(rc)
	defer cancel()
	d := map[string]any{"S": srv, "Dr": dr, "Step": step, "Steps": filesSteps, "Levels": filesapi.Levels}
	switch step {
	case "folder":
		browse := rc.r.URL.Query().Get("browse")
		if browse == "" {
			browse = dr.Browse
		}
		var dl filesapi.DirList
		err := s.filesCall(ctx, rc, srv, filesapi.OpDirsList, filesapi.DirsListParams{Path: browse}, &dl)
		if err != nil && browse != "" {
			// A stale or bad folder: start again from the roots.
			browse = ""
			err = s.filesCall(ctx, rc, srv, filesapi.OpDirsList, filesapi.DirsListParams{}, &dl)
		}
		if err == nil && browse == "" && len(dl.Roots) == 1 {
			browse = dl.Roots[0]
			err = s.filesCall(ctx, rc, srv, filesapi.OpDirsList, filesapi.DirsListParams{Path: browse}, &dl)
		}
		if err != nil {
			d["Error"] = s.filesErr(rc, err)
		}
		rc.sess.mu.Lock()
		dr.Browse = browse
		rc.sess.mu.Unlock()
		d["DL"] = dl
	case "access":
		q := strings.TrimSpace(rc.r.URL.Query().Get("q"))
		d["Q"] = q
		if q != "" {
			err := rc.withConn(ctx, func(conn *ad.Conn) error {
				var hits []groupHit
				for e, err := range conn.Search(ctx, ad.SearchRequest{Filter: andFilters(groupFilter, searchFilter(q, "sAMAccountName", "cn", "description")),
					Attributes: ad.GroupAttributes, SortBy: "cn", Limit: 20}) {
					if err != nil {
						return err
					}
					g := ad.GroupFromEntry(e)
					hits = append(hits, groupHit{Name: g.Name, DN: g.DN, SID: g.SID.String(), Description: g.Description})
				}
				d["Hits"] = hits
				return nil
			})
			if err != nil {
				s.log.Warn("share wizard: group search failed", "err", err)
				d["Error"] = rc.T(s.adErrorKey(err))
			}
		}
	case "options":
		if st, e := s.statusOf(ctx, rc, srv, false); st != nil {
			d["Shadow"] = st.ShadowCopies
		} else {
			d["Error"] = e
		}
	}
	rc.render(http.StatusOK, "files_wizard", d)
}

// handleShareWizardPost applies one step's form to the draft.
func (s *Server) handleShareWizardPost(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	dr := rc.filesDraftFor(srv)
	if dr == nil {
		rc.flashErr("files.wizard.expired")
		rc.redirect(serverURL(srv))
		return
	}
	rc.sess.mu.Lock()
	next, errKey, args := applyWizardForm(rc, dr)
	rc.sess.mu.Unlock()
	if errKey != "" {
		rc.flashErr(errKey, args...)
	}
	if next == "plan" {
		s.proposeSharePlan(rc, srv, dr)
		return
	}
	rc.redirect(next)
}

// applyWizardForm changes the draft (caller holds the session lock) and
// returns where to go next.
func applyWizardForm(rc *reqCtx, dr *filesDraft) (string, string, []any) {
	srv := store.FileServer{ID: dr.ServerID}
	sp := &dr.Spec
	switch rc.form("action") {
	case "folder":
		back := wizardURL(srv, "folder")
		if dr.Create {
			name := rc.form("name")
			if !filesapi.ValidShareName(name) {
				return back, "files.wizard.err.name", nil
			}
			sp.Name = name
		}
		comment := rc.form("comment")
		if filesapi.ValidComment(comment) != nil {
			return back, "files.wizard.err.comment", nil
		}
		sp.Comment = comment
		newDir, chosen := rc.form("newdir"), rc.form("path")
		switch {
		case newDir != "":
			if !dr.Create {
				return back, "files.wizard.err.newdir_edit", nil
			}
			p := path.Join(dr.Browse, newDir)
			if strings.Contains(newDir, "/") || filesapi.ValidSharePath(p) != nil {
				return back, "files.wizard.err.folder_name", nil
			}
			sp.Path, sp.CreateDir = p, true
		case chosen != "":
			if filesapi.ValidSharePath(chosen) != nil {
				return back, "files.wizard.err.folder", nil
			}
			sp.Path, sp.CreateDir = chosen, false
		case sp.Path == "":
			return back, "files.wizard.err.folder", nil
		}
		return wizardURL(srv, "access"), "", nil
	case "add", "level":
		back := wizardURL(srv, "access")
		sid, level := rc.form("sid"), rc.form("level")
		if !filesapi.ValidDomainSID(sid) || !slices.Contains(filesapi.Levels, level) {
			return back, "form.invalid", nil
		}
		for i := range sp.Access {
			if sp.Access[i].SID == sid {
				sp.Access[i].Level = level
				return back, "", nil
			}
		}
		if rc.form("action") == "level" {
			return back, "form.invalid", nil
		}
		if len(sp.Access) >= filesapi.MaxGrants {
			return back, "files.wizard.err.too_many", []any{filesapi.MaxGrants}
		}
		name := rc.form("name")
		if len(name) > 256 {
			name = name[:256]
		}
		sp.Access = append(sp.Access, filesapi.Grant{SID: sid, Level: level, Name: name})
		return back, "", nil
	case "remove":
		sid := rc.form("sid")
		sp.Access = slices.DeleteFunc(sp.Access, func(g filesapi.Grant) bool { return g.SID == sid })
		return wizardURL(srv, "access"), "", nil
	case "options":
		sp.Browseable = rc.form("browseable") == "1"
		sp.AccessBasedEnum = rc.form("abe") == "1"
		sp.RecycleBin = rc.form("recycle") == "1"
		sp.ShadowCopies = rc.form("shadow") == "1"
		if rc.form("go") == "plan" {
			return "plan", "", nil
		}
		return wizardURL(srv, "options"), "", nil
	case "next":
		step := rc.form("step")
		if !slices.Contains(filesSteps, step) {
			step = "folder"
		}
		return wizardURL(srv, step), "", nil
	}
	return wizardURL(srv, "folder"), "form.invalid", nil
}

func (s *Server) handleShareWizardDiscard(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	rc.setFilesDraft(nil)
	rc.flashOK("files.wizard.discarded")
	rc.redirect(serverURL(srv))
}

func (s *Server) handleShareWizardPlan(rc *reqCtx) {
	srv, ok := s.fileServer(rc)
	if !ok {
		return
	}
	dr := rc.filesDraftFor(srv)
	if dr == nil {
		rc.flashErr("files.wizard.expired")
		rc.redirect(serverURL(srv))
		return
	}
	s.proposeSharePlan(rc, srv, dr)
}

// proposeSharePlan asks the agent for the exact plan of the draft and
// proposes it (re-authentication required). The apply is bound to the
// plan's digest: the agent re-plans and refuses if anything changed.
func (s *Server) proposeSharePlan(rc *reqCtx, srv store.FileServer, dr *filesDraft) {
	rc.sess.mu.Lock()
	spec, create := dr.Spec, dr.Create
	spec.Access = slices.Clone(dr.Spec.Access)
	rc.sess.mu.Unlock()
	back := wizardURL(srv, "options")
	if spec.Name == "" || spec.Path == "" {
		rc.flashErr("files.wizard.err.folder")
		rc.redirect(wizardURL(srv, "folder"))
		return
	}
	if len(spec.Access) == 0 {
		rc.flashErr("files.wizard.err.no_access")
		rc.redirect(wizardURL(srv, "access"))
		return
	}
	ctx, cancel := filesTimeout(rc)
	defer cancel()
	var pl filesapi.Plan
	if err := s.filesCall(ctx, rc, srv, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: spec, Create: create}, &pl); err != nil {
		rc.sess.addFlash("error", s.filesErr(rc, err))
		rc.redirect(back)
		return
	}
	if pl.NoChange {
		rc.setFilesDraft(nil)
		rc.flashOK("files.plan.no_change")
		rc.redirect(shareURL(srv, pl.Name))
		return
	}
	action, title, summary := "files.share_update", rc.T("files.plan.update_title", pl.Name), rc.T("files.plan.update_summary", pl.Name, srv.Name)
	if create {
		action, title, summary = "files.share_create", rc.T("files.plan.create_title", pl.Name), rc.T("files.plan.create_summary", pl.Name, srv.Name, pl.Path)
	}
	digest := pl.Digest
	p := &pendingOp{perm: PermFilesWrite, action: action, target: srv.Name + "/" + pl.Name, reauth: true, reauthKey: "files.reauth", title: title, summary: summary,
		warning: s.planWarnings(rc, pl), preview: planText(pl, srv), files: planView(pl), back: back, done: rc.T("files.plan.done", pl.Name)}
	p.run = func(ctx context.Context, rc *reqCtx) error {
		var ar filesapi.ApplyResult
		if err := s.filesCall(ctx, rc, srv, filesapi.OpShareApply, filesapi.SharePlanParams{Spec: spec, Create: create, Digest: digest}, &ar); err != nil {
			return err
		}
		rc.sess.mu.Lock()
		if rc.sess.filesDraft == dr {
			rc.sess.filesDraft = nil
		}
		rc.sess.mu.Unlock()
		p.back = shareURL(srv, pl.Name)
		return nil
	}
	rc.propose(p)
}

// browseLink is the folder picker's link to another folder.
func browseLink(srvID, p string) string {
	return "/admin/files/" + srvID + "/wizard?step=folder&browse=" + url.QueryEscape(p)
}
