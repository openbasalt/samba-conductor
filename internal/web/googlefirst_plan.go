package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// The Google-first plan: requested from conductor-sync (g2a.plan), shown
// grouped by scope and kind with its skips, warnings and limits, and
// applied operation by operation through conductor-provisioner after a
// typed digest prefix and re-authentication. Limits are never overridden
// here: a blocked scope is not applied.

// g2aApplier executes the operations of a Google-first plan, one method
// per operation kind. ref is the correlation value the provisioner keeps
// in its own audit log (the plan run). The provisioner re-checks every
// operation against its own invariants (scope, privileged accounts,
// ceilings, the marker, the current values) and refuses what does not
// hold.
type g2aApplier interface {
	Update(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) error
	Rename(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) error
	Reenable(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) error
	Create(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) (g2aCreated, error)
	Disable(ctx context.Context, actor provapi.Actor, ref string, op syncapi.G2AOp) error
}

// g2aCreated identifies the account a create made.
type g2aCreated struct {
	SID, ObjectGUID string
}

// errG2AUnsupported: the operation kind is unknown to this conductor.
var errG2AUnsupported = errors.New("web: unknown Google-first operation kind")

// Timeouts: a plan reads Google and AD; an apply runs every operation and
// then reports them, whatever happens to the browser's request.
const (
	g2aPlanTimeout  = 3 * time.Minute
	g2aApplyTimeout = 10 * time.Minute
	// gfOpsShown bounds the operations shown per kind on the plan page.
	gfOpsShown = 200
	// gfAuditSkips bounds the privileged skips audited one by one per plan.
	gfAuditSkips = 100
)

// roleGroupSIDs are conductor's admin, helpdesk and auditor role groups:
// their members are privileged for the plan (P1).
func (s *Server) roleGroupSIDs() []string {
	var out []string
	for _, list := range [][]string{sidStrings(s.roleSIDs.admin), sidStrings(s.roleSIDs.helpdesk), sidStrings(s.roleSIDs.auditor)} {
		for _, v := range list {
			if !slices.Contains(out, v) && len(out) < 32 {
				out = append(out, v)
			}
		}
	}
	return out
}

func sidStrings(list []sid.SID) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		out = append(out, v.String())
	}
	return out
}

// ---- plan ----

// handleGoogleFirstPlan checks P3, requests a plan for one scope or all,
// audits it (with every privileged account skipped) and opens it.
func (s *Server) handleGoogleFirstPlan(rc *reqCtx) {
	if s.gfDisabled(rc) {
		return
	}
	ctx, cancel := context.WithTimeout(rc.ctx(), g2aPlanTimeout)
	defer cancel()
	back := "/admin/google-first"
	scope := rc.form("scope")
	if scope != "" && !syncapi.ValidG2AScopeName(scope) {
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	gf, err := s.googleFirst(ctx, rc, true)
	if err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(back)
		return
	}
	if !gf.Enabled {
		rc.flashErr("gf.plan.err_off")
		rc.redirect(back)
		return
	}
	if r := s.p3Check(ctx, rc, gf.GoogleDomain); !r.OK() {
		s.audit(ctx, rc, "g2a.p3_refused", "google-first", "plan request: "+r.summary(), store.ResultDenied)
		rc.sess.addFlash("error", s.errMessage(rc.T, p3Error(r)))
		rc.redirect(back)
		return
	}
	var pl syncapi.G2APlan
	if err := s.syncCall(ctx, rc, syncapi.OpG2APlan, syncapi.G2APlanParams{Scope: scope, RoleGroupSIDs: s.roleGroupSIDs()}, &pl); err != nil {
		s.audit(ctx, rc, "g2a.plan", "google-first", "scope="+orAll(scope)+"; "+s.syncErrT(func(k string, a ...any) string { return s.cat.T("en", k, a...) }, err), store.ResultFailed)
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(back)
		return
	}
	s.auditPlan(ctx, rc, scope, &pl)
	rc.flashOK("gf.plan.done", pl.RunID)
	rc.redirect(fmt.Sprintf("/admin/google-first/runs/%d", pl.RunID))
}

func orAll(scope string) string {
	if scope == "" {
		return "all"
	}
	return scope
}

// auditPlan records the plan (counts) and each privileged account it
// skipped, so a human acts on them in AD (P1).
func (s *Server) auditPlan(ctx context.Context, rc *reqCtx, scope string, pl *syncapi.G2APlan) {
	var b strings.Builder
	fmt.Fprintf(&b, "scope=%s; run %d, digest %s; P3 check passed", orAll(scope), pl.RunID, pl.Digest)
	skips := 0
	for _, sp := range pl.Scopes {
		counts := map[string]int{}
		for _, o := range sp.Ops {
			counts[o.Kind]++
		}
		fmt.Fprintf(&b, "\n%s mode=%s source=%d managed=%d blocked=%v", sp.Name, sp.Mode, sp.SourceSize, sp.Managed, sp.Blocked)
		for _, k := range syncapi.G2AKinds {
			if counts[k] > 0 {
				fmt.Fprintf(&b, " %s=%d", k, counts[k])
			}
		}
		for _, sk := range sp.Skipped {
			if sk.Reason != syncapi.G2ASkipPrivileged {
				continue
			}
			skips++
			if skips <= gfAuditSkips {
				s.audit(ctx, rc, "g2a.skip.privileged", sk.DN, fmt.Sprintf("run %d, scope %s, account %s: %s", pl.RunID, sp.Name, sk.SAM,
					strings.Join(sk.Detail, ", ")), store.ResultOK)
			}
		}
	}
	if skips > 0 {
		fmt.Fprintf(&b, "\nprivileged accounts skipped: %d", skips)
	}
	s.audit(ctx, rc, "g2a.plan", "run "+fmt.Sprint(pl.RunID), b.String(), store.ResultOK)
}

// g2aFullPlan reads a run with every operation of its plan (pages of 500
// merged by scope).
func (s *Server) g2aFullPlan(ctx context.Context, rc *reqCtx, id int64) (*syncapi.RunDetail, error) {
	var first *syncapi.RunDetail
	got := 0
	for offset := 0; ; {
		var det syncapi.RunDetail
		if err := s.syncCall(ctx, rc, syncapi.OpRunGet, syncapi.RunGetParams{ID: id, Offset: offset, Limit: 500}, &det); err != nil {
			return nil, err
		}
		if det.G2A == nil {
			return &det, nil
		}
		n := 0
		for _, sp := range det.G2A.Scopes {
			n += len(sp.Ops)
		}
		if first == nil {
			first = &det
		} else {
			for _, sp := range det.G2A.Scopes {
				for i := range first.G2A.Scopes {
					if first.G2A.Scopes[i].Name == sp.Name {
						first.G2A.Scopes[i].Ops = append(first.G2A.Scopes[i].Ops, sp.Ops...)
					}
				}
			}
		}
		got += n
		offset += n
		if n == 0 || got >= det.OpsMatching {
			return first, nil
		}
	}
}

// ---- plan page ----

// gfOpView is one operation with what conductor reported for it.
type gfOpView struct {
	syncapi.G2AOp
	Result *syncapi.G2AOpResult
}

// gfKindGroup is the operations of one kind in a scope.
type gfKindGroup struct {
	Kind  string
	Ops   []gfOpView
	Count int
	More  int
}

// gfScopeView is one scope of the plan page.
type gfScopeView struct {
	syncapi.G2AScopePlan
	Groups     []gfKindGroup
	Privileged []syncapi.G2ASkipped
	Skips      []syncapi.G2ASkipped
	// CurrentMode is the scope's mode now ("" when it was removed since).
	CurrentMode string
	// Applies: the scope's operations run when the plan is applied.
	Applies bool
	Count   int
	// Confirmation is what is typed to switch the scope to apply.
	Confirmation string
}

// gfApplicable reports whether the operations of a planned scope can be
// applied now: apply in the plan and in the current settings, within its
// limits, and the mode on.
func gfApplicable(sp syncapi.G2AScopePlan, gf syncapi.GoogleFirstSettings) bool {
	if !gf.Enabled || sp.Blocked || sp.Mode != syncapi.G2AModeApply {
		return false
	}
	i := gfScopeIndex(gf, sp.Name)
	return i >= 0 && gf.Scopes[i].Mode == syncapi.G2AModeApply
}

// gfScopeViews builds the plan page's scopes.
func gfScopeViews(pl *syncapi.G2APlan, results []syncapi.G2AOpResult, gf syncapi.GoogleFirstSettings) []gfScopeView {
	bySeq := map[int]*syncapi.G2AOpResult{}
	for i := range results {
		bySeq[results[i].Seq] = &results[i]
	}
	var out []gfScopeView
	for _, sp := range pl.Scopes {
		v := gfScopeView{G2AScopePlan: sp, Applies: gfApplicable(sp, gf), Count: len(sp.Ops), Confirmation: modeConfirmation(sp.Name, pl.Digest)}
		if i := gfScopeIndex(gf, sp.Name); i >= 0 {
			v.CurrentMode = gf.Scopes[i].Mode
		}
		for _, k := range syncapi.G2AKinds {
			g := gfKindGroup{Kind: k}
			for _, o := range sp.Ops {
				if o.Kind != k {
					continue
				}
				g.Count++
				if len(g.Ops) < gfOpsShown {
					g.Ops = append(g.Ops, gfOpView{G2AOp: o, Result: bySeq[o.Seq]})
				}
			}
			if g.Count > 0 {
				g.More = g.Count - len(g.Ops)
				v.Groups = append(v.Groups, g)
			}
		}
		for _, sk := range sp.Skipped {
			if sk.Reason == syncapi.G2ASkipPrivileged {
				v.Privileged = append(v.Privileged, sk)
			} else {
				v.Skips = append(v.Skips, sk)
			}
		}
		out = append(out, v)
	}
	return out
}

// handleGoogleFirstRun shows a plan.
func (s *Server) handleGoogleFirstRun(rc *reqCtx) {
	if s.gfDisabled(rc) {
		return
	}
	id, ok := runIDParam(rc)
	if !ok {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	det, err := s.g2aFullPlan(ctx, rc, id)
	if err != nil {
		if syncapi.ErrorCodeOf(err) == syncapi.CodeNotFound {
			rc.errorPage(http.StatusNotFound, "err.not_found")
			return
		}
		rc.render(http.StatusOK, "google_first_run", map[string]any{"Error": s.syncErr(rc, err)})
		return
	}
	if det.G2A == nil {
		rc.errorPage(http.StatusNotFound, "gf.run.not_g2a")
		return
	}
	d := map[string]any{"R": det, "CanWrite": rc.roles.Has(PermSyncWrite), "Short": shortDigest(det.G2A.Digest),
		"Confirm": applyConfirmation(det.G2A.Digest)}
	gf, err := s.googleFirst(ctx, rc, true)
	if err != nil {
		d["Error"] = s.syncErr(rc, err)
	}
	d["GF"] = gf
	views := gfScopeViews(det.G2A, det.G2AResults, gf)
	d["Scopes"] = views
	last, _, _ := s.g2aLatest(ctx, rc)
	latest := last != nil && last.Run.ID == id
	d["Latest"] = latest
	d["P3"] = s.p3Check(ctx, rc, gf.GoogleDomain)
	applicable := 0
	for _, v := range views {
		if v.Applies {
			applicable += v.Count
		}
	}
	d["Applicable"] = applicable
	switch {
	case det.Run.Status != syncapi.StatusPlanned:
		d["NotApply"] = "closed"
	case !latest:
		d["NotApply"] = "not_latest"
	case !gf.Enabled:
		d["NotApply"] = "off"
	case applicable == 0:
		d["NotApply"] = "nothing"
	case s.g2a == nil:
		d["NotApply"] = "unsupported"
	}
	rc.render(http.StatusOK, "google_first_run", d)
}

// ---- apply ----

// gfApplyOp is one operation to apply with its scope.
type gfApplyOp struct {
	Scope string
	Op    syncapi.G2AOp
}

// gfApplyOps returns the operations to apply, in the global apply order
// (updates, renames, re-enables, creates, disables; then Seq).
func gfApplyOps(pl *syncapi.G2APlan, gf syncapi.GoogleFirstSettings) []gfApplyOp {
	var out []gfApplyOp
	for _, sp := range pl.Scopes {
		if !gfApplicable(sp, gf) {
			continue
		}
		for _, o := range sp.Ops {
			out = append(out, gfApplyOp{Scope: sp.Name, Op: o})
		}
	}
	rank := func(k string) int {
		if i := slices.Index(syncapi.G2AKinds, k); i >= 0 {
			return i
		}
		return len(syncapi.G2AKinds)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank(out[i].Op.Kind), rank(out[j].Op.Kind)
		if ri != rj {
			return ri < rj
		}
		return out[i].Op.Seq < out[j].Op.Seq
	})
	return out
}

// applyConfirmation is what is typed to apply a plan: the first 8
// characters of its digest.
func applyConfirmation(digest string) string {
	if len(digest) > 8 {
		return digest[:8]
	}
	return digest
}

// handleGoogleFirstRunApply checks the typed digest prefix against a fresh
// read of the plan and the settings, then proposes the apply
// (re-authentication required).
func (s *Server) handleGoogleFirstRunApply(rc *reqCtx) {
	if s.gfDisabled(rc) {
		return
	}
	id, ok := runIDParam(rc)
	if !ok {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	back := fmt.Sprintf("/admin/google-first/runs/%d", id)
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	refuse := func(key string, args ...any) {
		s.audit(ctx, rc, "g2a.apply", fmt.Sprintf("run %d", id), "refused: "+key, store.ResultDenied)
		rc.flashErr(key, args...)
		rc.redirect(back)
	}
	if s.g2a == nil {
		refuse("gf.apply.err_unsupported")
		return
	}
	det, err := s.g2aFullPlan(ctx, rc, id)
	if err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(back)
		return
	}
	if det.G2A == nil {
		rc.errorPage(http.StatusNotFound, "gf.run.not_g2a")
		return
	}
	pl := det.G2A
	switch {
	case det.Run.Status != syncapi.StatusPlanned:
		refuse("gf.apply.err_closed")
		return
	case rc.form("digest") != pl.Digest:
		refuse("gf.apply.err_changed")
		return
	case rc.form("confirm") != applyConfirmation(pl.Digest):
		refuse("gf.apply.err_confirm", applyConfirmation(pl.Digest))
		return
	}
	if last, _, err := s.g2aLatest(ctx, rc); err != nil || last == nil || last.Run.ID != id {
		refuse("gf.apply.err_not_latest")
		return
	}
	gf, err := s.googleFirst(ctx, rc, true)
	if err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(back)
		return
	}
	if !gf.Enabled {
		refuse("gf.plan.err_off")
		return
	}
	if r := s.p3Check(ctx, rc, gf.GoogleDomain); !r.OK() {
		s.audit(ctx, rc, "g2a.p3_refused", fmt.Sprintf("run %d", id), "apply: "+r.summary(), store.ResultDenied)
		rc.sess.addFlash("error", s.errMessage(rc.T, p3Error(r)))
		rc.redirect(back)
		return
	}
	ops := gfApplyOps(pl, gf)
	if len(ops) == 0 {
		refuse("gf.apply.err_nothing")
		return
	}
	lines := []string{"conductor g2a apply (through conductor-provisioner)", fmt.Sprintf("run: %d", id), "digest: " + pl.Digest,
		"order: updates, renames, re-enables, creates, disables"}
	creates := 0
	for _, sp := range pl.Scopes {
		if !gfApplicable(sp, gf) {
			lines = append(lines, fmt.Sprintf("# scope %s: not applied (%s)", sp.Name, gfWhyNot(sp, gf)))
			continue
		}
		counts := map[string]int{}
		for _, o := range sp.Ops {
			counts[o.Kind]++
		}
		creates += counts[syncapi.G2AUserCreate]
		var parts []string
		for _, k := range syncapi.G2AKinds {
			if counts[k] > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
			}
		}
		lines = append(lines, fmt.Sprintf("scope %s: %s", sp.Name, strings.Join(parts, " ")))
	}
	lines = append(lines, "then: conductor-sync "+string(syncapi.OpG2AConfirm))
	warning := rc.T("gf.apply.warning")
	if creates > 0 && len(s.missingForLinks()) > 0 {
		warning += " " + rc.T("gf.apply.no_invitations")
	}
	p := &pendingOp{perm: PermSyncWrite, action: "g2a.apply", target: fmt.Sprintf("run %d", id), reauth: true, reauthKey: "gf.apply.reauth",
		title: rc.T("gf.apply.title", id), summary: rc.T("gf.apply.summary", len(ops)), warning: warning,
		preview: strings.Join(lines, "\n"), back: back}
	digest := pl.Digest
	p.run = func(ctx context.Context, rc *reqCtx) error {
		// The operations and their report run to the end even if the
		// browser goes away.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), g2aApplyTimeout)
		defer cancel()
		gf, err := s.googleFirst(ctx, rc, true)
		if err != nil {
			return err
		}
		if !gf.Enabled {
			return &gfError{key: "gf.plan.err_off"}
		}
		if r := s.p3Check(ctx, rc, gf.GoogleDomain); !r.OK() {
			s.audit(ctx, rc, "g2a.p3_refused", fmt.Sprintf("run %d", id), "apply: "+r.summary(), store.ResultDenied)
			return p3Error(r)
		}
		ops := gfApplyOps(pl, gf)
		if len(ops) == 0 {
			return &gfError{key: "gf.apply.err_nothing"}
		}
		out := s.g2aExecute(ctx, rc, id, digest, ops)
		p.preview += fmt.Sprintf("\n# done %d, failed %d, not attempted %d, invitations sent %d, failed %d, not possible %d",
			out.done, out.failed, out.skipped, out.invites, out.inviteErrs, out.noInvit)
		rc.sess.mu.Lock()
		actor := rc.sess.sam
		rc.sess.mu.Unlock()
		var res syncapi.G2AConfirmResult
		err = s.syncCall(ctx, rc, syncapi.OpG2AConfirm, syncapi.G2AConfirmParams{RunID: id, Digest: digest, Results: out.results, Actor: actor}, &res)
		if err != nil {
			s.audit(ctx, rc, "g2a.confirm", fmt.Sprintf("run %d", id), fmt.Sprintf("digest %s, %d results; refused", digest, len(out.results)), store.ResultFailed)
			p.preview += "\n# g2a.confirm failed"
			return err
		}
		s.audit(ctx, rc, "g2a.confirm", fmt.Sprintf("run %d", id), fmt.Sprintf("digest %s; status %s, done %d, failed %d, skipped %d, links %d",
			digest, res.Status, res.Done, res.Failed, res.Skipped, res.Links), store.ResultOK)
		p.done = rc.T("gf.apply.done", out.done, out.failed, out.skipped, rc.T("sync.status."+res.Status))
		if out.inviteErrs > 0 {
			rc.flashErr("gf.apply.invite_failed", out.inviteErrs)
		}
		return nil
	}
	rc.propose(p)
}

// gfWhyNot says (for the preview) why a scope of the plan is not applied.
func gfWhyNot(sp syncapi.G2AScopePlan, gf syncapi.GoogleFirstSettings) string {
	switch {
	case sp.Blocked:
		return "limits exceeded"
	case sp.Mode != syncapi.G2AModeApply:
		return "dry-run in the plan"
	case gfScopeIndex(gf, sp.Name) < 0:
		return "removed since the plan"
	}
	return "dry-run now"
}

// g2aOutcome is what an apply did.
type g2aOutcome struct {
	results                      []syncapi.G2AOpResult
	done, failed, skipped        int
	invites, inviteErrs, noInvit int
}

// g2aStops reports whether an error stops the apply: the provisioner is
// unreachable, off or at its hourly ceiling, or time ran out. The
// remaining operations are reported as not attempted.
func g2aStops(err error) bool {
	if errors.Is(err, errProvisionerOff) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	switch provapi.ErrorCodeOf(err) {
	case provapi.CodeRateLimited, provapi.CodeUnavailable:
		return true
	}
	return false
}

// g2aErrText is an operation's error as reported to conductor-sync and
// shown on the plan page: the provisioner's code and the translated
// message (with what collided or conflicted), bounded.
func g2aErrText(t func(string, ...any) string, err error) string {
	msg := provCode(err) + ": " + t(g2aErrKey(err), g2aErrKinds(err))
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return msg
}

// g2aOpDetail is the audit text of one applied operation: the run, the
// digest, the scope and the changes with before and after.
func g2aOpDetail(runID int64, digest, scope string, op syncapi.G2AOp) string {
	var b strings.Builder
	fmt.Fprintf(&b, "run %d, digest %s, seq %d, scope %s\ngoogle_id: %s\nsam: %s\nreason: %s", runID, digest, op.Seq, scope, op.GoogleID, op.SAM, op.Reason)
	for _, c := range op.Changes {
		fmt.Fprintf(&b, "\n%s: %q -> %q", c.Field, c.Before, c.After)
	}
	if op.MoveTo != "" {
		fmt.Fprintf(&b, "\nmove to: %s", op.MoveTo)
	}
	if op.Enable {
		b.WriteString("\nenable")
	}
	if op.Disable {
		b.WriteString("\ndisable")
	}
	return b.String()
}

// g2aMail is the address a create sets (its "mail" change).
func g2aMail(op syncapi.G2AOp) string {
	for _, c := range op.Changes {
		if c.Field == "mail" {
			return c.After
		}
	}
	return ""
}

// g2aExecute runs the operations through the applier, audits each one
// (g2a.apply.<kind>), issues the invitations of the accounts created when
// e-mail and the provisioner allow it, and returns the results to report.
func (s *Server) g2aExecute(ctx context.Context, rc *reqCtx, runID int64, digest string, ops []gfApplyOp) g2aOutcome {
	var out g2aOutcome
	actor := sessionActor(rc)
	rc.sess.mu.Lock()
	issuerSID, issuerName := rc.sess.userSID.String(), rc.sess.sam
	rc.sess.mu.Unlock()
	ref := fmt.Sprintf("g2a run %d", runID)
	links := len(s.missingForLinks()) == 0
	stopped := ""
	for _, a := range ops {
		op := a.Op
		r := syncapi.G2AOpResult{Seq: op.Seq}
		if stopped != "" {
			r.Status, r.Error = syncapi.G2AOpSkipped, "not attempted: "+stopped
			out.results = append(out.results, r)
			out.skipped++
			continue
		}
		var err error
		var created g2aCreated
		switch op.Kind {
		case syncapi.G2AUserUpdate:
			err = s.g2a.Update(ctx, actor, ref, op)
		case syncapi.G2AUserRename:
			err = s.g2a.Rename(ctx, actor, ref, op)
		case syncapi.G2AUserReenable:
			err = s.g2a.Reenable(ctx, actor, ref, op)
		case syncapi.G2AUserCreate:
			created, err = s.g2a.Create(ctx, actor, ref, op)
		case syncapi.G2AUserDisable:
			err = s.g2a.Disable(ctx, actor, ref, op)
		default:
			err = errG2AUnsupported
		}
		detail := g2aOpDetail(runID, digest, a.Scope, op)
		target := op.DN
		if target == "" {
			target = op.SAM
		}
		if err != nil {
			r.Status, r.Error = syncapi.G2AOpFailed, g2aErrText(rc.T, err)
			out.failed++
			s.audit(ctx, rc, "g2a.apply."+op.Kind, target, detail+"\n# error: "+provCode(err), resultOf(err))
			out.results = append(out.results, r)
			if g2aStops(err) {
				stopped = provCode(err)
			}
			continue
		}
		r.Status = syncapi.G2AOpDone
		if op.Kind == syncapi.G2AUserCreate {
			r.SID, r.ObjectGUID = created.SID, created.ObjectGUID
			detail += "\nsid: " + created.SID
		}
		out.done++
		s.audit(ctx, rc, "g2a.apply."+op.Kind, target, detail, store.ResultOK)
		out.results = append(out.results, r)
		if op.Kind != syncapi.G2AUserCreate || !op.Invite {
			continue
		}
		addr := g2aMail(op)
		if !links {
			out.noInvit++
			s.audit(ctx, rc, "invite.skipped", target, "Google-first create: e-mail, the provisioner or the public URL is not configured", store.ResultOK)
			continue
		}
		hours := s.passwordSettings(ctx).InviteHours
		inv, ierr := s.issueLink(ctx, issueRequest{actor: actor, sid: created.SID, purpose: provapi.PurposeInvite,
			lang: s.cfg.UI.DefaultLanguage, issuerSID: issuerSID, issuerName: issuerName})
		ipreview := invitePreview(op.SAM, created.SID, addr, hours) + "\n# " + ref
		if ierr != nil {
			out.inviteErrs++
			s.audit(ctx, rc, "invite.issued", target, ipreview+"\n# provisioner: "+provCode(ierr), resultOf(ierr))
			continue
		}
		out.invites++
		s.audit(ctx, rc, "invite.issued", target, ipreview+"\n# token "+inv.TokenID+", message "+strings.Join(inv.MailIDs, ",")+
			" to "+strings.Join(inv.Domains, ", "), store.ResultOK)
	}
	return out
}
