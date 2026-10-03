package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/ad/sambatool"
	"github.com/samba-conductor/conductor-sync/syncapi"
	"github.com/samba-conductor/conductor/internal/directory"
	"github.com/samba-conductor/conductor/internal/store"
	"github.com/samba-conductor/conductor/internal/totp"
)

// pendingTTL bounds how long a preview may wait for confirmation.
const pendingTTL = 10 * time.Minute

// pendingOp is a previewed write awaiting confirmation. The exact
// ad.Operation shown in the preview is the one applied: nothing is rebuilt
// from the confirmation request.
type pendingOp struct {
	id      string
	created time.Time
	perm    Perm   // re-checked at confirmation
	action  string // audit action, e.g. "user.reset_password"
	target  string // DN or user
	title   string // translated title of the confirmation page
	summary string // translated one-line description
	warning string // translated warning (optional)
	// op is an LDAP write applied with the user's own connection; run is
	// a non-LDAP action (2FA reset, enrollment link). Exactly one is set.
	op  *ad.Operation
	run func(ctx context.Context, rc *reqCtx) error
	// preview text shown and audited (LDIF with secrets redacted).
	preview string
	// reauth requires password + TOTP again (writes to administrators).
	reauth bool
	// back is where to go after confirming or cancelling.
	back string
	// done is the translated success message.
	done string
}

// propose stores a pending operation and sends the browser to its preview.
func (rc *reqCtx) propose(p *pendingOp) {
	p.id = newToken()[:22]
	p.created = rc.s.now()
	if p.op != nil {
		p.preview = p.op.Preview().String()
	}
	rc.sess.mu.Lock()
	if rc.sess.pending == nil {
		rc.sess.pending = map[string]*pendingOp{}
	}
	// Bound the number of open previews per session.
	if len(rc.sess.pending) >= 20 {
		var oldest string
		for id, o := range rc.sess.pending {
			if oldest == "" || o.created.Before(rc.sess.pending[oldest].created) {
				oldest = id
			}
		}
		delete(rc.sess.pending, oldest)
	}
	rc.sess.pending[p.id] = p
	rc.sess.mu.Unlock()
	rc.redirect("/confirm/" + p.id)
}

func (rc *reqCtx) pendingOp() *pendingOp {
	id := rc.r.PathValue("id")
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	p := rc.sess.pending[id]
	if p == nil || rc.s.now().Sub(p.created) > pendingTTL {
		delete(rc.sess.pending, id)
		return nil
	}
	return p
}

// confirmAllowed re-checks the operation's permission against fresh roles.
func (s *Server) confirmAllowed(rc *reqCtx, p *pendingOp) bool {
	if p.perm == PermSelf {
		return true
	}
	roles, err := s.rolesFor(rc.ctx(), rc.sess)
	if err != nil {
		s.sess.destroy(rc.ctx(), rc.sess)
		clearCookie(rc.w, sessionCookie)
		rc.redirectSignin("reauth")
		return false
	}
	rc.roles = roles
	if !roles.Has(p.perm) {
		s.audit(rc.ctx(), rc, "access.denied", p.target, p.action+" requires "+string(p.perm), store.ResultDenied)
		rc.errorPage(http.StatusForbidden, "err.forbidden")
		return false
	}
	return true
}

func (s *Server) confirmData(p *pendingOp, errMsg string) map[string]any {
	return map[string]any{"ID": p.id, "Title": p.title, "Summary": p.summary, "Warning": p.warning,
		"Preview": p.preview, "Reauth": p.reauth, "Back": p.back, "Error": errMsg, "Target": p.target}
}

// confirmPageData adds what the re-authentication form needs.
func (s *Server) confirmPageData(rc *reqCtx, p *pendingOp, errMsg string) map[string]any {
	d := s.confirmData(p, errMsg)
	if p.reauth {
		d["HasKeys"] = s.hasKeys(rc)
		d["CodeAllowed"] = !s.keyRequired(rc.roles)
	}
	return d
}

func (s *Server) handleConfirmPage(rc *reqCtx) {
	p := rc.pendingOp()
	if p == nil {
		rc.errorPage(http.StatusNotFound, "confirm.err.gone")
		return
	}
	if !s.confirmAllowed(rc, p) {
		return
	}
	rc.render(http.StatusOK, "confirm", s.confirmPageData(rc, p, ""))
}

func (s *Server) handleCancel(rc *reqCtx) {
	p := rc.pendingOp()
	if p == nil {
		rc.redirect("/")
		return
	}
	rc.sess.mu.Lock()
	delete(rc.sess.pending, p.id)
	rc.sess.mu.Unlock()
	rc.flashOK("confirm.cancelled")
	rc.redirect(p.back)
}

// reauthenticate verifies the password (a fresh Kerberos sign-in, whose
// ticket then replaces the session's) and a second-factor code.
func (s *Server) reauthenticate(ctx context.Context, rc *reqCtx) string {
	sess := rc.sess
	if s.accountFails.Blocked(sess.sam) || s.mfaFails.Blocked(sess.sam) {
		return "signin.err.rate_account"
	}
	cred, err := s.backend.SignIn(ctx, sess.sam, rc.rawForm("password"))
	if err != nil {
		s.accountFails.Fail(sess.sam)
		var ae *ad.AuthError
		if errors.As(err, &ae) {
			return "reauth.err.password"
		}
		return "err.directory"
	}
	if resp := rc.rawForm("response"); resp != "" {
		// A security key instead of a code.
		if err := s.verifyKey(ctx, sess, waReauth, resp); err != nil {
			cred.Close()
			s.mfaFails.Fail(sess.sam)
			s.log.Info("security key re-authentication refused", "user", sess.sam, "err", err)
			return "mfa.err.key"
		}
	} else {
		code := rc.form("code")
		sess.mu.Lock()
		keyRequired := s.keyRequired(sess.roles)
		sess.mu.Unlock()
		if keyRequired && !totp.LooksLikeRecoveryCode(code) {
			cred.Close()
			return "mfa.err.key_required"
		}
		ok, _, err := s.verifySecondFactor(ctx, sess, code)
		if err != nil || !ok {
			cred.Close()
			s.mfaFails.Fail(sess.sam)
			return "mfa.err.code"
		}
	}
	sess.mu.Lock()
	old := sess.cred
	sess.cred = cred
	sess.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return ""
}

func (s *Server) handleConfirm(rc *reqCtx) {
	p := rc.pendingOp()
	if p == nil {
		rc.errorPage(http.StatusNotFound, "confirm.err.gone")
		return
	}
	if !s.confirmAllowed(rc, p) {
		return
	}
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	if p.reauth {
		if key := s.reauthenticate(ctx, rc); key != "" {
			s.audit(ctx, rc, p.action, p.target, "re-authentication failed", store.ResultDenied)
			rc.render(http.StatusUnauthorized, "confirm", s.confirmPageData(rc, p, rc.T(key)))
			return
		}
	}
	// Single use: remove before applying.
	rc.sess.mu.Lock()
	delete(rc.sess.pending, p.id)
	rc.sess.mu.Unlock()
	var err error
	var perDC []ad.DCResult
	if p.op != nil && len(p.op.DCs()) > 0 {
		rc.sess.mu.Lock()
		cred := rc.sess.cred
		rc.sess.mu.Unlock()
		perDC, err = s.applyOnEveryDC(ctx, cred, p.op)
	} else if p.op != nil {
		err = rc.withConn(ctx, func(conn *ad.Conn) error { return conn.Apply(ctx, p.op) })
	} else {
		err = p.run(ctx, rc)
	}
	detail := p.preview
	if p.reauth {
		detail = "[re-authenticated]\n" + detail
	}
	if len(perDC) > 0 {
		detail += "\n# per DC: " + dcReport(func(k string, a ...any) string { return rc.s.cat.T("en", k, a...) }, perDC)
	}
	if err != nil {
		key := s.adErrorKey(err)
		s.log.Warn("operation failed", "action", p.action, "target", p.target, "user", rc.sess.sam, "err", err)
		s.audit(ctx, rc, p.action, p.target, detail+"\n# error: "+key, resultOf(err))
		rc.sess.addFlash("error", s.errMessage(rc.T, err))
		rc.redirect(p.back)
		return
	}
	s.audit(ctx, rc, p.action, p.target, detail, store.ResultOK)
	if p.done != "" {
		rc.sess.addFlash("ok", p.done)
	}
	rc.redirect(p.back)
}

func resultOf(err error) string {
	if errors.Is(err, ad.ErrAccessDenied) || errors.Is(err, errForbiddenTarget) {
		return store.ResultDenied
	}
	return store.ResultFailed
}

// errForbiddenTarget is raised when conductor itself refuses a target
// (a protected account for helpdesk, a domain controller).
var errForbiddenTarget = errors.New("web: target not allowed")

// adErrorKey maps an error to a friendly message key; details only go to
// the server log.
func (s *Server) adErrorKey(err error) string {
	switch {
	case errors.Is(err, errForbiddenTarget):
		return "err.protected"
	case errors.Is(err, ad.ErrAccessDenied):
		return "err.ad.access_denied"
	case errors.Is(err, ad.ErrPasswordPolicy):
		return "password.err.policy"
	case errors.Is(err, ad.ErrWrongPassword):
		return "password.err.current"
	case errors.Is(err, ad.ErrConflict):
		return "err.ad.conflict"
	case errors.Is(err, ad.ErrNotFound):
		return "err.ad.not_found"
	case errors.Is(err, ad.ErrAlreadyExists):
		return "err.ad.exists"
	case errors.Is(err, ad.ErrNoChange):
		return "err.ad.no_change"
	case errors.Is(err, ad.ErrProtectedObject):
		return "err.protected"
	case errors.Is(err, ad.ErrInvalid):
		return "form.invalid"
	case errors.Is(err, directory.ErrNoTicket):
		return "err.no_ticket"
	}
	var te *sambatool.ExitError
	if errors.As(err, &te) {
		return "err.tool"
	}
	var he *helper.Error
	if errors.As(err, &he) {
		switch he.Code {
		case helper.CodeUnavailable:
			return "backups.err.busy"
		case helper.CodeNotAllowed:
			return "backups.err.not_configured"
		}
		return "backups.err.helper"
	}
	if errors.Is(err, errHelperDisabled) {
		return "backups.err.helper"
	}
	var se *syncapi.Error
	if errors.As(err, &se) || errors.Is(err, errSyncDisabled) {
		return "sync.err.failed"
	}
	if isNotAllowedOnNonLeaf(err) {
		return "err.ad.not_empty"
	}
	return "err.ad.generic"
}
