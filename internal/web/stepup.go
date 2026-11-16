package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Step-up for changes to second factors. Adding a TOTP authenticator or a
// security key from self-service needs the account proven again recently:
// the password and an existing second factor (at sign-in or on the step-up
// page), or the password alone for a user who has no second factor yet. A
// session cookie used for a few minutes is then not enough to plant a
// factor of the thief's. Removing a factor already asks for the password
// and a factor on its own page; new recovery codes need a current code
// under the sign-in's limits.

// stepUpWindow is how long a step-up allows adding a second factor (long
// enough to scan a QR code and type the first code).
const stepUpWindow = 10 * time.Minute

// stepUpFresh reports whether the session proved the account within
// stepUpWindow: a second factor (sign-in, enrollment, re-authentication),
// or the password when the user has no second factor.
func (s *Server) stepUpFresh(rc *reqCtx, hasFactor bool) bool {
	rc.sess.mu.Lock()
	at := rc.sess.mfaAt
	if !hasFactor && rc.sess.pwAt.After(at) {
		at = rc.sess.pwAt
	}
	rc.sess.mu.Unlock()
	return !at.IsZero() && s.now().Sub(at) <= stepUpWindow
}

// requireStepUp lets an addition of a second factor through when the
// step-up is fresh; otherwise it audits the refusal, sends the user to the
// step-up page and returns false.
func (s *Server) requireStepUp(ctx context.Context, rc *reqCtx, action string) bool {
	if s.stepUpFresh(rc, s.hasSecondFactor(ctx, rc.sess.userSID.String())) {
		return true
	}
	s.audit(ctx, rc, action, rc.sess.sam, "step-up required", store.ResultDenied)
	rc.flashErr("stepup.needed")
	rc.redirect("/me/security/verify")
	return false
}

func (s *Server) stepUpData(rc *reqCtx, hasFactor bool) map[string]any {
	d := map[string]any{"HasFactor": hasFactor, "Action": "/me/security/verify"}
	if hasFactor {
		s.addReauthOptions(rc, d)
	}
	return d
}

func (s *Server) handleStepUpPage(rc *reqCtx) {
	hasFactor := s.hasSecondFactor(rc.ctx(), rc.sess.userSID.String())
	rc.render(http.StatusOK, "me_stepup", s.stepUpData(rc, hasFactor))
}

func (s *Server) handleStepUp(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	sess := rc.sess
	hasFactor := s.hasSecondFactor(ctx, sess.userSID.String())
	fail := func(status int, key string) {
		d := s.stepUpData(rc, hasFactor)
		d["Error"] = rc.T(key)
		rc.render(status, "me_stepup", d)
	}
	if !s.ipLimit.Allow("2fa:" + rc.limitIP()) {
		fail(http.StatusTooManyRequests, "signin.err.rate_ip")
		return
	}
	var key string
	if hasFactor {
		key = s.reauthenticate(ctx, rc)
	} else {
		key = s.reauthenticatePassword(ctx, rc)
	}
	if key != "" {
		s.audit(ctx, rc, "mfa.step_up", sess.sam, "refused", store.ResultDenied)
		fail(http.StatusUnauthorized, key)
		return
	}
	detail := "password and second factor"
	if !hasFactor {
		detail = "password (no second factor yet)"
	}
	s.audit(ctx, rc, "mfa.step_up", sess.sam, detail, store.ResultOK)
	rc.flashOK("stepup.done")
	rc.redirect("/me/security")
}

// reauthenticatePassword is the step-up of a user without a second factor:
// the password again, under the per-account limit. It returns an i18n key
// on failure.
func (s *Server) reauthenticatePassword(ctx context.Context, rc *reqCtx) string {
	sess := rc.sess
	if s.accountFails.Blocked(sess.sam) {
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
	sess.mu.Lock()
	old := sess.cred
	sess.cred = cred
	sess.pwAt = s.now()
	sess.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return ""
}

// endSessionAfterMFAFailures ends a session that guessed second-factor
// codes too often, as the sign-in does.
func (s *Server) endSessionAfterMFAFailures(rc *reqCtx) {
	ctx := rc.ctx()
	s.sess.destroy(ctx, rc.sess)
	clearCookie(rc.w, sessionCookie)
	rc.redirectSignin("")
}

// notifyFactorAdded tells the user by e-mail (the account's mail and the
// recovery address) that a second factor was added to the account.
func (s *Server) notifyFactorAdded(ctx context.Context, rc *reqCtx) {
	if s.mailq == nil || rc.sess == nil {
		return
	}
	rc.sess.mu.Lock()
	userSID, sam := rc.sess.userSID.String(), rc.sess.sam
	rc.sess.mu.Unlock()
	var addr string
	_ = rc.withConn(ctx, func(conn *ad.Conn) error {
		u, err := s.me(ctx, rc, conn)
		addr = u.Mail
		return err
	})
	s.notifyFactorAddedTo(ctx, userSID, sam, addr, rc.lang, rc.ip)
}

// notifyFactorAddedTo sends the notice of an added second factor to an
// account's mail and its recovery address.
func (s *Server) notifyFactorAddedTo(ctx context.Context, userSID, sam, addr, lang, from string) {
	if s.mailq == nil {
		return
	}
	extra := ""
	if r, err := s.store.GetRecoveryEmail(ctx, userSID); err == nil {
		extra = r.Address
	}
	if lang == "" {
		lang = s.cfg.UI.DefaultLanguage
	}
	for _, to := range recipients(addr, extra) {
		if _, err := s.queueMail(ctx, mail.TemplateFactorAdded, lang, to, mail.Data{Username: sam, When: s.now(), From: from},
			s.now().Add(mail.NotificationLifetime), "notify"); err != nil {
			s.log.Error("queueing a second factor notice", "user", sam, "err", err)
		}
	}
}
