package web

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Connected accounts (self-service): a signed-in user's own accounts on
// the directories conductor-sync provisions to. conductor knows nothing of
// a particular target: it shows what conductor-sync reports for each one
// (state, capabilities, password rules) and offers only the actions that
// target supports and allows now.
//
//   - Every action is for the signed-in user only: conductor-sync acts on
//     the request's actor (by SID), never on a user named in a form.
//   - Every action needs a session that passed a second factor; when that
//     was more than accountsFreshMFA ago, the confirmation asks for the
//     password and a second factor again (step-up).
//   - A generated password comes back from conductor-sync once. It is kept
//     in the session's memory only until the user opens the page that shows
//     it (once, no-store), and is never written to the database, a log or
//     the audit. A password the user types goes to conductor-sync once and
//     is never shown or kept after the confirmation.

// accountsFreshMFA is how recent the session's second factor must be for a
// connected-account action without asking for it again.
const accountsFreshMFA = 5 * time.Minute

// accountActionTimeout bounds one action (an activation reads the whole
// sync scope); it stays below the HTTP server's write timeout.
const accountActionTimeout = 85 * time.Second

var accountTargetRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// accountSecret is a generated password waiting to be shown once.
type accountSecret struct {
	Title, Address, Password string
	Activated                bool
	at                       time.Time
}

// keepAccountSecret stores a generated password in the session (memory
// only) and returns its reference.
func (rc *reqCtx) keepAccountSecret(v accountSecret) string {
	ref := newToken()[:22]
	v.at = rc.s.now()
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	if rc.sess.accountSecrets == nil {
		rc.sess.accountSecrets = map[string]accountSecret{}
	}
	for k, old := range rc.sess.accountSecrets {
		if rc.s.now().Sub(old.at) > pendingTTL {
			delete(rc.sess.accountSecrets, k)
		}
	}
	rc.sess.accountSecrets[ref] = v
	return ref
}

// accountReason translates a reason code from conductor-sync (an unknown
// code gives a generic sentence).
func accountReason(t func(string, ...any) string, code string) string {
	if code == "" {
		return ""
	}
	msg := t("accounts.reason." + code)
	if strings.HasPrefix(msg, "[") {
		return t("accounts.reason.other")
	}
	return msg
}

// accountView is one target as the page shows it.
type accountView struct {
	syncapi.TargetAccount
	ReasonText, ActivateText, PasswordText string
}

func (s *Server) accountViews(rc *reqCtx, list []syncapi.TargetAccount) []accountView {
	out := make([]accountView, 0, len(list))
	for _, a := range list {
		v := accountView{TargetAccount: a, ReasonText: accountReason(rc.T, a.Reason)}
		if !a.CanActivate && a.ActivateReason != syncapi.ReasonAlreadyActive && a.ActivateReason != syncapi.ReasonNotLinked {
			v.ActivateText = accountReason(rc.T, a.ActivateReason)
		}
		if !a.CanSetPassword && a.State != syncapi.AccountNotActivated && a.State != syncapi.AccountNotEligible {
			v.PasswordText = accountReason(rc.T, a.PasswordReason)
		}
		out = append(out, v)
	}
	return out
}

// secondFactor reports whether the session passed a second factor, and
// whether it did recently enough to act without a step-up.
func (s *Server) secondFactor(rc *reqCtx) (verified, fresh bool) {
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	verified = rc.sess.mfaVerified
	fresh = verified && !rc.sess.mfaAt.IsZero() && s.now().Sub(rc.sess.mfaAt) <= accountsFreshMFA
	return verified, fresh
}

func (s *Server) handleAccounts(rc *reqCtx) {
	d := map[string]any{}
	if s.sync == nil {
		d["Disabled"] = true
		rc.render(http.StatusOK, "me_accounts", d)
		return
	}
	verified, fresh := s.secondFactor(rc)
	d["MFA"], d["Fresh"] = verified, fresh
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	var st syncapi.AccountStatus
	if err := s.syncCall(ctx, rc, syncapi.OpAccountStatus, syncapi.AccountStatusParams{}, &st); err != nil {
		d["Error"] = s.syncErr(rc, err)
	} else {
		d["Targets"] = s.accountViews(rc, st.Targets)
	}
	rc.render(http.StatusOK, "me_accounts", d)
}

// accountAction proposes an activation or a password change, confirmed on
// the usual confirmation page (with a step-up when the second factor is
// not recent).
func (s *Server) accountAction(rc *reqCtx, activate bool) {
	const back = "/me/accounts"
	target := rc.r.PathValue("target")
	if !accountTargetRE.MatchString(target) || s.sync == nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	verified, fresh := s.secondFactor(rc)
	if !verified {
		rc.flashErr("accounts.err.mfa_needed")
		rc.redirect(back)
		return
	}
	mode := rc.form("mode")
	var chosen string
	switch mode {
	case syncapi.PasswordGenerate:
	case syncapi.PasswordChosen:
		chosen = rc.rawForm("password")
		if chosen == "" || chosen != rc.rawForm("confirm") {
			rc.flashErr("accounts.err.mismatch")
			rc.redirect(back)
			return
		}
	default:
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	var st syncapi.AccountStatus
	if err := s.syncCall(ctx, rc, syncapi.OpAccountStatus, syncapi.AccountStatusParams{Target: target}, &st); err != nil || len(st.Targets) != 1 {
		msg := rc.T("sync.err.failed")
		if err != nil {
			msg = s.syncErr(rc, err)
		}
		rc.sess.addFlash("error", msg)
		rc.redirect(back)
		return
	}
	a := st.Targets[0]
	allowed, reason := a.CanSetPassword, a.PasswordReason
	if activate {
		allowed, reason = a.CanActivate, a.ActivateReason
	}
	switch {
	case !allowed:
		rc.sess.addFlash("error", accountReason(rc.T, reason))
		rc.redirect(back)
		return
	case mode == syncapi.PasswordChosen && !a.ChosenPassword:
		rc.sess.addFlash("error", accountReason(rc.T, syncapi.ReasonChosenOff))
		rc.redirect(back)
		return
	case mode == syncapi.PasswordChosen && (utf8.RuneCountInString(chosen) < a.Rules.MinLength ||
		(a.Rules.MaxLength > 0 && utf8.RuneCountInString(chosen) > a.Rules.MaxLength)):
		rc.flashErr("accounts.err.length", a.Rules.MinLength, a.Rules.MaxLength)
		rc.redirect(back)
		return
	}
	op, action := syncapi.OpAccountSetPassword, "self.account_password"
	title, summary := rc.T("accounts.password.title", a.Title), rc.T("accounts.password.summary", a.Title, a.Address)
	if activate {
		op, action = syncapi.OpAccountActivate, "self.account_activate"
		title, summary = rc.T("accounts.activate.title", a.Title), rc.T("accounts.activate.summary", a.Title, a.Address)
	}
	pwLine := "generated by conductor-sync, shown to you once"
	if mode == syncapi.PasswordChosen {
		pwLine = "typed by you (not shown, not stored)"
	}
	preview := strings.Join([]string{"conductor-sync " + string(op), fmt.Sprintf("target: %s (%s)", a.Target, a.Title),
		"account: " + a.Address, "password: " + pwLine, "# " + rc.T("accounts.preview_note")}, "\n")
	p := &pendingOp{perm: PermSelf, action: action, target: a.Target + ":" + a.Address, reauth: !fresh,
		title: title, summary: summary, warning: rc.T("accounts.warn_once"), preview: preview, back: back,
		reauthKey: "accounts.reauth", previewHint: rc.T("accounts.preview_hint", a.Title)}
	if mode == syncapi.PasswordChosen {
		p.warning = ""
	}
	p.run = func(ctx context.Context, rc *reqCtx) error {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), accountActionTimeout)
		defer cancel()
		choice := syncapi.PasswordChoice{Mode: mode, Password: chosen}
		chosen = "" // the closure must not keep the user's password
		var res syncapi.AccountActionResult
		var err error
		if activate {
			err = s.syncCall(actx, rc, op, syncapi.AccountActivateParams{Target: target, PasswordChoice: choice}, &res)
		} else {
			err = s.syncCall(actx, rc, op, syncapi.AccountSetPasswordParams{Target: target, PasswordChoice: choice}, &res)
		}
		if err != nil {
			return err
		}
		if res.Password != "" {
			p.back = "/me/accounts/secret/" + rc.keepAccountSecret(accountSecret{Title: a.Title, Address: res.Account.Address,
				Password: res.Password, Activated: activate})
		}
		switch {
		case res.Password != "":
			// The password page says it; no second message.
			p.done = ""
		case activate && len(res.Warnings) > 0:
			p.done = rc.T("accounts.activate.done_warnings", a.Title)
		case activate:
			p.done = rc.T("accounts.activate.done", a.Title)
		default:
			p.done = rc.T("accounts.password.done", a.Title)
		}
		return nil
	}
	rc.propose(p)
}

func (s *Server) handleAccountActivate(rc *reqCtx) { s.accountAction(rc, true) }

func (s *Server) handleAccountPassword(rc *reqCtx) { s.accountAction(rc, false) }

// handleAccountSecret shows a generated password once: the reference is
// single use, the page is not cached, and the password leaves the session.
func (s *Server) handleAccountSecret(rc *reqCtx) {
	ref := rc.r.PathValue("ref")
	rc.sess.mu.Lock()
	v, ok := rc.sess.accountSecrets[ref]
	delete(rc.sess.accountSecrets, ref)
	rc.sess.mu.Unlock()
	if !ok || s.now().Sub(v.at) > pendingTTL {
		rc.errorPage(http.StatusNotFound, "accounts.secret.gone")
		return
	}
	s.audit(rc.ctx(), rc, "self.account_password_shown", v.Address, "the generated password was shown to the user (once)", store.ResultOK)
	rc.w.Header().Set("Cache-Control", "no-store")
	rc.render(http.StatusOK, "me_account_secret", map[string]any{"S": v})
}
