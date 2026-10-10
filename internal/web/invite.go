package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Invitations, the administrator side: the user page offers "Send
// invitation" when conductor-provisioner says the account is in its scope
// and not privileged, lists the account's open tokens with "Revoke", and
// the user creation page can create a disabled account and invite it in
// the same confirmation. The invited person sets the first password on
// the link pages (link.go); the account is enabled only at the end.

// inviteView is the invitation part of the user page.
type inviteView struct {
	// Missing lists what is not configured ("mail", "provisioner",
	// "public_url"); the section explains it instead of the button.
	Missing []string
	// Err is a translated error from the provisioner.
	Err string
	// Can: the button is offered. Otherwise Reason (a message key) says
	// why, with the privilege kinds when that is the reason.
	Can    bool
	Reason string
	Kinds  []string
	Mail   string
	Hours  int
	Tokens []tokenView
}

// tokenView is one token of the account on the user page.
type tokenView struct {
	provapi.TokenInfo
	Open bool
}

// missingForLinks lists what invitations and resets need but lack.
func (s *Server) missingForLinks() []string {
	var out []string
	if s.mailq == nil {
		out = append(out, "mail")
	}
	if s.prov == nil {
		out = append(out, "provisioner")
	}
	if s.publicBase() == "" {
		out = append(out, "public_url")
	}
	return out
}

// inviteReason says why an account cannot be invited ("" when it can).
func inviteReason(u provapi.UserResult) string {
	switch {
	case u.Privileged:
		return "invite.reason.privileged"
	case !u.InScope:
		return "invite.reason.out_of_scope"
	case len(recipients(u.Mail)) == 0:
		return "invite.reason.no_mail"
	}
	return ""
}

// inviteInfo gathers the invitation section of a user page.
func (s *Server) inviteInfo(ctx context.Context, rc *reqCtx, userSID string, protected bool) *inviteView {
	v := &inviteView{Missing: s.missingForLinks(), Hours: s.passwordSettings(ctx).InviteHours}
	if len(v.Missing) > 0 {
		return v
	}
	actor := sessionActor(rc)
	var u provapi.UserResult
	if err := s.provCall(ctx, actor, provapi.OpUserCheck, &provapi.UserCheckParams{SID: userSID}, &u); err != nil {
		v.Err = rc.T(provErrKey(err))
		return v
	}
	v.Mail, v.Kinds = u.Mail, u.PrivilegedReasons
	v.Reason = inviteReason(u)
	if v.Reason == "" && protected && !rc.roles.Admin {
		v.Reason = "err.protected"
	}
	v.Can = v.Reason == ""
	var list []provapi.TokenInfo
	if err := s.provCall(ctx, actor, provapi.OpTokenList, &provapi.TokenListParams{SID: userSID}, &list); err != nil {
		v.Err = rc.T(provErrKey(err))
		return v
	}
	for _, t := range list {
		v.Tokens = append(v.Tokens, tokenView{TokenInfo: t, Open: t.State == provapi.StateOpen || t.State == provapi.StatePasswordSet})
	}
	return v
}

// invitePreview is the text of an invitation's preview (and audit).
func invitePreview(sam, userSID, addr string, hours int) string {
	return "issue a one-time invitation link for " + sam + " (" + userSID + "), valid " + itoa(hours) +
		" hours (or less if conductor-provisioner's own limit is shorter)\nmail it to an address at " + mail.Domain(addr) +
		"\nthe account is enabled when the invited person finishes"
}

// inviteRun issues the invitation of a confirmed preview and adds the
// token and the message to the preview text that is audited.
func (s *Server) inviteRun(p *pendingOp, userSID string) func(ctx context.Context, rc *reqCtx) error {
	return func(ctx context.Context, rc *reqCtx) error {
		rc.sess.mu.Lock()
		issuerSID, issuerName := rc.sess.userSID.String(), rc.sess.sam
		rc.sess.mu.Unlock()
		out, err := s.issueLink(ctx, issueRequest{actor: sessionActor(rc), sid: userSID, purpose: provapi.PurposeInvite,
			lang: s.cfg.UI.DefaultLanguage, issuerSID: issuerSID, issuerName: issuerName})
		if err != nil {
			p.preview += "\n# provisioner: " + provCode(err)
			return err
		}
		p.preview += "\n# token " + out.TokenID + ", message " + strings.Join(out.MailIDs, ",") + " to " + strings.Join(out.Domains, ", ") +
			", expires " + out.ExpiresAt.UTC().Format(time.RFC3339)
		return nil
	}
}

// handleUserInvite previews an invitation for an existing account.
func (s *Server) handleUserInvite(rc *reqCtx) {
	if len(s.missingForLinks()) > 0 {
		rc.errorPage(http.StatusConflict, "invite.err.off")
		return
	}
	s.userAction(rc, PermUsersHelpdesk, func(ctx context.Context, _ *ad.Conn, u ad.User) (*pendingOp, error) {
		return s.inviteOp(ctx, rc, u), nil
	})
}

// inviteOp builds the preview of an invitation after asking the
// provisioner about the account; when it cannot be invited, it says why
// on the user page and returns nil.
func (s *Server) inviteOp(ctx context.Context, rc *reqCtx, u ad.User) *pendingOp {
	back := "/admin/users/" + u.GUID.String()
	var chk provapi.UserResult
	if err := s.provCall(ctx, sessionActor(rc), provapi.OpUserCheck, &provapi.UserCheckParams{SID: u.SID.String()}, &chk); err != nil {
		s.audit(ctx, rc, "invite.refused", u.DN, "user.check: "+provCode(err), store.ResultFailed)
		rc.flashErr(provErrKey(err))
		rc.redirect(back)
		return nil
	}
	if reason := inviteReason(chk); reason != "" {
		s.audit(ctx, rc, "invite.refused", u.DN, reason+" "+strings.Join(chk.PrivilegedReasons, ","), store.ResultDenied)
		rc.flashErr(reason)
		rc.redirect(back)
		return nil
	}
	hours := s.passwordSettings(ctx).InviteHours
	p := &pendingOp{action: "invite.issued", title: rc.T("invite.title", u.SAMAccountName),
		summary: rc.T("invite.summary", u.SAMAccountName, chk.Mail, hours), preview: invitePreview(u.SAMAccountName, u.SID.String(), chk.Mail, hours),
		done: rc.T("invite.done", chk.Mail)}
	p.run = s.inviteRun(p, u.SID.String())
	return p
}

// handleUserTokenRevoke previews revoking the account's open tokens of one
// purpose.
func (s *Server) handleUserTokenRevoke(rc *reqCtx) {
	purpose := rc.form("purpose")
	if purpose != provapi.PurposeInvite && purpose != provapi.PurposeReset {
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	if s.prov == nil {
		rc.errorPage(http.StatusConflict, "invite.err.off")
		return
	}
	s.userAction(rc, PermUsersHelpdesk, func(_ context.Context, _ *ad.Conn, u ad.User) (*pendingOp, error) {
		return s.revokeOp(rc, u, purpose), nil
	})
}

// revokeOp builds the preview of revoking an account's open links.
func (s *Server) revokeOp(rc *reqCtx, u ad.User, purpose string) *pendingOp {
	target := u.SID.String()
	p := &pendingOp{action: purpose + ".revoked", title: rc.T("tokens.revoke.title", u.SAMAccountName),
		summary: rc.T("tokens.revoke.summary."+purpose, u.SAMAccountName),
		preview: "revoke the open " + purpose + " links of " + u.SAMAccountName + " (" + target + ")", done: rc.T("tokens.revoke.done")}
	p.run = func(ctx context.Context, rc *reqCtx) error {
		var rr provapi.TokenRevokeResult
		if err := s.provCall(ctx, sessionActor(rc), provapi.OpTokenRevoke, &provapi.TokenRevokeParams{SID: target, Purpose: purpose, Reason: "admin"}, &rr); err != nil {
			return err
		}
		p.preview += "\n# revoked: " + itoa(rr.Revoked)
		return nil
	}
	return p
}

// dnWithin reports whether dn is ou or below it.
func dnWithin(dn, ou string) bool {
	n, o := escape.NormalizeDN(dn), escape.NormalizeDN(ou)
	return n == o || strings.HasSuffix(n, ","+o)
}

// inviteScopeOK reports whether new accounts below parent can be invited:
// the provisioner's scope OUs contain it.
func (s *Server) inviteScopeOK(ctx context.Context, rc *reqCtx, parent string) (bool, error) {
	var st provapi.StatusResult
	if err := s.provCall(ctx, sessionActor(rc), provapi.OpStatus, nil, &st); err != nil {
		return false, err
	}
	for _, ou := range st.ScopeOUs {
		if dnWithin(parent, ou) {
			return true, nil
		}
	}
	return false, nil
}

// sidOfUserAD reads the SID of a user by DN with the session's own
// credential.
func (s *Server) sidOfUserAD(ctx context.Context, rc *reqCtx, dn string) (string, error) {
	var userSID string
	err := rc.withConn(ctx, func(conn *ad.Conn) error {
		u, err := conn.GetUser(ctx, dn)
		userSID = u.SID.String()
		return err
	})
	return userSID, err
}

// inviteAfterCreate is what the creation of an invited account does once
// the account exists: read its SID, issue the invitation and audit it.
func (s *Server) inviteAfterCreate(sam, addr, dn string, hours int) func(ctx context.Context, rc *reqCtx) error {
	return func(ctx context.Context, rc *reqCtx) error {
		ip := &pendingOp{preview: invitePreview(sam, "new account", addr, hours)}
		userSID, err := s.sidOfUser(ctx, rc, dn)
		if err == nil {
			err = s.inviteRun(ip, userSID)(ctx, rc)
		}
		result := store.ResultOK
		if err != nil {
			result = resultOf(err)
		}
		s.audit(ctx, rc, "invite.issued", dn, ip.preview, result)
		if err == nil {
			rc.flashOK("invite.done", addr)
		}
		return err
	}
}

// ---- automatic re-issue of an unused invitation ----

// sweepInvites re-issues, once, the invitations that expired unused when
// invite.auto_reissue is on; the re-issue is made for the administrator
// who issued the first one.
func (s *Server) sweepInvites(ctx context.Context) {
	if !s.passwordsOn() {
		return
	}
	now := s.now()
	defer func() {
		if err := s.store.PruneLinkTokens(ctx, now.Add(-7*24*time.Hour)); err != nil {
			s.log.Warn("pruning link tokens", "err", err)
		}
	}()
	if !s.passwordSettings(ctx).InviteAutoReissue {
		return
	}
	rows, err := s.store.ExpiredInvites(ctx, now, 20)
	if err != nil {
		s.log.Error("reading expired invitations", "err", err)
		return
	}
	for _, t := range rows {
		s.reissueInvite(ctx, t)
	}
}

// reissueInvite looks at one expired invitation.
func (s *Server) reissueInvite(ctx context.Context, t store.LinkToken) {
	defer func() {
		if err := s.store.MarkLinkTokenHandled(ctx, t.TokenID); err != nil {
			s.log.Error("marking an invitation handled", "err", err)
		}
	}()
	if t.ReissueOf != "" || t.IssuerSID == "" {
		return // only the first invitation, and only an administrator's
	}
	bg := &reqCtx{s: s, r: (&http.Request{Header: http.Header{}}).WithContext(ctx), actorHint: "conductor"}
	actor := provapi.Actor{User: t.IssuerName, SID: t.IssuerSID, Session: "auto-reissue", IP: ""}
	var list []provapi.TokenInfo
	if err := s.provCall(ctx, actor, provapi.OpTokenList, &provapi.TokenListParams{SID: t.UserSID}, &list); err != nil {
		s.log.Warn("automatic re-issue: token list", "user", t.Username, "err", err)
		return
	}
	unused := false
	for _, x := range list {
		if x.TokenID == t.TokenID {
			unused = x.State == provapi.StateOpen || x.State == provapi.StateExpired
		}
	}
	if !unused {
		return
	}
	out, err := s.issueLink(ctx, issueRequest{actor: actor, sid: t.UserSID, purpose: provapi.PurposeInvite, lang: t.Lang,
		issuerSID: t.IssuerSID, issuerName: t.IssuerName, reissueOf: t.TokenID})
	if err != nil {
		s.audit(ctx, bg, "invite.reissued", t.Username, "automatic re-issue of token "+t.TokenID+" failed: "+provCode(err), store.ResultFailed)
		return
	}
	s.audit(ctx, bg, "invite.reissued", t.Username, "automatic re-issue of token "+t.TokenID+" for "+t.IssuerName+": token "+out.TokenID+
		" to "+strings.Join(out.Domains, ", "), store.ResultOK)
}
