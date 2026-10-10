package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-provisioner/provapi"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// One-time links (invitations and resets), the notification after a
// password change, and the recovery address used by resets.

var (
	errNoPublicURL = errors.New("web: no public URL to build links from (server.public_url)")
	errNoAddress   = errors.New("web: the account has no address to send the link to")
)

// recoveryChangeBlock is how long after a change of the recovery address
// resets do not go to it.
const recoveryChangeBlock = 72 * time.Hour

// issueRequest is one token to issue and mail.
type issueRequest struct {
	actor   provapi.Actor
	sid     string
	purpose string
	// lang of the message.
	lang string
	// extra recipients besides the account's mail attribute (the
	// recovery address of a reset).
	extra []string
	// issuer recorded for the automatic re-issue (empty: the public form).
	issuerSID, issuerName string
	reissueOf             string
}

// issued is what issueLink did.
type issued struct {
	TokenID   string
	SAM       string
	Mail      string
	ExpiresAt time.Time
	// Domains are the recipients' domains (audit), MailIDs the queue ids.
	Domains []string
	MailIDs []string
}

// issueLink asks the provisioner for a token, records conductor's view of
// it (its own expiry: the shorter of both wins) and queues the message to
// the account's mail and the extra recipients. A token whose message
// cannot be queued is revoked.
func (s *Server) issueLink(ctx context.Context, r issueRequest) (issued, error) {
	var out issued
	base := s.publicBase()
	if base == "" {
		return out, errNoPublicURL
	}
	if s.mailq == nil {
		return out, errMailOff
	}
	set := s.passwordSettings(ctx)
	var res provapi.TokenIssueResult
	if err := s.provCall(ctx, r.actor, provapi.OpTokenIssue, &provapi.TokenIssueParams{SID: r.sid, Purpose: r.purpose,
		Reference: "conductor-" + newToken()[:16]}, &res); err != nil {
		return out, err
	}
	now := s.now()
	expires := res.ExpiresAt
	if own := now.Add(set.lifetime(r.purpose)); own.Before(expires) {
		expires = own
	}
	out = issued{TokenID: res.TokenID, SAM: res.SAM, Mail: res.Mail, ExpiresAt: expires}
	revoke := func(reason string) {
		var rr provapi.TokenRevokeResult
		if err := s.provCall(ctx, r.actor, provapi.OpTokenRevoke, &provapi.TokenRevokeParams{SID: r.sid, Purpose: r.purpose, Reason: reason}, &rr); err != nil {
			s.log.Error("revoking a token whose message failed", "token_id", res.TokenID, "err", err)
		}
	}
	to := recipients(append([]string{res.Mail}, r.extra...)...)
	if len(to) == 0 {
		revoke("no-address")
		return out, errNoAddress
	}
	if err := s.store.PutLinkToken(ctx, store.LinkToken{TokenID: res.TokenID, Purpose: r.purpose, UserSID: r.sid, Username: res.SAM,
		Lang: r.lang, IssuerSID: r.issuerSID, IssuerName: r.issuerName, IssuedAt: now, ExpiresAt: expires, ReissueOf: r.reissueOf}); err != nil {
		revoke("internal")
		return out, err
	}
	tmpl := mail.TemplateReset
	if r.purpose == provapi.PurposeInvite {
		tmpl = mail.TemplateInvitation
	}
	d := mail.Data{Link: base + "/link/" + res.Token, Username: res.SAM, Expires: expires, ValidFor: expires.Sub(now)}
	for _, addr := range to {
		id, err := s.queueMail(ctx, tmpl, r.lang, addr, d, expires, "token:"+res.TokenID)
		if err != nil {
			revoke("mail-failed")
			return out, err
		}
		out.MailIDs = append(out.MailIDs, id)
		out.Domains = append(out.Domains, mail.Domain(addr))
	}
	return out, nil
}

// recipients keeps the valid, distinct addresses (case-insensitive).
func recipients(addrs ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, err := mail.ParseRecipient(a); err != nil {
			continue
		}
		k := strings.ToLower(a)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	return out
}

// hasSecondFactor reports whether a user enrolled TOTP or a security key.
func (s *Server) hasSecondFactor(ctx context.Context, userSID string) bool {
	if _, err := s.store.GetTOTP(ctx, userSID); err == nil {
		return true
	}
	return s.keyCount(ctx, userSID) > 0
}

// resetRecoveryAddress is the recovery address a reset may go to: verified
// and not changed in the last 72 hours ("" otherwise).
func (s *Server) resetRecoveryAddress(ctx context.Context, userSID string) string {
	r, err := s.store.GetRecoveryEmail(ctx, userSID)
	if err != nil {
		return ""
	}
	if s.now().Sub(r.ChangedAt) < recoveryChangeBlock {
		return ""
	}
	return r.Address
}

// identifierHash correlates repeated reset requests in the audit log
// without storing what was typed: SHA-256 of the lower-cased input, first
// 16 hex digits.
func identifierHash(v string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(v))))
	return hex.EncodeToString(h[:])[:16]
}

// pwChange is a password change to notify the user of.
type pwChange struct {
	SID, SAM, Mail string
	Lang           string
	// From is the client address of the change; ByAdmin says an
	// administrator made it instead.
	From    string
	ByAdmin bool
}

// notifyPasswordChanged queues password_changed to the account's mail and
// its recovery address, when mail is on and the setting allows it. Errors
// are logged: the change already happened.
func (s *Server) notifyPasswordChanged(ctx context.Context, c pwChange) {
	if s.mailq == nil || !s.passwordSettings(ctx).NotifyChanged {
		return
	}
	extra := ""
	if r, err := s.store.GetRecoveryEmail(ctx, c.SID); err == nil {
		extra = r.Address
	}
	if c.Lang == "" {
		c.Lang = s.cfg.UI.DefaultLanguage
	}
	d := mail.Data{Username: c.SAM, When: s.now(), ByAdministrator: c.ByAdmin}
	if !c.ByAdmin {
		d.From = c.From
	}
	for _, addr := range recipients(c.Mail, extra) {
		if _, err := s.queueMail(ctx, mail.TemplatePasswordChanged, c.Lang, addr, d, s.now().Add(mail.NotificationLifetime), "notify"); err != nil {
			s.log.Error("queueing a password change notification", "user", c.SAM, "err", err)
		}
	}
}
