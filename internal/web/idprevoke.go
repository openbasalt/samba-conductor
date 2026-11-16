package web

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Revocation at conductor-idp. A change of an account's second factors in
// conductor (added, removed, reset, new recovery codes) or a password reset
// by an administrator asks conductor-idp, when the single sign-on section
// is configured, to end the account's sessions, tokens and consents
// (user.revoke): sign-ins made with the old credentials must not outlive
// the change. A failed call is audited and shown to whoever made the
// change (or written to the bulk row), never dropped.

// idpRevokeTimeout bounds one revocation call.
const idpRevokeTimeout = 15 * time.Second

// errIDPRevoke wraps a failed revocation (shown as sso.revoke.failed).
type errIDPRevoke struct {
	user string
	err  error
}

func (e *errIDPRevoke) Error() string {
	return fmt.Sprintf("web: conductor-idp could not revoke %s: %v", e.user, e.err)
}

func (e *errIDPRevoke) Unwrap() error { return e.err }

// revokeActor is the actor named in the revocation: the signed-in user,
// or conductor itself when there is none (an invitation link).
func revokeActor(rc *reqCtx) idpapi.Actor {
	if rc != nil && rc.sess != nil {
		rc.sess.mu.Lock()
		sam, userSID, hash := rc.sess.sam, rc.sess.userSID, rc.sess.hash
		rc.sess.mu.Unlock()
		if _, err := sid.Parse(userSID.String()); err == nil && sam != "" && len(hash) >= 16 {
			return idpapi.Actor{User: sam, SID: userSID.String(), Session: hash[:16], IP: rc.ip}
		}
	}
	a := idpapi.Actor{User: "conductor", SID: "S-1-5-18", Session: "conductor-system"}
	if rc != nil {
		a.IP = rc.ip
	}
	return a
}

// revokeIdPUser ends the sessions, tokens and consents of sam at
// conductor-idp (nothing to do without [idp]) and audits the outcome as
// sso.user_revoke. The error is an *errIDPRevoke.
func (s *Server) revokeIdPUser(ctx context.Context, rc *reqCtx, sam, reason string) error {
	if s.idp == nil || sam == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, idpRevokeTimeout)
	defer cancel()
	var out idpapi.UserRevoked
	req, err := idpapi.NewRequest(newToken()[:24], idpapi.OpUserRevoke, revokeActor(rc), idpapi.UserRevokeParams{User: sam, Reason: reason})
	if err == nil {
		var resp idpapi.Response
		if resp, err = s.idp.Call(ctx, req); err == nil {
			err = idpapi.DecodeResult(resp, &out)
		}
	}
	if err != nil {
		s.log.Error("conductor-idp revocation failed", "user", sam, "reason", reason, "err", err)
		s.audit(ctx, rc, "sso.user_revoke", sam, "after "+reason+"\n# error: "+err.Error(), store.ResultFailed)
		return &errIDPRevoke{user: sam, err: err}
	}
	s.audit(ctx, rc, "sso.user_revoke", sam, fmt.Sprintf("after %s: %d refresh tokens, %d consents", reason, out.RefreshTokens, out.Consents),
		store.ResultOK)
	return nil
}

// revokeIdPAfter runs revokeIdPUser for a change made from a page and
// shows a failure to the user who made it.
func (s *Server) revokeIdPAfter(ctx context.Context, rc *reqCtx, sam, reason string) {
	var re *errIDPRevoke
	if err := s.revokeIdPUser(ctx, rc, sam, reason); errors.As(err, &re) {
		rc.flashErr("sso.revoke.failed", sam)
	}
}
