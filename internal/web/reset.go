package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-provisioner/provapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// The public password reset form. Its answer is always the same page with
// the same status, given before any lookup: the work (find the account,
// check it, issue a token, queue the message) runs in the background, so
// the answer reveals neither whether the account exists nor whether it is
// eligible or has an address. The audit log keeps a hash of what was
// typed, never the text.

const (
	// resetsPerAddress requests per client address per resetAddressWindow.
	resetsPerAddress   = 5
	resetAddressWindow = 15 * time.Minute
	// Per account, counted silently.
	resetsPerAccountHour = 3
	resetsPerAccountDay  = 5
	// resetWorkTimeout bounds the background work of one request.
	resetWorkTimeout = time.Minute
	// maxIdentifier bounds what the form accepts.
	maxIdentifier = 256
)

// resetOffered reports whether the public form is on (the setting, mail,
// the provisioner and a public URL for the links).
func (s *Server) resetOffered(ctx context.Context) bool {
	return s.linkAvailable() && s.passwordSettings(ctx).ResetEnabled
}

func (s *Server) handleResetPage(rc *reqCtx) {
	if !s.resetOffered(rc.ctx()) {
		rc.errorPage(http.StatusNotFound, "reset.off")
		return
	}
	rc.ensurePreCookie()
	rc.render(http.StatusOK, "reset", map[string]any{})
}

func (s *Server) handleReset(rc *reqCtx) {
	ctx := rc.ctx()
	if !s.resetOffered(ctx) {
		rc.errorPage(http.StatusNotFound, "reset.off")
		return
	}
	rc.actorHint = provapi.PublicUser
	typed := rc.form("identifier")
	hash := identifierHash(typed)
	if !s.ipLimit.Allow("reset:"+rc.ip) || !s.resetIPLimit.Allow(rc.ip) {
		// The same page: nothing is queued.
		s.audit(ctx, rc, "reset.refused", "id:"+hash, "per-address limit", store.ResultDenied)
	} else {
		// Detached from the request: the answer does not wait for it.
		bg := &reqCtx{s: s, r: rc.r.Clone(context.Background()), ip: rc.ip, lang: rc.lang, actorHint: provapi.PublicUser}
		s.bgJobs.Add(1)
		go func() {
			defer s.bgJobs.Done()
			s.resetWork(bg, typed, hash)
		}()
	}
	rc.render(http.StatusOK, "reset_sent", map[string]any{})
}

// resetWork is the background part of a reset request.
func (s *Server) resetWork(rc *reqCtx, typed, hash string) {
	ctx, cancel := context.WithTimeout(context.Background(), resetWorkTimeout)
	defer cancel()
	ref := "reset-" + newToken()[:12]
	s.audit(ctx, rc, "reset.requested", "id:"+hash, "request "+ref, store.ResultPending)
	refuse := func(target, reason string) {
		s.audit(ctx, rc, "reset.refused", target, "request "+ref+": "+reason, store.ResultDenied)
	}
	if typed == "" || len(typed) > maxIdentifier || strings.ContainsFunc(typed, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		refuse("id:"+hash, "not a username or an address")
		return
	}
	actor := publicActor(ref, rc.ip)
	var u provapi.UserResult
	if err := s.provCall(ctx, actor, provapi.OpUserFind, &provapi.UserFindParams{UsernameOrMail: typed}, &u); err != nil {
		refuse("id:"+hash, "lookup: "+provCode(err))
		return
	}
	target := u.SAM
	switch {
	case !u.InScope:
		refuse(target, "outside the provisioner's scope")
		return
	case u.Privileged:
		refuse(target, "privileged account ("+strings.Join(u.PrivilegedReasons, ",")+")")
		return
	case !u.Enabled && !u.Locked:
		refuse(target, "account disabled")
		return
	}
	set := s.passwordSettings(ctx)
	if set.ResetMFA == resetMFAAlways && !s.hasSecondFactor(ctx, u.SID) {
		refuse(target, "no second factor (reset.mfa = always)")
		return
	}
	alt := s.resetRecoveryAddress(ctx, u.SID)
	if len(recipients(u.Mail, alt)) == 0 {
		refuse(target, "no address")
		return
	}
	if !s.resetHourLimit.Allow(u.SID) || !s.resetDayLimit.Allow(u.SID) {
		refuse(target, "per-account limit")
		return
	}
	var extra []string
	if alt != "" {
		extra = []string{alt}
	}
	out, err := s.issueLink(ctx, issueRequest{actor: actor, sid: u.SID, purpose: provapi.PurposeReset, lang: rc.lang, extra: extra})
	if err != nil {
		s.log.Warn("reset link not issued", "user", u.SAM, "err", err)
		refuse(target, "issue: "+provCode(err))
		return
	}
	s.audit(ctx, rc, "reset.mailed", target, "request "+ref+": token "+out.TokenID+" to "+strings.Join(out.Domains, ", ")+
		" (expires "+out.ExpiresAt.UTC().Format(time.RFC3339)+")", store.ResultOK)
}
