package web

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// The public pages of invitation and reset links. GET /link/{token} only
// validates the token (mail scanners that prefetch links consume
// nothing) and shows a button; its POST moves the token into a link
// record kept in memory (the token sealed) and a short-lived __Host-link
// cookie, so the token leaves the address bar and the history. The steps
// that follow (second factor of a reset, the password, the enrollment of
// an invitation) run on that record. Invalid, expired, used and revoked
// links all get the same neutral page with the same status.

const (
	linkCookie = "__Host-link"
	// linkTTL bounds a link record (and its cookie).
	linkTTL = 10 * time.Minute
	// maxLinkRecords bounds memory; the oldest record goes first.
	maxLinkRecords = 10000
	// linkFailuresPerHour: failed token checks per client address.
	linkFailuresPerHour = 10
	// maxLinkMFAFailures revokes a reset token after that many wrong
	// second factors.
	maxLinkMFAFailures = 5
)

// Enrollment step of an invitation.
const (
	enrollRequired = "required"
	enrollOptional = "optional"
)

// linkRecord is one link flow in progress.
type linkRecord struct {
	// id names the record in the audit log and in provisioner calls.
	id      string
	hash    string // SHA-256 of the cookie value (the map key)
	sealed  []byte // the token, sealed with the state key
	expires time.Time

	tokenID, purpose string
	sid, sam, dn     string
	addr             string // the account's mail attribute

	// sess is a transient session (never in the session table): CSRF,
	// TOTP enrollment and WebAuthn ceremonies of the visitor.
	sess *Session

	mu          sync.Mutex
	needMFA     bool // a reset of a user with a second factor
	mfaOK       bool
	mfaFailures int
	passwordSet bool
	enroll      string // enrollRequired, enrollOptional or "" after the password of an invitation
	done        bool
	codes       []string // recovery codes to show once on the last page
}

// linkStore holds the records by cookie hash.
type linkStore struct {
	mu     sync.Mutex
	byHash map[string]*linkRecord
}

func (m *linkStore) put(r *linkRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.byHash) >= maxLinkRecords {
		var oldest *linkRecord
		for _, x := range m.byHash {
			if oldest == nil || x.expires.Before(oldest.expires) {
				oldest = x
			}
		}
		delete(m.byHash, oldest.hash)
	}
	m.byHash[r.hash] = r
}

// get returns the live record of a cookie value.
func (m *linkStore) get(cookie string, now time.Time) *linkRecord {
	if cookie == "" || len(cookie) > 128 {
		return nil
	}
	h := hashToken(cookie)
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.byHash[h]
	if r == nil {
		return nil
	}
	if now.After(r.expires) {
		delete(m.byHash, h)
		return nil
	}
	return r
}

func (m *linkStore) drop(r *linkRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byHash, r.hash)
}

// sweep drops expired records.
func (m *linkStore) sweep(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, r := range m.byHash {
		if now.After(r.expires) {
			delete(m.byHash, h)
		}
	}
}

var linkTokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// dummyLinkToken stands in for a malformed token, so the provisioner is
// asked (and answers not_found) like for any other unknown token.
const dummyLinkToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// linkAvailable reports whether the link pages work at all.
func (s *Server) linkAvailable() bool { return s.passwordsOn() && s.publicBase() != "" }

// linkInvalid renders the neutral page of every link that cannot be used.
func (s *Server) linkInvalid(rc *reqCtx) {
	if rc.link != nil {
		s.links.drop(rc.link)
	}
	if _, err := rc.r.Cookie(linkCookie); err == nil {
		clearCookie(rc.w, linkCookie)
	}
	rc.sess = nil
	rc.render(http.StatusOK, "link_invalid", map[string]any{"Reset": s.resetOffered(rc.ctx())})
}

// linkCheck validates a token with the provisioner (never consuming it)
// and applies conductor's own expiry. A malformed token is checked as an
// unknown one so every invalid link takes the same path.
func (s *Server) linkCheck(ctx context.Context, actor provapi.Actor, token string) (provapi.TokenCheckResult, error) {
	if !linkTokenRE.MatchString(token) {
		token = dummyLinkToken
	}
	var res provapi.TokenCheckResult
	if err := s.provCall(ctx, actor, provapi.OpTokenCheck, &provapi.TokenCheckParams{Token: token}, &res); err != nil {
		return res, err
	}
	if lt, err := s.store.GetLinkToken(ctx, res.TokenID); err == nil && !s.now().Before(lt.ExpiresAt) {
		// conductor's own lifetime is shorter than the provisioner's.
		var rr provapi.TokenRevokeResult
		if err := s.provCall(ctx, actor, provapi.OpTokenRevoke, &provapi.TokenRevokeParams{SID: res.SID, Purpose: res.Purpose, Reason: "expired"}, &rr); err != nil {
			s.log.Warn("revoking an expired token", "token_id", res.TokenID, "err", err)
		}
		return res, &provapi.Error{Code: provapi.CodeExpired, Message: "expired (conductor's lifetime)"}
	}
	return res, nil
}

// linkRefused audits a refused link with the provisioner's code.
func (s *Server) linkRefused(ctx context.Context, rc *reqCtx, target, detail string, err error) {
	s.audit(ctx, rc, "link.refused", target, strings.TrimSpace(detail+" code="+provCode(err)), store.ResultDenied)
}

// linkLimited applies the per-address limits of the public link pages.
func (s *Server) linkLimited(rc *reqCtx) bool {
	return !s.ipLimit.Allow("link:"+rc.ip) || s.linkFails.Blocked(rc.ip)
}

func linkTimeout(rc *reqCtx) (context.Context, context.CancelFunc) {
	return context.WithTimeout(rc.ctx(), requestTimeout)
}

// handleLinkPage validates the token and offers the button that starts
// the flow.
func (s *Server) handleLinkPage(rc *reqCtx) {
	ctx, cancel := linkTimeout(rc)
	defer cancel()
	rc.actorHint = provapi.PublicUser
	if !s.linkAvailable() {
		s.linkInvalid(rc)
		return
	}
	if s.linkLimited(rc) {
		s.audit(ctx, rc, "link.refused", rc.ip, "per-address limit", store.ResultDenied)
		s.linkInvalid(rc)
		return
	}
	token := rc.r.PathValue("token")
	res, err := s.linkCheck(ctx, publicActor("open-"+newToken()[:12], rc.ip), token)
	if err != nil {
		s.linkFails.Fail(rc.ip)
		s.linkRefused(ctx, rc, res.SAM, "opened", err)
		s.linkInvalid(rc)
		return
	}
	s.audit(ctx, rc, res.Purpose+".opened", res.SAM, "token "+res.TokenID, store.ResultOK)
	rc.ensurePreCookie()
	rc.render(http.StatusOK, "link", map[string]any{"Purpose": res.Purpose, "SAM": res.SAM, "Action": "/link/" + token + "/start"})
}

// handleLinkStart moves the token into a link record and its cookie.
func (s *Server) handleLinkStart(rc *reqCtx) {
	ctx, cancel := linkTimeout(rc)
	defer cancel()
	rc.actorHint = provapi.PublicUser
	if !s.linkAvailable() || s.linkLimited(rc) {
		s.linkInvalid(rc)
		return
	}
	token := rc.r.PathValue("token")
	id := newToken()[:16]
	res, err := s.linkCheck(ctx, publicActor(id, rc.ip), token)
	if err != nil {
		s.linkFails.Fail(rc.ip)
		s.linkRefused(ctx, rc, res.SAM, "start", err)
		s.linkInvalid(rc)
		return
	}
	userSID, err := sid.Parse(res.SID)
	if err != nil {
		s.linkInvalid(rc)
		return
	}
	sealed, err := s.box.Seal([]byte(token), []byte("link:"+id))
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	now := s.now()
	cookie := newToken()
	rec := &linkRecord{id: id, hash: hashToken(cookie), sealed: sealed, expires: now.Add(linkTTL), tokenID: res.TokenID, purpose: res.Purpose,
		sid: res.SID, sam: strings.ToLower(res.SAM), dn: res.DN, addr: res.Mail}
	rec.sess = &Session{sam: rec.sam, dn: res.DN, userSID: userSID, displayName: res.SAM, csrf: newToken(), created: now, lastSeen: now,
		expires: rec.expires, ip: rc.ip, userAgent: rc.r.UserAgent()}
	next := "/link/password"
	switch res.Purpose {
	case provapi.PurposeReset:
		rec.needMFA = s.hasSecondFactor(ctx, res.SID)
		if !rec.needMFA && s.passwordSettings(ctx).ResetMFA == resetMFAAlways {
			// The second factor was removed after the link was issued.
			s.audit(ctx, rc, "link.refused", res.SAM, "reset needs a second factor (reset.mfa = always)", store.ResultDenied)
			s.linkInvalid(rc)
			return
		}
		if rec.needMFA {
			next = "/link/2fa"
		}
	case provapi.PurposeInvite:
		if res.PasswordSet {
			rec.passwordSet = true
			next = ""
		}
	}
	s.links.put(rec)
	setCookie(rc.w, linkCookie, cookie, int(linkTTL/time.Second))
	rc.link, rc.sess = rec, rec.sess
	if next == "" {
		// An invitation whose password is set already: what is left.
		s.linkAfterPassword(ctx, rc)
		return
	}
	rc.redirect(next)
}

// openToken unseals the record's token.
func (s *Server) openToken(rec *linkRecord) (string, error) {
	b, err := s.box.Open(rec.sealed, []byte("link:"+rec.id))
	if err != nil {
		return "", err
	}
	defer clear(b)
	return string(b), nil
}

// linkStep is where a record's flow is: the path its pages redirect to.
func linkStep(rec *linkRecord) string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	switch {
	case rec.done:
		return "/link/done"
	case rec.needMFA && !rec.mfaOK:
		return "/link/2fa"
	case !rec.passwordSet:
		return "/link/password"
	case rec.enroll != "":
		return "/link/enroll"
	}
	return "/link/done"
}

// atStep redirects to the record's current step unless it is want.
func atStep(rc *reqCtx, want string) bool {
	if step := linkStep(rc.link); step != want {
		rc.redirect(step)
		return false
	}
	return true
}

// linkFailed handles a provisioner refusal during a flow: a refusal of
// the token ends the flow on the neutral page; anything else is shown on
// the page as a temporary error (render).
func (s *Server) linkFailed(ctx context.Context, rc *reqCtx, step string, err error, render func(key string)) {
	rec := rc.link
	switch provapi.ErrorCodeOf(err) {
	case provapi.CodeRateLimited:
		s.linkRefused(ctx, rc, rec.sam, step, err)
		render("link.err.busy")
	case provapi.CodeUnavailable, provapi.CodeDirectory, provapi.CodeInternal, "":
		s.log.Warn("link step failed", "step", step, "err", err)
		s.linkRefused(ctx, rc, rec.sam, step, err)
		render("link.err.unavailable")
	default:
		s.linkRefused(ctx, rc, rec.sam, step, err)
		s.linkInvalid(rc)
	}
}

// ---- second factor before a reset ----

func (s *Server) linkMFAData(rc *reqCtx, errKey string) map[string]any {
	d := map[string]any{}
	if errKey != "" {
		d["Error"] = rc.T(errKey)
	}
	if s.wa != nil {
		if opts, err := s.beginCeremony(rc.ctx(), rc.sess, waSignin); err == nil {
			d["KeyOptions"] = opts
		}
	}
	return d
}

func (s *Server) handleLinkMFAPage(rc *reqCtx) {
	if !atStep(rc, "/link/2fa") {
		return
	}
	rc.render(http.StatusOK, "link_2fa", s.linkMFAData(rc, ""))
}

func (s *Server) handleLinkMFA(rc *reqCtx) {
	s.linkMFA(rc, func(ctx context.Context) (bool, string) {
		ok, _, err := s.verifyCodeFor(ctx, rc.link.sid, rc.form("code"))
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.Error("2FA verification at reset", "user", rc.link.sam, "err", err)
		}
		return ok, "code"
	})
}

func (s *Server) handleLinkMFAKey(rc *reqCtx) {
	s.linkMFA(rc, func(ctx context.Context) (bool, string) {
		err := s.verifyKey(ctx, rc.sess, waSignin, rc.rawForm("response"))
		if err != nil {
			s.log.Info("security key refused at reset", "user", rc.link.sam, "err", err)
		}
		return err == nil, "security key"
	})
}

// linkMFA runs a second-factor check of a reset; maxLinkMFAFailures wrong
// answers revoke the token.
func (s *Server) linkMFA(rc *reqCtx, verify func(ctx context.Context) (bool, string)) {
	if !atStep(rc, "/link/2fa") {
		return
	}
	ctx, cancel := linkTimeout(rc)
	defer cancel()
	rec := rc.link
	if !s.ipLimit.Allow("2fa:" + rc.ip) {
		rc.render(http.StatusTooManyRequests, "link_2fa", s.linkMFAData(rc, "signin.err.rate_ip"))
		return
	}
	ok, how := false, "blocked"
	if !s.mfaFails.Blocked(rec.sam) {
		ok, how = verify(ctx)
	}
	if ok {
		s.mfaFails.Reset(rec.sam)
		rec.mu.Lock()
		rec.mfaOK = true
		rec.mu.Unlock()
		s.audit(ctx, rc, "reset.mfa", rec.sam, how, store.ResultOK)
		rc.redirect("/link/password")
		return
	}
	s.mfaFails.Fail(rec.sam)
	rec.mu.Lock()
	rec.mfaFailures++
	n := rec.mfaFailures
	rec.mu.Unlock()
	s.audit(ctx, rc, "reset.mfa", rec.sam, how+" refused", store.ResultDenied)
	if n >= maxLinkMFAFailures || how == "blocked" {
		var rr provapi.TokenRevokeResult
		err := s.provCall(ctx, publicActor(rec.id, rc.ip), provapi.OpTokenRevoke,
			&provapi.TokenRevokeParams{SID: rec.sid, Purpose: provapi.PurposeReset, Reason: "mfa-failed"}, &rr)
		result := store.ResultOK
		if err != nil {
			result = store.ResultFailed
			s.log.Error("revoking a reset token after second-factor failures", "user", rec.sam, "err", err)
		}
		s.audit(ctx, rc, "reset.revoked", rec.sam, "token "+rec.tokenID+": mfa-failed", result)
		s.linkInvalid(rc)
		return
	}
	key := "mfa.err.code"
	if how == "security key" {
		key = "mfa.err.key"
	}
	rc.render(http.StatusUnauthorized, "link_2fa", s.linkMFAData(rc, key))
}

// ---- password ----

func (s *Server) handleLinkPasswordPage(rc *reqCtx) {
	if !atStep(rc, "/link/password") {
		return
	}
	rc.render(http.StatusOK, "link_password", map[string]any{"Purpose": rc.link.purpose, "SAM": rc.link.sam})
}

// policyKeys maps the provisioner's password policy reasons to messages.
var policyKeys = map[string]string{
	provapi.ReasonTooShort:   "password.err.too_short",
	provapi.ReasonComplexity: "password.err.complexity",
	provapi.ReasonHistory:    "password.err.history",
	provapi.ReasonTooYoung:   "password.err.too_young",
}

func (s *Server) handleLinkPassword(rc *reqCtx) {
	if !atStep(rc, "/link/password") {
		return
	}
	ctx, cancel := linkTimeout(rc)
	defer cancel()
	rec := rc.link
	fail := func(status int, key string) {
		rc.render(status, "link_password", map[string]any{"Purpose": rec.purpose, "SAM": rec.sam, "Error": rc.T(key)})
	}
	if !s.ipLimit.Allow("password:" + rc.ip) {
		fail(http.StatusTooManyRequests, "signin.err.rate_ip")
		return
	}
	pw, confirm := rc.rawForm("new"), rc.rawForm("confirm")
	if pw == "" {
		fail(http.StatusBadRequest, "password.err.required")
		return
	}
	if pw != confirm {
		fail(http.StatusBadRequest, "password.err.mismatch")
		return
	}
	if len(pw) > provapi.MaxPasswordBytes || strings.ContainsRune(pw, 0) {
		fail(http.StatusBadRequest, "password.err.policy")
		return
	}
	token, err := s.openToken(rec)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	unlock := rec.purpose == provapi.PurposeReset && s.passwordSettings(ctx).ResetUnlock
	var res provapi.PasswordSetResult
	err = s.provCall(ctx, publicActor(rec.id, rc.ip), provapi.OpPasswordSet, &provapi.PasswordSetParams{Token: token, NewPassword: pw, Unlock: unlock}, &res)
	if err != nil {
		var pe *provapi.Error
		if errors.As(err, &pe) && pe.Code == provapi.CodePasswordPolicy {
			s.audit(ctx, rc, rec.purpose+".password_refused", rec.sam, "password policy: "+pe.Reason, store.ResultDenied)
			key, ok := policyKeys[pe.Reason]
			if !ok {
				key = "password.err.policy"
			}
			fail(http.StatusBadRequest, key)
			return
		}
		s.linkFailed(ctx, rc, "password", err, func(key string) { fail(http.StatusServiceUnavailable, key) })
		return
	}
	rec.mu.Lock()
	rec.passwordSet = true
	rec.mu.Unlock()
	if rec.purpose == provapi.PurposeReset {
		detail := "token " + rec.tokenID
		if unlock {
			detail += ", lockout cleared"
		}
		s.audit(ctx, rc, "reset.completed", rec.sam, detail, store.ResultOK)
		// Every conductor session of the user ends.
		n := s.sess.destroyUser(ctx, rec.sid)
		if n > 0 {
			s.audit(ctx, rc, "signout.everywhere", rec.sam, "after a password reset by e-mail: "+itoa(n)+" session(s)", store.ResultOK)
		}
		s.notifyPasswordChanged(ctx, pwChange{SID: rec.sid, SAM: rec.sam, Mail: res.Mail, Lang: rc.lang, From: rc.ip})
		rec.mu.Lock()
		rec.done = true
		rec.mu.Unlock()
		rc.redirect("/link/done")
		return
	}
	s.audit(ctx, rc, "invite.password_set", rec.sam, "token "+rec.tokenID, store.ResultOK)
	s.linkAfterPassword(ctx, rc)
}

// linkAfterPassword continues an invitation after its password: the
// enrollment of a second factor when the policy asks for one, else the
// completion.
func (s *Server) linkAfterPassword(ctx context.Context, rc *reqCtx) {
	rec := rc.link
	step := ""
	if !s.hasSecondFactor(ctx, rec.sid) {
		switch s.cfg.MFA.Policy {
		case config.MFARequired:
			step = enrollRequired
		case config.MFAOptional:
			step = enrollOptional
		}
	}
	if step != "" {
		rec.mu.Lock()
		rec.enroll = step
		rec.mu.Unlock()
		rc.redirect("/link/enroll")
		return
	}
	s.linkComplete(ctx, rc, "")
}

// linkComplete enables the invited account (invite.complete) and ends the
// flow.
func (s *Server) linkComplete(ctx context.Context, rc *reqCtx, note string) {
	rec := rc.link
	token, err := s.openToken(rec)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	var res provapi.InviteCompleteResult
	if err := s.provCall(ctx, publicActor(rec.id, rc.ip), provapi.OpInviteComplete, &provapi.InviteCompleteParams{Token: token}, &res); err != nil {
		s.linkFailed(ctx, rc, "complete", err, func(key string) { rc.errorPage(http.StatusServiceUnavailable, key) })
		return
	}
	detail := "token " + rec.tokenID
	if note != "" {
		detail += ", " + note
	}
	s.audit(ctx, rc, "invite.completed", rec.sam, detail, store.ResultOK)
	s.notifyPasswordChanged(ctx, pwChange{SID: rec.sid, SAM: rec.sam, Mail: rec.addr, Lang: rc.lang, From: rc.ip})
	rec.mu.Lock()
	rec.enroll, rec.done = "", true
	rec.mu.Unlock()
	rc.redirect("/link/done")
}

// ---- enrollment of an invitation ----

func (s *Server) linkEnrollData(rc *reqCtx, errKey string) map[string]any {
	d := s.enrollData(rc, "/link/enroll/qr.png", "/link/enroll")
	d["KeyAction"] = "/link/enroll/key"
	rc.link.mu.Lock()
	d["Skip"] = rc.link.enroll == enrollOptional
	rc.link.mu.Unlock()
	d["SkipAction"] = "/link/enroll/skip"
	if errKey != "" {
		d["Error"] = rc.T(errKey)
	}
	if s.wa != nil {
		if opts, err := s.beginCeremony(rc.ctx(), rc.sess, waRegister); err == nil {
			d["KeyOptions"] = opts
		}
	}
	return d
}

func (s *Server) handleLinkEnrollPage(rc *reqCtx) {
	if !atStep(rc, "/link/enroll") {
		return
	}
	rc.render(http.StatusOK, "enroll", s.linkEnrollData(rc, ""))
}

func (s *Server) handleLinkEnrollQR(rc *reqCtx) {
	if linkStep(rc.link) != "/link/enroll" {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	s.handleEnrollQR(rc)
}

func (s *Server) handleLinkEnroll(rc *reqCtx) {
	if !atStep(rc, "/link/enroll") {
		return
	}
	ctx, cancel := linkTimeout(rc)
	defer cancel()
	if !s.ipLimit.Allow("2fa:"+rc.ip) || s.mfaFails.Blocked(rc.link.sam) {
		rc.render(http.StatusTooManyRequests, "enroll", s.linkEnrollData(rc, "signin.err.rate_account"))
		return
	}
	codes, key := s.completeEnrollment(ctx, rc)
	if key != "" {
		rc.render(http.StatusUnauthorized, "enroll", s.linkEnrollData(rc, key))
		return
	}
	s.linkEnrolled(ctx, rc, codes, "totp")
}

func (s *Server) handleLinkEnrollKey(rc *reqCtx) {
	if !atStep(rc, "/link/enroll") {
		return
	}
	ctx, cancel := linkTimeout(rc)
	defer cancel()
	if !s.ipLimit.Allow("2fa:" + rc.ip) {
		rc.render(http.StatusTooManyRequests, "enroll", s.linkEnrollData(rc, "signin.err.rate_ip"))
		return
	}
	name, ok := cleanKeyName(rc.form("name"))
	if !ok {
		rc.render(http.StatusBadRequest, "enroll", s.linkEnrollData(rc, "keys.err.name"))
		return
	}
	if err := s.registerKey(ctx, rc.sess, name, rc.rawForm("response")); err != nil {
		s.log.Info("security key registration refused", "user", rc.link.sam, "err", err)
		s.audit(ctx, rc, "mfa.enroll", rc.link.sam, "security key registration refused", store.ResultDenied)
		rc.render(http.StatusBadRequest, "enroll", s.linkEnrollData(rc, "keys.err.register"))
		return
	}
	codes, err := s.ensureRecoveryCodes(ctx, rc.link.sid)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	s.audit(ctx, rc, "mfa.enroll", rc.link.sam, "security key "+name+" registered", store.ResultOK)
	s.linkEnrolled(ctx, rc, codes, "security key")
}

// linkEnrolled records the enrollment of an invitation and completes it.
func (s *Server) linkEnrolled(ctx context.Context, rc *reqCtx, codes []string, how string) {
	rec := rc.link
	rec.mu.Lock()
	if len(codes) > 0 {
		rec.codes = codes
	}
	rec.mu.Unlock()
	rc.sess.mu.Lock()
	rc.sess.newRecoveryCodes = nil
	rc.sess.mu.Unlock()
	s.audit(ctx, rc, "invite.enrolled", rec.sam, how, store.ResultOK)
	s.linkComplete(ctx, rc, "second factor "+how)
}

func (s *Server) handleLinkEnrollSkip(rc *reqCtx) {
	if !atStep(rc, "/link/enroll") {
		return
	}
	rc.link.mu.Lock()
	optional := rc.link.enroll == enrollOptional
	rc.link.mu.Unlock()
	if !optional {
		rc.render(http.StatusForbidden, "enroll", s.linkEnrollData(rc, "mfa.err.required"))
		return
	}
	ctx, cancel := linkTimeout(rc)
	defer cancel()
	s.linkComplete(ctx, rc, "second factor skipped")
}

// ---- the end ----

func (s *Server) handleLinkDone(rc *reqCtx) {
	if !atStep(rc, "/link/done") {
		return
	}
	rec := rc.link
	rec.mu.Lock()
	codes := rec.codes
	rec.codes = nil
	rec.mu.Unlock()
	d := map[string]any{"Purpose": rec.purpose, "SAM": rec.sam, "Codes": codes}
	// The record ends here: the page is shown once.
	s.links.drop(rec)
	clearCookie(rc.w, linkCookie)
	rc.render(http.StatusOK, "link_done", d)
}
