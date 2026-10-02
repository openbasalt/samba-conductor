package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/conductor/internal/directory"
	"github.com/samba-conductor/conductor/internal/store"
	"github.com/samba-conductor/conductor/internal/totp"
	"rsc.io/qr"
)

// signinMessages are the only notes /signin?m= may show.
var signinMessages = map[string]string{
	"signed_out":       "signin.msg.signed_out",
	"signed_out_all":   "signin.msg.signed_out_all",
	"password_changed": "signin.msg.password_changed",
	"reauth":           "signin.msg.reauth",
	"mfa_required":     "signin.msg.mfa_required",
	"expired":          "signin.msg.expired",
}

func (rc *reqCtx) form(name string) string { return strings.TrimSpace(rc.r.PostFormValue(name)) }

// rawForm returns a form value untrimmed (passwords).
func (rc *reqCtx) rawForm(name string) string { return rc.r.PostFormValue(name) }

func (rc *reqCtx) flashOK(key string, args ...any) {
	if rc.sess != nil {
		rc.sess.addFlash("ok", rc.T(key, args...))
	}
}

func (rc *reqCtx) flashErr(key string, args ...any) {
	if rc.sess != nil {
		rc.sess.addFlash("error", rc.T(key, args...))
	}
}

// ensurePreCookie sets the pre-session CSRF cookie of the sign-in form.
func (rc *reqCtx) ensurePreCookie() string {
	if c, err := rc.r.Cookie(preCookie); err == nil && len(c.Value) >= 32 && len(c.Value) <= 64 {
		return c.Value
	}
	tok := newToken()
	setCookie(rc.w, preCookie, tok, 3600)
	// Make it visible to this render too.
	rc.r.AddCookie(&http.Cookie{Name: preCookie, Value: tok})
	return tok
}

// landing is where a fully signed-in user starts.
func landing(r Roles) string {
	switch {
	case r.Has(PermDashboard):
		return "/admin"
	case r.Has(PermUsersRead):
		return "/admin/users"
	default:
		return "/me"
	}
}

func (s *Server) handleRoot(rc *reqCtx) { rc.redirect(landing(rc.roles)) }

// ---- sign-in ----

func (s *Server) handleSigninPage(rc *reqCtx) {
	if rc.sess != nil {
		switch rc.sess.snapshotStage() {
		case stageFull:
			rc.redirect("/")
			return
		case stageMFA:
			rc.redirect("/signin/2fa")
			return
		case stageEnroll:
			rc.redirect("/signin/enroll")
			return
		case stageMustChange:
			rc.redirect("/signin/password")
			return
		}
	}
	rc.ensurePreCookie()
	d := map[string]any{"Enroll": cleanLinkToken(rc.r.URL.Query().Get("enroll"))}
	if k, ok := signinMessages[rc.r.URL.Query().Get("m")]; ok {
		d["Notice"] = rc.T(k)
	}
	rc.render(http.StatusOK, "signin", d)
}

// cleanLinkToken accepts only the shape of an enrollment token.
func cleanLinkToken(t string) string {
	if len(t) < 32 || len(t) > 64 || strings.ContainsFunc(t, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
	}) {
		return ""
	}
	return t
}

func linkHash(tok string) string {
	h := sha256.Sum256([]byte("conductor-enroll\x00" + tok))
	return hex.EncodeToString(h[:])
}

func (s *Server) signinError(rc *reqCtx, status int, key, username, enroll string) {
	rc.ensurePreCookie()
	rc.render(status, "signin", map[string]any{"Error": rc.T(key), "Username": username, "Enroll": enroll})
}

func (s *Server) handleSignin(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	typed := rc.form("username")
	password := rc.rawForm("password")
	enroll := cleanLinkToken(rc.form("enroll"))
	rc.actorHint = clipName(typed)
	if !s.ipLimit.Allow("signin:" + rc.ip) {
		s.audit(ctx, rc, "signin.rate_limited", rc.ip, "per-address limit", store.ResultDenied)
		s.signinError(rc, http.StatusTooManyRequests, "signin.err.rate_ip", typed, enroll)
		return
	}
	sam, ok := directory.NormalizeUsername(typed, s.backend.Realm())
	if !ok || password == "" {
		s.signinError(rc, http.StatusUnauthorized, "signin.err.invalid", typed, enroll)
		return
	}
	rc.actorHint = sam
	if s.accountFails.Blocked(sam) {
		s.audit(ctx, rc, "signin.rate_limited", sam, "per-account limit", store.ResultDenied)
		s.signinError(rc, http.StatusTooManyRequests, "signin.err.rate_account", typed, enroll)
		return
	}
	cred, err := s.backend.SignIn(ctx, sam, password)
	if err != nil {
		s.signinFailed(rc, ctx, sam, typed, enroll, err)
		return
	}
	id, groups, err := s.identify(ctx, cred, sam)
	if err != nil {
		cred.Close()
		s.log.Error("identify after sign-in failed", "user", sam, "err", err)
		s.audit(ctx, rc, "signin.failure", sam, "directory lookup failed", store.ResultFailed)
		s.signinError(rc, http.StatusBadGateway, "err.directory", typed, enroll)
		return
	}
	s.accountFails.Reset(sam)
	roles := s.roleSIDs.resolve(id.SID, groups)
	enrolled := s.keyCount(ctx, id.SID.String()) > 0
	if _, err := s.store.GetTOTP(ctx, id.SID.String()); err == nil {
		enrolled = true
	} else if !errors.Is(err, store.ErrNotFound) {
		cred.Close()
		s.log.Error("reading 2FA state", "err", err)
		s.signinError(rc, http.StatusInternalServerError, "err.internal", typed, enroll)
		return
	}
	sess := &Session{sam: strings.ToLower(id.SAM), dn: id.DN, userSID: id.SID, displayName: id.DisplayName, cred: cred,
		ip: rc.ip, userAgent: rc.r.UserAgent(), roles: roles, rolesAt: s.now(), groupSIDs: groups}
	switch {
	case enrolled:
		sess.stage = stageMFA
	case s.mfaRequired(roles):
		if roles.Admin && s.cfg.AdminEnrollmentLinkRequired() {
			valid := false
			if enroll != "" {
				valid, _ = s.store.ValidEnrollLink(ctx, linkHash(enroll), sess.sam)
			}
			if !valid {
				cred.Close()
				s.audit(ctx, rc, "signin.failure", sam, "administrator without 2FA and without a valid enrollment link", store.ResultDenied)
				s.signinError(rc, http.StatusForbidden, "signin.err.admin_link", typed, "")
				return
			}
			sess.enrollLink = linkHash(enroll)
		}
		sess.stage = stageEnroll
		sess.enrollKeyOnly = s.keyRequired(roles)
	default:
		sess.stage = stageFull
	}
	tok, err := s.sess.create(ctx, sess)
	if err != nil {
		cred.Close()
		s.log.Error("creating session", "err", err)
		s.signinError(rc, http.StatusInternalServerError, "err.internal", typed, enroll)
		return
	}
	setCookie(rc.w, sessionCookie, tok, 0)
	clearCookie(rc.w, preCookie)
	rc.sess = sess
	s.audit(ctx, rc, "signin.password", sam, "mechanism="+cred.Mechanism()+" next="+sess.stage.String()+" roles="+strings.Join(roles.Names(), ","), store.ResultOK)
	switch sess.stage {
	case stageMFA:
		rc.redirect("/signin/2fa")
	case stageEnroll:
		rc.redirect("/signin/enroll")
	default:
		rc.redirect(landing(roles))
	}
}

func clipName(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
}

// signinFailed maps a refused sign-in to a clear message. Only expired /
// must-change passwords (proven right by AD) lead to the change page.
func (s *Server) signinFailed(rc *reqCtx, ctx context.Context, sam, typed, enroll string, err error) {
	var ae *ad.AuthError
	if !errors.As(err, &ae) {
		s.log.Error("sign-in: directory unavailable", "user", sam, "err", err)
		s.audit(ctx, rc, "signin.failure", sam, "directory unavailable", store.ResultFailed)
		s.signinError(rc, http.StatusBadGateway, "err.directory", typed, enroll)
		return
	}
	detail := "reason=" + ae.Reason.String() + " code=" + ae.Code
	if ae.PasswordVerified() {
		sess := &Session{sam: sam, stage: stageMustChange, ip: rc.ip, userAgent: rc.r.UserAgent()}
		tok, cerr := s.sess.create(ctx, sess)
		if cerr != nil {
			s.signinError(rc, http.StatusInternalServerError, "err.internal", typed, enroll)
			return
		}
		setCookie(rc.w, sessionCookie, tok, 0)
		clearCookie(rc.w, preCookie)
		s.audit(ctx, rc, "signin.password_change_required", sam, detail, store.ResultPending)
		rc.redirect("/signin/password")
		return
	}
	key := "signin.err.invalid"
	switch ae.Reason {
	case ad.ReasonAccountLocked:
		key = "signin.err.locked"
	case ad.ReasonAccountDisabled:
		key = "signin.err.disabled"
	case ad.ReasonAccountExpired:
		key = "signin.err.account_expired"
	case ad.ReasonLogonHours, ad.ReasonWorkstationRestricted, ad.ReasonAccountRestricted:
		key = "signin.err.restricted"
	case ad.ReasonClockSkew:
		key = "signin.err.clock"
	case ad.ReasonPasswordExpired, ad.ReasonPasswordMustChange:
		// Not proven: AD said "expired" without verifying the password.
		key = "signin.err.invalid"
	}
	if key == "signin.err.invalid" {
		s.accountFails.Fail(sam)
	}
	s.audit(ctx, rc, "signin.failure", sam, detail, store.ResultDenied)
	s.signinError(rc, http.StatusUnauthorized, key, typed, enroll)
}

// ---- password change for expired / must-change accounts ----

func (s *Server) handleExpiredPasswordPage(rc *reqCtx) {
	rc.render(http.StatusOK, "signin_password", map[string]any{"Username": rc.sess.sam})
}

func (s *Server) handleExpiredPassword(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	sam := rc.sess.sam
	fail := func(status int, key string) {
		rc.render(status, "signin_password", map[string]any{"Username": sam, "Error": rc.T(key)})
	}
	if !s.ipLimit.Allow("signin:" + rc.ip) {
		fail(http.StatusTooManyRequests, "signin.err.rate_ip")
		return
	}
	if s.accountFails.Blocked(sam) {
		fail(http.StatusTooManyRequests, "signin.err.rate_account")
		return
	}
	oldPw, newPw, confirm := rc.rawForm("current"), rc.rawForm("new"), rc.rawForm("confirm")
	if oldPw == "" || newPw == "" {
		fail(http.StatusBadRequest, "password.err.required")
		return
	}
	if newPw != confirm {
		fail(http.StatusBadRequest, "password.err.mismatch")
		return
	}
	err := s.backend.ChangeExpiredPassword(ctx, sam, oldPw, newPw)
	if err != nil {
		key, result := passwordChangeError(err)
		if key == "password.err.current" {
			s.accountFails.Fail(sam)
		}
		s.log.Info("expired password change refused", "user", sam, "err", err)
		s.audit(ctx, rc, "password.change_expired", sam, "", result)
		fail(http.StatusBadRequest, key)
		return
	}
	s.accountFails.Reset(sam)
	s.audit(ctx, rc, "password.change_expired", sam, "kpasswd (old password verified)", store.ResultOK)
	s.sess.destroy(ctx, rc.sess)
	clearCookie(rc.w, sessionCookie)
	rc.redirectSignin("password_changed")
}

// passwordChangeError maps a password change error to a message.
func passwordChangeError(err error) (string, string) {
	var ae *ad.AuthError
	switch {
	case errors.As(err, &ae) && ae.Reason == ad.ReasonInvalidCredentials, errors.Is(err, ad.ErrWrongPassword):
		return "password.err.current", store.ResultDenied
	case errors.As(err, &ae):
		return "signin.err.restricted", store.ResultDenied
	case errors.Is(err, ad.ErrPasswordPolicy):
		return "password.err.policy", store.ResultFailed
	case errors.Is(err, ad.ErrAccessDenied):
		return "err.ad.access_denied", store.ResultDenied
	}
	return "err.directory", store.ResultFailed
}

// ---- second factor ----

// mfaPageData prepares the second-factor page: the code form (TOTP or
// recovery code) and, when the user has security keys, a key assertion.
func (s *Server) mfaPageData(rc *reqCtx, errMsg string) map[string]any {
	sess := rc.sess
	sess.mu.Lock()
	roles := sess.roles
	sess.mu.Unlock()
	d := map[string]any{"Error": errMsg, "KeyRequired": s.keyRequired(roles)}
	if s.wa != nil {
		if opts, err := s.beginCeremony(rc.ctx(), sess, waSignin); err == nil {
			d["KeyOptions"] = opts
		}
	}
	return d
}

func (s *Server) handleMFAPage(rc *reqCtx) {
	rc.render(http.StatusOK, "signin_2fa", s.mfaPageData(rc, ""))
}

// secondFactorDone ends the sign-in after a verified second factor: a full
// session with a new cookie value, unless administrators must use a
// security key and this one has none yet (then registering one is next).
func (s *Server) secondFactorDone(rc *reqCtx, detail string) {
	ctx := rc.ctx()
	sess := rc.sess
	sess.mu.Lock()
	sess.mfaVerified = true
	roles, keyOK := sess.roles, sess.keyOK
	userSID := sess.userSID.String()
	sess.mu.Unlock()
	next := stageFull
	if s.keyRequired(roles) && !keyOK && s.keyCount(ctx, userSID) == 0 {
		sess.mu.Lock()
		sess.enrollKeyOnly = true
		sess.mu.Unlock()
		next = stageEnroll
	}
	tok, err := s.sess.rotate(ctx, sess, next)
	if err != nil {
		rc.render(http.StatusInternalServerError, "signin_2fa", s.mfaPageData(rc, rc.T("err.internal")))
		return
	}
	setCookie(rc.w, sessionCookie, tok, 0)
	s.audit(ctx, rc, "mfa.verify", sess.sam, detail, store.ResultOK)
	if next == stageEnroll {
		rc.redirect("/signin/enroll")
		return
	}
	rc.redirect(landing(roles))
}

// verifySecondFactor checks a TOTP or recovery code for the session's user,
// with replay protection. It returns (ok, usedRecoveryCode).
func (s *Server) verifySecondFactor(ctx context.Context, sess *Session, code string) (bool, bool, error) {
	userSID := sess.userSID.String()
	if totp.LooksLikeRecoveryCode(code) {
		ok, err := s.store.UseRecoveryCode(ctx, userSID, totp.HashRecoveryCode(userSID, code))
		return ok, ok, err
	}
	rec, err := s.store.GetTOTP(ctx, userSID)
	if err != nil {
		return false, false, err
	}
	sec, err := s.box.Open(rec.Secret, []byte(userSID))
	if err != nil {
		return false, false, err
	}
	defer clear(sec)
	step, ok := totp.Verify(sec, code, s.now())
	if !ok {
		return false, false, nil
	}
	fresh, err := s.store.UseTOTPStep(ctx, userSID, step)
	return fresh, false, err
}

// maxMFAFailures ends a sign-in after this many wrong codes.
const maxMFAFailures = 5

func (s *Server) handleMFA(rc *reqCtx) {
	ctx := rc.ctx()
	sess := rc.sess
	fail := func(status int, key string) {
		rc.render(status, "signin_2fa", s.mfaPageData(rc, rc.T(key)))
	}
	if !s.ipLimit.Allow("2fa:" + rc.ip) {
		fail(http.StatusTooManyRequests, "signin.err.rate_ip")
		return
	}
	if s.mfaFails.Blocked(sess.sam) {
		s.audit(ctx, rc, "mfa.rate_limited", sess.sam, "", store.ResultDenied)
		s.sess.destroy(ctx, sess)
		clearCookie(rc.w, sessionCookie)
		rc.ensurePreCookie()
		rc.render(http.StatusTooManyRequests, "signin", map[string]any{"Error": rc.T("signin.err.rate_account")})
		return
	}
	sess.mu.Lock()
	keyRequired := s.keyRequired(sess.roles)
	sess.mu.Unlock()
	code := rc.form("code")
	if keyRequired && !totp.LooksLikeRecoveryCode(code) {
		// Administrators must use a security key; a recovery code is the
		// only other way in.
		s.audit(ctx, rc, "mfa.verify", sess.sam, "TOTP refused: security key required", store.ResultDenied)
		fail(http.StatusUnauthorized, "mfa.err.key_required")
		return
	}
	ok, recovery, err := s.verifySecondFactor(ctx, sess, code)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Error("2FA verification", "user", sess.sam, "err", err)
		fail(http.StatusInternalServerError, "err.internal")
		return
	}
	if !ok {
		s.mfaFails.Fail(sess.sam)
		sess.mu.Lock()
		sess.mfaFailures++
		n := sess.mfaFailures
		sess.mu.Unlock()
		s.audit(ctx, rc, "mfa.verify", sess.sam, "", store.ResultDenied)
		if n >= maxMFAFailures {
			s.sess.destroy(ctx, sess)
			clearCookie(rc.w, sessionCookie)
			rc.redirectSignin("")
			return
		}
		fail(http.StatusUnauthorized, "mfa.err.code")
		return
	}
	s.mfaFails.Reset(sess.sam)
	detail := "totp"
	if recovery {
		detail = "recovery code"
		left, _ := s.store.RecoveryCodesLeft(ctx, sess.userSID.String())
		sess.addFlash("info", rc.T("mfa.recovery_used", left))
		if keyRequired {
			// The emergency path of a key-only administrator.
			sess.mu.Lock()
			sess.keyOK = true
			sess.mu.Unlock()
		}
	}
	s.secondFactorDone(rc, detail)
}

// ---- enrollment (sign-in flow and self-service share it) ----

func (s *Server) enrollSecret(sess *Session) ([]byte, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.enrollSecret == nil {
		sec, err := totp.NewSecret()
		if err != nil {
			return nil, err
		}
		sess.enrollSecret = sec
	}
	return append([]byte(nil), sess.enrollSecret...), nil
}

func (s *Server) enrollData(rc *reqCtx, qrPath, action string) map[string]any {
	sec, err := s.enrollSecret(rc.sess)
	if err != nil {
		return map[string]any{"Error": rc.T("err.internal")}
	}
	return map[string]any{"Secret": totp.EncodeSecret(sec), "QR": qrPath, "Action": action,
		"Account": rc.sess.sam + "@" + s.backend.Realm(), "Issuer": s.cfg.MFA.Issuer}
}

// enrollPageData prepares the sign-in enrollment page: TOTP (unless only a
// security key is accepted) and the registration of a key.
func (s *Server) enrollPageData(rc *reqCtx) map[string]any {
	rc.sess.mu.Lock()
	keyOnly := rc.sess.enrollKeyOnly
	rc.sess.mu.Unlock()
	d := map[string]any{"KeyOnly": keyOnly, "KeyAction": "/signin/enroll/key"}
	if !keyOnly {
		d = s.enrollData(rc, "/signin/enroll/qr.png", "/signin/enroll")
		d["KeyAction"] = "/signin/enroll/key"
	}
	if s.wa != nil {
		if opts, err := s.beginCeremony(rc.ctx(), rc.sess, waRegister); err == nil {
			d["KeyOptions"] = opts
		}
	}
	return d
}

func (s *Server) handleEnrollPage(rc *reqCtx) {
	rc.render(http.StatusOK, "enroll", s.enrollPageData(rc))
}

// handleEnrollQR renders the otpauth URI of the pending secret as a PNG.
func (s *Server) handleEnrollQR(rc *reqCtx) {
	sec, err := s.enrollSecret(rc.sess)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	code, err := qr.Encode(totpURI(s, rc.sess, sec), qr.M)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	code.Scale = 6
	rc.w.Header().Set("Content-Type", "image/png")
	_, _ = rc.w.Write(code.PNG())
}

func totpURI(s *Server, sess *Session, sec []byte) string {
	return totp.URI(s.cfg.MFA.Issuer, sess.sam+"@"+s.backend.Realm(), sec)
}

// completeEnrollment verifies the first code and stores the enrollment.
// It returns the recovery codes to show once.
func (s *Server) completeEnrollment(ctx context.Context, rc *reqCtx) ([]string, string) {
	sess := rc.sess
	sec, err := s.enrollSecret(sess)
	if err != nil {
		return nil, "err.internal"
	}
	step, ok := totp.Verify(sec, rc.form("code"), s.now())
	if !ok {
		s.mfaFails.Fail(sess.sam)
		s.audit(ctx, rc, "mfa.enroll", sess.sam, "wrong first code", store.ResultDenied)
		return nil, "mfa.err.code"
	}
	sess.mu.Lock()
	link := sess.enrollLink
	userSID := sess.userSID.String()
	sess.mu.Unlock()
	if link != "" {
		consumed, err := s.store.ConsumeEnrollLink(ctx, link, sess.sam)
		if err != nil || !consumed {
			s.audit(ctx, rc, "mfa.enroll", sess.sam, "enrollment link no longer valid", store.ResultDenied)
			return nil, "signin.err.admin_link"
		}
	}
	sealed, err := s.box.Seal(sec, []byte(userSID))
	if err != nil {
		return nil, "err.internal"
	}
	codes, err := totp.NewRecoveryCodes()
	if err != nil {
		return nil, "err.internal"
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = totp.HashRecoveryCode(userSID, c)
	}
	if err := s.store.EnrollTOTP(ctx, store.TOTPRecord{UserSID: userSID, Username: sess.sam, Secret: sealed, LastStep: step}, hashes); err != nil {
		s.log.Error("storing 2FA enrollment", "err", err)
		return nil, "err.internal"
	}
	sess.mu.Lock()
	clear(sess.enrollSecret)
	sess.enrollSecret = nil
	sess.enrollLink = ""
	sess.mfaVerified = true
	sess.newRecoveryCodes = codes
	sess.mu.Unlock()
	detail := "totp enrolled"
	if link != "" {
		detail += " with an enrollment link"
	}
	s.audit(ctx, rc, "mfa.enroll", sess.sam, detail, store.ResultOK)
	return codes, ""
}

func (s *Server) handleEnroll(rc *reqCtx) {
	ctx := rc.ctx()
	rc.sess.mu.Lock()
	keyOnly := rc.sess.enrollKeyOnly
	rc.sess.mu.Unlock()
	if keyOnly {
		d := s.enrollPageData(rc)
		d["Error"] = rc.T("mfa.err.key_required")
		rc.render(http.StatusForbidden, "enroll", d)
		return
	}
	if !s.ipLimit.Allow("2fa:" + rc.ip) {
		d := s.enrollPageData(rc)
		d["Error"] = rc.T("signin.err.rate_ip")
		rc.render(http.StatusTooManyRequests, "enroll", d)
		return
	}
	if _, key := s.completeEnrollment(ctx, rc); key != "" {
		d := s.enrollPageData(rc)
		d["Error"] = rc.T(key)
		rc.render(http.StatusUnauthorized, "enroll", d)
		return
	}
	tok, err := s.sess.rotate(ctx, rc.sess, stageFull)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	setCookie(rc.w, sessionCookie, tok, 0)
	rc.redirect("/me/recovery-codes")
}

// handleRecoveryCodes shows freshly generated recovery codes exactly once.
func (s *Server) handleRecoveryCodes(rc *reqCtx) {
	rc.sess.mu.Lock()
	codes := rc.sess.newRecoveryCodes
	rc.sess.newRecoveryCodes = nil
	rc.sess.mu.Unlock()
	if len(codes) == 0 {
		rc.redirect("/me/security")
		return
	}
	rc.render(http.StatusOK, "recovery_codes", map[string]any{"Codes": codes, "Next": landing(rc.roles)})
}

// ---- sign-out ----

func (s *Server) handleSignout(rc *reqCtx) {
	s.audit(rc.ctx(), rc, "signout", rc.sess.sam, "", store.ResultOK)
	s.sess.destroy(rc.ctx(), rc.sess)
	clearCookie(rc.w, sessionCookie)
	rc.redirectSignin("signed_out")
}

// pngMagic lets tests recognize a PNG.
var pngMagic = []byte("\x89PNG")

func isPNG(b []byte) bool { return bytes.HasPrefix(b, pngMagic) }

// enrollLinkTTL is how long an administrator enrollment link stays valid.
const enrollLinkTTL = 24 * time.Hour

// NewEnrollLinkToken returns a fresh enrollment link token and the hash the
// store keeps for it (used by `conductor enroll-link`).
func NewEnrollLinkToken() (token, hash string) {
	token = newToken()
	return token, linkHash(token)
}
