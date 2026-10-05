package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

// WebAuthn (security keys and platform authenticators) as a second factor,
// next to TOTP. The browser part is static/webauthn.js, the only script of
// the application, served only on the second-factor pages (route.script)
// under a per-response CSP nonce. A ceremony's challenge lives in the
// server-side session, bound to its purpose, and is used once.

// Ceremony purposes.
const (
	waRegister = "register"
	waSignin   = "signin"
	waReauth   = "reauth"
)

// waUser adapts a conductor user to go-webauthn.
type waUser struct {
	id      []byte
	name    string
	display string
	creds   []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte                         { return u.id }
func (u waUser) WebAuthnName() string                       { return u.name }
func (u waUser) WebAuthnDisplayName() string                { return u.display }
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// userHandle is the WebAuthn user handle of an AD user: derived from the
// SID, so it is stable and contains no readable personal data.
func userHandle(userSID string) []byte {
	h := sha256.Sum256([]byte("conductor-webauthn\x00" + userSID))
	return h[:]
}

func newWebAuthn(c *config.Config) (*webauthn.WebAuthn, error) {
	if !c.WebAuthn.Enabled() {
		return nil, nil
	}
	return webauthn.New(&webauthn.Config{
		RPID:                  c.WebAuthn.RPID,
		RPDisplayName:         c.WebAuthn.DisplayName,
		RPOrigins:             c.WebAuthnAllOrigins(),
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
			UserVerification: protocol.VerificationPreferred,
		},
	})
}

// keyRequired reports whether a user with these roles must use a security
// key (TOTP is then not accepted).
func (s *Server) keyRequired(r Roles) bool {
	return r.Admin && s.cfg.WebAuthn.Enabled() && s.cfg.WebAuthn.AdminRequired
}

// waUserFor loads a session user's credentials.
func (s *Server) waUserFor(ctx context.Context, sess *Session) (waUser, []store.WebAuthnCredential, error) {
	sess.mu.Lock()
	userSID, sam, display := sess.userSID.String(), sess.sam, sess.displayName
	sess.mu.Unlock()
	return s.waUserBySID(ctx, userSID, sam, display)
}

// waUserBySID loads a user's credentials by SID.
func (s *Server) waUserBySID(ctx context.Context, userSID, sam, display string) (waUser, []store.WebAuthnCredential, error) {
	rows, err := s.store.WebAuthnCredentials(ctx, userSID)
	if err != nil {
		return waUser{}, nil, err
	}
	u := waUser{id: userHandle(userSID), name: sam + "@" + strings.ToLower(s.backend.Realm()), display: display}
	for _, r := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal(r.Data, &c); err != nil {
			return waUser{}, nil, err
		}
		u.creds = append(u.creds, c)
	}
	return u, rows, nil
}

// keyCount returns how many security keys a user has (0 when WebAuthn is
// off).
func (s *Server) keyCount(ctx context.Context, userSID string) int {
	if s.wa == nil {
		return 0
	}
	rows, err := s.store.WebAuthnCredentials(ctx, userSID)
	if err != nil {
		return 0
	}
	return len(rows)
}

func (s *Server) hasKeys(rc *reqCtx) bool {
	if rc.sess == nil {
		return false
	}
	rc.sess.mu.Lock()
	userSID := rc.sess.userSID.String()
	rc.sess.mu.Unlock()
	return s.keyCount(rc.ctx(), userSID) > 0
}

// beginCeremony starts a registration or an assertion for the session's
// user and returns the options JSON for the page.
func (s *Server) beginCeremony(ctx context.Context, sess *Session, purpose string) (string, error) {
	if s.wa == nil {
		return "", errWebAuthnOff
	}
	u, _, err := s.waUserFor(ctx, sess)
	if err != nil {
		return "", err
	}
	var options any
	var data *webauthn.SessionData
	if purpose == waRegister {
		exclude := make([]protocol.CredentialDescriptor, 0, len(u.creds))
		for _, c := range u.creds {
			exclude = append(exclude, c.Descriptor())
		}
		options, data, err = s.wa.BeginRegistration(u, webauthn.WithExclusions(exclude))
	} else {
		if len(u.creds) == 0 {
			return "", errNoKeys
		}
		options, data, err = s.wa.BeginLogin(u)
	}
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	sess.mu.Lock()
	sess.waCeremony, sess.waPurpose = data, purpose
	sess.mu.Unlock()
	return string(b), nil
}

var (
	errWebAuthnOff = errors.New("web: WebAuthn is not configured")
	errNoKeys      = errors.New("web: no security keys")
	errCeremony    = errors.New("web: no matching WebAuthn ceremony")
)

// takeCeremony returns and forgets the session's pending ceremony of a
// purpose (single use).
func takeCeremony(sess *Session, purpose string) (*webauthn.SessionData, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	data, p := sess.waCeremony, sess.waPurpose
	sess.waCeremony, sess.waPurpose = nil, ""
	if data == nil || p != purpose {
		return nil, errCeremony
	}
	return data, nil
}

// verifyKey checks an assertion ("response" form field) for the session's
// user and records the use of the key.
func (s *Server) verifyKey(ctx context.Context, sess *Session, purpose, response string) error {
	if s.wa == nil {
		return errWebAuthnOff
	}
	data, err := takeCeremony(sess, purpose)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(response))
	if err != nil {
		return err
	}
	u, _, err := s.waUserFor(ctx, sess)
	if err != nil {
		return err
	}
	cred, err := s.wa.ValidateLogin(u, *data, parsed)
	if err != nil {
		return err
	}
	if cred.Authenticator.CloneWarning {
		// The signature counter went backwards: possibly a cloned key.
		return errors.New("web: authenticator counter regressed (possible clone)")
	}
	b, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	sess.mu.Lock()
	userSID := sess.userSID.String()
	sess.mu.Unlock()
	return s.store.UseWebAuthnCredential(ctx, userSID, base64.RawURLEncoding.EncodeToString(cred.ID), b)
}

// registerKey finishes a registration ("response" form field) and stores
// the new credential under name.
func (s *Server) registerKey(ctx context.Context, sess *Session, name, response string) error {
	if s.wa == nil {
		return errWebAuthnOff
	}
	data, err := takeCeremony(sess, waRegister)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(response))
	if err != nil {
		return err
	}
	u, _, err := s.waUserFor(ctx, sess)
	if err != nil {
		return err
	}
	cred, err := s.wa.CreateCredential(u, *data, parsed)
	if err != nil {
		return err
	}
	b, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	sess.mu.Lock()
	userSID, sam := sess.userSID.String(), sess.sam
	sess.mu.Unlock()
	return s.store.AddWebAuthnCredential(ctx, store.WebAuthnCredential{ID: base64.RawURLEncoding.EncodeToString(cred.ID),
		UserSID: userSID, Username: sam, Name: name, Data: b})
}

// cleanKeyName validates the name a user gives a key.
func cleanKeyName(n string) (string, bool) {
	n = strings.TrimSpace(n)
	if n == "" || len([]rune(n)) > 64 || strings.ContainsFunc(n, func(r rune) bool { return r < 0x20 }) {
		return "", false
	}
	return n, true
}

// ensureRecoveryCodes gives a user recovery codes when they have none (a
// first security key registered without TOTP) and returns them to show.
func (s *Server) ensureRecoveryCodes(ctx context.Context, userSID string) ([]string, error) {
	if n, err := s.store.RecoveryCodesLeft(ctx, userSID); err != nil || n > 0 {
		return nil, err
	}
	codes, err := totp.NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = totp.HashRecoveryCode(userSID, c)
	}
	return codes, s.store.ReplaceRecoveryCodes(ctx, userSID, hashes)
}

// ---- sign-in with a key (stage MFA) ----

func (s *Server) handleMFAKey(rc *reqCtx) {
	ctx := rc.ctx()
	sess := rc.sess
	if !s.ipLimit.Allow("2fa:"+rc.ip) || s.mfaFails.Blocked(sess.sam) {
		rc.render(http.StatusTooManyRequests, "signin_2fa", s.mfaPageData(rc, rc.T("signin.err.rate_ip")))
		return
	}
	if err := s.verifyKey(ctx, sess, waSignin, rc.rawForm("response")); err != nil {
		s.mfaFails.Fail(sess.sam)
		sess.mu.Lock()
		sess.mfaFailures++
		n := sess.mfaFailures
		sess.mu.Unlock()
		s.log.Info("security key sign-in refused", "user", sess.sam, "err", err)
		s.audit(ctx, rc, "mfa.verify", sess.sam, "security key refused", store.ResultDenied)
		if n >= maxMFAFailures {
			s.sess.destroy(ctx, sess)
			clearCookie(rc.w, sessionCookie)
			rc.redirectSignin("")
			return
		}
		rc.render(http.StatusUnauthorized, "signin_2fa", s.mfaPageData(rc, rc.T("mfa.err.key")))
		return
	}
	s.mfaFails.Reset(sess.sam)
	sess.mu.Lock()
	sess.keyOK = true
	sess.mu.Unlock()
	s.secondFactorDone(rc, "security key")
}

// ---- enrollment with a key (stage enroll) ----

func (s *Server) handleEnrollKey(rc *reqCtx) {
	ctx := rc.ctx()
	sess := rc.sess
	fail := func(status int, key string) {
		d := s.enrollPageData(rc)
		d["Error"] = rc.T(key)
		rc.render(status, "enroll", d)
	}
	if !s.ipLimit.Allow("2fa:" + rc.ip) {
		fail(http.StatusTooManyRequests, "signin.err.rate_ip")
		return
	}
	name, ok := cleanKeyName(rc.form("name"))
	if !ok {
		fail(http.StatusBadRequest, "keys.err.name")
		return
	}
	sess.mu.Lock()
	link := sess.enrollLink
	userSID := sess.userSID.String()
	sess.mu.Unlock()
	if link != "" {
		if valid, _ := s.store.ValidEnrollLink(ctx, link, sess.sam); !valid {
			s.audit(ctx, rc, "mfa.enroll", sess.sam, "enrollment link no longer valid", store.ResultDenied)
			fail(http.StatusForbidden, "signin.err.admin_link")
			return
		}
	}
	if err := s.registerKey(ctx, sess, name, rc.rawForm("response")); err != nil {
		s.log.Info("security key registration refused", "user", sess.sam, "err", err)
		s.audit(ctx, rc, "mfa.enroll", sess.sam, "security key registration refused", store.ResultDenied)
		fail(http.StatusBadRequest, "keys.err.register")
		return
	}
	if link != "" {
		if consumed, err := s.store.ConsumeEnrollLink(ctx, link, sess.sam); err != nil || !consumed {
			// The key is stored but the link was used meanwhile: remove it.
			_ = s.store.DeleteWebAuthnCredentials(ctx, userSID)
			s.audit(ctx, rc, "mfa.enroll", sess.sam, "enrollment link no longer valid", store.ResultDenied)
			fail(http.StatusForbidden, "signin.err.admin_link")
			return
		}
	}
	codes, err := s.ensureRecoveryCodes(ctx, userSID)
	if err != nil {
		fail(http.StatusInternalServerError, "err.internal")
		return
	}
	sess.mu.Lock()
	sess.enrollLink, sess.enrollKeyOnly = "", false
	sess.mfaVerified, sess.keyOK, sess.mfaAt = true, true, s.now()
	if len(codes) > 0 {
		sess.newRecoveryCodes = codes
	}
	clear(sess.enrollSecret)
	sess.enrollSecret = nil
	sess.mu.Unlock()
	detail := "security key " + name + " registered"
	if link != "" {
		detail += " with an enrollment link"
	}
	s.audit(ctx, rc, "mfa.enroll", sess.sam, detail, store.ResultOK)
	tok, err := s.sess.rotate(ctx, sess, stageFull)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	setCookie(rc.w, sessionCookie, tok, 0)
	if len(codes) > 0 {
		rc.redirect("/me/recovery-codes")
		return
	}
	sess.mu.Lock()
	roles := sess.roles
	sess.mu.Unlock()
	rc.redirect(landing(roles))
}

// ---- self-service keys ----

func (s *Server) handleKeyRegister(rc *reqCtx) {
	ctx := rc.ctx()
	if s.wa == nil {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	if s.cfg.MFA.Policy == config.MFAOff && !s.mfaRequired(rc.roles) {
		rc.errorPage(http.StatusForbidden, "err.forbidden")
		return
	}
	if !s.ipLimit.Allow("2fa:" + rc.ip) {
		rc.flashErr("signin.err.rate_ip")
		rc.redirect("/me/security")
		return
	}
	name, ok := cleanKeyName(rc.form("name"))
	if !ok {
		rc.flashErr("keys.err.name")
		rc.redirect("/me/security")
		return
	}
	if err := s.registerKey(ctx, rc.sess, name, rc.rawForm("response")); err != nil {
		s.log.Info("security key registration refused", "user", rc.sess.sam, "err", err)
		s.audit(ctx, rc, "mfa.key_register", rc.sess.sam, "refused", store.ResultDenied)
		rc.flashErr("keys.err.register")
		rc.redirect("/me/security")
		return
	}
	codes, err := s.ensureRecoveryCodes(ctx, rc.sess.userSID.String())
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.sess.mu.Lock()
	rc.sess.keyOK = true
	if len(codes) > 0 {
		rc.sess.newRecoveryCodes = codes
	}
	rc.sess.mu.Unlock()
	s.audit(ctx, rc, "mfa.key_register", rc.sess.sam, "security key "+name, store.ResultOK)
	if len(codes) > 0 {
		rc.redirect("/me/recovery-codes")
		return
	}
	rc.flashOK("keys.registered", name)
	rc.redirect("/me/security")
}

// keyRemovalAllowed refuses removing the last second factor of a user who
// must have one (and the last key of a user who must have a key).
func (s *Server) keyRemovalAllowed(ctx context.Context, rc *reqCtx, keys int) bool {
	if keys > 1 {
		return true
	}
	if s.keyRequired(rc.roles) {
		return false
	}
	_, err := s.store.GetTOTP(ctx, rc.sess.userSID.String())
	hasTOTP := err == nil
	return hasTOTP || !s.mfaRequired(rc.roles)
}

// handleKeyRemovePage asks for re-authentication before removing a key.
func (s *Server) handleKeyRemovePage(rc *reqCtx) {
	ctx := rc.ctx()
	id := rc.r.PathValue("id")
	_, rows, err := s.waUserFor(ctx, rc.sess)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	var name string
	for _, r := range rows {
		if r.ID == id {
			name = r.Name
		}
	}
	if name == "" {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	d := map[string]any{"Name": name, "ID": id, "Action": "/me/2fa/keys/" + id + "/remove"}
	if !s.keyRemovalAllowed(ctx, rc, len(rows)) {
		d["Refused"] = true
	}
	s.addReauthOptions(rc, d)
	rc.render(http.StatusOK, "key_remove", d)
}

func (s *Server) handleKeyRemove(rc *reqCtx) {
	ctx := rc.ctx()
	id := rc.r.PathValue("id")
	_, rows, err := s.waUserFor(ctx, rc.sess)
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	var name string
	for _, r := range rows {
		if r.ID == id {
			name = r.Name
		}
	}
	if name == "" {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	if !s.keyRemovalAllowed(ctx, rc, len(rows)) {
		rc.errorPage(http.StatusForbidden, "keys.err.last")
		return
	}
	if key := s.reauthenticate(ctx, rc); key != "" {
		s.audit(ctx, rc, "mfa.key_remove", rc.sess.sam, "re-authentication failed", store.ResultDenied)
		rc.flashErr(key)
		rc.redirect("/me/security")
		return
	}
	if err := s.store.DeleteWebAuthnCredential(ctx, rc.sess.userSID.String(), id); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	s.audit(ctx, rc, "mfa.key_remove", rc.sess.sam, "security key "+name, store.ResultOK)
	rc.flashOK("keys.removed", name)
	rc.redirect("/me/security")
}

// addReauthOptions prepares a page that re-authenticates: password plus a
// code field, plus the key option when the user has keys.
func (s *Server) addReauthOptions(rc *reqCtx, d map[string]any) {
	d["CodeAllowed"] = !s.keyRequired(rc.roles)
	if s.wa == nil {
		return
	}
	opts, err := s.beginCeremony(rc.ctx(), rc.sess, waReauth)
	if err == nil {
		d["KeyOptions"] = opts
	}
}

// handleConfirmKeyPage is the confirmation of a previewed operation that
// needs re-authentication, with a security key.
func (s *Server) handleConfirmKeyPage(rc *reqCtx) {
	p := rc.pendingOp()
	if p == nil {
		rc.errorPage(http.StatusNotFound, "confirm.err.gone")
		return
	}
	if !s.confirmAllowed(rc, p) {
		return
	}
	d := s.confirmData(p, "")
	s.addReauthOptions(rc, d)
	d["Action"] = "/confirm/" + p.id
	rc.render(http.StatusOK, "confirm_key", d)
}

// handleBulkKeyPage is the same for applying a bulk job.
func (s *Server) handleBulkKeyPage(rc *reqCtx) {
	job, stored, ok := s.jobForOwner(rc)
	if !ok {
		return
	}
	if job == nil || stored.Status != store.JobPreviewed {
		rc.redirect("/admin/bulk/" + stored.ID)
		return
	}
	d := map[string]any{"Title": rc.T("bulk.apply_title"), "Summary": rc.T("bulk.apply", stored.Total), "Action": "/admin/bulk/" + stored.ID + "/apply",
		"Back": "/admin/bulk/" + stored.ID}
	s.addReauthOptions(rc, d)
	rc.render(http.StatusOK, "confirm_key", d)
}

// handleWellKnownWebAuthn publishes the related origins (WebAuthn Level 3):
// browsers fetch https://<rp_id>/.well-known/webauthn to learn which other
// origins may use credentials of this RP ID.
func (s *Server) handleWellKnownWebAuthn(rc *reqCtx) {
	if !s.cfg.WebAuthn.Enabled() || len(s.cfg.WebAuthn.RelatedOrigins) == 0 {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	b, err := json.Marshal(map[string][]string{"origins": s.cfg.WebAuthnAllOrigins()})
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.w.Header().Set("Content-Type", "application/json")
	rc.w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = rc.w.Write(b)
}
