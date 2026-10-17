package web

import (
	"context"
	"errors"
	"net/http"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

// selfField is one attribute a user may edit on their own account. The set
// is what Samba's default SELF rights allow (Personal Information, Phone
// and Mail Options, Web Information), verified in the lab by the ad
// library's TestLabSelfWritableAttributes.
type selfField struct {
	Attr  string
	Label string // i18n key
	get   func(ad.User) string
	set   func(*ad.UserUpdate, *string)
}

var selfFields = []selfField{
	{"telephoneNumber", "attr.telephoneNumber", func(u ad.User) string { return u.TelephoneNumber }, func(x *ad.UserUpdate, v *string) { x.TelephoneNumber = v }},
	{"mobile", "attr.mobile", func(u ad.User) string { return u.Mobile }, func(x *ad.UserUpdate, v *string) { x.Mobile = v }},
	{"homePhone", "attr.homePhone", func(u ad.User) string { return u.HomePhone }, func(x *ad.UserUpdate, v *string) { x.HomePhone = v }},
	{"physicalDeliveryOfficeName", "attr.office", func(u ad.User) string { return u.Office }, func(x *ad.UserUpdate, v *string) { x.Office = v }},
	{"streetAddress", "attr.streetAddress", func(u ad.User) string { return u.StreetAddress }, func(x *ad.UserUpdate, v *string) { x.StreetAddress = v }},
	{"l", "attr.city", func(u ad.User) string { return u.City }, func(x *ad.UserUpdate, v *string) { x.City = v }},
	{"st", "attr.state", func(u ad.User) string { return u.State }, func(x *ad.UserUpdate, v *string) { x.State = v }},
	{"postalCode", "attr.postalCode", func(u ad.User) string { return u.PostalCode }, func(x *ad.UserUpdate, v *string) { x.PostalCode = v }},
	{"wWWHomePage", "attr.homePage", func(u ad.User) string { return u.HomePage }, func(x *ad.UserUpdate, v *string) { x.HomePage = v }},
}

// adminFields are the attributes administrators edit (the full UserUpdate).
var adminFields = append([]selfField{
	{"displayName", "attr.displayName", func(u ad.User) string { return u.DisplayName }, func(x *ad.UserUpdate, v *string) { x.DisplayName = v }},
	{"givenName", "attr.givenName", func(u ad.User) string { return u.GivenName }, func(x *ad.UserUpdate, v *string) { x.GivenName = v }},
	{"sn", "attr.sn", func(u ad.User) string { return u.Surname }, func(x *ad.UserUpdate, v *string) { x.Surname = v }},
	{"mail", "attr.mail", func(u ad.User) string { return u.Mail }, func(x *ad.UserUpdate, v *string) { x.Mail = v }},
	{"description", "attr.description", func(u ad.User) string { return u.Description }, func(x *ad.UserUpdate, v *string) { x.Description = v }},
	{"title", "attr.title", func(u ad.User) string { return u.Title }, func(x *ad.UserUpdate, v *string) { x.Title = v }},
	{"department", "attr.department", func(u ad.User) string { return u.Department }, func(x *ad.UserUpdate, v *string) { x.Department = v }},
	{"company", "attr.company", func(u ad.User) string { return u.Company }, func(x *ad.UserUpdate, v *string) { x.Company = v }},
}, selfFields...)

// fieldView is a field with its current value for templates.
type fieldView struct {
	Attr, Label, Value string
}

func fieldViews(fields []selfField, u ad.User) []fieldView {
	out := make([]fieldView, len(fields))
	for i, f := range fields {
		out[i] = fieldView{Attr: f.Attr, Label: f.Label, Value: f.get(u)}
	}
	return out
}

// updateFromForm builds an update with only the changed fields.
func updateFromForm(rc *reqCtx, fields []selfField, u ad.User) (ad.UserUpdate, int) {
	var upd ad.UserUpdate
	n := 0
	for _, f := range fields {
		if _, present := rc.r.PostForm[f.Attr]; !present {
			continue
		}
		v := rc.form(f.Attr)
		if v == f.get(u) {
			continue
		}
		f.set(&upd, &v)
		n++
	}
	return upd, n
}

func (s *Server) me(ctx context.Context, rc *reqCtx, conn *ad.Conn) (ad.User, error) {
	rc.sess.mu.Lock()
	dn := rc.sess.dn
	rc.sess.mu.Unlock()
	return conn.GetUser(ctx, dn)
}

func (s *Server) handleMe(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		u, err := s.me(ctx, rc, conn)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "me", map[string]any{"U": u, "Fields": fieldViews(selfFields, u)})
		return nil
	})
}

func (s *Server) handleMeEditPage(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		u, err := s.me(ctx, rc, conn)
		if err != nil {
			return err
		}
		rc.render(http.StatusOK, "me_edit", map[string]any{"U": u, "Fields": fieldViews(selfFields, u)})
		return nil
	})
}

func (s *Server) handleMeEdit(rc *reqCtx) {
	rc.view(func(ctx context.Context, conn *ad.Conn) error {
		u, err := s.me(ctx, rc, conn)
		if err != nil {
			return err
		}
		upd, n := updateFromForm(rc, selfFields, u)
		if n == 0 {
			rc.flashOK("form.no_change")
			rc.redirect("/me")
			return nil
		}
		op, err := ad.UpdateUser(u.DN, upd)
		if err != nil {
			rc.render(http.StatusBadRequest, "me_edit", map[string]any{"U": u, "Fields": fieldViews(selfFields, u), "Error": rc.T("form.invalid")})
			return nil
		}
		rc.propose(&pendingOp{perm: PermSelf, action: "self.update_profile", target: u.DN, op: op,
			title: rc.T("me.edit.title"), summary: rc.T("confirm.summary.self_update", n), back: "/me", done: rc.T("me.edit.done")})
		return nil
	})
}

func (s *Server) handleMePasswordPage(rc *reqCtx) {
	rc.render(http.StatusOK, "me_password", map[string]any{})
}

func (s *Server) handleMePassword(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	sam := rc.sess.sam
	fail := func(status int, key string) {
		rc.render(status, "me_password", map[string]any{"Error": rc.T(key)})
	}
	if !s.ipLimit.Allow("password:"+rc.ip) || s.accountFails.Blocked(sam) {
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
	rc.sess.mu.Lock()
	dn := rc.sess.dn
	rc.sess.mu.Unlock()
	op, err := ad.ChangePassword(dn, oldPw, newPw)
	if err != nil {
		fail(http.StatusBadRequest, "password.err.required")
		return
	}
	err = rc.withConn(ctx, func(conn *ad.Conn) error { return conn.Apply(ctx, op) })
	if err != nil {
		key, result := passwordChangeError(err)
		if key == "password.err.current" {
			s.accountFails.Fail(sam)
		}
		s.log.Info("self password change refused", "user", sam, "err", err)
		s.audit(ctx, rc, "self.change_password", dn, "", result)
		fail(http.StatusBadRequest, key)
		return
	}
	s.audit(ctx, rc, "self.change_password", dn, op.Preview().String(), store.ResultOK)
	// The notification goes to the account's mail (read with the
	// session's ticket, still valid) and the recovery address.
	var addr string
	_ = rc.withConn(ctx, func(conn *ad.Conn) error {
		u, err := s.me(ctx, rc, conn)
		addr = u.Mail
		return err
	})
	rc.sess.mu.Lock()
	userSID := rc.sess.userSID.String()
	rc.sess.mu.Unlock()
	s.notifyPasswordChanged(ctx, pwChange{SID: userSID, SAM: sam, Mail: addr, Lang: rc.lang, From: rc.ip})
	rc.flashOK("password.done")
	rc.redirect("/me")
}

// ---- security: 2FA and sessions ----

func (s *Server) handleSecurity(rc *reqCtx) {
	ctx := rc.ctx()
	userSID := rc.sess.userSID.String()
	rec, err := s.store.GetTOTP(ctx, userSID)
	enrolled := err == nil
	left, _ := s.store.RecoveryCodesLeft(ctx, userSID)
	sessions, _ := s.store.UserSessions(ctx, userSID)
	rc.sess.mu.Lock()
	current := rc.sess.hash
	rc.sess.mu.Unlock()
	required := s.mfaRequired(rc.roles)
	allowed := s.cfg.MFA.Policy != config.MFAOff || required
	canEnroll := !enrolled && allowed && !(rc.roles.Admin && s.cfg.AdminEnrollmentLinkRequired()) && !s.keyRequired(rc.roles)
	d := map[string]any{"Enrolled": enrolled, "Since": rec.CreatedAt, "CodesLeft": left,
		"Required": required, "CanEnroll": canEnroll, "Sessions": sessions, "Current": current,
		"Policy": s.cfg.MFA.Policy, "WebAuthn": s.wa != nil, "KeyRequired": s.keyRequired(rc.roles)}
	keys, _ := s.store.WebAuthnCredentials(ctx, userSID)
	d["Keys"] = keys
	// TOTP can be turned off when 2FA is optional, or when keys remain.
	d["CanDisable"] = enrolled && (!required || len(keys) > 0)
	d["HasCodes"] = enrolled || len(keys) > 0
	// The recovery address needs e-mail (its verification code).
	d["Recovery"] = s.mailq != nil
	if s.wa != nil && allowed && (enrolled || len(keys) > 0 || !(rc.roles.Admin && s.cfg.AdminEnrollmentLinkRequired())) {
		if opts, err := s.beginCeremony(ctx, rc.sess, waRegister); err == nil {
			d["KeyOptions"] = opts
		}
	}
	rc.render(http.StatusOK, "me_security", d)
}

func (s *Server) handleSelfEnrollStart(rc *reqCtx) {
	if _, err := s.store.GetTOTP(rc.ctx(), rc.sess.userSID.String()); err == nil {
		rc.redirect("/me/security")
		return
	}
	if s.cfg.MFA.Policy == config.MFAOff && !s.mfaRequired(rc.roles) {
		rc.errorPage(http.StatusForbidden, "err.forbidden")
		return
	}
	if rc.roles.Admin && s.cfg.AdminEnrollmentLinkRequired() {
		// Administrators enroll through a link only.
		rc.errorPage(http.StatusForbidden, "signin.err.admin_link")
		return
	}
	if s.keyRequired(rc.roles) {
		rc.errorPage(http.StatusForbidden, "mfa.err.key_required")
		return
	}
	rc.render(http.StatusOK, "enroll", s.enrollData(rc, "/me/2fa/qr.png", "/me/2fa/enroll"))
}

func (s *Server) handleSelfEnroll(rc *reqCtx) {
	if _, err := s.store.GetTOTP(rc.ctx(), rc.sess.userSID.String()); err == nil {
		rc.redirect("/me/security")
		return
	}
	if (s.cfg.MFA.Policy == config.MFAOff && !s.mfaRequired(rc.roles)) || (rc.roles.Admin && s.cfg.AdminEnrollmentLinkRequired()) {
		rc.errorPage(http.StatusForbidden, "err.forbidden")
		return
	}
	if !s.ipLimit.Allow("2fa:"+rc.ip) || s.mfaFails.Blocked(rc.sess.sam) {
		d := s.enrollData(rc, "/me/2fa/qr.png", "/me/2fa/enroll")
		d["Error"] = rc.T("signin.err.rate_account")
		rc.render(http.StatusTooManyRequests, "enroll", d)
		return
	}
	if _, key := s.completeEnrollment(rc.ctx(), rc); key != "" {
		d := s.enrollData(rc, "/me/2fa/qr.png", "/me/2fa/enroll")
		d["Error"] = rc.T(key)
		rc.render(http.StatusUnauthorized, "enroll", d)
		return
	}
	rc.redirect("/me/recovery-codes")
}

// handleSelfDisable removes the user's own 2FA (password and a code
// required; not available when 2FA is mandatory for the user).
func (s *Server) handleSelfDisable(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	if s.mfaRequired(rc.roles) && s.keyCount(ctx, rc.sess.userSID.String()) == 0 {
		rc.errorPage(http.StatusForbidden, "mfa.err.required")
		return
	}
	if key := s.reauthenticate(ctx, rc); key != "" {
		s.audit(ctx, rc, "mfa.disable", rc.sess.sam, "re-authentication failed", store.ResultDenied)
		rc.flashErr(key)
		rc.redirect("/me/security")
		return
	}
	if err := s.store.DeleteTOTP(ctx, rc.sess.userSID.String()); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	s.audit(ctx, rc, "mfa.disable", rc.sess.sam, "", store.ResultOK)
	rc.flashOK("mfa.disabled")
	rc.redirect("/me/security")
}

// handleNewRecoveryCodes replaces the recovery codes (a current code is
// required).
func (s *Server) handleNewRecoveryCodes(rc *reqCtx) {
	ctx := rc.ctx()
	ok, _, err := s.verifySecondFactor(ctx, rc.sess, rc.form("code"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	if !ok {
		s.mfaFails.Fail(rc.sess.sam)
		s.audit(ctx, rc, "mfa.recovery_codes", rc.sess.sam, "wrong code", store.ResultDenied)
		rc.flashErr("mfa.err.code")
		rc.redirect("/me/security")
		return
	}
	userSID := rc.sess.userSID.String()
	codes, err := totp.NewRecoveryCodes()
	if err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = totp.HashRecoveryCode(userSID, c)
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, userSID, hashes); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	rc.sess.mu.Lock()
	rc.sess.newRecoveryCodes = codes
	rc.sess.mu.Unlock()
	s.audit(ctx, rc, "mfa.recovery_codes", rc.sess.sam, "regenerated", store.ResultOK)
	rc.redirect("/me/recovery-codes")
}

func (s *Server) handleSelfQR(rc *reqCtx) { s.handleEnrollQR(rc) }

// handleSignoutEverywhere ends every session of the user, this one too.
func (s *Server) handleSignoutEverywhere(rc *reqCtx) {
	ctx := rc.ctx()
	n := s.sess.destroyUser(ctx, rc.sess.userSID.String())
	s.audit(ctx, rc, "signout.everywhere", rc.sess.sam, "sessions ended: "+itoa(n), store.ResultOK)
	clearCookie(rc.w, sessionCookie)
	rc.redirectSignin("signed_out_all")
}
