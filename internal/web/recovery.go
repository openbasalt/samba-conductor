package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// The recovery address (self-service): an optional second address for
// password resets by e-mail and the notifications of password changes.
// Setting it needs the password (and the second factor when the user has
// one) and a 6-digit code sent to the new address; the previous address
// is told about the change, and resets do not go to an address changed
// in the last 72 hours.

const (
	// recoveryCodeTTL and recoveryCodeTries bound a verification code.
	recoveryCodeTTL   = 15 * time.Minute
	recoveryCodeTries = 5
	// recoveryCodesPerHour bounds the codes sent for one user.
	recoveryCodesPerHour = 5
)

// recoveryPending is an address waiting for its code (in the session).
type recoveryPending struct {
	address  string
	codeHash string
	expires  time.Time
	tries    int
}

func recoveryCodeHash(userSID, code string) string {
	h := sha256.Sum256([]byte("conductor-recovery\x00" + userSID + "\x00" + code))
	return hex.EncodeToString(h[:])
}

// newRecoveryCode draws a 6-digit code.
func newRecoveryCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		panic(err) // crypto/rand never fails on Linux
	}
	return fmt.Sprintf("%06d", n.Int64())
}

// maskAddress shows an address as a***@domain.
func maskAddress(a string) string {
	at := strings.LastIndexByte(a, '@')
	if at < 1 {
		return "***"
	}
	r := []rune(a[:at])
	return string(r[0]) + "***" + a[at:]
}

// reauthSelf verifies the password and, when the user has a second
// factor, a code (TOTP or recovery code). The fresh ticket replaces the
// session's.
func (s *Server) reauthSelf(ctx context.Context, rc *reqCtx) string {
	sess := rc.sess
	sess.mu.Lock()
	userSID := sess.userSID.String()
	sess.mu.Unlock()
	if s.hasSecondFactor(ctx, userSID) {
		return s.reauthenticate(ctx, rc)
	}
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
	sess.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return ""
}

func (s *Server) recoveryPage(ctx context.Context, rc *reqCtx, status int, errKey string) {
	rc.sess.mu.Lock()
	userSID := rc.sess.userSID.String()
	pending := rc.sess.recoveryPending
	rc.sess.mu.Unlock()
	d := map[string]any{"Mail": s.mailq != nil, "HasMFA": s.hasSecondFactor(ctx, userSID)}
	if r, err := s.store.GetRecoveryEmail(ctx, userSID); err == nil {
		d["Current"] = maskAddress(r.Address)
		d["Since"] = r.ChangedAt
		d["Blocked"] = s.now().Sub(r.ChangedAt) < recoveryChangeBlock
		d["Until"] = r.ChangedAt.Add(recoveryChangeBlock)
	}
	if pending != nil && s.now().Before(pending.expires) {
		d["Pending"] = maskAddress(pending.address)
	}
	if errKey != "" {
		d["Error"] = rc.T(errKey)
	}
	rc.render(status, "me_recovery", d)
}

func (s *Server) handleRecoveryEmailPage(rc *reqCtx) {
	s.recoveryPage(rc.ctx(), rc, http.StatusOK, "")
}

// handleRecoveryEmailSet re-authenticates and sends a code to the new
// address.
func (s *Server) handleRecoveryEmailSet(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	if s.mailq == nil {
		rc.errorPage(http.StatusConflict, "settings.mail.off.title")
		return
	}
	addr := rc.form("address")
	if _, err := mail.ParseRecipient(addr); err != nil || strings.ContainsAny(addr, "<>") {
		s.recoveryPage(ctx, rc, http.StatusBadRequest, "recaddr.err.address")
		return
	}
	if !s.ipLimit.Allow("password:" + rc.ip) {
		s.recoveryPage(ctx, rc, http.StatusTooManyRequests, "signin.err.rate_ip")
		return
	}
	rc.sess.mu.Lock()
	sam, userSID := rc.sess.sam, rc.sess.userSID.String()
	rc.sess.mu.Unlock()
	if key := s.reauthSelf(ctx, rc); key != "" {
		s.audit(ctx, rc, "self.recovery_email_set", sam, "re-authentication failed", store.ResultDenied)
		s.recoveryPage(ctx, rc, http.StatusUnauthorized, key)
		return
	}
	if !s.recoveryCodeLimit.Allow(userSID) {
		s.audit(ctx, rc, "self.recovery_email_set", sam, "verification codes: more than 5 per hour", store.ResultDenied)
		s.recoveryPage(ctx, rc, http.StatusTooManyRequests, "recaddr.err.limited")
		return
	}
	code := newRecoveryCode()
	expires := s.now().Add(recoveryCodeTTL)
	if _, err := s.queueMail(ctx, mail.TemplateAlternateVerify, rc.lang, addr, mail.Data{Username: sam, Code: code, Expires: expires,
		ValidFor: recoveryCodeTTL}, expires, "recovery-verify"); err != nil {
		s.log.Error("queueing a verification code", "err", err)
		s.recoveryPage(ctx, rc, http.StatusInternalServerError, "err.internal")
		return
	}
	rc.sess.mu.Lock()
	rc.sess.recoveryPending = &recoveryPending{address: addr, codeHash: recoveryCodeHash(userSID, code), expires: expires}
	rc.sess.mu.Unlock()
	s.audit(ctx, rc, "self.recovery_email_code", sam, "verification code sent to an address at "+mail.Domain(addr), store.ResultOK)
	rc.flashOK("recaddr.code_sent", maskAddress(addr))
	rc.redirect("/me/recovery-email")
}

// handleRecoveryEmailVerify checks the code and stores the address.
func (s *Server) handleRecoveryEmailVerify(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	rc.sess.mu.Lock()
	sam, userSID := rc.sess.sam, rc.sess.userSID.String()
	p := rc.sess.recoveryPending
	rc.sess.mu.Unlock()
	if p == nil || !s.now().Before(p.expires) {
		s.recoveryPage(ctx, rc, http.StatusBadRequest, "recaddr.err.expired")
		return
	}
	code := strings.ReplaceAll(rc.form("code"), " ", "")
	if !tokensEqual(recoveryCodeHash(userSID, code), p.codeHash) {
		rc.sess.mu.Lock()
		p.tries++
		tries := p.tries
		if tries >= recoveryCodeTries {
			rc.sess.recoveryPending = nil
		}
		rc.sess.mu.Unlock()
		s.audit(ctx, rc, "self.recovery_email_set", sam, "wrong verification code", store.ResultDenied)
		key := "recaddr.err.code"
		if tries >= recoveryCodeTries {
			key = "recaddr.err.expired"
		}
		s.recoveryPage(ctx, rc, http.StatusUnauthorized, key)
		return
	}
	rc.sess.mu.Lock()
	rc.sess.recoveryPending = nil
	rc.sess.mu.Unlock()
	now := s.now()
	old, oldErr := s.store.GetRecoveryEmail(ctx, userSID)
	replaced := oldErr == nil && !strings.EqualFold(old.Address, p.address)
	if err := s.store.SetRecoveryEmail(ctx, store.RecoveryEmail{UserSID: userSID, Address: p.address, VerifiedAt: now, ChangedAt: now,
		PreviousNotified: replaced}); err != nil {
		s.log.Error("storing a recovery address", "err", err)
		s.recoveryPage(ctx, rc, http.StatusInternalServerError, "err.internal")
		return
	}
	detail := "verified address at " + mail.Domain(p.address)
	if replaced {
		detail += ", replacing one at " + mail.Domain(old.Address)
		s.notifyRecoveryChanged(ctx, rc, old.Address, sam)
	}
	s.audit(ctx, rc, "self.recovery_email_set", sam, detail, store.ResultOK)
	rc.flashOK("recaddr.saved")
	rc.redirect("/me/recovery-email")
}

// handleRecoveryEmailRemove removes the address and tells it.
func (s *Server) handleRecoveryEmailRemove(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	rc.sess.mu.Lock()
	sam, userSID := rc.sess.sam, rc.sess.userSID.String()
	rc.sess.recoveryPending = nil
	rc.sess.mu.Unlock()
	old, err := s.store.GetRecoveryEmail(ctx, userSID)
	if err != nil {
		rc.redirect("/me/recovery-email")
		return
	}
	if err := s.store.DeleteRecoveryEmail(ctx, userSID); err != nil {
		rc.errorPage(http.StatusInternalServerError, "err.internal")
		return
	}
	s.notifyRecoveryChanged(ctx, rc, old.Address, sam)
	s.audit(ctx, rc, "self.recovery_email_removed", sam, "address at "+mail.Domain(old.Address), store.ResultOK)
	rc.flashOK("recaddr.removed")
	rc.redirect("/me/recovery-email")
}

// notifyRecoveryChanged tells a previous recovery address that it is no
// longer used.
func (s *Server) notifyRecoveryChanged(ctx context.Context, rc *reqCtx, addr, sam string) {
	if s.mailq == nil {
		return
	}
	if _, err := s.queueMail(ctx, mail.TemplateAlternateChanged, rc.lang, addr, mail.Data{Username: sam, When: s.now(), From: rc.ip},
		s.now().Add(mail.NotificationLifetime), "recovery-changed"); err != nil {
		s.log.Error("queueing the notice to a previous recovery address", "err", err)
	}
}
