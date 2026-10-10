package web

import (
	"context"
	"net/http"
	"strconv"

	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

// Settings > Passwords: invitations, the public reset form, the second
// factor at reset, unlock on reset and notifications. Administrators
// only; a change is previewed (before and after) and confirmed with the
// password and a fresh second factor, and audited as settings.update.

func (s *Server) handlePasswordSettings(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	s.passwordSettingsPage(ctx, rc, http.StatusOK, s.passwordSettings(ctx), "")
}

// passwordSettingsPage renders the page with the form values p.
func (s *Server) passwordSettingsPage(ctx context.Context, rc *reqCtx, status int, p passwordSettings, errKey string) {
	d := map[string]any{"P": p, "Missing": s.missingForLinks(), "Policy": s.cfg.MFA.Policy}
	if errKey != "" {
		d["Error"] = rc.T(errKey)
	}
	if s.prov != nil {
		var st provapi.StatusResult
		if err := s.provCall(ctx, sessionActor(rc), provapi.OpStatus, nil, &st); err != nil {
			d["ProvErr"] = rc.T(provErrKey(err))
		} else {
			d["Prov"] = st
		}
	}
	rc.render(status, "settings_passwords", d)
}

// passwordSettingsFromForm reads the form; ok is false when a number does
// not parse or a value is out of range.
func passwordSettingsFromForm(rc *reqCtx) (passwordSettings, bool) {
	hours, err1 := strconv.Atoi(rc.form("invite_hours"))
	minutes, err2 := strconv.Atoi(rc.form("reset_minutes"))
	p := passwordSettings{InviteHours: hours, ResetMinutes: minutes, ResetMFA: rc.form("reset_mfa"),
		InviteAutoReissue: rc.form("invite_auto_reissue") == "1", ResetEnabled: rc.form("reset_enabled") == "1",
		ResetUnlock: rc.form("reset_unlock") == "1", NotifyChanged: rc.form("notify_password_changed") == "1"}
	return p, err1 == nil && err2 == nil && p.validate()
}

// handlePasswordSettingsPost previews a change of the settings.
func (s *Server) handlePasswordSettingsPost(rc *reqCtx) {
	ctx, cancel := context.WithTimeout(rc.ctx(), requestTimeout)
	defer cancel()
	next, ok := passwordSettingsFromForm(rc)
	if !ok {
		s.passwordSettingsPage(ctx, rc, http.StatusBadRequest, next, "settings.passwords.invalid")
		return
	}
	before := s.passwordSettings(ctx)
	if before == next {
		rc.flashOK("form.no_change")
		rc.redirect("/admin/settings/passwords")
		return
	}
	preview := "before:\n" + before.describe() + "after:\n" + next.describe()
	rc.propose(&pendingOp{perm: PermSettings, action: "settings.update", target: "passwords", reauth: true,
		title: rc.T("settings.passwords.title"), summary: rc.T("settings.passwords.summary"), preview: preview,
		back: "/admin/settings/passwords", done: rc.T("settings.passwords.saved"),
		run: func(ctx context.Context, rc *reqCtx) error {
			rc.sess.mu.Lock()
			by := rc.sess.sam
			rc.sess.mu.Unlock()
			return s.store.PutSettings(ctx, next.values(), by)
		}})
}
