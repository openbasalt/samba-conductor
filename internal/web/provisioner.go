package web

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

// Invitations and password resets by e-mail: conductor never holds the AD
// write right they need. conductor-provisioner does (a delegated account
// on the managed OUs only), owns the one-time tokens (stored there as
// hashes) and enforces its own rules: target in scope, never a privileged
// account, hourly ceilings. conductor asks it over a local Unix socket
// (provapi), for the signed-in user or, on the public pages, for an
// anonymous visitor identified by the link record.

// ProvisionerClient calls conductor-provisioner's API.
type ProvisionerClient interface {
	Call(ctx context.Context, req provapi.Request) (provapi.Response, error)
}

var errProvisionerOff = errors.New("web: conductor-provisioner is not enabled ([provisioner] in conductor.toml)")

// passwordsOn reports whether invitations and resets by e-mail can work:
// both [mail] and [provisioner] are on.
func (s *Server) passwordsOn() bool { return s.prov != nil && s.mailq != nil }

// sessionActor is the signed-in user as a provisioner actor.
func sessionActor(rc *reqCtx) provapi.Actor {
	rc.sess.mu.Lock()
	defer rc.sess.mu.Unlock()
	return provapi.Actor{User: rc.sess.sam, SID: rc.sess.userSID.String(), Session: rc.sess.hash[:16], IP: rc.ip}
}

// publicActor is an anonymous visitor of a public page: ref identifies
// the link record or the reset request (never a cookie or a token).
func publicActor(ref, ip string) provapi.Actor {
	return provapi.Actor{User: provapi.PublicUser, Session: ref, IP: ip}
}

// provCall runs one provisioner operation and decodes its result into out
// (nil: ignored).
func (s *Server) provCall(ctx context.Context, actor provapi.Actor, op provapi.Op, params provapi.Params, out any) error {
	if s.prov == nil {
		return errProvisionerOff
	}
	req, err := provapi.NewRequest(provapi.NewRequestID(), op, actor, params)
	if err != nil {
		return err
	}
	resp, err := s.prov.Call(ctx, req)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return provapi.DecodeResult(resp, out)
}

// provErrKey is the message key of a provisioner error on the admin pages.
func provErrKey(err error) string {
	if errors.Is(err, errProvisionerOff) {
		return "prov.err.off"
	}
	switch provapi.ErrorCodeOf(err) {
	case provapi.CodeOutOfScope:
		return "prov.err.out_of_scope"
	case provapi.CodePrivileged:
		return "prov.err.privileged"
	case provapi.CodeRateLimited:
		return "prov.err.rate_limited"
	case provapi.CodeNotFound:
		return "prov.err.not_found"
	case provapi.CodeUnavailable:
		return "prov.err.unavailable"
	case provapi.CodeInvalidParams:
		return "prov.err.invalid"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "prov.err.unavailable"
	}
	return "prov.err.failed"
}

// provCode is the code of a provisioner error for the audit log.
func provCode(err error) string {
	if c := provapi.ErrorCodeOf(err); c != "" {
		return string(c)
	}
	if errors.Is(err, errProvisionerOff) {
		return "off"
	}
	return "error"
}

// ---- settings (Settings > Passwords) ----

// Reset second-factor policies.
const (
	resetMFAIfEnrolled = "if-enrolled"
	resetMFAAlways     = "always"
)

// passwordSettings are the settings of invitations, resets and
// notifications, stored in the settings table (one key each).
type passwordSettings struct {
	InviteHours       int
	InviteAutoReissue bool
	ResetEnabled      bool
	ResetMinutes      int
	ResetMFA          string
	ResetUnlock       bool
	NotifyChanged     bool
}

// defaultPasswordSettings are the safe defaults.
func defaultPasswordSettings() passwordSettings {
	return passwordSettings{InviteHours: 72, ResetMinutes: 30, ResetMFA: resetMFAIfEnrolled, ResetUnlock: true, NotifyChanged: true}
}

// Setting keys.
const (
	setInviteHours   = "invite.hours"
	setInviteReissue = "invite.auto_reissue"
	setResetEnabled  = "reset.enabled"
	setResetMinutes  = "reset.minutes"
	setResetMFA      = "reset.mfa"
	setResetUnlock   = "reset.unlock"
	setNotifyChanged = "notify.password_changed"
)

// validate checks the ranges.
func (p passwordSettings) validate() bool {
	return p.InviteHours >= 1 && p.InviteHours <= 168 && p.ResetMinutes >= 5 && p.ResetMinutes <= 120 &&
		(p.ResetMFA == resetMFAIfEnrolled || p.ResetMFA == resetMFAAlways)
}

// values renders the settings as stored JSON values.
func (p passwordSettings) values() map[string]string {
	b := func(v bool) string { return strconv.FormatBool(v) }
	mfa, _ := json.Marshal(p.ResetMFA)
	return map[string]string{setInviteHours: strconv.Itoa(p.InviteHours), setInviteReissue: b(p.InviteAutoReissue),
		setResetEnabled: b(p.ResetEnabled), setResetMinutes: strconv.Itoa(p.ResetMinutes), setResetMFA: string(mfa),
		setResetUnlock: b(p.ResetUnlock), setNotifyChanged: b(p.NotifyChanged)}
}

// describe is the settings as one line per key (preview and audit).
func (p passwordSettings) describe() string {
	v := p.values()
	out := ""
	for _, k := range []string{setInviteHours, setInviteReissue, setResetEnabled, setResetMinutes, setResetMFA, setResetUnlock, setNotifyChanged} {
		out += k + " = " + v[k] + "\n"
	}
	return out
}

// passwordSettings reads the settings; a missing or unreadable value keeps
// its default (logged).
func (s *Server) passwordSettings(ctx context.Context) passwordSettings {
	p := defaultPasswordSettings()
	m, err := s.store.Settings(ctx)
	if err != nil {
		s.log.Error("reading settings", "err", err)
		return p
	}
	readInt := func(k string, dst *int) {
		if v, ok := m[k]; ok {
			if err := json.Unmarshal([]byte(v), dst); err != nil {
				s.log.Warn("ignoring a stored setting", "key", k, "err", err)
			}
		}
	}
	readBool := func(k string, dst *bool) {
		if v, ok := m[k]; ok {
			if err := json.Unmarshal([]byte(v), dst); err != nil {
				s.log.Warn("ignoring a stored setting", "key", k, "err", err)
			}
		}
	}
	readInt(setInviteHours, &p.InviteHours)
	readBool(setInviteReissue, &p.InviteAutoReissue)
	readBool(setResetEnabled, &p.ResetEnabled)
	readInt(setResetMinutes, &p.ResetMinutes)
	if v, ok := m[setResetMFA]; ok {
		_ = json.Unmarshal([]byte(v), &p.ResetMFA)
	}
	readBool(setResetUnlock, &p.ResetUnlock)
	readBool(setNotifyChanged, &p.NotifyChanged)
	if !p.validate() {
		s.log.Warn("stored password settings out of range; using the defaults")
		return defaultPasswordSettings()
	}
	return p
}

// lifetime is conductor's own validity of a token of a purpose (the
// provisioner's configuration may be shorter: the shorter wins).
func (p passwordSettings) lifetime(purpose string) time.Duration {
	if purpose == provapi.PurposeInvite {
		return time.Duration(p.InviteHours) * time.Hour
	}
	return time.Duration(p.ResetMinutes) * time.Minute
}
