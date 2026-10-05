package web

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/totp"
)

// The 2FA socket: conductor serves its second-factor store to
// conductor-idp, so a user has one enrollment (TOTP, recovery codes,
// security keys) and one policy for both (protocol in idpapi, mfa.go).
//
//   - Only the configured UIDs (the conductor-idp user) are served, checked
//     with SO_PEERCRED on every connection; the socket file is 0660 with
//     the conductor-idp group as well.
//   - The policy is conductor's: the user's group SIDs (read from AD by
//     conductor-idp) are mapped to conductor's roles exactly as at sign-in.
//   - Wrong codes and failed keys count against the same per-user limit
//     as conductor's own sign-in, and every verification is audited here
//     with the action "idp.mfa_*".
//   - WebAuthn ceremonies started for the IdP live here (single use, five
//     minutes, bound to the user); the IdP's origin must be one of
//     conductor's WebAuthn origins (below rp_id, or a related origin).

// overflowUID is what SO_PEERCRED reports for a peer whose UID is not
// mapped into this process's user namespace (systemd PrivateUsers=yes).
const overflowUID = 65534

// mfaCeremonyTTL bounds a WebAuthn ceremony started for the IdP.
const mfaCeremonyTTL = 5 * time.Minute

type idpCeremony struct {
	userSID string
	data    *webauthn.SessionData
	created time.Time
}

// idpCeremonies are the pending WebAuthn assertions of the IdP.
type idpCeremonies struct {
	mu sync.Mutex
	m  map[string]idpCeremony
}

func (c *idpCeremonies) put(id string, v idpCeremony) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]idpCeremony{}
	}
	for k, old := range c.m {
		if time.Since(old.created) > mfaCeremonyTTL {
			delete(c.m, k)
		}
	}
	if len(c.m) < 10_000 {
		c.m[id] = v
	}
}

func (c *idpCeremonies) take(id, userSID string) (*webauthn.SessionData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[id]
	delete(c.m, id)
	if !ok || v.userSID != userSID || time.Since(v.created) > mfaCeremonyTTL {
		return nil, false
	}
	return v.data, true
}

// ServeMFA serves the 2FA socket on ln until ctx ends. allowed are the
// peer UIDs admitted.
func (s *Server) ServeMFA(ctx context.Context, ln *net.UnixListener, allowed []int) error {
	ok := map[int]bool{}
	for _, u := range allowed {
		ok[u] = true
	}
	if len(ok) == 0 {
		return errors.New("web: the 2FA socket admits nobody (idp.mfa_allowed_users)")
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			s.log.Warn("2FA socket: accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = c.Close() }()
			uid, err := s.mfaPeer(c)
			if err != nil || !ok[uid] {
				if uid == overflowUID {
					s.log.Warn("2FA socket: peer UID not mapped; conductor.service needs PrivateUsers=no to serve conductor-idp (see docs/install.md)")
				} else {
					s.log.Warn("2FA socket: connection refused, peer not allowed", "uid", uid, "err", err)
				}
				return
			}
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			line, err := bufio.NewReader(io.LimitReader(c, idpapi.MFAMaxMessage)).ReadBytes('\n')
			var req idpapi.MFARequest
			a := idpapi.MFAAnswer{V: idpapi.MFAProtocolVersion}
			if err != nil || json.Unmarshal(line, &req) != nil {
				a.Error = idpapi.MFAErrBadRequest
			} else {
				rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
				a = s.answerMFA(rctx, req)
				cancel()
			}
			_ = json.NewEncoder(c).Encode(a)
		}()
	}
	wg.Wait()
	return nil
}

// mfaPeer reads SO_PEERCRED (replaced in tests).
func (s *Server) mfaPeer(c *net.UnixConn) (int, error) {
	if s.mfaPeerCred != nil {
		return s.mfaPeerCred(c)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if serr != nil {
		return -1, serr
	}
	return int(cred.Uid), nil
}

// mfaAudit records an IdP verification in conductor's audit log.
func (s *Server) mfaAudit(ctx context.Context, req idpapi.MFARequest, action, detail, result string) {
	e := store.AuditEvent{ActorSID: req.UserSID, ActorName: strings.ToLower(req.User), Action: action, Target: req.User,
		Detail: detail, Result: result, UserAgent: "conductor-idp"}
	if _, err := s.store.AppendAudit(ctx, e); err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
}

// answerMFA handles one request.
func (s *Server) answerMFA(ctx context.Context, req idpapi.MFARequest) idpapi.MFAAnswer {
	a := idpapi.MFAAnswer{V: idpapi.MFAProtocolVersion}
	if err := req.Validate(); err != nil {
		a.Error = idpapi.MFAErrBadRequest
		if err.Error() == idpapi.MFAErrVersion {
			a.Error = idpapi.MFAErrVersion
		}
		return a
	}
	userSID, err := sid.Parse(req.UserSID)
	if err != nil {
		a.Error = idpapi.MFAErrBadRequest
		return a
	}
	groups := make([]sid.SID, 0, len(req.Groups))
	for _, g := range req.Groups {
		if v, err := sid.Parse(g); err == nil {
			groups = append(groups, v)
		}
	}
	roles := s.roleSIDs.resolve(userSID, groups)
	limitKey := "idp:" + strings.ToLower(req.User)
	switch req.Op {
	case idpapi.MFAOpStatus:
		_, err := s.store.GetTOTP(ctx, req.UserSID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			a.Error = idpapi.MFAErrInternal
			return a
		}
		a.TOTP = err == nil
		a.Keys = s.keyCount(ctx, req.UserSID)
		a.Enrolled = a.TOTP || a.Keys > 0
		a.Required = s.mfaRequired(roles)
		a.Policy = s.cfg.MFA.Policy
		a.KeyRequired = s.keyRequired(roles)
		return a

	case idpapi.MFAOpVerify:
		if s.mfaFails.Blocked(limitKey) {
			s.mfaAudit(ctx, req, "idp.mfa_verify", "rate limited", store.ResultDenied)
			a.Error = idpapi.MFAErrRateLimited
			return a
		}
		if s.keyRequired(roles) && !totp.LooksLikeRecoveryCode(req.Code) {
			s.mfaAudit(ctx, req, "idp.mfa_verify", "TOTP refused: security key required", store.ResultDenied)
			a.Error = idpapi.MFAErrKeyRequired
			return a
		}
		ok, recovery, err := s.verifyCodeFor(ctx, req.UserSID, req.Code)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.Error("2FA socket: verification failed", "user", req.User, "err", err)
			a.Error = idpapi.MFAErrInternal
			return a
		}
		if !ok {
			s.mfaFails.Fail(limitKey)
			s.mfaAudit(ctx, req, "idp.mfa_verify", "wrong code", store.ResultDenied)
			return a
		}
		detail := "totp"
		if recovery {
			detail = "recovery code"
		}
		s.mfaAudit(ctx, req, "idp.mfa_verify", detail, store.ResultOK)
		a.OK, a.Recovery = true, recovery
		return a

	case idpapi.MFAOpKeyBegin:
		if s.wa == nil {
			a.Error = idpapi.MFAErrNoKeys
			return a
		}
		u, _, err := s.waUserBySID(ctx, req.UserSID, req.User, req.User)
		if err != nil {
			a.Error = idpapi.MFAErrInternal
			return a
		}
		if len(u.creds) == 0 {
			a.Error = idpapi.MFAErrNoKeys
			return a
		}
		options, data, err := s.wa.BeginLogin(u)
		if err != nil {
			a.Error = idpapi.MFAErrInternal
			return a
		}
		b, err := json.Marshal(options)
		if err != nil {
			a.Error = idpapi.MFAErrInternal
			return a
		}
		id := newToken()[:32]
		s.idpCeremonies.put(id, idpCeremony{userSID: req.UserSID, data: data, created: time.Now()})
		a.Ceremony, a.Options = id, b
		return a

	case idpapi.MFAOpKeyFinish:
		if s.wa == nil {
			a.Error = idpapi.MFAErrNoKeys
			return a
		}
		if s.mfaFails.Blocked(limitKey) {
			s.mfaAudit(ctx, req, "idp.mfa_key", "rate limited", store.ResultDenied)
			a.Error = idpapi.MFAErrRateLimited
			return a
		}
		data, ok := s.idpCeremonies.take(req.Ceremony, req.UserSID)
		if !ok {
			a.Error = idpapi.MFAErrCeremony
			return a
		}
		if err := s.finishIdPKey(ctx, req, data); err != nil {
			s.mfaFails.Fail(limitKey)
			s.log.Info("2FA socket: security key refused", "user", req.User, "err", err)
			s.mfaAudit(ctx, req, "idp.mfa_key", "security key refused", store.ResultDenied)
			return a
		}
		s.mfaAudit(ctx, req, "idp.mfa_key", "security key", store.ResultOK)
		a.OK = true
		return a
	}
	a.Error = idpapi.MFAErrBadRequest
	return a
}

// finishIdPKey validates an assertion made on the IdP's page and records
// the key's use (signature counter).
func (s *Server) finishIdPKey(ctx context.Context, req idpapi.MFARequest, data *webauthn.SessionData) error {
	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(req.Response))
	if err != nil {
		return err
	}
	u, _, err := s.waUserBySID(ctx, req.UserSID, req.User, req.User)
	if err != nil {
		return err
	}
	cred, err := s.wa.ValidateLogin(u, *data, parsed)
	if err != nil {
		return err
	}
	if cred.Authenticator.CloneWarning {
		return errors.New("web: authenticator counter regressed (possible clone)")
	}
	b, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	return s.store.UseWebAuthnCredential(ctx, req.UserSID, base64.RawURLEncoding.EncodeToString(cred.ID), b)
}
