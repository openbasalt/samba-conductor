package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor/internal/directory"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Cookie names. The __Host- prefix makes the browser refuse them unless
// Secure, Path=/ and without Domain: no subdomain can plant or read them.
const (
	sessionCookie = "__Host-conductor"
	preCookie     = "__Host-conductor-pre"
)

// stage is where a session is in the sign-in flow.
type stage int

const (
	// stageMustChange: the password was right but must be changed (expired
	// or pwdLastSet=0); no credential is held, only the change page works.
	stageMustChange stage = iota + 1
	// stageMFA: password verified, TOTP or recovery code pending.
	stageMFA
	// stageEnroll: password verified, 2FA enrollment required first.
	stageEnroll
	// stageFull: signed in.
	stageFull
)

func (s stage) String() string {
	switch s {
	case stageMustChange:
		return "must-change"
	case stageMFA:
		return "mfa"
	case stageEnroll:
		return "enroll"
	case stageFull:
		return "full"
	}
	return "unknown"
}

// Session is one signed-in browser. The credential (Kerberos ticket) is
// only in memory; the store keeps metadata for the sessions list.
type Session struct {
	mu sync.Mutex

	hash        string // SHA-256 of the cookie value (the map key)
	stage       stage
	sam         string // lower-cased sAMAccountName
	dn          string
	userSID     sid.SID
	displayName string
	cred        *directory.Credential
	csrf        string
	created     time.Time
	lastSeen    time.Time
	expires     time.Time // absolute
	ip          string
	userAgent   string

	mfaVerified bool
	// mfaAt is when this session last passed a second factor (the sign-in,
	// an enrollment or a re-authentication): the self-service actions on
	// connected accounts ask for a new one when it is older than a few
	// minutes.
	mfaAt     time.Time
	roles     Roles
	rolesAt   time.Time
	groupSIDs []sid.SID

	// enrollment in progress (secret not yet stored)
	enrollSecret []byte
	enrollLink   string // hash of the admin enrollment link token
	// recovery codes to show once
	newRecoveryCodes []string
	// one-shot messages
	flashes []flash
	// previewed operations awaiting confirmation
	pending map[string]*pendingOp
	// failed second-factor attempts in this session
	mfaFailures int
	// issued enrollment link to show once
	issuedLink string
	// pending WebAuthn ceremony (challenge) and its purpose, single use
	waCeremony *webauthn.SessionData
	waPurpose  string
	// keyOK: this sign-in used a security key (or a recovery code, or
	// registered a key); required when administrators must use keys.
	keyOK bool
	// enrollKeyOnly: the enrollment stage accepts only a security key.
	enrollKeyOnly bool
	// syncDraft is the Google Workspace sync setup in progress.
	syncDraft *syncDraft
	// syncConn is the edit of the sync's connection settings in progress
	// (it may hold a new AD bind password until it is saved or dropped).
	syncConn *syncConnDraft
	// filesDraft is the share wizard in progress.
	filesDraft *filesDraft
	// ssoSecrets are client secrets returned by conductor-idp, kept until
	// shown once (by a random reference in the URL).
	ssoSecrets map[string]ssoSecret
	// accountSecrets are generated passwords of connected accounts, kept in
	// memory only until shown once (by a random reference in the URL).
	accountSecrets map[string]accountSecret
	// brandDraft is the branding edit waiting for its preview and
	// confirmation (it holds the uploaded images until then).
	brandDraft *brandDraft
}

type flash struct {
	Kind string // "ok", "error", "info"
	Msg  string // already translated
}

func (s *Session) addFlash(kind, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flashes = append(s.flashes, flash{Kind: kind, Msg: msg})
}

func (s *Session) takeFlashes() []flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flashes
	s.flashes = nil
	return f
}

func (s *Session) snapshotStage() stage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stage
}

// sessions is the in-memory session table, mirrored to the store.
type sessions struct {
	mu    sync.Mutex
	byID  map[string]*Session
	store *store.Store
	now   func() time.Time
	idle  time.Duration
	abs   time.Duration
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on Linux
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// create registers a session and returns its cookie value.
func (m *sessions) create(ctx context.Context, s *Session) (string, error) {
	tok := newToken()
	now := m.now()
	s.hash = hashToken(tok)
	s.csrf = newToken()
	s.created, s.lastSeen = now, now
	s.expires = now.Add(m.abs)
	if s.cred != nil {
		if e := s.cred.Expires(); !e.IsZero() && e.Before(s.expires) {
			s.expires = e
		}
	}
	if s.stage != stageFull {
		// Sign-in steps must finish quickly.
		if e := now.Add(10 * time.Minute); e.Before(s.expires) {
			s.expires = e
		}
	}
	s.pending = map[string]*pendingOp{}
	m.mu.Lock()
	m.byID[s.hash] = s
	m.mu.Unlock()
	err := m.store.PutSession(ctx, store.SessionRow{IDHash: s.hash, UserSID: s.userSID.String(), Username: s.sam,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: s.expires, IP: s.ip, UserAgent: s.userAgent})
	return tok, err
}

// rotate gives a session a new cookie value (after a privilege change, so a
// value seen before the change is worthless), keeping its state.
func (m *sessions) rotate(ctx context.Context, s *Session, newStage stage) (string, error) {
	m.mu.Lock()
	delete(m.byID, s.hash)
	m.mu.Unlock()
	_ = m.store.DeleteSession(ctx, s.hash)
	tok := newToken()
	now := m.now()
	s.mu.Lock()
	s.hash = hashToken(tok)
	s.csrf = newToken()
	s.stage = newStage
	s.lastSeen = now
	if newStage == stageFull {
		s.expires = now.Add(m.abs)
		if s.cred != nil {
			if e := s.cred.Expires(); !e.IsZero() && e.Before(s.expires) {
				s.expires = e
			}
		}
	}
	row := store.SessionRow{IDHash: s.hash, UserSID: s.userSID.String(), Username: s.sam, CreatedAt: s.created,
		LastSeenAt: now, ExpiresAt: s.expires, IP: s.ip, UserAgent: s.userAgent}
	s.mu.Unlock()
	m.mu.Lock()
	m.byID[s.hash] = s
	m.mu.Unlock()
	return tok, m.store.PutSession(ctx, row)
}

// get returns the live session for a cookie value, enforcing the idle and
// absolute timeouts.
func (m *sessions) get(ctx context.Context, tok string) *Session {
	if tok == "" || len(tok) > 128 {
		return nil
	}
	h := hashToken(tok)
	m.mu.Lock()
	s := m.byID[h]
	m.mu.Unlock()
	if s == nil {
		return nil
	}
	now := m.now()
	s.mu.Lock()
	expired := now.After(s.expires) || now.Sub(s.lastSeen) > m.idle
	if !expired {
		s.lastSeen = now
	}
	s.mu.Unlock()
	if expired {
		m.destroy(ctx, s)
		return nil
	}
	_ = m.store.TouchSession(ctx, h, now)
	return s
}

// destroy ends a session and forgets its credential.
func (m *sessions) destroy(ctx context.Context, s *Session) {
	m.mu.Lock()
	delete(m.byID, s.hash)
	m.mu.Unlock()
	s.mu.Lock()
	if s.cred != nil {
		s.cred.Close()
	}
	s.pending = nil
	s.enrollSecret = nil
	s.waCeremony = nil
	s.mu.Unlock()
	_ = m.store.DeleteSession(ctx, s.hash)
}

// destroyUser ends every session of a user ("sign out everywhere", 2FA
// reset by an administrator).
func (m *sessions) destroyUser(ctx context.Context, userSID string) int {
	hashes, _ := m.store.DeleteUserSessions(ctx, userSID)
	m.mu.Lock()
	var victims []*Session
	for h, s := range m.byID {
		if s.userSID.String() == userSID {
			victims = append(victims, s)
			delete(m.byID, h)
		}
	}
	m.mu.Unlock()
	for _, s := range victims {
		s.mu.Lock()
		if s.cred != nil {
			s.cred.Close()
		}
		s.mu.Unlock()
	}
	return max(len(hashes), len(victims))
}

// sweep drops expired sessions and stale pending operations.
func (m *sessions) sweep(ctx context.Context) {
	now := m.now()
	m.mu.Lock()
	var dead []*Session
	for _, s := range m.byID {
		s.mu.Lock()
		if now.After(s.expires) || now.Sub(s.lastSeen) > m.idle {
			dead = append(dead, s)
		} else {
			for id, p := range s.pending {
				if now.Sub(p.created) > pendingTTL {
					delete(s.pending, id)
				}
			}
		}
		s.mu.Unlock()
	}
	m.mu.Unlock()
	for _, s := range dead {
		m.destroy(ctx, s)
	}
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func clearCookie(w http.ResponseWriter, name string) { setCookie(w, name, "", -1) }

func tokensEqual(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
