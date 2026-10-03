// Package helperd is conductor-helper: the only part of Samba Conductor
// that runs as root. It listens on a Unix socket that only the conductor
// user may use (checked with SO_PEERCRED on every connection, not just by
// file permissions), accepts the typed, allowlisted requests of the ad
// helper protocol, runs the matching samba-tool operation against the local
// database, and logs every call with its caller.
//
// Two peers are admitted, each with its own operation set:
//   - the conductor user: read-only domain information (P1) and, in P3, the
//     backup status, "back up now" / "run drill now" requests and backup
//     policy changes;
//   - the conductor-backup user (P3, only when backups are configured):
//     the online domain backup, whose output is an archive encrypted to
//     the recipients of a root-owned file (see backup.go).
package helperd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor-ad/sambatool"
)

// Config of the helper.
type Config struct {
	// Socket path (its directory must exist; systemd RuntimeDirectory).
	Socket string
	// AllowedUID is the only peer user ID accepted (the conductor user).
	AllowedUID int
	// SocketGID owns the socket so the conductor user can reach it (0660).
	SocketGID int
	// SambaTool binary (default "samba-tool").
	SambaTool string
	// MaxConcurrent bounds parallel calls (default 4).
	MaxConcurrent int
	Logger        *slog.Logger
	// Backup enables the backup operations (nil: not configured).
	Backup *BackupConfig
	// BackupSocket is the second socket, for conductor-backup only
	// (mode 0660, group = the conductor-backup user's group), used when
	// Backup is set.
	BackupSocket string
	// Version is reported in backup archives.
	Version string
}

// peer is who is calling.
type peer int

const (
	peerNone peer = iota
	peerConductor
	peerBackup
)

func (p peer) String() string {
	switch p {
	case peerConductor:
		return "conductor"
	case peerBackup:
		return "conductor-backup"
	}
	return "unknown"
}

// enabled lists, per peer, the subset of the protocol allowlist this
// version serves.
var enabled = map[peer]map[helper.OpName]bool{
	peerConductor: {
		helper.OpPing:            true,
		helper.OpDomainLevel:     true,
		helper.OpFSMORoles:       true,
		helper.OpDCList:          true,
		helper.OpBackupStatus:    true,
		helper.OpBackupTrigger:   true,
		helper.OpBackupPolicySet: true,
	},
	peerBackup: {
		helper.OpPing:               true,
		helper.OpDomainBackupOnline: true,
	},
}

// opTimeout bounds one operation.
func opTimeout(op helper.OpName) time.Duration {
	if op == helper.OpDomainBackupOnline {
		return 45 * time.Minute
	}
	return 90 * time.Second
}

// Server is a running helper.
type Server struct {
	cfg Config
	ln  *net.UnixListener
	// bln is the conductor-backup socket (nil without backups).
	bln    *net.UnixListener
	sem    chan struct{}
	runner *sambatool.Runner
	log    *slog.Logger
	wg     sync.WaitGroup
	// backupMu allows one backup at a time.
	backupMu sync.Mutex
	// peerCred is replaced in tests.
	peerCred func(*net.UnixConn) (uid, pid int, err error)
}

// Listen creates the socket (replacing a stale one) with mode 0660 and
// group SocketGID.
func Listen(cfg Config) (*Server, error) {
	if !filepath.IsAbs(cfg.Socket) {
		return nil, errors.New("helperd: socket path must be absolute")
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 4
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	ln, err := listenSocket(cfg.Socket, cfg.SocketGID)
	if err != nil {
		return nil, err
	}
	var bln *net.UnixListener
	if cfg.Backup != nil {
		if !filepath.IsAbs(cfg.BackupSocket) || cfg.BackupSocket == cfg.Socket {
			_ = ln.Close()
			return nil, errors.New("helperd: the backup socket path must be absolute and differ from the main socket")
		}
		if bln, err = listenSocket(cfg.BackupSocket, cfg.Backup.PeerGID); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}
	s := &Server{cfg: cfg, ln: ln, bln: bln, sem: make(chan struct{}, cfg.MaxConcurrent), log: cfg.Logger,
		runner:   &sambatool.Runner{Binary: cfg.SambaTool, Credentials: sambatool.LocalSystem{}, Timeout: time.Minute},
		peerCred: peerCredentials}
	return s, nil
}

// listenSocket creates a socket (replacing a stale one) with mode 0660 and
// the given group.
func listenSocket(path string, gid int) (*net.UnixListener, error) {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("helperd: %s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}
	// Create the socket with no permissions for others from the start.
	old := syscall.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("helperd: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("helperd: chown socket: %w", err)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// peerCredentials reads SO_PEERCRED of the connection.
func peerCredentials(c *net.UnixConn) (int, int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, -1, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1, -1, err
	}
	if serr != nil {
		return -1, -1, serr
	}
	return int(cred.Uid), int(cred.Pid), nil
}

// Serve accepts connections on both sockets until ctx ends.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
		if s.bln != nil {
			_ = s.bln.Close()
		}
	}()
	errc := make(chan error, 2)
	go func() { errc <- s.accept(ctx, s.ln, peerConductor) }()
	if s.bln != nil {
		go func() { errc <- s.accept(ctx, s.bln, peerBackup) }()
	}
	err := <-errc
	if s.bln != nil {
		_ = s.ln.Close()
		_ = s.bln.Close()
		if e2 := <-errc; err == nil {
			err = e2
		}
	}
	s.wg.Wait()
	return err
}

// accept serves one socket; every connection must come from that socket's
// peer.
func (s *Server) accept(ctx context.Context, ln *net.UnixListener, expect peer) error {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, c, expect)
		}()
	}
}

// Addr returns the socket path.
func (s *Server) Addr() string { return s.cfg.Socket }

func (s *Server) handle(ctx context.Context, c *net.UnixConn, expect peer) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	uid, pid, perr := s.peerCred(c)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	req, err := helper.NewReader(c).ReadRequest()
	who := peerNone
	switch {
	case perr != nil:
	case expect == peerConductor && uid == s.cfg.AllowedUID:
		who = peerConductor
	case expect == peerBackup && s.cfg.Backup != nil && uid == s.cfg.Backup.PeerUID:
		who = peerBackup
	}
	if who == peerNone {
		// Each socket admits only its own peer (the conductor user, or
		// conductor-backup on the backup socket), whatever the socket's
		// file permissions say.
		s.log.Warn("helper: peer refused", "peer_uid", uid, "peer_pid", pid, "err", perr)
		_ = helper.WriteMessage(c, helper.ErrorResponse(safeID(req.ID), helper.CodeForbidden, "peer not allowed"))
		return
	}
	if err != nil {
		s.log.Warn("helper: unreadable request", "peer_pid", pid, "err", err)
		_ = helper.WriteMessage(c, helper.ErrorResponse("unknown", helper.CodeBadRequest, "unreadable request"))
		return
	}
	// The connection lives as long as the operation may take.
	_ = c.SetDeadline(time.Now().Add(opTimeout(req.Op) + 30*time.Second))
	start := time.Now()
	resp := s.dispatch(ctx, who, req)
	attrs := []any{"id", req.ID, "op", req.Op, "peer", who.String(), "caller_user", req.Caller.User, "caller_sid", req.Caller.SID,
		"caller_session", req.Caller.SessionID, "caller_ip", req.Caller.SourceIP, "peer_pid", pid,
		"ok", resp.OK, "duration_ms", time.Since(start).Milliseconds()}
	if resp.Error != nil {
		attrs = append(attrs, "error_code", resp.Error.Code)
	}
	// The audit trail of the helper: journald via stderr.
	s.log.Info("helper call", attrs...)
	_ = helper.WriteMessage(c, resp)
}

func (s *Server) dispatch(ctx context.Context, who peer, req helper.Request) helper.Response {
	params, err := req.Decode()
	if err != nil {
		var he *helper.Error
		if errors.As(err, &he) {
			return helper.ErrorResponse(safeID(req.ID), he.Code, he.Message)
		}
		return helper.ErrorResponse(safeID(req.ID), helper.CodeBadRequest, "invalid request")
	}
	if !enabled[who][req.Op] {
		return helper.ErrorResponse(req.ID, helper.CodeNotAllowed, fmt.Sprintf("operation %q is not enabled for %s", req.Op, who))
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return helper.ErrorResponse(req.ID, helper.CodeUnavailable, "shutting down")
	}
	cctx, cancel := context.WithTimeout(ctx, opTimeout(req.Op))
	defer cancel()
	result, err := s.run(cctx, req, params)
	if err != nil {
		var he *helper.Error
		if errors.As(err, &he) {
			// A typed refusal (not configured, busy, invalid state) is safe
			// to return as is.
			s.log.Warn("helper operation refused", "id", req.ID, "op", req.Op, "code", he.Code, "msg", he.Message)
			return helper.ErrorResponse(req.ID, he.Code, he.Message)
		}
		s.log.Error("helper operation failed", "id", req.ID, "op", req.Op, "err", err)
		// samba-tool output stays in the helper's log, not in the response.
		return helper.ErrorResponse(req.ID, helper.CodeFailed, "operation failed; see the helper log")
	}
	resp, err := helper.OKResponse(req.ID, result)
	if err != nil {
		return helper.ErrorResponse(req.ID, helper.CodeFailed, "encoding result")
	}
	return resp
}

func (s *Server) run(ctx context.Context, req helper.Request, params helper.Params) (any, error) {
	switch req.Op {
	case helper.OpDomainBackupOnline:
		return s.backupOnline(ctx, req)
	case helper.OpBackupStatus:
		return s.backupStatus()
	case helper.OpBackupTrigger:
		return s.backupTrigger(ctx, req, params.(*helper.BackupTriggerParams))
	case helper.OpBackupPolicySet:
		return struct{}{}, s.backupPolicySet(req, params.(*helper.BackupPolicy))
	case helper.OpPing:
		return helper.PingResult{Version: helper.ProtocolVersion, Time: time.Now().UTC()}, nil
	case helper.OpDomainLevel:
		l, err := sambatool.Run(ctx, s.runner, sambatool.DomainLevelShow{})
		if err != nil {
			return nil, err
		}
		return helper.DomainLevelResult{Forest: l.Forest, Domain: l.Domain, LowestDC: l.LowestDC}, nil
	case helper.OpFSMORoles:
		roles, err := sambatool.Run(ctx, s.runner, sambatool.FSMOShow{})
		if err != nil {
			return nil, err
		}
		out := helper.FSMORolesResult{}
		for _, r := range roles {
			out.Roles = append(out.Roles, helper.FSMORole{Role: r.Role, Owner: r.Owner})
		}
		return out, nil
	case helper.OpDCList:
		dns, err := sambatool.Run(ctx, s.runner, sambatool.GroupListMembers{Group: "Domain Controllers"})
		if err != nil {
			return nil, err
		}
		return helper.DCListResult{DCs: dns}, nil
	}
	return nil, fmt.Errorf("helperd: no handler for %q", req.Op)
}

func safeID(id string) string {
	if len(id) >= 8 && len(id) <= 64 && !strings.ContainsFunc(id, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
	}) {
		return id
	}
	return "unknown"
}
