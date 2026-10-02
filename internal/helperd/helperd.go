// Package helperd is conductor-helper: the only part of Samba Conductor
// that runs as root. It listens on a Unix socket that only the conductor
// user may use (checked with SO_PEERCRED on every connection, not just by
// file permissions), accepts the typed, allowlisted requests of the ad
// helper protocol, runs the matching samba-tool operation against the local
// database, and logs every call with its caller.
//
// P1 enables read-only operations only: ping, functional levels, FSMO
// roles and the list of domain controllers.
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

	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/ad/sambatool"
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
}

// enabled is the subset of the protocol allowlist this version serves.
var enabled = map[helper.OpName]bool{
	helper.OpPing:        true,
	helper.OpDomainLevel: true,
	helper.OpFSMORoles:   true,
	helper.OpDCList:      true,
}

// Server is a running helper.
type Server struct {
	cfg    Config
	ln     *net.UnixListener
	sem    chan struct{}
	runner *sambatool.Runner
	log    *slog.Logger
	wg     sync.WaitGroup
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
	if st, err := os.Lstat(cfg.Socket); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("helperd: %s exists and is not a socket", cfg.Socket)
		}
		_ = os.Remove(cfg.Socket)
	}
	// Create the socket with no permissions for others from the start.
	old := syscall.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.Socket, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("helperd: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if os.Geteuid() == 0 {
		if err := os.Chown(cfg.Socket, 0, cfg.SocketGID); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("helperd: chown socket: %w", err)
		}
	}
	if err := os.Chmod(cfg.Socket, 0o660); err != nil {
		_ = ln.Close()
		return nil, err
	}
	s := &Server{cfg: cfg, ln: ln, sem: make(chan struct{}, cfg.MaxConcurrent), log: cfg.Logger,
		runner:   &sambatool.Runner{Binary: cfg.SambaTool, Credentials: sambatool.LocalSystem{}, Timeout: time.Minute},
		peerCred: peerCredentials}
	return s, nil
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

// Serve accepts connections until ctx ends.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, c)
		}()
	}
}

// Addr returns the socket path.
func (s *Server) Addr() string { return s.cfg.Socket }

func (s *Server) handle(ctx context.Context, c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	uid, pid, perr := s.peerCred(c)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	req, err := helper.NewReader(c).ReadRequest()
	if perr != nil || uid != s.cfg.AllowedUID {
		// Only the conductor user may use the helper, whatever the socket's
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
	start := time.Now()
	resp := s.dispatch(ctx, req)
	attrs := []any{"id", req.ID, "op", req.Op, "caller_user", req.Caller.User, "caller_sid", req.Caller.SID,
		"caller_session", req.Caller.SessionID, "caller_ip", req.Caller.SourceIP, "peer_pid", pid,
		"ok", resp.OK, "duration_ms", time.Since(start).Milliseconds()}
	if resp.Error != nil {
		attrs = append(attrs, "error_code", resp.Error.Code)
	}
	// The audit trail of the helper: journald via stderr.
	s.log.Info("helper call", attrs...)
	_ = helper.WriteMessage(c, resp)
}

func (s *Server) dispatch(ctx context.Context, req helper.Request) helper.Response {
	if _, err := req.Decode(); err != nil {
		var he *helper.Error
		if errors.As(err, &he) {
			return helper.ErrorResponse(safeID(req.ID), he.Code, he.Message)
		}
		return helper.ErrorResponse(safeID(req.ID), helper.CodeBadRequest, "invalid request")
	}
	if !enabled[req.Op] {
		return helper.ErrorResponse(req.ID, helper.CodeNotAllowed, fmt.Sprintf("operation %q is not enabled in this version", req.Op))
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return helper.ErrorResponse(req.ID, helper.CodeUnavailable, "shutting down")
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	result, err := s.run(cctx, req.Op)
	if err != nil {
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

func (s *Server) run(ctx context.Context, op helper.OpName) (any, error) {
	switch op {
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
	return nil, fmt.Errorf("helperd: no handler for %q", op)
}

func safeID(id string) string {
	if len(id) >= 8 && len(id) <= 64 && !strings.ContainsFunc(id, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
	}) {
		return id
	}
	return "unknown"
}
