// Command conductor is the Samba Conductor web administrator and
// self-service portal.
//
//	conductor serve        run the web server (systemd unit conductor.service)
//	conductor setup        first run: domain, CA pin, role groups, first admin's 2FA link
//	conductor enroll-link  issue a one-time 2FA enrollment link for an administrator
//	conductor audit verify check the audit log's hash chain
//	conductor audit export write the audit log as JSON lines
//	conductor templates    list, show and check the self-service template overrides
//	conductor healthcheck  container healthcheck (TLS handshake pinned to its certificate)
//	conductor version
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor-files/filesapi"
	"github.com/openbasalt/samba-conductor-idp/idpapi"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/directory"
	"github.com/openbasalt/samba-conductor/internal/secret"
	"github.com/openbasalt/samba-conductor/internal/store"
	"github.com/openbasalt/samba-conductor/internal/web"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "enroll-link":
		err = cmdEnrollLink(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "templates":
		err = cmdTemplates(os.Args[2:])
	case "healthcheck":
		err = cmdHealthcheck(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("conductor", buildVersion())
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "conductor:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: conductor <command> [flags]

commands:
  serve        run the web server
  setup        first-run configuration (as root)
  enroll-link  issue a one-time 2FA enrollment link (as the conductor user)
  audit verify check the audit log hash chain (as the conductor user)
  audit export write the audit log as JSON lines
  templates    list | show NAME | check: template overrides of the self-service pages
  healthcheck  exit 0 when the listener answers with conductor's certificate (containers)
  version      print the version
`)
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return "dev-" + s.Value[:12]
			}
		}
	}
	return version
}

// ---- serve ----

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "configuration file")
	_ = fs.Parse(args)
	syscall.Umask(0o077)
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.State.Database)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	keyPath, err := cfg.MFAKeyPath()
	if err != nil {
		return err
	}
	key, err := secret.LoadKeyFile(keyPath)
	if err != nil {
		return err
	}
	box, err := secret.New(key)
	clear(key)
	if err != nil {
		return err
	}
	dir, err := directory.New(cfg)
	if err != nil {
		return err
	}
	var hc web.HelperClient
	if cfg.Helper.Enabled {
		hc = helperClient{socket: cfg.Helper.Socket}
	}
	var sc web.SyncClient
	if cfg.Sync.Enabled {
		sc = syncClient{socket: cfg.Sync.Socket}
	}
	var fc web.FilesClient
	if cfg.Files.Enabled {
		c, err := newFilesClient(cfg)
		if err != nil {
			return fmt.Errorf("files: %w", err)
		}
		log.Info("file servers section on", "key", c.id.Pin, "name", c.name)
		fc = c
	}
	var ic web.IDPClient
	if cfg.IDP.Enabled {
		ic = idpClient{socket: cfg.IDP.Socket}
	}
	srv, err := web.New(web.Deps{Config: cfg, Store: st, Backend: dir, MFABox: box, Helper: hc, Sync: sc, Files: fc, IDP: ic,
		Logger: log, Version: buildVersion()})
	if err != nil {
		return err
	}
	if err := srv.Start(ctx); err != nil {
		return err
	}
	fds := activationFiles()
	if cfg.IDP.MFASocket {
		mln, err := mfaListener(cfg, fds["mfa"])
		if err != nil {
			return fmt.Errorf("2FA socket: %w", err)
		}
		uids, err := lookupUIDs(cfg.MFAAllowedUserNames(), cfg.IDP.MFAAllowedUIDs)
		if err != nil {
			return fmt.Errorf("2FA socket: %w", err)
		}
		log.Info("2FA socket for conductor-idp", "socket", mln.Addr().String(), "allowed_uids", uids)
		go func() {
			if err := srv.ServeMFA(ctx, mln, uids); err != nil {
				log.Error("2FA socket stopped", "err", err)
			}
		}()
	}
	delete(fds, "mfa")
	ln, err := listener(cfg, fds)
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if cfg.TLS() {
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLSCert, cfg.Server.TLSKey)
		if err != nil {
			return fmt.Errorf("TLS certificate: %w", err)
		}
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
		ln = tls.NewListener(ln, hs.TLSConfig)
	}
	log.Info("conductor listening", "addr", ln.Addr().String(), "tls", cfg.TLS(), "realm", cfg.Domain.Realm, "version", buildVersion())
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}

// activationFiles returns the sockets passed by systemd, by name
// (FileDescriptorName=; unnamed ones are called "unknown" or after their
// unit). The 2FA socket unit names its socket "mfa".
func activationFiles() map[string]*os.File {
	out := map[string]*os.File{}
	if pid, _ := strconv.Atoi(os.Getenv("LISTEN_PID")); pid != os.Getpid() {
		return out
	}
	n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	for i := 0; i < n; i++ {
		name := "unknown"
		if i < len(names) && names[i] != "" {
			name = names[i]
		}
		if _, dup := out[name]; dup {
			name = fmt.Sprintf("%s.%d", name, i)
		}
		out[name] = os.NewFile(uintptr(3+i), "systemd-"+name)
	}
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")
	return out
}

// listener uses a socket passed by systemd (socket activation, e.g. port
// 443 without any capability) or opens server.listen.
func listener(cfg *config.Config, fds map[string]*os.File) (net.Listener, error) {
	for _, f := range fds {
		ln, err := net.FileListener(f)
		_ = f.Close()
		return ln, err
	}
	return net.Listen("tcp", cfg.Server.Listen)
}

// mfaListener is the 2FA socket: the one systemd passed
// (conductor-mfa.socket) or idp.mfa_socket_path created here (mode 0660,
// group idp.mfa_socket_group).
func mfaListener(cfg *config.Config, f *os.File) (*net.UnixListener, error) {
	if f != nil {
		l, err := net.FileListener(f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		ul, ok := l.(*net.UnixListener)
		if !ok {
			_ = l.Close()
			return nil, errors.New("systemd passed a non-Unix socket as \"mfa\"")
		}
		return ul, nil
	}
	path := cfg.IDP.MFASocketPath
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}
	old := syscall.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(true)
	if g := cfg.IDP.MFASocketGroup; g != "" {
		gid, err := strconv.Atoi(g)
		if err != nil {
			grp, lerr := user.LookupGroup(g)
			if lerr != nil {
				_ = ln.Close()
				return nil, lerr
			}
			gid, _ = strconv.Atoi(grp.Gid)
		}
		if err := os.Chown(path, -1, gid); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("socket group %s: %w (conductor's user must be a member)", g, err)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// lookupUIDs resolves user names and adds explicit UIDs.
func lookupUIDs(names []string, uids []int) ([]int, error) {
	out := append([]int(nil), uids...)
	for _, n := range names {
		u, err := user.Lookup(n)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", n, err)
		}
		id, err := strconv.Atoi(u.Uid)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// idpClient calls conductor-idp's management API.
type idpClient struct{ socket string }

func (c idpClient) Call(ctx context.Context, req idpapi.Request) (idpapi.Response, error) {
	return idpapi.Call(ctx, c.socket, req)
}

// syncClient calls conductor-sync's management API.
type syncClient struct{ socket string }

func (c syncClient) Call(ctx context.Context, req syncapi.Request) (syncapi.Response, error) {
	return syncapi.Call(ctx, c.socket, req)
}

// filesClient reaches conductor-files agents with conductor's own key
// pair (generated on first start in files.key_dir, 0700), pinning each
// agent's key.
type filesClient struct {
	id   filesapi.Identity
	name string
}

func newFilesClient(cfg *config.Config) (*filesClient, error) {
	if err := os.MkdirAll(cfg.Files.KeyDir, 0o700); err != nil {
		return nil, err
	}
	name := cfg.Files.Name
	if name == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, err
		}
		name = h
	}
	id, err := filesapi.LoadOrCreateIdentity(cfg.Files.KeyDir, name)
	if err != nil {
		return nil, err
	}
	return &filesClient{id: id, name: name}, nil
}

func (c *filesClient) Call(ctx context.Context, addr, agentPin string, req filesapi.Request) (filesapi.Response, error) {
	return filesapi.Call(ctx, addr, c.id, agentPin, req)
}

func (c *filesClient) Pin() string  { return c.id.Pin }
func (c *filesClient) Name() string { return c.name }

type helperClient struct{ socket string }

func (h helperClient) Call(ctx context.Context, req helper.Request) (helper.Response, error) {
	return helper.Call(ctx, h.socket, req)
}

// ---- audit ----

func cmdAudit(args []string) error {
	if len(args) < 1 || (args[0] != "verify" && args[0] != "export") {
		return errors.New("usage: conductor audit verify|export [--config FILE]")
	}
	fs := flag.NewFlagSet("audit "+args[0], flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "configuration file")
	_ = fs.Parse(args[1:])
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := checkDBOwner(cfg.State.Database); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.State.Database)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if args[0] == "export" {
		_, err := st.ExportAudit(ctx, store.AuditFilter{}, os.Stdout)
		return err
	}
	res, err := st.VerifyAudit(ctx)
	if err != nil {
		return err
	}
	if res.BrokenAt != 0 {
		return fmt.Errorf("audit chain BROKEN at row %d: %s (%d rows verified before it)", res.BrokenAt, res.Reason, res.Rows)
	}
	fmt.Printf("audit chain OK: %d rows, head %s\n", res.Rows, res.LastHash)
	return nil
}

// checkDBOwner refuses to open the database as another user than its
// owner: root would leave root-owned WAL files the service cannot open.
func checkDBOwner(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if ok && int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("run this as the database owner (uid %d), e.g. sudo -u conductor conductor …", sys.Uid)
	}
	return nil
}
