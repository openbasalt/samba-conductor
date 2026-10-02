// Command conductor is the Samba Conductor web administrator and
// self-service portal.
//
//	conductor serve        run the web server (systemd unit conductor.service)
//	conductor setup        first run: domain, CA pin, role groups, first admin's 2FA link
//	conductor enroll-link  issue a one-time 2FA enrollment link for an administrator
//	conductor audit verify check the audit log's hash chain
//	conductor audit export write the audit log as JSON lines
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
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/conductor/internal/config"
	"github.com/samba-conductor/conductor/internal/directory"
	"github.com/samba-conductor/conductor/internal/secret"
	"github.com/samba-conductor/conductor/internal/store"
	"github.com/samba-conductor/conductor/internal/web"
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
	srv, err := web.New(web.Deps{Config: cfg, Store: st, Backend: dir, MFABox: box, Helper: hc, Logger: log, Version: buildVersion()})
	if err != nil {
		return err
	}
	if err := srv.Start(ctx); err != nil {
		return err
	}
	ln, err := listener(cfg)
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

// listener uses a socket passed by systemd (socket activation, e.g. port
// 443 without any capability) or opens server.listen.
func listener(cfg *config.Config) (net.Listener, error) {
	if pid, _ := strconv.Atoi(os.Getenv("LISTEN_PID")); pid == os.Getpid() {
		if n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS")); n >= 1 {
			f := os.NewFile(3, "systemd-socket")
			ln, err := net.FileListener(f)
			_ = f.Close()
			return ln, err
		}
	}
	return net.Listen("tcp", cfg.Server.Listen)
}

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
