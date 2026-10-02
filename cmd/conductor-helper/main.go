// Command conductor-helper is Samba Conductor's privileged local helper:
// it runs as root on the domain controller, listens on a Unix socket that
// only the conductor user may use, and performs a small allowlist of typed
// samba-tool operations (read-only in this version). See internal/helperd.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/conductor/internal/helperd"
)

var version = "dev"

func main() {
	socket := flag.String("socket", helper.DefaultSocketPath, "Unix socket path")
	allow := flag.String("allow-user", "conductor", "the only user allowed to connect")
	tool := flag.String("samba-tool", "/usr/bin/samba-tool", "samba-tool binary")
	showVersion := flag.Bool("version", false, "print the version")
	flag.Parse()
	if *showVersion {
		fmt.Println("conductor-helper", version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log, *socket, *allow, *tool); err != nil {
		log.Error("conductor-helper stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, socket, allow, tool string) error {
	u, err := user.Lookup(allow)
	if err != nil {
		return fmt.Errorf("allowed user %q: %w", allow, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if !filepath.IsAbs(tool) {
		return fmt.Errorf("--samba-tool must be an absolute path")
	}
	// The socket directory (systemd RuntimeDirectory) must let the
	// conductor group traverse it and nobody else.
	dir := filepath.Dir(socket)
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o750); err != nil {
			return err
		}
	}
	s, err := helperd.Listen(helperd.Config{Socket: socket, AllowedUID: uid, SocketGID: gid, SambaTool: tool, Logger: log})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("conductor-helper listening", "socket", socket, "allowed_uid", uid, "version", version)
	return s.Serve(ctx)
}
