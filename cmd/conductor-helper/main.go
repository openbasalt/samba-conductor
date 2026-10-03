// Command conductor-helper is Samba Conductor's privileged local helper:
// it runs as root on the domain controller, listens on a Unix socket that
// only the conductor user (and, when backups are configured in
// /etc/conductor/helper.toml, the conductor-backup user) may use, and
// performs a small allowlist of typed operations. See internal/helperd.
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

	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor/internal/helperd"
)

var version = "dev"

func main() {
	socket := flag.String("socket", helper.DefaultSocketPath, "Unix socket path")
	allow := flag.String("allow-user", "conductor", "the only user allowed to connect")
	tool := flag.String("samba-tool", "/usr/bin/samba-tool", "samba-tool binary")
	cfgPath := flag.String("config", helperd.DefaultConfigPath, "helper configuration (optional; enables backups)")
	backupSocket := flag.String("backup-socket", helper.DefaultBackupSocketPath, "Unix socket for conductor-backup (when backups are enabled)")
	showVersion := flag.Bool("version", false, "print the version")
	flag.Parse()
	if *showVersion {
		fmt.Println("conductor-helper", version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log, *socket, *backupSocket, *allow, *tool, *cfgPath); err != nil {
		log.Error("conductor-helper stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, socket, backupSocket, allow, tool, cfgPath string) error {
	u, err := user.Lookup(allow)
	if err != nil {
		return fmt.Errorf("allowed user %q: %w", allow, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if !filepath.IsAbs(tool) {
		return fmt.Errorf("--samba-tool must be an absolute path")
	}
	backup, err := helperd.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	// The socket directory (systemd RuntimeDirectory) lets only the
	// conductor group in; with backups, conductor-backup must reach its own
	// socket there too, so the directory is traverse-only (0711, no listing)
	// and each socket keeps its 0660 group and SO_PEERCRED check.
	dir := filepath.Dir(socket)
	mode := os.FileMode(0o750)
	if backup != nil {
		mode = 0o711
		if filepath.Dir(backupSocket) != dir {
			return fmt.Errorf("--backup-socket must be in %s", dir)
		}
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(dir, mode); err != nil {
			return err
		}
	}
	if backup != nil {
		log.Info("backups enabled", "peer_uid", backup.PeerUID, "account", backup.Account, "dc", backup.DC, "state_dir", backup.StateDir)
	}
	s, err := helperd.Listen(helperd.Config{Socket: socket, AllowedUID: uid, SocketGID: gid, SambaTool: tool, Logger: log,
		Backup: backup, BackupSocket: backupSocket, Version: version})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("conductor-helper listening", "socket", socket, "allowed_uid", uid, "version", version)
	return s.Serve(ctx)
}
