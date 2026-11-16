package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"syscall"

	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/secret"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// The audit chain is keyed with a root-only key (store.SetAuditKey). The
// service gets it as a systemd credential; command line tools that append
// or verify rows read it as root, then drop to the database owner before
// they open the database, so no root-owned file ends up next to it.

// cliAuditKeyPath is the audit key a command line tool reads:
// audit.key_file, else the systemd credential when run under systemd, else
// the packaged location.
func cliAuditKeyPath(cfg *config.Config) string {
	if cfg.Audit.KeyFile != "" {
		return cfg.Audit.KeyFile
	}
	if p, err := cfg.AuditKeyPath(); err == nil {
		return p
	}
	return config.DefaultAuditKeyFile
}

// loadAuditKey reads and checks an audit key file.
func loadAuditKey(path string) ([]byte, error) {
	key, err := secret.LoadKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit key: %w", err)
	}
	return key, nil
}

// becomeOwnerOf runs the rest of the process as the owner of path (the
// database, or its directory): nothing to do when that is already the
// user; root drops to it (groups, group, user); anyone else is refused.
func becomeOwnerOf(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid, gid := int(sys.Uid), int(sys.Gid)
	switch os.Geteuid() {
	case uid:
		return nil
	case 0:
		// Go applies these to every thread of the process (Linux).
		if err := syscall.Setgroups([]int{}); err != nil {
			return fmt.Errorf("dropping privileges: %w", err)
		}
		if err := syscall.Setgid(gid); err != nil {
			return fmt.Errorf("dropping privileges: %w", err)
		}
		if err := syscall.Setuid(uid); err != nil {
			return fmt.Errorf("dropping privileges: %w", err)
		}
		return nil
	}
	return fmt.Errorf("run this as root (sudo conductor ...) or as the database owner (uid %d)", uid)
}

// openStoreCLI opens the database for a command line tool as its owner.
// With needKey the audit key is read first (it is root-only, so the tool
// must then run as root) and set on the store.
func openStoreCLI(ctx context.Context, cfg *config.Config, ownerOf string, needKey bool) (*store.Store, error) {
	var key []byte
	if needKey {
		path := cliAuditKeyPath(cfg)
		k, err := loadAuditKey(path)
		if err != nil {
			if os.Geteuid() != 0 {
				return nil, fmt.Errorf("%w (the audit key %s is readable by root only: run sudo conductor ...)", err, path)
			}
			return nil, err
		}
		key = k
		defer clear(key)
	}
	if err := becomeOwnerOf(ownerOf); err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, cfg.State.Database)
	if err != nil {
		return nil, err
	}
	if key != nil {
		if err := st.SetAuditKey(key); err != nil {
			_ = st.Close()
			return nil, err
		}
	}
	return st, nil
}

// auditJournal is the sink that copies every audit row, without its
// detail, to the service log (journald under systemd): a record of the
// chain's hashes that conductor cannot rewrite afterwards.
func auditJournal(log *slog.Logger) func(store.AuditEvent) {
	return func(e store.AuditEvent) {
		log.Info("audit", "audit_id", e.ID, "action", e.Action, "actor", e.ActorName, "actor_sid", e.ActorSID,
			"target", e.Target, "result", e.Result, "ip", e.IP, "hash", e.Hash, "keyed", e.Keyed)
	}
}
