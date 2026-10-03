package helperd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultConfigPath is the helper's optional configuration file. Without
// it (or with [backup] enabled = false) the backup operations are off.
const DefaultConfigPath = "/etc/conductor/helper.toml"

// fileConfig is helper.toml.
type fileConfig struct {
	Backup backupFile `toml:"backup"`
}

type backupFile struct {
	Enabled bool `toml:"enabled"`
	// PeerUser is the local user allowed to ask for backups.
	PeerUser string `toml:"peer_user"`
	// Account: the AD account samba-tool uses.
	Account string `toml:"account"`
	// PasswordCredential: systemd credential name holding the account's
	// password ($CREDENTIALS_DIRECTORY/<name>, LoadCredential= in the
	// conductor-backup drop-in of the helper unit). PasswordFile is the
	// alternative (a root-only file) for hosts without systemd.
	PasswordCredential string   `toml:"password_credential"`
	PasswordFile       string   `toml:"password_file"`
	Server             string   `toml:"server"`
	DC                 string   `toml:"dc"`
	RecipientsFile     string   `toml:"recipients_file"`
	StateDir           string   `toml:"state_dir"`
	WorkDir            string   `toml:"work_dir"`
	ConductorDB        string   `toml:"conductor_db"`
	ExtraFiles         []string `toml:"extra_files"`
	Python             string   `toml:"python"`
	Samba              string   `toml:"samba"`
}

var (
	accountRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	dcNameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	credRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// LoadConfig reads helper.toml. A missing file means "no backups" (nil).
func LoadConfig(path string) (*BackupConfig, error) {
	var fc fileConfig
	md, err := toml.DecodeFile(path, &fc)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("helper config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("helper config: unknown keys: %s", strings.Join(keys, ", "))
	}
	if !fc.Backup.Enabled {
		return nil, nil
	}
	return fc.Backup.resolve(os.Getenv("CREDENTIALS_DIRECTORY"))
}

func (b backupFile) resolve(credDir string) (*BackupConfig, error) {
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&b.PeerUser, "conductor-backup")
	def(&b.Server, "127.0.0.1")
	def(&b.RecipientsFile, "/etc/conductor-backup/recipients.txt")
	def(&b.StateDir, "/var/lib/conductor-backup")
	def(&b.WorkDir, "/tmp/conductor-backup")
	def(&b.Python, "/usr/bin/python3")
	def(&b.Samba, "/usr/sbin/samba")
	def(&b.PasswordCredential, "backup-account")
	if b.DC == "" {
		h, _ := os.Hostname()
		b.DC = strings.ToLower(strings.SplitN(h, ".", 2)[0])
	}
	var errs []error
	if !accountRE.MatchString(b.Account) {
		errs = append(errs, errors.New("backup.account must be an AD account name"))
	}
	if !dcNameRE.MatchString(b.DC) {
		errs = append(errs, fmt.Errorf("backup.dc %q must be a lower-case host name", b.DC))
	}
	for k, v := range map[string]string{"recipients_file": b.RecipientsFile, "state_dir": b.StateDir, "work_dir": b.WorkDir,
		"python": b.Python, "samba": b.Samba} {
		if !filepath.IsAbs(v) || filepath.Clean(v) != v {
			errs = append(errs, fmt.Errorf("backup.%s must be a clean absolute path", k))
		}
	}
	if b.ConductorDB != "" && !filepath.IsAbs(b.ConductorDB) {
		errs = append(errs, errors.New("backup.conductor_db must be absolute"))
	}
	pwFile := b.PasswordFile
	if pwFile == "" {
		if !credRE.MatchString(b.PasswordCredential) {
			errs = append(errs, errors.New("backup.password_credential must be a credential name"))
		} else if credDir == "" {
			errs = append(errs, errors.New("backup: no $CREDENTIALS_DIRECTORY (LoadCredential=backup-account:… in the helper unit) and no password_file"))
		} else {
			pwFile = filepath.Join(credDir, b.PasswordCredential)
		}
	} else if !filepath.IsAbs(pwFile) {
		errs = append(errs, errors.New("backup.password_file must be absolute"))
	}
	for _, f := range b.ExtraFiles {
		if !filepath.IsAbs(f) {
			errs = append(errs, fmt.Errorf("backup.extra_files: %q is not absolute", f))
		}
	}
	u, err := user.Lookup(b.PeerUser)
	var uid, gid int
	if err != nil {
		errs = append(errs, fmt.Errorf("backup.peer_user %q: %w", b.PeerUser, err))
	} else {
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
		if uid == 0 {
			errs = append(errs, errors.New("backup.peer_user must not be root"))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	files := append(append([]string(nil), DefaultBackupFiles...), b.ExtraFiles...)
	return &BackupConfig{PeerUID: uid, PeerGID: gid, Account: b.Account, PasswordFile: pwFile, Server: b.Server, DC: b.DC,
		RecipientsFile: b.RecipientsFile, StateDir: b.StateDir, WorkDir: b.WorkDir, ConductorDB: b.ConductorDB, Files: files,
		Python: b.Python, Samba: b.Samba}, nil
}
