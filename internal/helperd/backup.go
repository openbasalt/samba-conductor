package helperd

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // Content-MD5 for S3 uploads; integrity is SHA-256
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor-ad/sambatool"

	_ "modernc.org/sqlite" // pure-Go SQLite for the conductor state snapshot
)

// BackupConfig enables the backup operations (P3). Everything that decides
// where data goes and who can read it is here, in root-owned files:
// nothing in a request can change it.
type BackupConfig struct {
	// PeerUID/PeerGID: the conductor-backup user (the only peer allowed to
	// ask for a backup) and the owner of the archives it receives.
	PeerUID, PeerGID int
	// Account is the AD account samba-tool uses (replication rights only,
	// see docs); PasswordFile holds its password (systemd credential).
	Account      string
	PasswordFile string
	// Server is the DC samba-tool backs up (default 127.0.0.1: this DC,
	// over loopback, within the unit's IPAddressAllow=localhost).
	Server string
	// DC is this DC's short name (archive IDs).
	DC string
	// RecipientsFile lists the age recipients (root-owned, not writable by
	// anyone else).
	RecipientsFile string
	// StateDir is conductor-backup's state directory (spool/, requests/,
	// policy.json, state.json).
	StateDir string
	// WorkDir holds the plaintext while the archive is built (the unit's
	// private /tmp: tmpfs on Debian 13); everything is shredded after.
	WorkDir string
	// ConductorDB is conductor's database ("" = not included).
	ConductorDB string
	// Files are host files added to the archive (configs, no secrets);
	// the TLS files named in smb.conf are added too.
	Files []string
	// Python and Samba binaries (facts, version).
	Python string
	Samba  string
}

// DefaultBackupFiles are the host files a full recovery needs.
var DefaultBackupFiles = []string{
	"/etc/samba/smb.conf",
	"/etc/krb5.conf",
	"/etc/conductor/conductor.toml",
	"/etc/conductor/helper.toml",
	"/etc/conductor-backup/conductor-backup.toml",
	"/etc/conductor-backup/recipients.txt",
	"/etc/chrony/chrony.conf",
}

func errNotConfigured() error {
	return &helper.Error{Code: helper.CodeNotAllowed, Message: "backups are not configured on this domain controller"}
}

// ---- files in conductor-backup's state directory ----
//
// conductor-backup owns its state directory, so as root the helper never
// follows a path inside it: directories are opened with O_NOFOLLOW and
// files are created with openat(O_CREAT|O_EXCL|O_NOFOLLOW), chowned through
// the descriptor and renamed into place.

func (s *Server) openStateDir() (*os.File, error) {
	b := s.cfg.Backup
	fd, err := syscall.Open(b.StateDir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("state directory %s: %w", b.StateDir, err)
	}
	f := os.NewFile(uintptr(fd), b.StateDir)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || int(st.Uid) != b.PeerUID {
		_ = f.Close()
		return nil, fmt.Errorf("state directory %s must belong to the conductor-backup user", b.StateDir)
	}
	return f, nil
}

// subdir opens (creating it 0700 for the peer when missing) a directory
// inside dir, never through a symbolic link.
func (s *Server) subdir(dir *os.File, name string) (*os.File, error) {
	open := func() (int, error) {
		return syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	}
	fd, err := open()
	if errors.Is(err, syscall.ENOENT) {
		if err := syscall.Mkdirat(int(dir.Fd()), name, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
			return nil, err
		}
		fd, err = open()
		if err == nil {
			_ = syscall.Fchown(fd, s.cfg.Backup.PeerUID, s.cfg.Backup.PeerGID)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s/%s: %w", dir.Name(), name, err)
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name)), nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// createAt creates a new private file in dir owned by the peer, under a
// temporary name; commit renames it to name.
func (s *Server) createAt(dir *os.File) (*os.File, string, error) {
	tmp := ".tmp-" + randHex(8)
	fd, err := syscall.Openat(int(dir.Fd()), tmp, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, "", err
	}
	if err := syscall.Fchown(fd, s.cfg.Backup.PeerUID, s.cfg.Backup.PeerGID); err != nil {
		_ = syscall.Close(fd)
		_ = syscall.Unlinkat(int(dir.Fd()), tmp)
		return nil, "", err
	}
	return os.NewFile(uintptr(fd), tmp), tmp, nil
}

func commitAt(dir *os.File, f *os.File, tmp, name string) error {
	err := f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = syscall.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name)
	}
	if err != nil {
		_ = syscall.Unlinkat(int(dir.Fd()), tmp)
	}
	return err
}

func (s *Server) writeFileAt(dir *os.File, name string, data []byte) error {
	f, tmp, err := s.createAt(dir)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = syscall.Unlinkat(int(dir.Fd()), tmp)
		return err
	}
	return commitAt(dir, f, tmp, name)
}

func readFileAt(dir *os.File, name string, limit int64) ([]byte, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is too large", name)
	}
	return b, nil
}

// ---- recipients ----

var recipientLineRE = regexp.MustCompile(`^age1[0-9a-z]{58}$`)

// recipientsOwner is the UID that must own the recipients file and its
// directory (root; tests replace it).
var recipientsOwner uint32

// loadRecipients reads the age recipients from a root-owned file that
// nobody else may write (nor its directory): whoever controls it decides
// who can read every future backup.
func loadRecipients(path string) ([]age.Recipient, []string, error) {
	for _, p := range []string{path, filepath.Dir(path)} {
		st, err := os.Lstat(p)
		if err != nil {
			return nil, nil, err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != recipientsOwner || st.Mode().Perm()&0o022 != 0 || st.Mode()&fs.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("%s must be owned by root and writable by root only", p)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var recips []age.Recipient
	var fps []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !recipientLineRE.MatchString(line) {
			return nil, nil, errors.New("recipients file: only age X25519 recipients (age1…) are supported")
		}
		r, err := age.ParseX25519Recipient(line)
		if err != nil {
			return nil, nil, fmt.Errorf("recipients file: %w", err)
		}
		recips = append(recips, r)
		fps = append(fps, helper.RecipientFingerprint(line))
	}
	if len(recips) == 0 || len(recips) > 20 {
		return nil, nil, errors.New("recipients file: 1-20 recipients are required")
	}
	return recips, fps, nil
}

// ---- facts about the directory ----

// facts is what the embedded Python script reports (local sam.ldb, system
// session; no network, no input).
type facts struct {
	Realm      string                 `json:"realm"`
	DomainSID  string                 `json:"domain_sid"`
	PrivateDir string                 `json:"private_dir"`
	Users      int                    `json:"users"`
	Groups     int                    `json:"groups"`
	Samples    []helper.ArchiveSample `json:"samples"`
}

// factsScript counts what `samba-tool user list` shows (normal accounts)
// and picks objects whose SIDs a drill compares: Administrator, the five
// lowest-RID users from 1000 up, Domain Admins and Domain Users.
const factsScript = `
import json
import ldb
from samba.samdb import SamDB
from samba.auth import system_session
from samba.param import LoadParm
lp = LoadParm()
lp.load_default()
s = SamDB(url=lp.samdb_url(), session_info=system_session(), lp=lp)
base = s.domain_dn()
dsid = str(s.get_domain_sid())
def sid(m):
    return s.schema_format_value("objectSid", m["objectSid"][0]).decode()
def rid(m):
    return int(sid(m).rsplit("-", 1)[1])
users = s.search(base=base, scope=ldb.SCOPE_SUBTREE, expression="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512))", attrs=["sAMAccountName", "objectSid"])
groups = s.search(base=base, scope=ldb.SCOPE_SUBTREE, expression="(objectClass=group)", attrs=["sAMAccountName", "objectSid"])
samples = []
picked = 0
for m in sorted(users, key=rid):
    r = rid(m)
    if r == 500 or (r >= 1000 and picked < 5):
        if r >= 1000:
            picked += 1
        samples.append({"kind": "user", "name": str(m["sAMAccountName"][0]), "sid": sid(m)})
bygrid = {rid(m): m for m in groups if sid(m).startswith(dsid + "-")}
for r in (512, 513):
    if r in bygrid:
        samples.append({"kind": "group", "name": str(bygrid[r]["sAMAccountName"][0]), "sid": sid(bygrid[r])})
print(json.dumps({"realm": lp.get("realm"), "domain_sid": dsid, "private_dir": lp.get("private dir"), "users": len(users), "groups": len(groups), "samples": samples}))
`

func (s *Server) facts(ctx context.Context) (facts, error) {
	var f facts
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.Backup.Python, "-")
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Stdin = strings.NewReader(factsScript)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return f, fmt.Errorf("reading directory facts: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	if err := json.Unmarshal(out.Bytes(), &f); err != nil || f.Realm == "" {
		return f, fmt.Errorf("directory facts: %v", err)
	}
	return f, nil
}

// ---- backup ----

// hostFile is a host file to archive.
type hostFile struct{ member, path string }

var tlsParamRE = regexp.MustCompile(`(?i)^\s*tls\s+(certfile|keyfile|cafile)\s*=\s*(\S.*?)\s*$`)

// hostFiles lists the configured files that exist (regular, at most 1 MiB)
// and the TLS files smb.conf names.
func (s *Server) hostFiles(privateDir string) ([]hostFile, []helper.ArchiveTLSFile) {
	var out []hostFile
	seen := map[string]bool{}
	add := func(p string) string {
		p = filepath.Clean(p)
		if seen[p] || !filepath.IsAbs(p) {
			return ""
		}
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
			return ""
		}
		member := helper.ArchiveFilesDir + strings.TrimPrefix(p, "/")
		if !helper.SafeMember(member) {
			return ""
		}
		seen[p] = true
		out = append(out, hostFile{member: member, path: p})
		return member
	}
	for _, p := range s.cfg.Backup.Files {
		add(p)
	}
	var tls []helper.ArchiveTLSFile
	if b, err := os.ReadFile("/etc/samba/smb.conf"); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			m := tlsParamRE.FindStringSubmatch(sc.Text())
			if m == nil {
				continue
			}
			p := m[2]
			if !filepath.IsAbs(p) {
				p = filepath.Join(privateDir, p)
			}
			if member := add(p); member != "" {
				tls = append(tls, helper.ArchiveTLSFile{Param: strings.ToLower(m[1]), Value: m[2], Member: member})
			}
		}
	}
	return out, tls
}

// snapshotConductorDB writes a consistent copy of conductor's database
// without its sessions (VACUUM INTO from a read-only connection, then a
// DELETE and VACUUM in the copy so no freed page keeps them).
func snapshotConductorDB(ctx context.Context, src, dst string) error {
	db, err := sql.Open("sqlite", "file:"+src+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "VACUUM INTO '"+strings.ReplaceAll(dst, "'", "''")+"'")
	_ = db.Close()
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	cp, err := sql.Open("sqlite", "file:"+dst+"?_pragma=secure_delete(1)")
	if err != nil {
		return err
	}
	defer func() { _ = cp.Close() }()
	if _, err := cp.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return fmt.Errorf("snapshot: removing sessions: %w", err)
	}
	_, err = cp.ExecContext(ctx, "VACUUM")
	return err
}

// versions describes the source.
func (s *Server) versions(ctx context.Context) map[string]string {
	v := map[string]string{"conductor-helper": s.cfg.Version}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, s.cfg.Backup.Samba, "--version").Output(); err == nil {
		v["samba"] = strings.TrimPrefix(strings.TrimSpace(string(out)), "Version ")
	}
	if l, err := sambatool.Run(ctx, s.runner, sambatool.DomainLevelShow{}); err == nil {
		v["forest_level"], v["domain_level"] = l.Forest, l.Domain
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				v["os"] = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}
	return v
}

func shredFile(path string) {
	st, err := os.Lstat(path)
	if err != nil {
		return
	}
	if st.Mode().IsRegular() && st.Size() > 0 {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			zero := make([]byte, 1<<20)
			for left := st.Size(); left > 0; {
				n := min(int64(len(zero)), left)
				if _, err := f.Write(zero[:n]); err != nil {
					break
				}
				left -= n
			}
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(path)
}

// shredTree overwrites and removes every regular file under dir, then dir.
func shredTree(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			shredFile(p)
		}
		return nil
	})
	_ = os.RemoveAll(dir)
}

// countWriter counts bytes.
type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("backup account credential: %w", err)
	}
	pw := strings.TrimRight(string(b), "\r\n")
	if pw == "" || len(pw) > 512 || strings.ContainsAny(pw, "\n\x00") {
		return "", errors.New("backup account credential is empty or malformed")
	}
	return pw, nil
}

// backupOnline takes the online backup, builds the archive and encrypts it
// into conductor-backup's spool. Plaintext exists only in the work
// directory and is shredded before returning.
func (s *Server) backupOnline(ctx context.Context, req helper.Request) (helper.BackupOnlineResult, error) {
	var res helper.BackupOnlineResult
	b := s.cfg.Backup
	if b == nil {
		return res, errNotConfigured()
	}
	if !s.backupMu.TryLock() {
		return res, &helper.Error{Code: helper.CodeUnavailable, Message: "a backup is already running"}
	}
	defer s.backupMu.Unlock()
	start := time.Now().UTC()
	recips, fps, err := loadRecipients(b.RecipientsFile)
	if err != nil {
		return res, err
	}
	pw, err := readSecret(b.PasswordFile)
	if err != nil {
		return res, err
	}
	stateDir, err := s.openStateDir()
	if err != nil {
		return res, err
	}
	defer func() { _ = stateDir.Close() }()
	spool, err := s.subdir(stateDir, "spool")
	if err != nil {
		return res, err
	}
	defer func() { _ = spool.Close() }()

	if err := os.MkdirAll(b.WorkDir, 0o700); err != nil {
		return res, err
	}
	work, err := os.MkdirTemp(b.WorkDir, "backup-")
	if err != nil {
		return res, err
	}
	defer shredTree(work)

	before, err := s.facts(ctx)
	if err != nil {
		return res, err
	}
	out := filepath.Join(work, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		return res, err
	}
	runner := &sambatool.Runner{Binary: s.cfg.SambaTool, Credentials: sambatool.Password{Username: b.Account, Password: pw}, Timeout: 40 * time.Minute}
	if _, err := sambatool.Run(ctx, runner, sambatool.DomainBackupOnline{Server: b.Server, TargetDir: out}); err != nil {
		return res, err
	}
	found, _ := filepath.Glob(filepath.Join(out, "samba-backup-*.tar.bz2"))
	if len(found) != 1 {
		return res, fmt.Errorf("expected one samba backup file, found %d", len(found))
	}
	after, err := s.facts(ctx)
	if err != nil {
		return res, err
	}
	id := helper.NewBackupID(start, b.DC)
	meta := helper.ArchiveMeta{Format: helper.ArchiveFormat, ID: id, Realm: strings.ToUpper(after.Realm), DC: b.DC, CreatedAt: start,
		DomainSID: after.DomainSID, Users: helper.CountRange{Min: min(before.Users, after.Users), Max: max(before.Users, after.Users)},
		Groups:    helper.CountRange{Min: min(before.Groups, after.Groups), Max: max(before.Groups, after.Groups)},
		SambaFile: helper.ArchiveSambaDir + filepath.Base(found[0])}
	// Samples that did not change while samba-tool ran.
	was := map[string]string{}
	for _, x := range before.Samples {
		was[x.Kind+"/"+x.Name] = x.SID
	}
	for _, x := range after.Samples {
		if was[x.Kind+"/"+x.Name] == x.SID {
			meta.Samples = append(meta.Samples, x)
		}
	}
	meta.Versions = s.versions(ctx)
	members := []hostFile{{member: meta.SambaFile, path: found[0]}}
	if b.ConductorDB != "" {
		if _, err := os.Stat(b.ConductorDB); err == nil {
			dbCopy := filepath.Join(work, "conductor.db")
			if err := snapshotConductorDB(ctx, b.ConductorDB, dbCopy); err != nil {
				return res, err
			}
			meta.ConductorDB = true
			members = append(members, hostFile{member: helper.ArchiveConductorDB, path: dbCopy})
		}
	}
	files, tls := s.hostFiles(after.PrivateDir)
	meta.TLS = tls
	for _, f := range files {
		meta.Files = append(meta.Files, f.member)
	}
	members = append(members, files...)

	// The archive: tar → age → (spool file, SHA-256, MD5, size).
	f, tmp, err := s.createAt(spool)
	if err != nil {
		return res, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = syscall.Unlinkat(int(spool.Fd()), tmp)
		}
	}()
	sh, mh, count := sha256.New(), md5.New(), &countWriter{}
	aw, err := age.Encrypt(io.MultiWriter(f, sh, mh, count), recips...)
	if err != nil {
		return res, err
	}
	tw := tar.NewWriter(aw)
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return res, err
	}
	contents := []string{helper.ArchiveMetaName}
	if err := tw.WriteHeader(&tar.Header{Name: helper.ArchiveMetaName, Mode: 0o600, Size: int64(len(metaJSON)), ModTime: start, Typeflag: tar.TypeReg}); err != nil {
		return res, err
	}
	if _, err := tw.Write(metaJSON); err != nil {
		return res, err
	}
	for _, m := range members {
		if err := addFile(tw, m.member, m.path, start); err != nil {
			return res, fmt.Errorf("archiving %s: %w", m.member, err)
		}
		contents = append(contents, m.member)
	}
	if err := tw.Close(); err != nil {
		return res, err
	}
	if err := aw.Close(); err != nil {
		return res, err
	}
	name := id + ".tar.age"
	ok = true
	if err := commitAt(spool, f, tmp, name); err != nil {
		return res, err
	}
	sort.Strings(contents[1:])
	return helper.BackupOnlineResult{ID: id, File: name, Size: count.n, SHA256: hex.EncodeToString(sh.Sum(nil)),
		MD5: base64.StdEncoding.EncodeToString(mh.Sum(nil)), CreatedAt: start, Realm: meta.Realm, DC: b.DC, Recipients: fps,
		Versions: meta.Versions, Contents: contents, Users: after.Users, Groups: after.Groups,
		DurationMS: time.Since(start).Milliseconds()}, nil
}

func addFile(tw *tar.Writer, member, path string, at time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: member, Mode: 0o600, Size: st.Size(), ModTime: at, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	n, err := io.Copy(tw, f)
	if err == nil && n != st.Size() {
		err = errors.New("file changed while archiving")
	}
	return err
}

// ---- status, requests, policy (conductor) ----

// backupStatus returns conductor-backup's status, completed with what the
// helper knows first-hand: the current policy, the recipients and requests
// not processed yet.
func (s *Server) backupStatus() (helper.BackupStatus, error) {
	var st helper.BackupStatus
	b := s.cfg.Backup
	if b == nil {
		return st, nil
	}
	dir, err := s.openStateDir()
	if err != nil {
		return st, err
	}
	defer func() { _ = dir.Close() }()
	if raw, err := readFileAt(dir, "state.json", 1<<20); err == nil {
		if err := json.Unmarshal(raw, &st); err != nil {
			return st, fmt.Errorf("state.json: %w", err)
		}
	} else if !errors.Is(err, syscall.ENOENT) {
		return st, err
	}
	st.Configured = true
	if st.DC == "" {
		st.DC = b.DC
	}
	st.Policy, st.PolicyCustom = helper.DefaultBackupPolicy(), false
	if raw, err := readFileAt(dir, "policy.json", 64<<10); err == nil {
		var p helper.BackupPolicy
		if json.Unmarshal(raw, &p) == nil && p.Validate() == nil {
			st.Policy, st.PolicyCustom = p, true
		}
	}
	if _, fps, err := loadRecipients(b.RecipientsFile); err == nil {
		st.Recipients = fps
	}
	if reqs, err := s.subdir(dir, "requests"); err == nil {
		have := map[string]bool{}
		for _, p := range st.Pending {
			have[p.ID] = true
		}
		names, _ := reqs.Readdirnames(64)
		sort.Strings(names)
		for _, n := range names {
			if !strings.HasSuffix(n, ".json") || have[strings.TrimSuffix(n, ".json")] {
				continue
			}
			var r helper.BackupRequest
			if raw, err := readFileAt(reqs, n, 64<<10); err == nil && json.Unmarshal(raw, &r) == nil {
				st.Pending = append(st.Pending, r)
			}
		}
		_ = reqs.Close()
	}
	// Keep the answer within one protocol message.
	for {
		raw, _ := json.Marshal(st)
		if len(raw) < helper.MaxMessageSize-4096 || len(st.Backups) == 0 {
			break
		}
		st.Backups = st.Backups[:len(st.Backups)-1]
	}
	return st, nil
}

// maxPendingRequests bounds the request files (a stuck conductor-backup
// must not let them pile up).
const maxPendingRequests = 10

// backupTrigger writes a "back up now" or "run drill now" request.
func (s *Server) backupTrigger(_ context.Context, req helper.Request, p *helper.BackupTriggerParams) (helper.BackupTriggerResult, error) {
	var res helper.BackupTriggerResult
	if s.cfg.Backup == nil {
		return res, errNotConfigured()
	}
	dir, err := s.openStateDir()
	if err != nil {
		return res, err
	}
	defer func() { _ = dir.Close() }()
	reqs, err := s.subdir(dir, "requests")
	if err != nil {
		return res, err
	}
	defer func() { _ = reqs.Close() }()
	if names, _ := reqs.Readdirnames(maxPendingRequests + 1); len(names) >= maxPendingRequests {
		return res, &helper.Error{Code: helper.CodeUnavailable, Message: "too many requests are waiting; is conductor-backup running?"}
	}
	now := time.Now().UTC()
	id := p.Action + "-" + now.Format("20060102T150405Z") + "-" + randHex(6)
	r := helper.BackupRequest{ID: id, Kind: p.Action, RequestedBy: req.Caller.User, SID: req.Caller.SID, At: now}
	raw, err := json.Marshal(r)
	if err != nil {
		return res, err
	}
	if err := s.writeFileAt(reqs, id+".json", raw); err != nil {
		return res, err
	}
	s.log.Info("backup request written", "request", id, "action", p.Action, "caller_user", req.Caller.User)
	return helper.BackupTriggerResult{RequestID: id}, nil
}

// backupPolicySet replaces the policy (already validated by the protocol).
func (s *Server) backupPolicySet(req helper.Request, p *helper.BackupPolicy) error {
	if s.cfg.Backup == nil {
		return errNotConfigured()
	}
	dir, err := s.openStateDir()
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := s.writeFileAt(dir, "policy.json", append(raw, '\n')); err != nil {
		return err
	}
	s.log.Info("backup policy written", "caller_user", req.Caller.User, "policy", string(raw))
	return nil
}
