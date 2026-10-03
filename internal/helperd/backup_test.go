package helperd

import (
	"archive/tar"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/samba-conductor/ad/helper"
)

// fakeBackupTool answers `domain backup online` (checking the password it
// receives on PASSWD_FD and that it is not in argv) and `domain level show`.
const fakeBackupTool = `#!/bin/sh
case "$1 $2 $3" in
"domain backup online")
  for a in "$@"; do case "$a" in *s3cr3t*) echo "password in argv" >&2; exit 9;; esac; done
  pw=$(cat <&3)
  [ "$pw" = "s3cr3t-pw" ] || { echo "bad password" >&2; exit 2; }
  for a in "$@"; do case "$a" in --targetdir=*) dir="${a#--targetdir=}";; --server=*) srv="${a#--server=}";; esac; done
  [ "$srv" = "127.0.0.1" ] || exit 3
  printf 'BZh9 fake samba backup' > "$dir/samba-backup-lab.test-2026-10-03T01-13-50.811615.tar.bz2"
  echo "Creating backup file" >&2 ;;
"domain level show") printf 'Forest function level: (Windows) 2016\nDomain function level: (Windows) 2016\nLowest function level of a DC: (Windows) 2016\n' ;;
*) echo "unexpected: $*" >&2; exit 1 ;;
esac
`

const fakePython = `#!/bin/sh
cat >/dev/null
echo '{"realm":"LAB.TEST","domain_sid":"S-1-5-21-1-2-3","private_dir":"/nonexistent","users":3,"groups":2,"samples":[{"kind":"user","name":"Administrator","sid":"S-1-5-21-1-2-3-500"}]}'
`

type backupEnv struct {
	dir, stateDir string
	identity      *age.X25519Identity
	cfg           Config
}

func newBackupEnv(t *testing.T, conductorUID, backupUID int) *backupEnv {
	t.Helper()
	recipientsOwner = uint32(os.Getuid())
	t.Cleanup(func() { recipientsOwner = 0 })
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	id, _ := age.GenerateX25519Identity()
	confDir := filepath.Join(dir, "etc")
	_ = os.Mkdir(confDir, 0o755)
	recips := filepath.Join(confDir, "recipients.txt")
	_ = os.WriteFile(recips, []byte("# operator offline key\n"+id.Recipient().String()+"\n"), 0o644)
	stateDir := filepath.Join(dir, "state")
	_ = os.Mkdir(stateDir, 0o750)
	db := filepath.Join(dir, "conductor.db")
	sdb, err := sql.Open("sqlite", "file:"+db+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"CREATE TABLE sessions (id TEXT)", "CREATE TABLE audit (id INTEGER, action TEXT)",
		"INSERT INTO sessions VALUES ('live-session-token')", "INSERT INTO audit VALUES (1, 'user.create')"} {
		if _, err := sdb.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	_ = sdb.Close()
	extra := write("app.toml", "[x]\n", 0o644)
	e := &backupEnv{dir: dir, stateDir: stateDir, identity: id}
	e.cfg = Config{Socket: filepath.Join(dir, "helper.sock"), BackupSocket: filepath.Join(dir, "backup.sock"), AllowedUID: conductorUID, SocketGID: os.Getgid(),
		SambaTool: write("samba-tool", fakeBackupTool, 0o755), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test",
		Backup: &BackupConfig{PeerUID: backupUID, PeerGID: os.Getgid(), Account: "svc-backup", PasswordFile: write("pw", "s3cr3t-pw\n", 0o600),
			Server: "127.0.0.1", DC: "dc1", RecipientsFile: recips, StateDir: stateDir, WorkDir: filepath.Join(dir, "work"),
			ConductorDB: db, Files: []string{extra, "/nonexistent/file"}, Python: write("python3", fakePython, 0o755),
			Samba: write("samba", "#!/bin/sh\necho 'Version 4.22.11-Debian'\n", 0o755)}}
	return e
}

// start returns the conductor socket and the conductor-backup socket.
func (e *backupEnv) start(t *testing.T) (string, string) {
	t.Helper()
	s, err := Listen(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	st, err := os.Stat(e.cfg.BackupSocket)
	if err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("backup socket %v %v", st, err)
	}
	return e.cfg.Socket, e.cfg.BackupSocket
}

func callP(t *testing.T, sock string, op helper.OpName, params helper.Params, out any) error {
	t.Helper()
	req, err := helper.NewRequest("req-"+strings.ReplaceAll(string(op), ".", "-"), op, caller, params)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := helper.Call(ctx, sock, req)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return helper.DecodeResult(resp, out)
}

func TestBackupOnlineProducesEncryptedArchive(t *testing.T) {
	me := os.Getuid()
	e := newBackupEnv(t, me+1, me) // we are the conductor-backup peer
	main, sock := e.start(t)
	// The conductor socket refuses conductor-backup.
	var fe *helper.Error
	if err := callP(t, main, helper.OpPing, nil, &helper.PingResult{}); !errors.As(err, &fe) || fe.Code != helper.CodeForbidden {
		t.Fatalf("conductor-backup on the conductor socket: %v", err)
	}
	var res helper.BackupOnlineResult
	if err := callP(t, sock, helper.OpDomainBackupOnline, helper.BackupOnlineParams{Label: "scheduled"}, &res); err != nil {
		t.Fatal(err)
	}
	if !helper.BackupIDRE.MatchString(res.ID) || res.File != res.ID+".tar.age" || res.Users != 3 || len(res.Recipients) != 1 {
		t.Fatalf("result %+v", res)
	}
	if res.Recipients[0] != helper.RecipientFingerprint(e.identity.Recipient().String()) || res.Versions["samba"] != "4.22.11-Debian" {
		t.Fatalf("recipients/versions %+v", res)
	}
	p := filepath.Join(e.stateDir, "spool", res.File)
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 || st.Size() != res.Size {
		t.Fatalf("spool file %v %v", st, err)
	}
	// Nothing but ciphertext is left: the work directory is empty.
	if entries, _ := os.ReadDir(e.cfg.Backup.WorkDir); len(entries) != 0 {
		t.Fatalf("plaintext left in the work dir: %v", entries)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "fake samba backup") || strings.Contains(string(raw), "live-session-token") {
		t.Fatal("plaintext in the archive file")
	}
	// The operator's identity decrypts it.
	r, err := age.Decrypt(strings.NewReader(string(raw)), e.identity)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(r)
	got := map[string][]byte{}
	var order []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		got[h.Name] = b
		order = append(order, h.Name)
	}
	if order[0] != helper.ArchiveMetaName {
		t.Fatalf("members %v", order)
	}
	var meta helper.ArchiveMeta
	if err := json.Unmarshal(got[helper.ArchiveMetaName], &meta); err != nil || meta.Validate() != nil {
		t.Fatalf("meta %+v %v", meta, err)
	}
	if !meta.ConductorDB || meta.Users != (helper.CountRange{Min: 3, Max: 3}) || len(meta.Samples) != 1 || meta.DomainSID != "S-1-5-21-1-2-3" {
		t.Fatalf("meta %+v", meta)
	}
	if string(got[meta.SambaFile]) != "BZh9 fake samba backup" {
		t.Fatal("samba member")
	}
	extraMember := "files" + filepath.Join(e.dir, "app.toml")
	if string(got[extraMember]) != "[x]\n" {
		t.Fatalf("host file missing: %v", order)
	}
	// conductor's snapshot keeps the audit log and drops the sessions.
	snap := filepath.Join(t.TempDir(), "c.db")
	_ = os.WriteFile(snap, got[helper.ArchiveConductorDB], 0o600)
	db, _ := sql.Open("sqlite", "file:"+snap)
	defer func() { _ = db.Close() }()
	var sessions, audit int
	_ = db.QueryRow("SELECT count(*) FROM sessions").Scan(&sessions)
	_ = db.QueryRow("SELECT count(*) FROM audit").Scan(&audit)
	if sessions != 0 || audit != 1 {
		t.Fatalf("snapshot sessions=%d audit=%d", sessions, audit)
	}
	if strings.Contains(string(got[helper.ArchiveConductorDB]), "live-session-token") {
		t.Fatal("session token still in the snapshot's pages")
	}
	// conductor-backup may not use conductor's operations.
	var he *helper.Error
	for _, op := range []helper.OpName{helper.OpBackupStatus, helper.OpDomainLevel} {
		if err := callP(t, sock, op, nil, nil); !errors.As(err, &he) || he.Code != helper.CodeNotAllowed {
			t.Fatalf("%s as conductor-backup: %v", op, err)
		}
	}
}

func TestBackupRefusesUnsafeRecipients(t *testing.T) {
	me := os.Getuid()
	e := newBackupEnv(t, me+1, me)
	_ = os.Chmod(e.cfg.Backup.RecipientsFile, 0o666)
	_, sock := e.start(t)
	err := callP(t, sock, helper.OpDomainBackupOnline, helper.BackupOnlineParams{Label: "manual"}, &helper.BackupOnlineResult{})
	if err == nil {
		t.Fatal("group/world-writable recipients file accepted")
	}
	if entries, _ := os.ReadDir(filepath.Join(e.stateDir, "spool")); len(entries) != 0 {
		t.Fatalf("spool not empty: %v", entries)
	}
}

func TestConductorBackupOperations(t *testing.T) {
	me := os.Getuid()
	// We are conductor (it takes precedence); the state directory belongs to
	// the same UID, standing in for conductor-backup.
	e := newBackupEnv(t, me, me)
	e.cfg.Backup.PeerUID = me + 1 // the backup socket is not ours
	sock, bsock := e.start(t)
	var fe *helper.Error
	if err := callP(t, bsock, helper.OpPing, nil, &helper.PingResult{}); !errors.As(err, &fe) || fe.Code != helper.CodeForbidden {
		t.Fatalf("conductor on the backup socket: %v", err)
	}
	e.cfg.Backup.PeerUID = me
	var he *helper.Error
	if err := callP(t, sock, helper.OpDomainBackupOnline, helper.BackupOnlineParams{Label: "manual"}, nil); !errors.As(err, &he) || he.Code != helper.CodeNotAllowed {
		t.Fatalf("backup as conductor: %v", err)
	}
	var st helper.BackupStatus
	if err := callP(t, sock, helper.OpBackupStatus, nil, &st); err != nil || !st.Configured || st.PolicyCustom || len(st.Recipients) != 1 {
		t.Fatalf("status %+v %v", st, err)
	}
	pol := helper.DefaultBackupPolicy()
	pol.Retention.Daily = 9
	if err := callP(t, sock, helper.OpBackupPolicySet, pol, &struct{}{}); err != nil {
		t.Fatal(err)
	}
	var tr helper.BackupTriggerResult
	if err := callP(t, sock, helper.OpBackupTrigger, helper.BackupTriggerParams{Action: helper.TriggerBackup}, &tr); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(e.stateDir, "requests", tr.RequestID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var req helper.BackupRequest
	if json.Unmarshal(b, &req) != nil || req.RequestedBy != caller.User || req.SID != caller.SID || req.Kind != helper.TriggerBackup {
		t.Fatalf("request %s", b)
	}
	// state.json written by conductor-backup is merged.
	_ = os.WriteFile(filepath.Join(e.stateDir, "state.json"), []byte(`{"configured":true,"realm":"LAB.TEST","backups":[{"id":"20261003T011350Z-dc1","status":"ok","size":10}]}`), 0o600)
	st = helper.BackupStatus{}
	if err := callP(t, sock, helper.OpBackupStatus, nil, &st); err != nil {
		t.Fatal(err)
	}
	if !st.PolicyCustom || st.Policy.Retention.Daily != 9 || len(st.Pending) != 1 || len(st.Backups) != 1 {
		t.Fatalf("status %+v", st)
	}
	// Bounded request queue.
	for i := 0; i < maxPendingRequests; i++ {
		_ = callP(t, sock, helper.OpBackupTrigger, helper.BackupTriggerParams{Action: helper.TriggerDrill}, &tr)
	}
	if err := callP(t, sock, helper.OpBackupTrigger, helper.BackupTriggerParams{Action: helper.TriggerDrill}, &tr); !errors.As(err, &he) || he.Code != helper.CodeUnavailable {
		t.Fatalf("queue bound: %v", err)
	}
	// conductor-backup replaced its requests directory with a symlink: the
	// helper (root) never writes through it.
	_ = os.RemoveAll(filepath.Join(e.stateDir, "requests"))
	target := t.TempDir()
	_ = os.Symlink(target, filepath.Join(e.stateDir, "requests"))
	if err := callP(t, sock, helper.OpBackupTrigger, helper.BackupTriggerParams{Action: helper.TriggerBackup}, &tr); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("file written through the symlink: %v", entries)
	}
}

func TestBackupsNotConfigured(t *testing.T) {
	sock := startHelper(t, os.Getuid())
	var st helper.BackupStatus
	if err := callP(t, sock, helper.OpBackupStatus, nil, &st); err != nil || st.Configured {
		t.Fatalf("status %+v %v", st, err)
	}
	var he *helper.Error
	if err := callP(t, sock, helper.OpBackupTrigger, helper.BackupTriggerParams{Action: helper.TriggerBackup}, nil); !errors.As(err, &he) || he.Code != helper.CodeNotAllowed {
		t.Fatalf("trigger: %v", err)
	}
}

func TestLoadConfig(t *testing.T) {
	if c, err := LoadConfig(filepath.Join(t.TempDir(), "none.toml")); c != nil || err != nil {
		t.Fatalf("missing file: %v %v", c, err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "helper.toml")
	_ = os.WriteFile(p, []byte("[backup]\nenabled = true\naccount = \"svc-backup\"\npeer_user = \"root\"\npassword_file = \"/x/pw\"\nstate_dir = \"relative\"\n"), 0o644)
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "state_dir") || !strings.Contains(err.Error(), "root") {
		t.Fatalf("invalid config: %v", err)
	}
	_ = os.WriteFile(p, []byte("[backup]\nenabled = true\ntypo = 1\n"), 0o644)
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("unknown key: %v", err)
	}
	_ = os.WriteFile(p, []byte("[backup]\nenabled = false\n"), 0o644)
	if c, err := LoadConfig(p); c != nil || err != nil {
		t.Fatalf("disabled: %v %v", c, err)
	}
}
