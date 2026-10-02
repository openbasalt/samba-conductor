package helperd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/samba-conductor/ad/helper"
)

// fakeSambaTool prints canned output per subcommand.
const fakeSambaTool = `#!/bin/sh
case "$1 $2" in
"domain level") printf 'Forest function level: (Windows) 2016\nDomain function level: (Windows) 2016\nLowest function level of a DC: (Windows) 2016\n' ;;
"fsmo show") printf 'SchemaMasterRole owner: CN=NTDS Settings,CN=DC1,CN=Servers,CN=S,CN=Sites,CN=Configuration,DC=lab\nPdcEmulationMasterRole owner: CN=NTDS Settings,CN=DC1,CN=Servers,CN=S,CN=Sites,CN=Configuration,DC=lab\n' ;;
"group listmembers") [ "$4" = "--" ] && [ "$5" = "Domain Controllers" ] && printf 'CN=DC1,OU=Domain Controllers,DC=lab\nCN=DC2,OU=Domain Controllers,DC=lab\n' ;;
*) echo "unexpected: $*" >&2; exit 1 ;;
esac
`

func startHelper(t *testing.T, allowedUID int) string {
	t.Helper()
	dir := t.TempDir()
	tool := filepath.Join(dir, "samba-tool")
	if err := os.WriteFile(tool, []byte(fakeSambaTool), 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "helper.sock")
	s, err := Listen(Config{Socket: sock, AllowedUID: allowedUID, SocketGID: os.Getgid(), SambaTool: tool,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v %v", st.Mode(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return sock
}

var caller = helper.Caller{User: "lab.admin", SID: "S-1-5-21-1-2-3-1105", SessionID: "0123456789abcdef", SourceIP: "10.93.0.1"}

func call(t *testing.T, sock string, op helper.OpName, out any) error {
	t.Helper()
	req, err := helper.NewRequest("req-"+string(op)[:4]+"-0001", op, caller, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := helper.Call(ctx, sock, req)
	if err != nil {
		return err
	}
	return helper.DecodeResult(resp, out)
}

func TestReadOnlyOperations(t *testing.T) {
	sock := startHelper(t, os.Getuid())
	var ping helper.PingResult
	if err := call(t, sock, helper.OpPing, &ping); err != nil || ping.Version != helper.ProtocolVersion {
		t.Fatalf("ping %+v %v", ping, err)
	}
	var lvl helper.DomainLevelResult
	if err := call(t, sock, helper.OpDomainLevel, &lvl); err != nil || lvl.Domain != "(Windows) 2016" {
		t.Fatalf("level %+v %v", lvl, err)
	}
	var fsmo helper.FSMORolesResult
	if err := call(t, sock, helper.OpFSMORoles, &fsmo); err != nil || len(fsmo.Roles) != 2 {
		t.Fatalf("fsmo %+v %v", fsmo, err)
	}
	var dcs helper.DCListResult
	if err := call(t, sock, helper.OpDCList, &dcs); err != nil || len(dcs.DCs) != 2 {
		t.Fatalf("dcs %+v %v", dcs, err)
	}
}

func TestAllowlistAndPeerCheck(t *testing.T) {
	sock := startHelper(t, os.Getuid())
	// In the protocol allowlist but not enabled in P1.
	var he *helper.Error
	req, _ := helper.NewRequest("req-backup-0002", helper.OpDomainBackupOnline, caller, helper.BackupOnlineParams{Label: "x"})
	_, err := helper.Call(context.Background(), sock, req)
	if !errors.As(err, &he) || he.Code != helper.CodeNotAllowed {
		t.Fatalf("not enabled op: %v", err)
	}
	// A raw request with an unknown operation never reaches samba-tool.
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte(`{"version":1,"id":"req-raw-00001","op":"exec","caller":{"user":"x","sid":"S-1-5-21-1-2-3-4","session_id":"s"},"sent_at":"2026-10-02T00:00:00Z"}` + "\n"))
	resp, err := helper.NewReader(c).ReadResponse()
	_ = c.Close()
	if err != nil || resp.OK || resp.Error.Code != helper.CodeNotAllowed {
		t.Fatalf("raw exec: %+v %v", resp, err)
	}

	// Another user (here: any UID but ours) is refused even though the
	// socket file is reachable.
	other := startHelper(t, os.Getuid()+1)
	err = call(t, other, helper.OpPing, &helper.PingResult{})
	if !errors.As(err, &he) || he.Code != helper.CodeForbidden {
		t.Fatalf("foreign peer: %v", err)
	}
}

func TestRefusesNonSocketPath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(p, []byte("x"), 0o600)
	if _, err := Listen(Config{Socket: p, AllowedUID: os.Getuid()}); err == nil {
		t.Fatal("replaced a regular file")
	}
	if _, err := Listen(Config{Socket: "relative.sock"}); err == nil {
		t.Fatal("relative path accepted")
	}
}
