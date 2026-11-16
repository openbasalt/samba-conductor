package helperd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-ad/helper"
)

func callAs(t *testing.T, sock string, c helper.Caller, op helper.OpName, params helper.Params, out any) error {
	t.Helper()
	req, err := helper.NewRequest("req-as-"+strings.ReplaceAll(string(op), ".", "-"), op, c, params)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := helper.Call(ctx, sock, req)
	if err != nil {
		return err
	}
	return helper.DecodeResult(resp, out)
}

// TestRetentionFloorAndCaller: a policy below the floor of helper.toml is
// refused, and changes must name a well-formed domain account.
func TestRetentionFloorAndCaller(t *testing.T) {
	me := os.Getuid()
	e := newBackupEnv(t, me, me)
	e.cfg.Backup.RetentionFloor = helper.BackupRetention{Daily: 5, Weekly: 2, Monthly: 3}
	sock, _ := e.start(t)
	var he *helper.Error
	low := helper.DefaultBackupPolicy()
	low.Retention = helper.BackupRetention{Daily: 1, Weekly: 0, Monthly: 0}
	if err := callP(t, sock, helper.OpBackupPolicySet, low, &struct{}{}); !errors.As(err, &he) || he.Code != helper.CodeBadRequest ||
		!strings.Contains(he.Message, "floor") {
		t.Fatalf("policy below the floor: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.stateDir, "policy.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("policy below the floor written")
	}
	ok := helper.DefaultBackupPolicy()
	ok.Retention = helper.BackupRetention{Daily: 5, Weekly: 2, Monthly: 3}
	if err := callP(t, sock, helper.OpBackupPolicySet, ok, &struct{}{}); err != nil {
		t.Fatalf("policy at the floor: %v", err)
	}
	// conductor's background identity only reads.
	system := helper.Caller{User: "conductor", SID: "S-1-5-18", SessionID: "background-poller"}
	if err := callAs(t, sock, system, helper.OpBackupTrigger, helper.BackupTriggerParams{Action: helper.TriggerBackup}, &helper.BackupTriggerResult{}); !errors.As(err, &he) ||
		he.Code != helper.CodeBadRequest {
		t.Fatalf("change as the system identity: %v", err)
	}
	if err := callAs(t, sock, system, helper.OpBackupStatus, nil, &helper.BackupStatus{}); err != nil {
		t.Fatalf("status as the system identity: %v", err)
	}
	bad := caller
	bad.User = "lab.admin\nforged log line"
	if err := callAs(t, sock, bad, helper.OpBackupStatus, nil, &helper.BackupStatus{}); !errors.As(err, &he) || he.Code != helper.CodeBadRequest {
		t.Fatalf("malformed caller: %v", err)
	}
	bad = caller
	bad.SourceIP = "not-an-ip"
	if err := callAs(t, sock, bad, helper.OpBackupStatus, nil, &helper.BackupStatus{}); !errors.As(err, &he) || he.Code != helper.CodeBadRequest {
		t.Fatalf("malformed address: %v", err)
	}
}

func TestDefaultRetentionFloor(t *testing.T) {
	b := &BackupConfig{}
	if b.floor() != helper.DefaultBackupPolicy().Retention {
		t.Fatalf("default floor %+v", b.floor())
	}
	seven := 7
	zero := 0
	if r, err := (retentionFloorFile{Weekly: &zero}).resolve(); err != nil || r.Weekly != 0 || r.Daily != seven {
		t.Fatalf("partial floor %+v %v", r, err)
	}
	if _, err := (retentionFloorFile{Daily: &zero}).resolve(); err == nil {
		t.Fatal("daily floor 0 accepted")
	}
}
