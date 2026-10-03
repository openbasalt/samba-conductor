package web

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-sync/syncapi"
	"github.com/openbasalt/samba-conductor/internal/store"
)

// Connection settings of the Google Workspace sync (P5c): how conductor-sync
// reaches AD and Google, the ownership marker and the alert webhook, plus
// the write-only secrets (the AD bind password, the Google service account
// key, the webhook HMAC secret). Editing follows the same rules as the rest
// of the sync section, with more care because these settings decide where
// conductor-sync connects and sends credentials:
//
//   - the edit is a draft in the signed-in session; saving needs a
//     successful connection test of exactly that draft (AD and/or Google,
//     whichever part changed), a preview of every changed setting and a
//     fresh second factor; conductor-sync signs in to AD again before it
//     stores an AD change;
//   - the ownership marker has its own form with a strong warning and a
//     typed confirmation (conductor-sync requires it too);
//   - secrets are write only: pages show whether each one is configured,
//     where it comes from and who changed it when, never a value; a new
//     value lives only in the draft or in the pending confirmation and is
//     never rendered, logged or audited (the audit names the secret);
//   - every saved change is a settings version; any earlier version can be
//     restored (rollback) with the same preview and re-authentication.
//     Secrets are not versioned.

const syncConnURL = "/admin/sync/config/connection"

// syncConnDraft is an edit of the connection settings in progress.
type syncConnDraft struct {
	Base int64
	// S is the whole settings set, with the edited connection and tenant
	// (customer, admin subject).
	S syncapi.Settings
	// adPassword is a new bind password entered with the draft (for a new
	// bind account); never rendered.
	adPassword string
	Test       *syncapi.TestResult
	// testedHash identifies the draft the last test ran with (password
	// included), so a save is refused after an untested change.
	testedHash string
}

// HasPassword is used by the template (the value itself is never exposed).
func (d *syncConnDraft) HasPassword() bool { return d.adPassword != "" }

func (d *syncConnDraft) hash() string {
	h := sha256.New()
	b, _ := json.Marshal(struct {
		C *syncapi.ConnectionSettings
		G syncapi.GoogleSettings
	}{d.S.Connection, d.S.Google})
	h.Write(b)
	h.Write([]byte{0})
	h.Write([]byte(d.adPassword))
	return hex.EncodeToString(h.Sum(nil))
}

// Tested reports whether the last test ran with the draft as it is now.
func (d *syncConnDraft) Tested() bool { return d.Test != nil && d.testedHash == d.hash() }

// adChanged and googleChanged compare the draft with the settings in force.
func adChanged(cur, next syncapi.Settings) bool {
	if cur.Connection == nil || next.Connection == nil {
		return cur.Connection != next.Connection
	}
	a, b := cur.Connection.AD, next.Connection.AD
	return !strings.EqualFold(a.Realm, b.Realm) || !slices.Equal(a.DCs, b.DCs) || !slices.Equal(a.Preferred, b.Preferred) ||
		!slices.Equal(a.DNSServers, b.DNSServers) || strings.TrimSpace(a.CAPEM) != strings.TrimSpace(b.CAPEM) ||
		a.BindUser != b.BindUser || a.Auth != b.Auth
}

func googleChanged(cur, next syncapi.Settings) bool {
	if cur.Google.Customer != next.Google.Customer || cur.Google.AdminSubject != next.Google.AdminSubject {
		return true
	}
	if cur.Connection == nil || next.Connection == nil {
		return cur.Connection != next.Connection
	}
	return cur.Connection.Google != next.Connection.Google
}

// needsTest says which connection test a save of the draft needs.
func (d *syncConnDraft) needsTest(cur syncapi.Settings) (ad, google bool) {
	return adChanged(cur, d.S) || d.adPassword != "", googleChanged(cur, d.S)
}

// caInfo describes one certificate of the pinned CA (public data).
type caInfo struct {
	Subject, Issuer string
	NotAfter        time.Time
	Expired         bool
	SHA256          string
}

func caInfos(text string, now time.Time) ([]caInfo, bool) {
	var out []caInfo
	rest := []byte(text)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return out, false
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return out, false
		}
		sum := sha256.Sum256(c.Raw)
		var fp []string
		for _, x := range sum[:8] {
			fp = append(fp, fmt.Sprintf("%02X", x))
		}
		out = append(out, caInfo{Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotAfter: c.NotAfter,
			Expired: now.After(c.NotAfter), SHA256: strings.Join(fp, ":") + "…"})
	}
	return out, len(out) > 0
}

// conn returns s.Connection, never nil (an older conductor-sync may omit it).
func conn(s *syncapi.Settings) *syncapi.ConnectionSettings {
	if s.Connection == nil {
		s.Connection = &syncapi.ConnectionSettings{}
	}
	return s.Connection
}

// cloneSettings deep-copies the connection part (the rest is replaced
// field by field, never mutated in place).
func cloneSettings(s syncapi.Settings) syncapi.Settings {
	if s.Connection != nil {
		c := *s.Connection
		c.AD.DCs, c.AD.Preferred, c.AD.DNSServers = slices.Clone(c.AD.DCs), slices.Clone(c.AD.Preferred), slices.Clone(c.AD.DNSServers)
		s.Connection = &c
	}
	return s
}

// ---- the page ----

func (s *Server) handleSyncConnection(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	d := map[string]any{"CanWrite": rc.roles.Has(PermSyncWrite)}
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		d["Error"] = s.syncErr(rc, err)
		rc.render(http.StatusOK, "sync_connection", d)
		return
	}
	conn(&cfg.Settings)
	d["C"] = cfg
	cur := cloneSettings(cfg.Settings)
	conn(&cur)
	values := cur
	rc.sess.mu.Lock()
	dr := rc.sess.syncConn
	var draft *syncConnDraft
	if dr != nil {
		cp := *dr
		draft = &cp
		values = cloneSettings(dr.S)
	}
	rc.sess.mu.Unlock()
	d["V"] = values
	d["Draft"] = draft
	if draft != nil {
		if draft.Base != cfg.Version {
			d["Stale"] = true
		}
		needAD, needGoogle := draft.needsTest(cur)
		d["NeedAD"], d["NeedGoogle"] = needAD, needGoogle
		d["Tested"] = draft.Tested()
		var v syncapi.ConfigValidateResult
		if err := s.syncCall(ctx, rc, syncapi.OpConfigValidate, syncapi.ConfigValidateParams{Settings: draft.S}, &v); err != nil {
			d["Error"] = s.syncErr(rc, err)
		} else {
			d["Validation"] = v
		}
	}
	if values.Connection != nil && values.Connection.AD.CAPEM != "" {
		d["CA"], _ = caInfos(values.Connection.AD.CAPEM, s.now())
	}
	type secretRow struct {
		syncapi.SecretInfo
		// Replace: the form kind (password, file); "" when not replaceable here.
		Replace string
	}
	var rows []secretRow
	for _, name := range syncapi.SecretNames {
		si := cfg.Secret(name)
		kind := "password"
		if name == syncapi.SecretGoogleKey {
			kind = "file"
		}
		rows = append(rows, secretRow{SecretInfo: si, Replace: kind})
	}
	d["Secrets"] = rows
	d["MarkerExample"] = syncapi.MarkerConfirmation("…")
	rc.render(http.StatusOK, "sync_connection", d)
}

// connForm applies the posted connection form to a draft.
func (s *Server) connForm(rc *reqCtx, dr *syncConnDraft, caUpload []byte) string {
	c := conn(&dr.S)
	c.AD.Realm = rc.form("realm")
	c.AD.DCs = words(rc.rawForm("dcs"))
	c.AD.Preferred = words(rc.rawForm("preferred"))
	c.AD.DNSServers = words(rc.rawForm("dns_servers"))
	c.AD.BindUser = rc.form("bind_user")
	if a := rc.form("auth"); a == "kerberos" || a == "simple" {
		c.AD.Auth = a
	}
	switch {
	case len(caUpload) > 0:
		c.AD.CAPEM = string(caUpload)
	case rc.form("ca_use_file") == "1":
		c.AD.CAPEM = ""
	default:
		c.AD.CAPEM = strings.TrimSpace(strings.ReplaceAll(rc.rawForm("ca_pem"), "\r\n", "\n"))
		if c.AD.CAPEM != "" {
			c.AD.CAPEM += "\n"
		}
	}
	if pw := rc.rawForm("new_password"); pw != "" {
		if err := syncapi.ValidateSecret(syncapi.SecretADBindPassword, pw); err != nil {
			return "sync.conn.err_password"
		}
		dr.adPassword = pw
	}
	if rc.form("drop_password") == "1" {
		dr.adPassword = ""
	}
	dr.S.Google.Customer = rc.form("customer")
	dr.S.Google.AdminSubject = rc.form("admin_subject")
	rps, err1 := strconv.ParseFloat(rc.form("requests_per_second"), 64)
	retries, err2 := strconv.Atoi(rc.form("max_retries"))
	if err1 != nil || err2 != nil {
		return "sync.setup.err_number"
	}
	c.Google.RequestsPerSecond, c.Google.MaxRetries = rps, retries
	c.Google.Timeout = rc.form("timeout")
	c.Alert.WebhookURL = rc.form("webhook_url")
	return ""
}

// maxCAUpload bounds an uploaded CA bundle (as conductor-sync does).
const maxCAUpload = 64 << 10

func (s *Server) handleSyncConnectionPost(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	if rc.form("go") == "discard" {
		rc.sess.mu.Lock()
		rc.sess.syncConn = nil
		rc.sess.mu.Unlock()
		rc.flashOK("sync.conn.discarded")
		rc.redirect(syncConnURL)
		return
	}
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(syncConnURL)
		return
	}
	var caUpload []byte
	if f, _, err := rc.r.FormFile("ca_upload"); err == nil {
		caUpload, err = io.ReadAll(io.LimitReader(f, maxCAUpload+1))
		_ = f.Close()
		if err != nil || len(caUpload) > maxCAUpload {
			rc.flashErr("sync.conn.err_ca")
			rc.redirect(syncConnURL)
			return
		}
		if _, ok := caInfos(string(caUpload), s.now()); !ok {
			rc.flashErr("sync.conn.err_ca")
			rc.redirect(syncConnURL)
			return
		}
	}
	rc.sess.mu.Lock()
	if rc.sess.syncConn == nil {
		rc.sess.syncConn = &syncConnDraft{Base: cfg.Version, S: cloneSettings(cfg.Settings)}
	}
	dr := rc.sess.syncConn
	errKey := s.connForm(rc, dr, caUpload)
	draft := *dr
	draft.S = cloneSettings(dr.S)
	rc.sess.mu.Unlock()
	if errKey != "" {
		rc.flashErr(errKey)
		rc.redirect(syncConnURL)
		return
	}
	switch rc.form("go") {
	case "test":
		s.connTest(ctx, rc, &draft)
	case "save":
		s.connSave(ctx, rc, &draft, cfg)
	default:
		rc.redirect(syncConnURL)
	}
}

// connTest runs conductor-sync's connection test with the draft (and the
// draft's new bind password, if any) and records which draft was tested.
func (s *Server) connTest(ctx context.Context, rc *reqCtx, draft *syncConnDraft) {
	settings := draft.S
	var res syncapi.TestResult
	if err := s.syncCall(ctx, rc, syncapi.OpConnectionTest, syncapi.ConnectionTestParams{Settings: &settings, ADPassword: draft.adPassword}, &res); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(syncConnURL)
		return
	}
	h := draft.hash()
	rc.sess.mu.Lock()
	if rc.sess.syncConn != nil {
		rc.sess.syncConn.Test, rc.sess.syncConn.testedHash = &res, h
	}
	rc.sess.mu.Unlock()
	result := store.ResultOK
	if !res.AD.OK || !res.Google.OK {
		result = store.ResultFailed
	}
	s.audit(ctx, rc, "sync.connection_test", "google", fmt.Sprintf("connection draft: ad=%v google=%v new_bind_password=%v", res.AD.OK, res.Google.OK, draft.adPassword != ""), result)
	rc.redirect(syncConnURL + "#test")
}

// connSave checks the draft (tested as it is, valid, changed) and proposes
// the new version with re-authentication.
func (s *Server) connSave(ctx context.Context, rc *reqCtx, draft *syncConnDraft, cfg syncapi.ConfigView) {
	if draft.Base != cfg.Version {
		rc.flashErr("sync.setup.stale")
		rc.redirect(syncConnURL)
		return
	}
	cur := cloneSettings(cfg.Settings)
	conn(&cur)
	needAD, needGoogle := draft.needsTest(cur)
	if needAD || needGoogle {
		switch {
		case !draft.Tested():
			rc.flashErr("sync.conn.err_untested")
			rc.redirect(syncConnURL)
			return
		case needAD && !draft.Test.AD.OK, needGoogle && !draft.Test.Google.OK:
			rc.flashErr("sync.conn.err_test_failed")
			rc.redirect(syncConnURL)
			return
		}
	}
	var v syncapi.ConfigValidateResult
	if err := s.syncCall(ctx, rc, syncapi.OpConfigValidate, syncapi.ConfigValidateParams{Settings: draft.S}, &v); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(syncConnURL)
		return
	}
	if !v.Valid {
		rc.flashErr("sync.setup.invalid")
		rc.redirect(syncConnURL)
		return
	}
	for _, c := range v.Changes {
		if c.Path == "connection.marker" {
			// The marker has its own form (typed confirmation).
			rc.flashErr("sync.marker.err_use_form")
			rc.redirect(syncConnURL)
			return
		}
	}
	if len(v.Changes) == 0 && draft.adPassword == "" {
		rc.flashOK("form.no_change")
		rc.redirect(syncConnURL)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "conductor-sync %s\nbase_version: %d\n", syncapi.OpConfigUpdate, draft.Base)
	for _, c := range v.Changes {
		fmt.Fprintf(&b, "%s\n", c.String())
	}
	if draft.adPassword != "" {
		// The name only: the value is never shown, logged or audited.
		fmt.Fprintf(&b, "secret %s: replaced\n", syncapi.SecretADBindPassword)
	}
	fmt.Fprintf(&b, "# %s", rc.T("sync.conn.preview_note"))
	comment := clipName(rc.form("comment"))
	settings, base, pw := draft.S, draft.Base, draft.adPassword
	warning := ""
	if needAD {
		warning = rc.T("sync.conn.ad_warning")
	}
	rc.propose(&pendingOp{perm: PermSyncWrite, action: "sync.connection_update", target: "google", reauth: true,
		title: rc.T("sync.conn.save_title"), summary: rc.T("sync.conn.save_summary", len(v.Changes)), warning: warning,
		preview: b.String(),
		run: func(ctx context.Context, rc *reqCtx) error {
			var res syncapi.ConfigUpdateResult
			if err := s.syncCall(ctx, rc, syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: base, Settings: settings,
				Comment: comment, ADPassword: pw}, &res); err != nil {
				return err
			}
			rc.sess.mu.Lock()
			rc.sess.syncConn = nil
			rc.sess.mu.Unlock()
			return nil
		},
		back: syncConnURL, done: rc.T("sync.conn.saved")})
}

// ---- the ownership marker ----

// handleSyncMarker changes the ownership marker: a typed confirmation bound
// to the new value, a strong warning, a fresh second factor.
func (s *Server) handleSyncMarker(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(syncConnURL)
		return
	}
	next := cloneSettings(cfg.Settings)
	c := conn(&next)
	old, marker := c.Marker, rc.form("marker")
	if marker == old {
		rc.flashOK("form.no_change")
		rc.redirect(syncConnURL)
		return
	}
	want := syncapi.MarkerConfirmation(marker)
	if rc.form("confirm") != want {
		s.audit(ctx, rc, "sync.marker", "google", "typed confirmation did not match", store.ResultDenied)
		rc.flashErr("sync.marker.err_confirm", want)
		rc.redirect(syncConnURL + "#marker")
		return
	}
	c.Marker = marker
	var v syncapi.ConfigValidateResult
	if err := s.syncCall(ctx, rc, syncapi.OpConfigValidate, syncapi.ConfigValidateParams{Settings: next}, &v); err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect(syncConnURL + "#marker")
		return
	}
	if !v.Valid {
		rc.sess.addFlash("error", rc.T("sync.setup.invalid")+" "+strings.Join(v.Errors, "; "))
		rc.redirect(syncConnURL + "#marker")
		return
	}
	preview := fmt.Sprintf("conductor-sync %s\nbase_version: %d\nconnection.marker: %s -> %s\nmarker_confirmation: %s", syncapi.OpConfigUpdate,
		cfg.Version, old, marker, want)
	base := cfg.Version
	rc.propose(&pendingOp{perm: PermSyncWrite, action: "sync.marker", target: "google", reauth: true,
		title: rc.T("sync.marker.title"), summary: rc.T("sync.marker.summary", old, marker), warning: rc.T("sync.marker.warning", old),
		preview: preview,
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.syncCall(ctx, rc, syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: base, Settings: next,
				Comment: "ownership marker " + old + " -> " + marker + " (conductor)", MarkerConfirmation: want}, &syncapi.ConfigUpdateResult{})
		},
		back: syncConnURL, done: rc.T("sync.marker.done", marker)})
}

// ---- secrets (write only) ----

func (s *Server) handleSyncSecret(rc *reqCtx) {
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	name, action := rc.form("name"), rc.form("action")
	if !slices.Contains(syncapi.SecretNames, name) || (action != "replace" && action != "remove") ||
		(name == syncapi.SecretGoogleKey && action == "replace") {
		rc.errorPage(http.StatusBadRequest, "form.invalid")
		return
	}
	back := syncConnURL + "#secrets"
	label := rc.T("sync.secret." + name)
	if action == "remove" {
		var cfg syncapi.ConfigView
		if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
			rc.sess.addFlash("error", s.syncErr(rc, err))
			rc.redirect(back)
			return
		}
		si := cfg.Secret(name)
		if si.Source != "database" {
			rc.flashErr("sync.secret.err_not_stored")
			rc.redirect(back)
			return
		}
		fallback := rc.T("sync.secret.fallback_none")
		if si.Credential != "" {
			fallback = rc.T("sync.secret.fallback_file", si.Credential)
		}
		preview := fmt.Sprintf("conductor-sync %s\nname: %s\n# %s", syncapi.OpSecretRemove, name, fallback)
		rc.propose(&pendingOp{perm: PermSyncWrite, action: "sync.secret_remove", target: name, reauth: true,
			title: rc.T("sync.secret.remove_title", label), summary: rc.T("sync.secret.remove_summary", label),
			warning: rc.T("sync.secret.remove_warning." + name), preview: preview,
			run: func(ctx context.Context, rc *reqCtx) error {
				return s.syncCall(ctx, rc, syncapi.OpSecretRemove, syncapi.SecretRemoveParams{Name: name}, &syncapi.SecretInfo{})
			},
			back: back, done: rc.T("sync.secret.removed", label)})
		return
	}
	value := rc.rawForm("value")
	if err := syncapi.ValidateSecret(name, value); err != nil {
		rc.flashErr("sync.secret.err_value." + name)
		rc.redirect(back)
		return
	}
	if name == syncapi.SecretADBindPassword {
		// Test before saving: a sign-in to AD with the settings in force
		// and the new password (conductor-sync checks it again).
		var res syncapi.TestResult
		if err := s.syncCall(ctx, rc, syncapi.OpConnectionTest, syncapi.ConnectionTestParams{ADPassword: value}, &res); err != nil {
			rc.sess.addFlash("error", s.syncErr(rc, err))
			rc.redirect(back)
			return
		}
		result := store.ResultOK
		if !res.AD.OK {
			result = store.ResultFailed
		}
		s.audit(ctx, rc, "sync.connection_test", "google", fmt.Sprintf("new bind password: ad=%v", res.AD.OK), result)
		if !res.AD.OK {
			rc.sess.addFlash("error", rc.T("sync.secret.err_ad_test")+" "+res.AD.Error)
			rc.redirect(back)
			return
		}
	}
	// The preview names the secret; the value lives only in this pending
	// operation until it is confirmed.
	preview := fmt.Sprintf("conductor-sync %s\nname: %s\n# %s", syncapi.OpSecretSet, name, rc.T("sync.secret.preview"))
	rc.propose(&pendingOp{perm: PermSyncWrite, action: "sync.secret_set", target: name, reauth: true,
		title: rc.T("sync.secret.replace_title", label), summary: rc.T("sync.secret.replace_summary", label), preview: preview,
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.syncCall(ctx, rc, syncapi.OpSecretSet, syncapi.SecretSetParams{Name: name, Value: value}, &syncapi.SecretInfo{})
		},
		back: back, done: rc.T("sync.secret.replaced", label)})
}

// ---- rollback ----

// rollbackDiff reads version id and what restoring it would change.
func (s *Server) rollbackDiff(ctx context.Context, rc *reqCtx, id int64) (*syncapi.ConfigVersionDetail, *syncapi.ConfigView, *syncapi.ConfigValidateResult, error) {
	var cfg syncapi.ConfigView
	if err := s.syncCall(ctx, rc, syncapi.OpConfigGet, nil, &cfg); err != nil {
		return nil, nil, nil, err
	}
	var ver syncapi.ConfigVersionDetail
	if err := s.syncCall(ctx, rc, syncapi.OpConfigVersion, syncapi.ConfigVersionParams{ID: id}, &ver); err != nil {
		return nil, nil, nil, err
	}
	var v syncapi.ConfigValidateResult
	if err := s.syncCall(ctx, rc, syncapi.OpConfigValidate, syncapi.ConfigValidateParams{Settings: ver.Settings}, &v); err != nil {
		return nil, nil, nil, err
	}
	return &ver, &cfg, &v, nil
}

// markerChange returns the new marker when a diff changes it.
func markerChange(changes []syncapi.Change) (string, bool) {
	for _, c := range changes {
		if c.Path == "connection.marker" {
			return c.New, true
		}
	}
	return "", false
}

func versionParam(rc *reqCtx) (int64, bool) {
	v := rc.r.URL.Query().Get("version")
	if rc.r.Method == http.MethodPost {
		v = rc.form("version")
	}
	id, err := strconv.ParseInt(v, 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) handleSyncRollbackPage(rc *reqCtx) {
	id, ok := versionParam(rc)
	if !ok {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	d := map[string]any{}
	ver, cfg, v, err := s.rollbackDiff(ctx, rc, id)
	if err != nil {
		if syncapi.ErrorCodeOf(err) == syncapi.CodeNotFound {
			rc.errorPage(http.StatusNotFound, "err.not_found")
			return
		}
		d["Error"] = s.syncErr(rc, err)
		rc.render(http.StatusOK, "sync_rollback", d)
		return
	}
	d["Ver"], d["C"], d["V"] = ver, cfg, v
	if m, ok := markerChange(v.Changes); ok {
		d["Marker"], d["MarkerConfirm"] = m, syncapi.MarkerConfirmation(m)
	}
	rc.render(http.StatusOK, "sync_rollback", d)
}

func (s *Server) handleSyncRollback(rc *reqCtx) {
	id, ok := versionParam(rc)
	if !ok {
		rc.errorPage(http.StatusNotFound, "err.not_found")
		return
	}
	page := fmt.Sprintf("/admin/sync/config/rollback?version=%d", id)
	ctx, cancel := syncTimeout(rc)
	defer cancel()
	ver, cfg, v, err := s.rollbackDiff(ctx, rc, id)
	if err != nil {
		rc.sess.addFlash("error", s.syncErr(rc, err))
		rc.redirect("/admin/sync/config")
		return
	}
	if !v.Valid {
		rc.sess.addFlash("error", rc.T("sync.setup.invalid")+" "+strings.Join(v.Errors, "; "))
		rc.redirect(page)
		return
	}
	if len(v.Changes) == 0 {
		rc.flashOK("form.no_change")
		rc.redirect("/admin/sync/config")
		return
	}
	confirm, warning := "", ""
	if m, ok := markerChange(v.Changes); ok {
		confirm = syncapi.MarkerConfirmation(m)
		if rc.form("confirm") != confirm {
			s.audit(ctx, rc, "sync.rollback", fmt.Sprintf("version %d", id), "typed confirmation of the marker change did not match", store.ResultDenied)
			rc.flashErr("sync.marker.err_confirm", confirm)
			rc.redirect(page)
			return
		}
		warning = rc.T("sync.marker.warning", conn(&cfg.Settings).Marker)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "conductor-sync %s\nbase_version: %d\nversion: %d\n", syncapi.OpConfigRollback, cfg.Version, id)
	for _, c := range v.Changes {
		fmt.Fprintf(&b, "%s\n", c.String())
	}
	fmt.Fprintf(&b, "# %s", rc.T("sync.rollback.secrets_note"))
	base := cfg.Version
	comment := clipName(rc.form("comment"))
	rc.propose(&pendingOp{perm: PermSyncWrite, action: "sync.rollback", target: fmt.Sprintf("version %d", id), reauth: true,
		title: rc.T("sync.rollback.title", ver.ID), summary: rc.T("sync.rollback.summary", len(v.Changes)), warning: warning,
		preview: b.String(),
		run: func(ctx context.Context, rc *reqCtx) error {
			return s.syncCall(ctx, rc, syncapi.OpConfigRollback, syncapi.ConfigRollbackParams{BaseVersion: base, Version: id, Comment: comment,
				MarkerConfirmation: confirm}, &syncapi.ConfigUpdateResult{})
		},
		back: "/admin/sync/config", done: rc.T("sync.rollback.done", id)})
}
