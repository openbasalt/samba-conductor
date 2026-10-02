package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/sid"
	"github.com/samba-conductor/conductor/internal/config"
	"github.com/samba-conductor/conductor/internal/secret"
	"github.com/samba-conductor/conductor/internal/store"
	"github.com/samba-conductor/conductor/internal/web"
	"golang.org/x/term"
)

// setupOpts are the answers of `conductor setup` (flags, or prompts).
type setupOpts struct {
	configPath     string
	realm          string
	dc             string
	caFile         string
	caFingerprint  string
	adminUser      string
	adminGroup     string
	helpdeskGroup  string
	auditorGroup   string
	listen         string
	tlsCert        string
	tlsKey         string
	behindProxy    bool
	mfaPolicy      string
	firstAdmin     string
	publicURL      string
	serviceUser    string
	force          bool
	nonInteractive bool
	webauthnRPID   string
}

func cmdSetup(args []string) error {
	var o setupOpts
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	fs.StringVar(&o.configPath, "config", config.DefaultPath, "configuration file to write")
	fs.StringVar(&o.realm, "realm", "", "Kerberos realm (default: from /etc/samba/smb.conf)")
	fs.StringVar(&o.dc, "dc", "", "preferred DC host name (default: this host's FQDN)")
	fs.StringVar(&o.caFile, "ca-file", "", "PEM file of the CA that signs the DCs' LDAPS certificates")
	fs.StringVar(&o.caFingerprint, "ca-fingerprint", "", "expected SHA-256 fingerprint of the CA read from the DC (non-interactive pinning)")
	fs.StringVar(&o.adminUser, "admin-user", "", "domain account used once to resolve group names (password asked, or read from stdin)")
	fs.StringVar(&o.adminGroup, "admin-group", "", "administrators group name (default: Domain Admins, RID 512)")
	fs.StringVar(&o.helpdeskGroup, "helpdesk-group", "", "helpdesk group name (optional)")
	fs.StringVar(&o.auditorGroup, "auditor-group", "", "auditor group name (optional)")
	fs.StringVar(&o.listen, "listen", ":8443", "listen address")
	fs.StringVar(&o.tlsCert, "tls-cert", "/etc/conductor/tls/cert.pem", "TLS certificate (built-in TLS)")
	fs.StringVar(&o.tlsKey, "tls-key", "/etc/conductor/tls/key.pem", "TLS private key")
	fs.BoolVar(&o.behindProxy, "behind-proxy", false, "serve plain HTTP on a loopback address for a local TLS reverse proxy")
	fs.StringVar(&o.mfaPolicy, "mfa-policy", config.MFAOptional, "2FA for non-privileged users: off, optional or required")
	fs.StringVar(&o.firstAdmin, "first-admin", "", "administrator who gets a one-time 2FA enrollment link")
	fs.StringVar(&o.publicURL, "public-url", "", "https URL users open (for the enrollment link)")
	fs.StringVar(&o.serviceUser, "service-user", "conductor", "system user conductor runs as")
	fs.BoolVar(&o.force, "force", false, "overwrite an existing configuration file")
	fs.BoolVar(&o.nonInteractive, "non-interactive", false, "never prompt (passwords from stdin)")
	fs.StringVar(&o.webauthnRPID, "webauthn-rp-id", "", "host name users open conductor with, to enable security keys (default: the host of --public-url)")
	_ = fs.Parse(args)
	if os.Geteuid() != 0 {
		return errors.New("setup writes /etc/conductor: run it as root")
	}
	in := bufio.NewReader(os.Stdin)
	interactive := !o.nonInteractive && term.IsTerminal(int(os.Stdin.Fd()))
	ask := func(prompt, def string) string {
		if !interactive {
			return def
		}
		if def != "" {
			fmt.Printf("%s [%s]: ", prompt, def)
		} else {
			fmt.Printf("%s: ", prompt)
		}
		line, _ := in.ReadString('\n')
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
		return def
	}
	if _, err := os.Stat(o.configPath); err == nil && !o.force {
		return fmt.Errorf("%s exists; use --force to overwrite", o.configPath)
	}
	svc, err := user.Lookup(o.serviceUser)
	if err != nil {
		return fmt.Errorf("service user %q: %w (create it first, see docs/install.md)", o.serviceUser, err)
	}
	gid, _ := strconv.Atoi(svc.Gid)
	uid, _ := strconv.Atoi(svc.Uid)

	// 1. Domain.
	if o.realm == "" {
		o.realm = detectRealm()
	}
	o.realm = strings.ToUpper(ask("Kerberos realm", o.realm))
	if o.realm == "" {
		return errors.New("realm is required")
	}
	if o.dc == "" {
		o.dc = hostFQDN()
	}
	o.dc = ask("Preferred domain controller", o.dc)

	// 2. CA pin.
	etc := filepath.Dir(o.configPath)
	caPath := filepath.Join(etc, "domain-ca.pem")
	caPEM, err := pinCA(o, interactive, ask)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(etc, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(caPath, caPEM, 0o644); err != nil {
		return err
	}
	fmt.Println("pinned domain CA written to", caPath)

	// 3. Role groups by name → SID, with a one-time sign-in.
	o.adminUser = ask("Domain account to look up groups (used once, not stored)", o.adminUser)
	if o.adminUser == "" {
		return errors.New("--admin-user is required to resolve group names")
	}
	pw, err := readPassword(in, interactive, "Password for "+o.adminUser+": ")
	if err != nil {
		return err
	}
	pool, err := ad.CertPoolFromPEM(caPEM)
	if err != nil {
		return err
	}
	acfg := ad.Config{Realm: o.realm, Preferred: []string{o.dc}, RootCAs: pool}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sess, err := ad.SignIn(ctx, acfg, o.adminUser, pw)
	pw = ""
	if err != nil {
		return fmt.Errorf("signing in as %s: %w", o.adminUser, err)
	}
	defer sess.Close()
	conn, err := ad.Connect(ctx, acfg, ad.KerberosAuth(sess))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	resolve := func(label, name string) ([]string, error) {
		name = ask(label+" group name (empty: none)", name)
		if name == "" {
			return nil, nil
		}
		g, err := conn.FindGroup(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("%s group %q: %w", label, name, err)
		}
		fmt.Printf("  %s group %q = %s\n", label, g.Name, g.SID)
		return []string{g.SID.String()}, nil
	}
	da, err := conn.WellKnownGroupSID(ctx, sid.RIDDomainAdmins)
	if err != nil {
		return err
	}
	fmt.Printf("  administrators default: Domain Admins = %s\n", da)
	var roles config.Roles
	if roles.AdminGroups, err = resolve("Administrators (besides Domain Admins: leave empty)", o.adminGroup); err != nil {
		return err
	}
	if roles.HelpdeskGroups, err = resolve("Helpdesk", o.helpdeskGroup); err != nil {
		return err
	}
	if roles.AuditorGroups, err = resolve("Auditor", o.auditorGroup); err != nil {
		return err
	}

	// 4. TOTP encryption key (systemd credential).
	keyPath := filepath.Join(etc, "credentials", "totp-key")
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return err
		}
		k, err := secret.GenerateKeyHex()
		if err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, []byte(k+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Println("generated the 2FA secret key", keyPath, "(back it up: without it every enrollment is lost)")
	}

	// 5. Configuration file.
	o.mfaPolicy = ask("2FA for regular users (off/optional/required)", o.mfaPolicy)
	cfgText, err := renderConfig(o, caPath, roles)
	if err != nil {
		return err
	}
	// Validate before writing.
	tmp := o.configPath + ".new"
	if err := os.WriteFile(tmp, cfgText, 0o640); err != nil {
		return err
	}
	if _, err := config.Load(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("generated configuration is invalid: %w", err)
	}
	if err := os.Chown(tmp, 0, gid); err != nil {
		return err
	}
	if err := os.Rename(tmp, o.configPath); err != nil {
		return err
	}
	fmt.Println("configuration written to", o.configPath)

	// 6. First administrator's enrollment link, created as the service user
	// so the database stays owned by it.
	o.firstAdmin = ask("Administrator to enroll first (empty: skip)", o.firstAdmin)
	if o.firstAdmin != "" {
		if o.publicURL == "" {
			o.publicURL = "https://" + o.dc + portSuffix(o.listen)
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.Command(self, "enroll-link", "--config", o.configPath, "--user", o.firstAdmin, "--base-url", o.publicURL)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("creating the enrollment link: %w", err)
		}
	}
	fmt.Println("next: systemctl enable --now conductor-helper conductor")
	return nil
}

func portSuffix(listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "443" || port == "" {
		return ""
	}
	return ":" + port
}

var realmRE = regexp.MustCompile(`(?mi)^\s*realm\s*=\s*(\S+)\s*$`)

func detectRealm() string {
	if b, err := os.ReadFile("/etc/samba/smb.conf"); err == nil {
		if m := realmRE.FindSubmatch(b); m != nil {
			return strings.ToUpper(string(m[1]))
		}
	}
	if _, dom, ok := strings.Cut(hostFQDN(), "."); ok {
		return strings.ToUpper(dom)
	}
	return ""
}

func hostFQDN() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	if strings.Contains(h, ".") {
		return h
	}
	if out, err := exec.Command("hostname", "-f").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return h
}

// pinCA returns the PEM of the CA to pin: from --ca-file, or read from the
// DC's LDAPS handshake and confirmed by fingerprint.
func pinCA(o setupOpts, interactive bool, ask func(string, string) string) ([]byte, error) {
	if o.caFile != "" {
		b, err := os.ReadFile(o.caFile)
		if err != nil {
			return nil, err
		}
		if _, err := ad.CertPoolFromPEM(b); err != nil {
			return nil, fmt.Errorf("%s: %w", o.caFile, err)
		}
		return b, nil
	}
	// Trust on first use, with the fingerprint shown or required: the only
	// connection made without verification, and it carries no credential.
	d := &net.Dialer{Timeout: 10 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(o.dc, "636"), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // fingerprint-confirmed pinning
	if err != nil {
		return nil, fmt.Errorf("reading the DC certificate chain: %w (or pass --ca-file)", err)
	}
	chain := c.ConnectionState().PeerCertificates
	_ = c.Close()
	var ca *x509.Certificate
	for _, cert := range chain {
		if cert.IsCA {
			ca = cert
		}
	}
	if ca == nil {
		return nil, errors.New("the DC does not send its CA certificate; pass --ca-file with the CA that signed it")
	}
	sum := sha256.Sum256(ca.Raw)
	fp := hex.EncodeToString(sum[:])
	fmt.Printf("CA presented by %s:\n  subject: %s\n  SHA-256: %s\n", o.dc, ca.Subject, fp)
	switch {
	case o.caFingerprint != "":
		if !strings.EqualFold(strings.ReplaceAll(o.caFingerprint, ":", ""), fp) {
			return nil, errors.New("CA fingerprint does not match --ca-fingerprint")
		}
	case interactive:
		if a := ask("Pin this CA? (yes/no)", "no"); a != "yes" {
			return nil, errors.New("CA not pinned")
		}
	default:
		return nil, errors.New("non-interactive setup needs --ca-file or --ca-fingerprint")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), nil
}

func readPassword(in *bufio.Reader, interactive bool, prompt string) (string, error) {
	if interactive {
		fmt.Print(prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return string(b), err
	}
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("password expected on stdin")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

var configTemplate = template.Must(template.New("cfg").Funcs(template.FuncMap{"q": tomlQuote, "list": tomlList}).Parse(
	`# Samba Conductor configuration, written by "conductor setup" on {{.Now}}.
# Reference: docs/config.md. Unknown keys are rejected.

[server]
listen = {{q .Listen}}
{{- if .BehindProxy}}
behind_proxy = true
trusted_proxies = ["127.0.0.1/32", "::1/128"]
{{- else}}
tls_cert = {{q .TLSCert}}
tls_key = {{q .TLSKey}}
{{- end}}

[domain]
realm = {{q .Realm}}
ca_file = {{q .CAFile}}
preferred = {{list .Preferred}}
simple_bind_fallback = false

[roles]
# Group SIDs. Empty admin_groups = Domain Admins (RID 512) of the domain.
admin_groups = {{list .Roles.AdminGroups}}
helpdesk_groups = {{list .Roles.HelpdeskGroups}}
auditor_groups = {{list .Roles.AuditorGroups}}
cache_seconds = 60

[mfa]
policy = {{q .MFAPolicy}}
delegated_roles_required = true
admin_enrollment_requires_link = true
issuer = "Samba Conductor"

[session]
idle_minutes = 15
absolute_hours = 8

[ratelimit]
per_ip_per_minute = 30
account_failures = 5
account_window_minutes = 15

[state]
database = "/var/lib/conductor/conductor.db"

[helper]
enabled = true
socket = "/run/conductor-helper/helper.sock"

[ui]
default_language = "en"

[webauthn]
# Security keys and platform authenticators as a second factor: rp_id is
# the host name users open conductor with (empty = off).
rp_id = {{q .RPID}}
admin_required = false

[bulk]
max_rows = 1000

[tools]
samba_tool = "/usr/bin/samba-tool"
`))

func renderConfig(o setupOpts, caPath string, roles config.Roles) ([]byte, error) {
	listen := o.listen
	if o.behindProxy && listen == ":8443" {
		listen = "127.0.0.1:8080"
	}
	rpID := o.webauthnRPID
	if rpID == "" && o.publicURL != "" {
		if u, err := url.Parse(o.publicURL); err == nil {
			rpID = u.Hostname()
		}
	}
	var sb strings.Builder
	err := configTemplate.Execute(&sb, map[string]any{"Now": time.Now().UTC().Format(time.RFC3339), "Listen": listen, "RPID": rpID,
		"BehindProxy": o.behindProxy, "TLSCert": o.tlsCert, "TLSKey": o.tlsKey, "Realm": o.realm, "CAFile": caPath,
		"Preferred": []string{o.dc}, "Roles": roles, "MFAPolicy": o.mfaPolicy})
	return []byte(sb.String()), err
}

// tomlQuote renders a TOML basic string; control characters are refused
// by the validation that follows (they cannot appear in these values).
func tomlQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func tomlList(v []string) string {
	parts := make([]string, len(v))
	for i, s := range v {
		parts[i] = tomlQuote(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// ---- enroll-link ----

func cmdEnrollLink(args []string) error {
	fs := flag.NewFlagSet("enroll-link", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "configuration file")
	username := fs.String("user", "", "administrator's username (sAMAccountName)")
	baseURL := fs.String("base-url", "", "https URL users open, e.g. https://dc1.example.com:8443")
	_ = fs.Parse(args)
	if *username == "" || strings.ContainsAny(*username, "@\\/ ") {
		return errors.New("--user USERNAME (sAMAccountName) is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := checkDBOwner(filepath.Dir(cfg.State.Database)); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.State.Database)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	tok, hash := web.NewEnrollLinkToken()
	if err := st.CreateEnrollLink(ctx, hash, *username, "cli", 24*time.Hour); err != nil {
		return err
	}
	if _, err := st.AppendAudit(ctx, store.AuditEvent{ActorName: "cli:" + currentUser(), Action: "mfa.enroll_link",
		Target: strings.ToLower(*username), Detail: "one-time 2FA enrollment link issued from the command line, valid 24 hours",
		Result: store.ResultOK}); err != nil {
		return err
	}
	base := strings.TrimRight(*baseURL, "/")
	if base == "" {
		base = "https://" + hostFQDN() + portSuffix(cfg.Server.Listen)
	}
	fmt.Printf("One-time 2FA enrollment link for %s (valid 24 hours; give it over a trusted channel):\n%s/signin?enroll=%s\n",
		*username, base, tok)
	return nil
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return strconv.Itoa(os.Getuid())
}
