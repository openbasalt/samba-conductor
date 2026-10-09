// Package config loads and validates /etc/conductor/conductor.toml.
//
// Unknown keys are an error (a typo must not silently fall back to a
// default), and every value that weakens security has to be spelled out.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-idp/branding"
)

// DefaultPath is where conductor looks for its configuration.
const DefaultPath = "/etc/conductor/conductor.toml"

// MFA policies for users without a privileged role.
const (
	MFAOff      = "off"
	MFAOptional = "optional"
	MFARequired = "required"
)

// Config is the whole file.
type Config struct {
	Server    Server    `toml:"server"`
	Domain    Domain    `toml:"domain"`
	Roles     Roles     `toml:"roles"`
	MFA       MFA       `toml:"mfa"`
	Session   Session   `toml:"session"`
	RateLimit RateLimit `toml:"ratelimit"`
	State     State     `toml:"state"`
	Helper    Helper    `toml:"helper"`
	UI        UI        `toml:"ui"`
	WebAuthn  WebAuthn  `toml:"webauthn"`
	Bulk      Bulk      `toml:"bulk"`
	Tools     Tools     `toml:"tools"`
	Sync      Sync      `toml:"sync"`
	Files     Files     `toml:"files"`
	IDP       IDP       `toml:"idp"`
	Branding  Branding  `toml:"branding"`
	Mail      Mail      `toml:"mail"`
}

// Mail security modes of the SMTP connection.
const (
	MailSTARTTLS = "starttls"
	MailTLS      = "tls"
	MailNone     = "none"
)

// Mail is the SMTP relay conductor sends its messages through (test
// messages now; invitations, password reset links and notifications use
// the same queue). Off while host is empty.
type Mail struct {
	// Host of the relay; empty turns mail off.
	Host string `toml:"host"`
	Port int    `toml:"port"`
	// Security: starttls (required, never downgraded), tls (implicit TLS)
	// or none (plain SMTP, only to a loopback relay).
	Security string `toml:"security"`
	// Username for SMTP AUTH PLAIN; empty: no authentication.
	Username string `toml:"username"`
	// PasswordFile holds the password when it does not come as the
	// systemd credential "smtp-password".
	PasswordFile string `toml:"password_file"`
	// From is the sender ("Name <address>" or an address).
	From    string `toml:"from"`
	ReplyTo string `toml:"reply_to"`
	// HelloName is the EHLO name; default the host name.
	HelloName string `toml:"hello_name"`
	// CAFile is an extra CA (PEM) for the relay's certificate, added to
	// the system roots.
	CAFile string `toml:"ca_file"`
	// MaxPerHour is the global ceiling of messages handed to the relay
	// per hour; above it messages wait in the queue.
	MaxPerHour int `toml:"max_per_hour"`
}

// Enabled reports whether a relay is configured.
func (m Mail) Enabled() bool { return m.Host != "" }

// Branding configures the level 2 branding of the self-service pages:
// template overrides read from a directory. The level 1 branding (logo,
// colors, texts) is edited in the admin UI (Settings > Branding) and kept
// in the database.
type Branding struct {
	// TemplatesDir holds overrides of the self-service partials
	// (header.html, footer.html, self-home.html) and an optional
	// custom.css; empty: none. Suggested: /etc/conductor/templates.
	TemplatesDir string `toml:"templates_dir"`
	// AllowedOrigins may serve images and fonts to the branded pages
	// ("https://host[:port]"), added to the CSP's img-src and font-src
	// there only. Empty: this origin only.
	AllowedOrigins []string `toml:"allowed_origins"`
}

// AllowedOrigins returns the normalized branding.allowed_origins.
func (c *Config) AllowedOrigins() []string {
	o, _ := branding.ParseOrigins(c.Branding.AllowedOrigins)
	return o
}

// IDP connects conductor with conductor-idp. Two independent parts, both
// off by default:
//
//   - Enabled: the "Single sign-on" section of the admin UI, which drives
//     conductor-idp's management API (idpapi) over a local Unix socket.
//   - MFASocket: conductor serves its 2FA store to conductor-idp (one
//     enrollment and one policy for both, security keys included), on a
//     Unix socket only conductor-idp's user may use (SO_PEERCRED).
type IDP struct {
	Enabled bool   `toml:"enabled"`
	Socket  string `toml:"socket"`
	// MFASocket enables the 2FA socket.
	MFASocket bool `toml:"mfa_socket"`
	// MFASocketPath is used when systemd passes no socket
	// (conductor-mfa.socket does, with FileDescriptorName=mfa).
	MFASocketPath string `toml:"mfa_socket_path"`
	// MFASocketGroup owns a socket conductor creates itself (the
	// conductor-idp group; conductor's user must be a member).
	MFASocketGroup string `toml:"mfa_socket_group"`
	// MFAAllowedUsers and MFAAllowedUIDs may use the 2FA socket; default
	// the conductor-idp user.
	MFAAllowedUsers []string `toml:"mfa_allowed_users"`
	MFAAllowedUIDs  []int    `toml:"mfa_allowed_uids"`
}

// MFAAllowedUserNames returns the users admitted to the 2FA socket by name.
func (c *Config) MFAAllowedUserNames() []string {
	if len(c.IDP.MFAAllowedUsers) == 0 && len(c.IDP.MFAAllowedUIDs) == 0 {
		return []string{"conductor-idp"}
	}
	return c.IDP.MFAAllowedUsers
}

// Files is the File servers section of the admin UI: conductor drives the
// conductor-files agents on domain-member file servers over TLS, both keys
// pinned (each server is enrolled from the UI with a one-time code). Off by
// default.
type Files struct {
	Enabled bool `toml:"enabled"`
	// KeyDir holds conductor's client key pair, generated on first start
	// (mode 0700; inside conductor's state directory by default).
	KeyDir string `toml:"key_dir"`
	// Name labels conductor's key on the agents (default: the host name).
	Name string `toml:"name"`
}

// Sync is the Google Workspace sync section of the admin UI: conductor
// talks to `conductor-sync serve` (its management API) over a local Unix
// socket. Off by default; conductor-sync may also run without it.
type Sync struct {
	Enabled bool   `toml:"enabled"`
	Socket  string `toml:"socket"`
}

// WebAuthn configures security keys and platform authenticators as a
// second factor. Off while rp_id is empty.
type WebAuthn struct {
	// RPID is the host name users open conductor with (the WebAuthn
	// relying party ID), e.g. "conductor.example.com".
	RPID string `toml:"rp_id"`
	// Origins allowed in ceremonies ("https://host[:port]"); default
	// https://<rp_id> plus the listen port when it is not 443.
	Origins []string `toml:"origins"`
	// DisplayName shown by the browser during registration.
	DisplayName string `toml:"display_name"`
	// AdminRequired makes a security key mandatory for administrators:
	// TOTP codes are no longer accepted for them (recovery codes are).
	AdminRequired bool `toml:"admin_required"`
	// RelatedOrigins are extra origins outside rp_id that may use the same
	// keys (WebAuthn related origins: conductor serves them at
	// /.well-known/webauthn, which browsers fetch from https://<rp_id>, so
	// conductor must answer on the rp_id host). Origins below rp_id (the
	// IdP on idp.example.com with rp_id example.com) need no listing here,
	// only in origins.
	RelatedOrigins []string `toml:"related_origins"`
}

// Enabled reports whether WebAuthn is configured.
func (w WebAuthn) Enabled() bool { return w.RPID != "" }

// Bulk bounds bulk operations (CSV import, actions on selected items).
type Bulk struct {
	// MaxRows per batch.
	MaxRows int `toml:"max_rows"`
}

// Tools are external programs conductor runs with the user's own
// Kerberos ticket (GPO creation and deletion need SYSVOL as well as LDAP).
type Tools struct {
	// SambaTool is the samba-tool binary (absolute path).
	SambaTool string `toml:"samba_tool"`
}

// Server is the HTTP listener.
type Server struct {
	// Listen address, e.g. ":8443" or "127.0.0.1:8080" (behind a proxy).
	Listen string `toml:"listen"`
	// TLSCert and TLSKey enable the built-in TLS listener.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
	// BehindProxy serves plain HTTP for a TLS-terminating reverse proxy on
	// the same host; only allowed on a loopback address.
	BehindProxy bool `toml:"behind_proxy"`
	// TrustedProxies whose X-Forwarded-For is believed (CIDRs). Required
	// with BehindProxy, refused without it.
	TrustedProxies []string `toml:"trusted_proxies"`
	// PublicURL is the https URL users open (https://host[:port]); links
	// conductor hands out, such as 2FA enrollment links, are built from it
	// and never from a request's Host header.
	PublicURL string `toml:"public_url"`
}

// Domain is how the AD domain is reached.
type Domain struct {
	Realm string `toml:"realm"`
	// CAFile pins the CA that signs the DCs' LDAPS certificates.
	CAFile string `toml:"ca_file"`
	// DCs replaces DNS SRV discovery when set.
	DCs []string `toml:"dcs"`
	// Preferred DCs are tried first (normally the local DC).
	Preferred []string `toml:"preferred"`
	// DNSServers used for SRV discovery instead of the system resolver.
	DNSServers []string `toml:"dns_servers"`
	// SimpleBindFallback allows LDAP simple bind over TLS when Kerberos is
	// unreachable. The password is then kept encrypted in memory for the
	// session. Off by default.
	SimpleBindFallback bool `toml:"simple_bind_fallback"`
}

// Roles map AD groups (by SID) to conductor roles.
type Roles struct {
	// AdminGroups: empty means the domain's Domain Admins (RID 512).
	AdminGroups    []string `toml:"admin_groups"`
	HelpdeskGroups []string `toml:"helpdesk_groups"`
	AuditorGroups  []string `toml:"auditor_groups"`
	// CacheSeconds bounds how long a role check is reused (at most 60).
	CacheSeconds int `toml:"cache_seconds"`
}

// MFA is the second-factor policy.
type MFA struct {
	// Policy for users without a privileged role: off, optional, required.
	// Administrators always need 2FA.
	Policy string `toml:"policy"`
	// DelegatedRolesRequired makes 2FA mandatory for helpdesk and auditor
	// too (default true).
	DelegatedRolesRequired *bool `toml:"delegated_roles_required"`
	// AdminEnrollmentRequiresLink: an administrator without 2FA may enroll
	// only through a one-time link issued by `conductor enroll-link` or by
	// another administrator (default true), so a stolen admin password is
	// not enough to register the thief's authenticator.
	AdminEnrollmentRequiresLink *bool `toml:"admin_enrollment_requires_link"`
	// Issuer shown in authenticator apps.
	Issuer string `toml:"issuer"`
	// KeyFile holds the 32-byte key that encrypts TOTP secrets. Empty:
	// $CREDENTIALS_DIRECTORY/totp-key (systemd LoadCredential).
	KeyFile string `toml:"key_file"`
}

// Session timeouts.
type Session struct {
	IdleMinutes   int `toml:"idle_minutes"`
	AbsoluteHours int `toml:"absolute_hours"`
}

// RateLimit for sign-in, 2FA and password pages.
type RateLimit struct {
	// PerIPPerMinute attempts from one address (all outcomes).
	PerIPPerMinute int `toml:"per_ip_per_minute"`
	// AccountFailures failed attempts per account within AccountWindowMinutes
	// before further attempts are refused (keeps AD lockouts from being
	// triggered through conductor).
	AccountFailures      int `toml:"account_failures"`
	AccountWindowMinutes int `toml:"account_window_minutes"`
}

// State is the local database.
type State struct {
	Database string `toml:"database"`
}

// Helper is the privileged local helper.
type Helper struct {
	Enabled bool   `toml:"enabled"`
	Socket  string `toml:"socket"`
}

// UI preferences.
type UI struct {
	// DefaultLanguage: "en" or "pt-BR".
	DefaultLanguage string `toml:"default_language"`
}

// Load reads and validates a configuration file.
func Load(path string) (*Config, error) {
	c := Default()
	md, err := toml.DecodeFile(path, c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Default returns the defaults every file starts from.
func Default() *Config {
	return &Config{
		Server:    Server{Listen: ":8443"},
		Roles:     Roles{CacheSeconds: 60},
		MFA:       MFA{Policy: MFAOptional, Issuer: "Samba Conductor"},
		Session:   Session{IdleMinutes: 15, AbsoluteHours: 8},
		RateLimit: RateLimit{PerIPPerMinute: 30, AccountFailures: 5, AccountWindowMinutes: 15},
		State:     State{Database: "/var/lib/conductor/conductor.db"},
		Helper:    Helper{Enabled: true, Socket: "/run/conductor-helper/helper.sock"},
		UI:        UI{DefaultLanguage: "en"},
		WebAuthn:  WebAuthn{DisplayName: "Samba Conductor"},
		Bulk:      Bulk{MaxRows: 1000},
		Tools:     Tools{SambaTool: "/usr/bin/samba-tool"},
		Sync:      Sync{Socket: "/run/conductor-sync/api.sock"},
		Files:     Files{KeyDir: "/var/lib/conductor/files"},
		IDP:       IDP{Socket: "/run/conductor-idp/api.sock", MFASocketPath: "/run/conductor/mfa.sock"},
		Mail:      Mail{Port: 587, Security: MailSTARTTLS, MaxPerHour: 200},
	}
}

// Validate checks the values and the security rules.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("config: "+format, a...)) }

	host, _, err := net.SplitHostPort(c.Server.Listen)
	if err != nil {
		bad("server.listen %q: %v", c.Server.Listen, err)
	}
	tlsOn := c.Server.TLSCert != "" || c.Server.TLSKey != ""
	switch {
	case tlsOn && (c.Server.TLSCert == "" || c.Server.TLSKey == ""):
		bad("server.tls_cert and server.tls_key go together")
	case tlsOn && c.Server.BehindProxy:
		bad("server.behind_proxy and built-in TLS are exclusive")
	case !tlsOn && !c.Server.BehindProxy:
		bad("TLS is required: set server.tls_cert/tls_key, or server.behind_proxy with a loopback listen address")
	case !tlsOn && !isLoopback(host):
		// Never plain HTTP on a public address.
		bad("server.behind_proxy requires a loopback listen address (got %q)", c.Server.Listen)
	}
	for _, p := range c.Server.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			bad("server.trusted_proxies %q: %v", p, err)
		}
	}
	if len(c.Server.TrustedProxies) > 0 && !c.Server.BehindProxy {
		bad("server.trusted_proxies only makes sense with server.behind_proxy")
	}
	if c.Server.BehindProxy && len(c.Server.TrustedProxies) == 0 {
		// Without it every request seems to come from the proxy: one rate
		// limit bucket for all clients and the proxy's address in the audit.
		bad(`server.trusted_proxies is required with server.behind_proxy (the proxy's addresses, e.g. ["127.0.0.1/32", "::1/128"])`)
	}
	if c.Server.PublicURL != "" {
		if u, err := url.Parse(c.Server.PublicURL); err != nil || u.Scheme != "https" || u.Host == "" ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			bad("server.public_url must be https://host[:port] without a path (got %q)", c.Server.PublicURL)
		}
	}

	if c.Domain.Realm == "" || strings.ContainsAny(c.Domain.Realm, " /\\") {
		bad("domain.realm is required")
	}
	if c.Domain.CAFile == "" || !filepath.IsAbs(c.Domain.CAFile) {
		bad("domain.ca_file must be an absolute path (the pinned domain CA)")
	}
	for _, s := range c.Domain.DNSServers {
		if _, err := netip.ParseAddr(s); err != nil {
			bad("domain.dns_servers %q is not an IP address", s)
		}
	}

	for name, list := range map[string][]string{"admin_groups": c.Roles.AdminGroups,
		"helpdesk_groups": c.Roles.HelpdeskGroups, "auditor_groups": c.Roles.AuditorGroups} {
		for _, s := range list {
			if _, err := sid.Parse(s); err != nil {
				bad("roles.%s: %q is not a SID (use `conductor setup` to resolve group names)", name, s)
			}
		}
	}
	if c.Roles.CacheSeconds < 0 || c.Roles.CacheSeconds > 60 {
		bad("roles.cache_seconds must be 0-60")
	}

	if !slices.Contains([]string{MFAOff, MFAOptional, MFARequired}, c.MFA.Policy) {
		bad("mfa.policy must be off, optional or required")
	}
	if c.MFA.KeyFile != "" && !filepath.IsAbs(c.MFA.KeyFile) {
		bad("mfa.key_file must be absolute")
	}
	if c.MFA.Issuer == "" || len(c.MFA.Issuer) > 64 || strings.ContainsAny(c.MFA.Issuer, ":") {
		bad("mfa.issuer must be 1-64 characters without ':'")
	}

	if c.Session.IdleMinutes < 1 || c.Session.IdleMinutes > 60 {
		bad("session.idle_minutes must be 1-60")
	}
	if c.Session.AbsoluteHours < 1 || c.Session.AbsoluteHours > 24 {
		bad("session.absolute_hours must be 1-24")
	}
	if c.RateLimit.PerIPPerMinute < 1 || c.RateLimit.AccountFailures < 1 || c.RateLimit.AccountWindowMinutes < 1 {
		bad("ratelimit values must be positive")
	}
	if !filepath.IsAbs(c.State.Database) {
		bad("state.database must be absolute")
	}
	if c.Helper.Enabled && !filepath.IsAbs(c.Helper.Socket) {
		bad("helper.socket must be absolute")
	}
	if c.UI.DefaultLanguage != "en" && c.UI.DefaultLanguage != "pt-BR" {
		bad("ui.default_language must be en or pt-BR")
	}
	if w := c.WebAuthn; w.Enabled() {
		if strings.ContainsAny(w.RPID, ":/ ") || !strings.Contains(w.RPID, ".") && w.RPID != "localhost" {
			bad("webauthn.rp_id must be a host name (no scheme or port)")
		}
		for _, o := range c.WebAuthnOrigins() {
			u, err := url.Parse(o)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || !hostWithin(u.Hostname(), w.RPID) {
				bad("webauthn.origins %q must be https://host[:port] with host = rp_id or below it", o)
			}
		}
		for _, o := range w.RelatedOrigins {
			u, err := url.Parse(o)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" {
				bad("webauthn.related_origins %q must be https://host[:port]", o)
			}
		}
		if w.DisplayName == "" || len(w.DisplayName) > 64 {
			bad("webauthn.display_name must be 1-64 characters")
		}
	} else if c.WebAuthn.AdminRequired {
		bad("webauthn.admin_required needs webauthn.rp_id")
	} else if len(c.WebAuthn.Origins) > 0 || len(c.WebAuthn.RelatedOrigins) > 0 {
		bad("webauthn.origins and related_origins need webauthn.rp_id")
	}
	if c.IDP.Enabled && !filepath.IsAbs(c.IDP.Socket) {
		bad("idp.socket must be absolute")
	}
	if c.IDP.MFASocket {
		if !filepath.IsAbs(c.IDP.MFASocketPath) {
			bad("idp.mfa_socket_path must be absolute")
		}
		for _, u := range c.IDP.MFAAllowedUIDs {
			if u <= 0 {
				bad("idp.mfa_allowed_uids: root and negative UIDs are not allowed")
			}
		}
		for _, u := range c.IDP.MFAAllowedUsers {
			if u == "" || u == "root" || u == "conductor" || strings.ContainsAny(u, " :/") {
				bad("idp.mfa_allowed_users: %q is not allowed", u)
			}
		}
	}
	if c.Branding.TemplatesDir != "" && !filepath.IsAbs(c.Branding.TemplatesDir) {
		bad("branding.templates_dir must be an absolute path")
	}
	if _, err := branding.ParseOrigins(c.Branding.AllowedOrigins); err != nil {
		bad("branding.allowed_origins: %v", err)
	}
	if c.Bulk.MaxRows < 1 || c.Bulk.MaxRows > 100000 {
		bad("bulk.max_rows must be 1-100000")
	}
	if !filepath.IsAbs(c.Tools.SambaTool) {
		bad("tools.samba_tool must be an absolute path")
	}
	if c.Sync.Enabled && !filepath.IsAbs(c.Sync.Socket) {
		bad("sync.socket must be absolute")
	}
	if c.Files.Enabled && !filepath.IsAbs(c.Files.KeyDir) {
		bad("files.key_dir must be absolute")
	}
	if len(c.Files.Name) > 253 || strings.ContainsAny(c.Files.Name, " \t\r\n%\\\"") {
		bad("files.name must be a host name")
	}
	errs = append(errs, c.Mail.validate()...)
	return errors.Join(errs...)
}

// validate checks [mail]; nothing is checked while mail is off.
func (m Mail) validate() []error {
	if !m.Enabled() {
		return nil
	}
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("config: "+format, a...)) }
	if strings.ContainsAny(m.Host, " /:\\\r\n\t@") && !isIPv6(m.Host) {
		bad("mail.host %q must be a host name or an IP address", m.Host)
	}
	if m.Port < 1 || m.Port > 65535 {
		bad("mail.port must be 1-65535")
	}
	switch m.Security {
	case MailSTARTTLS, MailTLS:
	case MailNone:
		if !isLoopback(m.Host) {
			// Never credentials or reset links in clear text over a network.
			bad("mail.security = \"none\" is only allowed with a loopback mail.host (got %q)", m.Host)
		}
	default:
		bad("mail.security must be starttls, tls or none")
	}
	if hasControl(m.Username) || len(m.Username) > 256 {
		bad("mail.username must be at most 256 characters without control characters")
	}
	if m.PasswordFile != "" && !filepath.IsAbs(m.PasswordFile) {
		bad("mail.password_file must be an absolute path")
	}
	if m.PasswordFile != "" && m.Username == "" {
		bad("mail.password_file needs mail.username")
	}
	if a, err := mail.ParseAddress(m.From); err != nil || hasControl(m.From) || !strings.Contains(a.Address, "@") {
		bad("mail.from %q must be an e-mail address, optionally with a name (\"Name <address>\")", m.From)
	}
	if m.ReplyTo != "" {
		if _, err := mail.ParseAddress(m.ReplyTo); err != nil || hasControl(m.ReplyTo) {
			bad("mail.reply_to %q must be an e-mail address", m.ReplyTo)
		}
	}
	if m.HelloName != "" && (len(m.HelloName) > 253 || strings.ContainsAny(m.HelloName, " \t\r\n/\\@<>")) {
		bad("mail.hello_name must be a host name")
	}
	if m.CAFile != "" && !filepath.IsAbs(m.CAFile) {
		bad("mail.ca_file must be an absolute path")
	}
	if m.MaxPerHour < 1 || m.MaxPerHour > 100000 {
		bad("mail.max_per_hour must be 1-100000")
	}
	return errs
}

func isIPv6(host string) bool {
	a, err := netip.ParseAddr(host)
	return err == nil && a.Is6()
}

// hasControl reports control characters (header injection, log forging).
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// MailPasswordPath resolves where the SMTP password comes from:
// mail.password_file, else the systemd credential smtp-password when
// present. Empty with a nil error: no password (no username either).
func (c *Config) MailPasswordPath() (string, error) {
	m := c.Mail
	if m.Username == "" {
		return "", nil
	}
	if m.PasswordFile != "" {
		return m.PasswordFile, nil
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		p := filepath.Join(dir, "smtp-password")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("config: mail.username is set but there is no password: add the systemd credential smtp-password or set mail.password_file")
}

// hostWithin reports whether host is rpID or a subdomain of it.
func hostWithin(host, rpID string) bool {
	h, r := strings.ToLower(host), strings.ToLower(rpID)
	return h == r || strings.HasSuffix(h, "."+r)
}

// WebAuthnAllOrigins are every origin a ceremony may come from: the
// origins (under rp_id) and the related origins.
func (c *Config) WebAuthnAllOrigins() []string {
	return append(slices.Clone(c.WebAuthnOrigins()), c.WebAuthn.RelatedOrigins...)
}

// PublicBaseURL is the base of the links conductor hands out: server.public_url,
// else the first WebAuthn origin, else "" (no link can be built).
func (c *Config) PublicBaseURL() string {
	if c.Server.PublicURL != "" {
		return strings.TrimRight(c.Server.PublicURL, "/")
	}
	if o := c.WebAuthnOrigins(); len(o) > 0 {
		return strings.TrimRight(o[0], "/")
	}
	return ""
}

// WebAuthnOrigins returns the configured origins, or the default derived
// from rp_id and the listen port.
func (c *Config) WebAuthnOrigins() []string {
	if len(c.WebAuthn.Origins) > 0 {
		return c.WebAuthn.Origins
	}
	if c.WebAuthn.RPID == "" {
		return nil
	}
	o := "https://" + c.WebAuthn.RPID
	if _, port, err := net.SplitHostPort(c.Server.Listen); err == nil && port != "443" && port != "" && !c.Server.BehindProxy {
		o += ":" + port
	}
	return []string{o}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// TLS reports whether the built-in TLS listener is used.
func (c *Config) TLS() bool { return c.Server.TLSCert != "" }

// IdleTimeout and AbsoluteTimeout of sessions.
func (c *Config) IdleTimeout() time.Duration {
	return time.Duration(c.Session.IdleMinutes) * time.Minute
}

// AbsoluteTimeout of sessions.
func (c *Config) AbsoluteTimeout() time.Duration {
	return time.Duration(c.Session.AbsoluteHours) * time.Hour
}

// RoleCacheTTL is how long a role check is reused.
func (c *Config) RoleCacheTTL() time.Duration {
	return time.Duration(c.Roles.CacheSeconds) * time.Second
}

// DelegatedMFARequired reports whether helpdesk/auditor need 2FA.
func (c *Config) DelegatedMFARequired() bool {
	return c.MFA.DelegatedRolesRequired == nil || *c.MFA.DelegatedRolesRequired
}

// AdminEnrollmentLinkRequired reports whether admins enroll only by link.
func (c *Config) AdminEnrollmentLinkRequired() bool {
	return c.MFA.AdminEnrollmentRequiresLink == nil || *c.MFA.AdminEnrollmentRequiresLink
}

// MFAKeyPath resolves the TOTP encryption key file.
func (c *Config) MFAKeyPath() (string, error) {
	if c.MFA.KeyFile != "" {
		return c.MFA.KeyFile, nil
	}
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", errors.New("config: no mfa.key_file and no systemd credentials directory (LoadCredential=totp-key:...)")
	}
	return filepath.Join(dir, "totp-key"), nil
}
