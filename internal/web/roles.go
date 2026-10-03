package web

import (
	"slices"

	"github.com/samba-conductor/ad/sid"
)

// Perm is what a route requires.
type Perm string

// Permissions. Roles map to sets of them (rolePerms); PermPublic and
// PermPreAuth are special and handled by the guard.
const (
	// PermPublic: no session needed (sign-in page, static assets).
	PermPublic Perm = "public"
	// PermPreAuth: a session in one of the route's sign-in stages.
	PermPreAuth Perm = "preauth"
	// PermSelf: any fully signed-in user (self-service).
	PermSelf Perm = "self"

	PermDashboard     Perm = "dashboard"
	PermUsersRead     Perm = "users.read"
	PermUsersHelpdesk Perm = "users.helpdesk" // reset password, unlock, enable/disable
	PermUsersWrite    Perm = "users.write"    // create, edit, move, delete, membership
	PermDirRead       Perm = "dir.read"       // groups, OUs, computers
	PermDirWrite      Perm = "dir.write"
	PermAuditRead     Perm = "audit.read"
	PermDomainRead    Perm = "domain.read" // helper: functional levels, FSMO, DCs
	PermMFAManage     Perm = "mfa.manage"  // reset another user's 2FA, issue enrollment links

	PermDNSRead     Perm = "dns.read"     // DNS zones and records
	PermDNSWrite    Perm = "dns.write"    // create/change/delete zones and records
	PermGPORead     Perm = "gpo.read"     // GPOs and their links
	PermGPOWrite    Perm = "gpo.write"    // create/delete GPOs, links, inheritance
	PermPolicyRead  Perm = "policy.read"  // domain password policy, PSOs, effective policy
	PermPolicyWrite Perm = "policy.write" // change them
	PermHealthRead  Perm = "health.read"  // lockouts across DCs, account health, CSV export
	PermBulk        Perm = "bulk"         // CSV import (create/update users)

	PermBackupRead  Perm = "backup.read"  // backups page (status, policy, drills)
	PermBackupWrite Perm = "backup.write" // back up now, run drill now, policy edits

	PermSyncRead  Perm = "sync.read"  // Google Workspace sync: status, plans, runs, settings
	PermSyncWrite Perm = "sync.write" // settings, key, plans, applies (administrators only)

	PermFilesRead  Perm = "files.read"  // file servers: status, shares, permissions, sessions
	PermFilesWrite Perm = "files.write" // enroll/remove servers, create/edit/remove shares
)

// allPerms lists every privileged permission (navigation, tests).
var allPerms = []Perm{PermDashboard, PermUsersRead, PermUsersHelpdesk, PermUsersWrite, PermDirRead, PermDirWrite,
	PermAuditRead, PermDomainRead, PermMFAManage, PermDNSRead, PermDNSWrite, PermGPORead, PermGPOWrite,
	PermPolicyRead, PermPolicyWrite, PermHealthRead, PermBulk, PermBackupRead, PermBackupWrite, PermSyncRead, PermSyncWrite, PermFilesRead, PermFilesWrite}

// privileged reports whether p is beyond self-service.
func (p Perm) privileged() bool {
	return p != PermPublic && p != PermPreAuth && p != PermSelf
}

// Roles of a signed-in user, from AD group SIDs.
type Roles struct {
	Admin    bool
	Helpdesk bool
	Auditor  bool
}

var rolePerms = map[string][]Perm{
	"admin":    allPerms,
	"helpdesk": {PermUsersRead, PermUsersHelpdesk, PermHealthRead},
	"auditor": {PermDashboard, PermUsersRead, PermDirRead, PermAuditRead, PermDomainRead, PermDNSRead, PermGPORead,
		PermPolicyRead, PermHealthRead, PermBackupRead, PermFilesRead},
}

// Has reports whether the roles grant p.
func (r Roles) Has(p Perm) bool {
	switch p {
	case PermPublic, PermPreAuth, PermSelf:
		return true
	}
	for role, on := range map[string]bool{"admin": r.Admin, "helpdesk": r.Helpdesk, "auditor": r.Auditor} {
		if on && slices.Contains(rolePerms[role], p) {
			return true
		}
	}
	return false
}

// Privileged reports any role beyond self-service.
func (r Roles) Privileged() bool { return r.Admin || r.Helpdesk || r.Auditor }

// Names lists the roles for display and audit.
func (r Roles) Names() []string {
	var out []string
	if r.Admin {
		out = append(out, "admin")
	}
	if r.Helpdesk {
		out = append(out, "helpdesk")
	}
	if r.Auditor {
		out = append(out, "auditor")
	}
	return out
}

// roleSIDs is the resolved role configuration.
type roleSIDs struct {
	admin    []sid.SID // empty: Domain Admins of the user's domain
	helpdesk []sid.SID
	auditor  []sid.SID
}

// Well-known RIDs and SIDs of groups whose members are domain-privileged.
// Accounts in them are "protected": helpdesk may not touch them and admin
// writes to them require re-authentication.
var (
	privilegedDomainRIDs = []uint32{512, 516, 518, 519, 520} // Domain Admins, DCs, Schema/Enterprise Admins, GP Creator Owners
	privilegedBuiltin    = []sid.SID{
		sid.MustParse("S-1-5-32-544"), // Administrators
		sid.MustParse("S-1-5-32-548"), // Account Operators
		sid.MustParse("S-1-5-32-549"), // Server Operators
		sid.MustParse("S-1-5-32-550"), // Print Operators
		sid.MustParse("S-1-5-32-551"), // Backup Operators
	}
)

// adminSIDs returns the admin group SIDs for a user of domain dom.
func (rs roleSIDs) adminSIDs(dom sid.SID) []sid.SID {
	if len(rs.admin) > 0 {
		return rs.admin
	}
	if da, err := dom.WithRID(512); err == nil {
		return []sid.SID{da}
	}
	return nil
}

// resolve maps a user's group SIDs to roles.
func (rs roleSIDs) resolve(userSID sid.SID, groups []sid.SID) Roles {
	dom, _ := userSID.Domain()
	hasAny := func(want []sid.SID) bool {
		for _, w := range want {
			if sid.Contains(groups, w) {
				return true
			}
		}
		return false
	}
	return Roles{Admin: hasAny(rs.adminSIDs(dom)), Helpdesk: hasAny(rs.helpdesk), Auditor: hasAny(rs.auditor)}
}

// protectedSIDs are the groups that make an account or a group sensitive:
// the configured admin groups plus the well-known privileged groups.
func (rs roleSIDs) protectedSIDs(dom sid.SID) []sid.SID {
	out := append([]sid.SID(nil), rs.adminSIDs(dom)...)
	for _, rid := range privilegedDomainRIDs {
		if s, err := dom.WithRID(rid); err == nil {
			out = append(out, s)
		}
	}
	return append(out, privilegedBuiltin...)
}

// isProtectedGroup reports whether a group SID is sensitive.
func (rs roleSIDs) isProtectedGroup(g sid.SID) bool {
	dom, ok := g.Domain()
	if !ok {
		return sid.Contains(privilegedBuiltin, g)
	}
	return sid.Contains(rs.protectedSIDs(dom), g)
}

// isProtectedMember reports whether an account with these group SIDs is
// sensitive.
func (rs roleSIDs) isProtectedMember(account sid.SID, groups []sid.SID) bool {
	dom, ok := account.Domain()
	if !ok {
		return true // unknown shape: be conservative
	}
	for _, p := range rs.protectedSIDs(dom) {
		if sid.Contains(groups, p) {
			return true
		}
	}
	return false
}
