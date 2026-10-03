package web

// routeTable lists every page. A handler is reachable only through this
// table, which the guard enforces; TestRouteGuards walks it.
func (s *Server) routeTable() []route {
	allStages := []stage{stageMustChange, stageMFA, stageEnroll, stageFull}
	return []route{
		// Sign-in (anonymous).
		{method: "GET", pattern: "/signin", perm: PermPublic, h: s.handleSigninPage},
		{method: "POST", pattern: "/signin", perm: PermPublic, h: s.handleSignin},
		// Sign-in steps (a session in a specific stage).
		{method: "GET", pattern: "/signin/password", perm: PermPreAuth, stages: []stage{stageMustChange}, h: s.handleExpiredPasswordPage},
		{method: "POST", pattern: "/signin/password", perm: PermPreAuth, stages: []stage{stageMustChange}, h: s.handleExpiredPassword},
		// The second-factor pages are the only ones allowed the WebAuthn
		// script (script: true).
		{method: "GET", pattern: "/signin/2fa", perm: PermPreAuth, stages: []stage{stageMFA}, h: s.handleMFAPage, script: true},
		{method: "POST", pattern: "/signin/2fa", perm: PermPreAuth, stages: []stage{stageMFA}, h: s.handleMFA},
		{method: "POST", pattern: "/signin/2fa/key", perm: PermPreAuth, stages: []stage{stageMFA}, h: s.handleMFAKey},
		{method: "GET", pattern: "/signin/enroll", perm: PermPreAuth, stages: []stage{stageEnroll}, h: s.handleEnrollPage, script: true},
		{method: "POST", pattern: "/signin/enroll", perm: PermPreAuth, stages: []stage{stageEnroll}, h: s.handleEnroll},
		{method: "POST", pattern: "/signin/enroll/key", perm: PermPreAuth, stages: []stage{stageEnroll}, h: s.handleEnrollKey},
		{method: "GET", pattern: "/signin/enroll/qr.png", perm: PermPreAuth, stages: []stage{stageEnroll}, h: s.handleEnrollQR},
		{method: "POST", pattern: "/signout", perm: PermPreAuth, stages: allStages, h: s.handleSignout},

		// Self-service.
		{method: "GET", pattern: "/{$}", perm: PermSelf, h: s.handleRoot},
		{method: "GET", pattern: "/me", perm: PermSelf, h: s.handleMe},
		{method: "GET", pattern: "/me/edit", perm: PermSelf, h: s.handleMeEditPage},
		{method: "POST", pattern: "/me/edit", perm: PermSelf, h: s.handleMeEdit},
		{method: "GET", pattern: "/me/password", perm: PermSelf, h: s.handleMePasswordPage},
		{method: "POST", pattern: "/me/password", perm: PermSelf, h: s.handleMePassword},
		{method: "GET", pattern: "/me/security", perm: PermSelf, h: s.handleSecurity, script: true},
		{method: "GET", pattern: "/me/recovery-codes", perm: PermSelf, h: s.handleRecoveryCodes},
		{method: "GET", pattern: "/me/2fa/enroll", perm: PermSelf, h: s.handleSelfEnrollStart},
		{method: "POST", pattern: "/me/2fa/enroll", perm: PermSelf, h: s.handleSelfEnroll},
		{method: "GET", pattern: "/me/2fa/qr.png", perm: PermSelf, h: s.handleSelfQR},
		{method: "POST", pattern: "/me/2fa/disable", perm: PermSelf, h: s.handleSelfDisable},
		{method: "POST", pattern: "/me/2fa/recovery-codes", perm: PermSelf, h: s.handleNewRecoveryCodes},
		{method: "POST", pattern: "/me/sessions/signout-all", perm: PermSelf, h: s.handleSignoutEverywhere},
		{method: "POST", pattern: "/me/2fa/keys/register", perm: PermSelf, h: s.handleKeyRegister},
		{method: "GET", pattern: "/me/2fa/keys/{id}/remove", perm: PermSelf, h: s.handleKeyRemovePage, script: true},
		{method: "POST", pattern: "/me/2fa/keys/{id}/remove", perm: PermSelf, h: s.handleKeyRemove},

		// Previews awaiting confirmation; each operation re-checks its own
		// permission (pendingOp.perm) before showing or applying.
		{method: "GET", pattern: "/confirm/{id}", perm: PermSelf, h: s.handleConfirmPage},
		{method: "POST", pattern: "/confirm/{id}", perm: PermSelf, h: s.handleConfirm},
		{method: "POST", pattern: "/confirm/{id}/cancel", perm: PermSelf, h: s.handleCancel},
		{method: "GET", pattern: "/confirm/{id}/key", perm: PermSelf, h: s.handleConfirmKeyPage, script: true},

		// Administration.
		{method: "GET", pattern: "/admin", perm: PermDashboard, h: s.handleDashboard},
		{method: "GET", pattern: "/admin/object", perm: PermUsersRead, h: s.handleObject},

		{method: "GET", pattern: "/admin/users", perm: PermUsersRead, h: s.handleUsers},
		{method: "GET", pattern: "/admin/users/new", perm: PermUsersWrite, h: s.handleUserNewPage},
		{method: "POST", pattern: "/admin/users/new", perm: PermUsersWrite, h: s.handleUserNew},
		{method: "GET", pattern: "/admin/users/{guid}", perm: PermUsersRead, h: s.handleUser},
		{method: "GET", pattern: "/admin/users/{guid}/edit", perm: PermUsersWrite, h: s.handleUserEditPage},
		{method: "POST", pattern: "/admin/users/{guid}/edit", perm: PermUsersWrite, h: s.handleUserEdit},
		{method: "POST", pattern: "/admin/users/{guid}/enable", perm: PermUsersHelpdesk, h: s.handleUserEnable},
		{method: "POST", pattern: "/admin/users/{guid}/disable", perm: PermUsersHelpdesk, h: s.handleUserDisable},
		{method: "POST", pattern: "/admin/users/{guid}/unlock", perm: PermUsersHelpdesk, h: s.handleUserUnlock},
		{method: "GET", pattern: "/admin/users/{guid}/reset-password", perm: PermUsersHelpdesk, h: s.handleUserResetPage},
		{method: "POST", pattern: "/admin/users/{guid}/reset-password", perm: PermUsersHelpdesk, h: s.handleUserReset},
		{method: "GET", pattern: "/admin/users/{guid}/move", perm: PermUsersWrite, h: s.handleUserMovePage},
		{method: "POST", pattern: "/admin/users/{guid}/move", perm: PermUsersWrite, h: s.handleUserMove},
		{method: "POST", pattern: "/admin/users/{guid}/delete", perm: PermUsersWrite, h: s.handleUserDelete},
		{method: "POST", pattern: "/admin/users/{guid}/groups/add", perm: PermUsersWrite, h: s.handleUserGroupAdd},
		{method: "POST", pattern: "/admin/users/{guid}/groups/remove", perm: PermUsersWrite, h: s.handleUserGroupRemove},
		{method: "POST", pattern: "/admin/users/{guid}/mfa/reset", perm: PermMFAManage, h: s.handleUserMFAReset},
		{method: "POST", pattern: "/admin/users/{guid}/mfa/link", perm: PermMFAManage, h: s.handleUserEnrollLink},

		{method: "GET", pattern: "/admin/groups", perm: PermDirRead, h: s.handleGroups},
		{method: "GET", pattern: "/admin/groups/new", perm: PermDirWrite, h: s.handleGroupNewPage},
		{method: "POST", pattern: "/admin/groups/new", perm: PermDirWrite, h: s.handleGroupNew},
		{method: "GET", pattern: "/admin/groups/{guid}", perm: PermDirRead, h: s.handleGroup},
		{method: "POST", pattern: "/admin/groups/{guid}/members/add", perm: PermDirWrite, h: s.handleGroupMemberAdd},
		{method: "POST", pattern: "/admin/groups/{guid}/members/remove", perm: PermDirWrite, h: s.handleGroupMemberRemove},
		{method: "POST", pattern: "/admin/groups/{guid}/delete", perm: PermDirWrite, h: s.handleGroupDelete},

		{method: "GET", pattern: "/admin/ous", perm: PermDirRead, h: s.handleOUs},
		{method: "POST", pattern: "/admin/ous/new", perm: PermDirWrite, h: s.handleOUNew},
		{method: "GET", pattern: "/admin/ous/{guid}", perm: PermDirRead, h: s.handleOU},
		{method: "POST", pattern: "/admin/ous/{guid}/rename", perm: PermDirWrite, h: s.handleOURename},
		{method: "POST", pattern: "/admin/ous/{guid}/move", perm: PermDirWrite, h: s.handleOUMove},
		{method: "POST", pattern: "/admin/ous/{guid}/delete", perm: PermDirWrite, h: s.handleOUDelete},

		{method: "GET", pattern: "/admin/computers", perm: PermDirRead, h: s.handleComputers},
		{method: "GET", pattern: "/admin/computers/{guid}", perm: PermDirRead, h: s.handleComputer},
		{method: "POST", pattern: "/admin/computers/{guid}/enable", perm: PermDirWrite, h: s.handleComputerEnable},
		{method: "POST", pattern: "/admin/computers/{guid}/disable", perm: PermDirWrite, h: s.handleComputerDisable},
		{method: "POST", pattern: "/admin/computers/{guid}/move", perm: PermDirWrite, h: s.handleComputerMove},
		{method: "POST", pattern: "/admin/computers/{guid}/delete", perm: PermDirWrite, h: s.handleComputerDelete},

		{method: "GET", pattern: "/admin/users/{guid}/policy", perm: PermPolicyRead, h: s.handleUserPolicy},
		// Actions on accounts selected in a list; each action re-checks
		// its own permission (helpdesk: enable/disable/unlock/reset).
		{method: "POST", pattern: "/admin/users/selected", perm: PermUsersHelpdesk, h: s.handleSelected},

		// DNS.
		{method: "GET", pattern: "/admin/dns", perm: PermDNSRead, h: s.handleDNSZones},
		{method: "GET", pattern: "/admin/dns/new", perm: PermDNSWrite, h: s.handleDNSZoneNewPage},
		{method: "POST", pattern: "/admin/dns/new", perm: PermDNSWrite, h: s.handleDNSZoneNew},
		{method: "GET", pattern: "/admin/dns/zones/{zone}", perm: PermDNSRead, h: s.handleDNSZone},
		{method: "POST", pattern: "/admin/dns/zones/{zone}/delete", perm: PermDNSWrite, h: s.handleDNSZoneDelete},
		{method: "POST", pattern: "/admin/dns/zones/{zone}/records/new", perm: PermDNSWrite, h: s.handleDNSRecordNew},
		{method: "GET", pattern: "/admin/dns/zones/{zone}/records/edit", perm: PermDNSWrite, h: s.handleDNSRecordEditPage},
		{method: "POST", pattern: "/admin/dns/zones/{zone}/records/edit", perm: PermDNSWrite, h: s.handleDNSRecordEdit},
		{method: "POST", pattern: "/admin/dns/zones/{zone}/records/delete", perm: PermDNSWrite, h: s.handleDNSRecordDelete},

		// Group Policy (links and flags; settings are edited with RSAT/GPMC).
		{method: "GET", pattern: "/admin/gpo", perm: PermGPORead, h: s.handleGPOs},
		{method: "GET", pattern: "/admin/gpo/new", perm: PermGPOWrite, h: s.handleGPONewPage},
		{method: "POST", pattern: "/admin/gpo/new", perm: PermGPOWrite, h: s.handleGPONew},
		{method: "GET", pattern: "/admin/gpo/links", perm: PermGPORead, h: s.handleGPContainer},
		{method: "POST", pattern: "/admin/gpo/links", perm: PermGPOWrite, h: s.handleGPContainerAction},
		{method: "POST", pattern: "/admin/gpo/inheritance", perm: PermGPOWrite, h: s.handleGPInheritance},
		{method: "GET", pattern: "/admin/gpo/{id}", perm: PermGPORead, h: s.handleGPO},
		{method: "POST", pattern: "/admin/gpo/{id}/link", perm: PermGPOWrite, h: s.handleGPOLinkTo},
		{method: "POST", pattern: "/admin/gpo/{id}/delete", perm: PermGPOWrite, h: s.handleGPODelete},

		// Password policy.
		{method: "GET", pattern: "/admin/policy", perm: PermPolicyRead, h: s.handlePolicy},
		{method: "GET", pattern: "/admin/policy/edit", perm: PermPolicyWrite, h: s.handlePolicyEditPage},
		{method: "POST", pattern: "/admin/policy/edit", perm: PermPolicyWrite, h: s.handlePolicyEdit},
		{method: "GET", pattern: "/admin/policy/pso/new", perm: PermPolicyWrite, h: s.handlePSONewPage},
		{method: "POST", pattern: "/admin/policy/pso/new", perm: PermPolicyWrite, h: s.handlePSONew},
		{method: "GET", pattern: "/admin/policy/pso/{guid}", perm: PermPolicyRead, h: s.handlePSO},
		{method: "POST", pattern: "/admin/policy/pso/{guid}/edit", perm: PermPolicyWrite, h: s.handlePSOEdit},
		{method: "POST", pattern: "/admin/policy/pso/{guid}/delete", perm: PermPolicyWrite, h: s.handlePSODelete},
		{method: "POST", pattern: "/admin/policy/pso/{guid}/apply", perm: PermPolicyWrite, h: s.handlePSOApply},
		{method: "POST", pattern: "/admin/policy/pso/{guid}/unapply", perm: PermPolicyWrite, h: s.handlePSOUnapply},

		// Lockouts and account health.
		{method: "GET", pattern: "/admin/lockouts", perm: PermHealthRead, h: s.handleLockouts},
		{method: "GET", pattern: "/admin/health", perm: PermHealthRead, h: s.handleHealth},
		{method: "GET", pattern: "/admin/health/export.csv", perm: PermHealthRead, h: s.handleHealthExport},

		// Bulk jobs: CSV import (administrators), and the preview/apply/
		// report of every job, shown to its owner only.
		{method: "GET", pattern: "/admin/bulk", perm: PermBulk, h: s.handleBulkIndex},
		{method: "GET", pattern: "/admin/bulk-templates/{kind}", perm: PermBulk, h: s.handleBulkTemplate},
		{method: "POST", pattern: "/admin/bulk/upload", perm: PermBulk, h: s.handleBulkUpload, maxBody: maxUpload + 64<<10},
		{method: "GET", pattern: "/admin/bulk/{id}", perm: PermUsersHelpdesk, h: s.handleBulkJob},
		{method: "GET", pattern: "/admin/bulk/{id}/key", perm: PermUsersHelpdesk, h: s.handleBulkKeyPage, script: true},
		{method: "POST", pattern: "/admin/bulk/{id}/apply", perm: PermUsersHelpdesk, h: s.handleBulkApply},
		{method: "POST", pattern: "/admin/bulk/{id}/cancel", perm: PermUsersHelpdesk, h: s.handleBulkCancel},
		{method: "POST", pattern: "/admin/bulk/{id}/retry", perm: PermUsersHelpdesk, h: s.handleBulkRetry},
		{method: "GET", pattern: "/admin/bulk/{id}/report.csv", perm: PermUsersHelpdesk, h: s.handleBulkReport},
		{method: "GET", pattern: "/admin/bulk/{id}/preview.ldif", perm: PermUsersHelpdesk, h: s.handleBulkPreviewLDIF},
		{method: "GET", pattern: "/admin/bulk/{id}/passwords.csv", perm: PermUsersHelpdesk, h: s.handleBulkPasswords},
		{method: "POST", pattern: "/admin/bulk/{id}/passwords/dismiss", perm: PermUsersHelpdesk, h: s.handleBulkPasswords},

		// Backups (conductor-backup through conductor-helper): status for
		// administrators and auditors; actions and policy for administrators,
		// each previewed and confirmed with re-authentication.
		{method: "GET", pattern: "/admin/backups", perm: PermBackupRead, h: s.handleBackups},
		{method: "GET", pattern: "/admin/backups/config", perm: PermBackupWrite, h: s.handleBackupConfigPage},
		{method: "POST", pattern: "/admin/backups/config", perm: PermBackupWrite, h: s.handleBackupConfig},
		{method: "POST", pattern: "/admin/backups/run", perm: PermBackupWrite, h: s.handleBackupRun},
		{method: "POST", pattern: "/admin/backups/drill", perm: PermBackupWrite, h: s.handleBackupDrill},

		// Google Workspace sync (conductor-sync's management API):
		// administrators only. Changes to the settings, the key and Google
		// are previewed and confirmed with re-authentication.
		{method: "GET", pattern: "/admin/sync", perm: PermSyncRead, h: s.handleSync},
		{method: "POST", pattern: "/admin/sync/plan", perm: PermSyncWrite, h: s.handleSyncPlan},
		{method: "POST", pattern: "/admin/sync/run-now", perm: PermSyncWrite, h: s.handleSyncRunNow},
		{method: "POST", pattern: "/admin/sync/mode", perm: PermSyncWrite, h: s.handleSyncMode},
		{method: "GET", pattern: "/admin/sync/jobs/{id}", perm: PermSyncRead, h: s.handleSyncJob},
		{method: "GET", pattern: "/admin/sync/runs", perm: PermSyncRead, h: s.handleSyncRuns},
		{method: "GET", pattern: "/admin/sync/runs/{id}", perm: PermSyncRead, h: s.handleSyncRun},
		{method: "POST", pattern: "/admin/sync/runs/{id}/apply", perm: PermSyncWrite, h: s.handleSyncRunApply},
		{method: "GET", pattern: "/admin/sync/config", perm: PermSyncRead, h: s.handleSyncConfig},
		{method: "GET", pattern: "/admin/sync/config/export", perm: PermSyncRead, h: s.handleSyncExport},
		{method: "GET", pattern: "/admin/sync/setup", perm: PermSyncWrite, h: s.handleSyncSetup},
		{method: "POST", pattern: "/admin/sync/setup/google", perm: PermSyncWrite, h: s.handleSyncSetupGoogle},
		{method: "POST", pattern: "/admin/sync/setup/key", perm: PermSyncWrite, h: s.handleSyncSetupKey, maxBody: maxKeyUpload + 64<<10},
		{method: "POST", pattern: "/admin/sync/setup/test", perm: PermSyncWrite, h: s.handleSyncSetupTest},
		{method: "POST", pattern: "/admin/sync/setup/scope", perm: PermSyncWrite, h: s.handleSyncSetupScope},
		{method: "POST", pattern: "/admin/sync/setup/mapping", perm: PermSyncWrite, h: s.handleSyncSetupMapping},
		{method: "POST", pattern: "/admin/sync/setup/templates", perm: PermSyncWrite, h: s.handleSyncSetupTemplates},
		{method: "POST", pattern: "/admin/sync/setup/safety", perm: PermSyncWrite, h: s.handleSyncSetupSafety},
		{method: "POST", pattern: "/admin/sync/setup/save", perm: PermSyncWrite, h: s.handleSyncSetupSave},
		{method: "POST", pattern: "/admin/sync/setup/discard", perm: PermSyncWrite, h: s.handleSyncSetupDiscard},

		{method: "GET", pattern: "/admin/audit", perm: PermAuditRead, h: s.handleAudit},
		{method: "GET", pattern: "/admin/audit/export", perm: PermAuditRead, h: s.handleAuditExport},
		{method: "GET", pattern: "/admin/domain", perm: PermDomainRead, h: s.handleDomain},
	}
}
