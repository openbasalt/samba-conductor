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

		// Invitation and reset links (no sign-in). GET /link/{token} only
		// validates; its POST moves the token into a link record (the
		// __Host-link cookie), on which the steps run (PermLink).
		{method: "GET", pattern: "/link/{token}", perm: PermPublic, anonymous: true, h: s.handleLinkPage},
		{method: "POST", pattern: "/link/{token}/start", perm: PermPublic, anonymous: true, h: s.handleLinkStart},
		{method: "GET", pattern: "/link/2fa", perm: PermLink, h: s.handleLinkMFAPage, script: true},
		{method: "POST", pattern: "/link/2fa", perm: PermLink, h: s.handleLinkMFA},
		{method: "POST", pattern: "/link/2fa/key", perm: PermLink, h: s.handleLinkMFAKey},
		{method: "GET", pattern: "/link/password", perm: PermLink, h: s.handleLinkPasswordPage},
		{method: "POST", pattern: "/link/password", perm: PermLink, h: s.handleLinkPassword},
		{method: "GET", pattern: "/link/enroll", perm: PermLink, h: s.handleLinkEnrollPage, script: true},
		{method: "POST", pattern: "/link/enroll", perm: PermLink, h: s.handleLinkEnroll},
		{method: "POST", pattern: "/link/enroll/key", perm: PermLink, h: s.handleLinkEnrollKey},
		{method: "POST", pattern: "/link/enroll/skip", perm: PermLink, h: s.handleLinkEnrollSkip},
		{method: "GET", pattern: "/link/enroll/qr.png", perm: PermLink, h: s.handleLinkEnrollQR},
		{method: "GET", pattern: "/link/done", perm: PermLink, h: s.handleLinkDone},
		// The public password reset form (when enabled in Settings >
		// Passwords): always the same answer.
		{method: "GET", pattern: "/reset", perm: PermPublic, anonymous: true, h: s.handleResetPage},
		{method: "POST", pattern: "/reset", perm: PermPublic, anonymous: true, h: s.handleReset},

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
		{method: "GET", pattern: "/me/recovery-email", perm: PermSelf, h: s.handleRecoveryEmailPage},
		{method: "POST", pattern: "/me/recovery-email", perm: PermSelf, h: s.handleRecoveryEmailSet},
		{method: "POST", pattern: "/me/recovery-email/verify", perm: PermSelf, h: s.handleRecoveryEmailVerify},
		{method: "POST", pattern: "/me/recovery-email/remove", perm: PermSelf, h: s.handleRecoveryEmailRemove},
		{method: "POST", pattern: "/me/2fa/keys/register", perm: PermSelf, h: s.handleKeyRegister},
		{method: "GET", pattern: "/me/2fa/keys/{id}/remove", perm: PermSelf, h: s.handleKeyRemovePage, script: true},
		{method: "POST", pattern: "/me/2fa/keys/{id}/remove", perm: PermSelf, h: s.handleKeyRemove},
		// Connected accounts (conductor-sync's targets): the user's own
		// accounts only; actions are confirmed, with a step-up when the
		// second factor is not recent. The page that shows a generated
		// password once may run the script (its copy button).
		{method: "GET", pattern: "/me/accounts", perm: PermSelf, h: s.handleAccounts},
		{method: "POST", pattern: "/me/accounts/{target}/activate", perm: PermSelf, h: s.handleAccountActivate},
		{method: "POST", pattern: "/me/accounts/{target}/password", perm: PermSelf, h: s.handleAccountPassword},
		{method: "GET", pattern: "/me/accounts/secret/{ref}", perm: PermSelf, h: s.handleAccountSecret, script: true},

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
		// Invitations and the account's open links (conductor-provisioner).
		{method: "POST", pattern: "/admin/users/{guid}/invite", perm: PermUsersHelpdesk, h: s.handleUserInvite},
		{method: "POST", pattern: "/admin/users/{guid}/tokens/revoke", perm: PermUsersHelpdesk, h: s.handleUserTokenRevoke},

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
		{method: "GET", pattern: "/admin/sync/config/connection", perm: PermSyncRead, h: s.handleSyncConnection},
		{method: "POST", pattern: "/admin/sync/config/connection", perm: PermSyncWrite, h: s.handleSyncConnectionPost, maxBody: maxCAUpload + 128<<10},
		{method: "POST", pattern: "/admin/sync/config/marker", perm: PermSyncWrite, h: s.handleSyncMarker},
		{method: "POST", pattern: "/admin/sync/config/secret", perm: PermSyncWrite, h: s.handleSyncSecret},
		{method: "GET", pattern: "/admin/sync/config/rollback", perm: PermSyncWrite, h: s.handleSyncRollbackPage},
		{method: "POST", pattern: "/admin/sync/config/rollback", perm: PermSyncWrite, h: s.handleSyncRollback},
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
		// Import from Google Workspace (a one-time read of Google through
		// conductor-sync, then a bulk job that creates the AD objects).
		{method: "GET", pattern: "/admin/sync/import", perm: PermSyncWrite, h: s.handleSyncImport},
		{method: "POST", pattern: "/admin/sync/import", perm: PermSyncWrite, h: s.handleSyncImportPost},

		// Google-first mode (Google Workspace to AD): the plan from
		// conductor-sync, applied through conductor-provisioner. Views for
		// PermSyncRead, changes for PermSyncWrite (administrators only);
		// every change is previewed and confirmed with re-authentication.
		{method: "GET", pattern: "/admin/google-first", perm: PermSyncRead, h: s.handleGoogleFirst},
		{method: "POST", pattern: "/admin/google-first/settings", perm: PermSyncWrite, h: s.handleGoogleFirstSettings},
		{method: "GET", pattern: "/admin/google-first/new-scope", perm: PermSyncWrite, h: s.handleGoogleFirstScopeNew},
		{method: "POST", pattern: "/admin/google-first/scopes", perm: PermSyncWrite, h: s.handleGoogleFirstScopePost},
		{method: "GET", pattern: "/admin/google-first/scopes/{name}", perm: PermSyncWrite, h: s.handleGoogleFirstScope},
		{method: "POST", pattern: "/admin/google-first/scopes/{name}/remove", perm: PermSyncWrite, h: s.handleGoogleFirstScopeRemove},
		{method: "POST", pattern: "/admin/google-first/scopes/{name}/mode", perm: PermSyncWrite, h: s.handleGoogleFirstScopeMode},
		{method: "POST", pattern: "/admin/google-first/plan", perm: PermSyncWrite, h: s.handleGoogleFirstPlan},
		{method: "GET", pattern: "/admin/google-first/runs/{id}", perm: PermSyncRead, h: s.handleGoogleFirstRun},
		{method: "POST", pattern: "/admin/google-first/runs/{id}/apply", perm: PermSyncWrite, h: s.handleGoogleFirstRunApply},

		// File servers (conductor-files agents): status, shares and
		// sessions for administrators and auditors; enrollment, removal
		// and share changes for administrators, each previewed with the
		// agent's plan and confirmed with re-authentication.
		{method: "GET", pattern: "/admin/files", perm: PermFilesRead, h: s.handleFiles},
		{method: "GET", pattern: "/admin/files/new", perm: PermFilesWrite, h: s.handleFilesNewPage},
		{method: "POST", pattern: "/admin/files/new", perm: PermFilesWrite, h: s.handleFilesNew},
		{method: "GET", pattern: "/admin/files/{id}", perm: PermFilesRead, h: s.handleFileServer},
		{method: "POST", pattern: "/admin/files/{id}/remove", perm: PermFilesWrite, h: s.handleFileServerRemove},
		{method: "GET", pattern: "/admin/files/{id}/sessions", perm: PermFilesRead, h: s.handleFileSessions},
		{method: "GET", pattern: "/admin/files/{id}/new-share", perm: PermFilesWrite, h: s.handleShareNew},
		{method: "GET", pattern: "/admin/files/{id}/wizard", perm: PermFilesWrite, h: s.handleShareWizard},
		{method: "POST", pattern: "/admin/files/{id}/wizard", perm: PermFilesWrite, h: s.handleShareWizardPost},
		{method: "POST", pattern: "/admin/files/{id}/wizard/plan", perm: PermFilesWrite, h: s.handleShareWizardPlan},
		{method: "POST", pattern: "/admin/files/{id}/wizard/discard", perm: PermFilesWrite, h: s.handleShareWizardDiscard},
		{method: "GET", pattern: "/admin/files/{id}/shares/{name}", perm: PermFilesRead, h: s.handleFileShare},
		{method: "GET", pattern: "/admin/files/{id}/shares/{name}/edit", perm: PermFilesWrite, h: s.handleShareEdit},
		{method: "POST", pattern: "/admin/files/{id}/shares/{name}/remove", perm: PermFilesWrite, h: s.handleFileShareRemove},

		// Single sign-on (conductor-idp's management API): administrators
		// only. Every change is previewed and confirmed with
		// re-authentication; a client secret is shown once.
		{method: "GET", pattern: "/admin/sso", perm: PermSSORead, h: s.handleSSO},
		{method: "GET", pattern: "/admin/sso/new", perm: PermSSOWrite, h: s.handleSSONew},
		{method: "GET", pattern: "/admin/sso/new/{preset}", perm: PermSSOWrite, h: s.handleSSOPreset},
		{method: "POST", pattern: "/admin/sso/new/{preset}", perm: PermSSOWrite, h: s.handleSSOPreset},
		{method: "GET", pattern: "/admin/sso/secret/{ref}", perm: PermSSOWrite, h: s.handleSSOSecret},
		{method: "GET", pattern: "/admin/sso/oidc", perm: PermSSORead, h: s.handleSSOClients},
		{method: "GET", pattern: "/admin/sso/oidc/new", perm: PermSSOWrite, h: s.handleSSOClientNew},
		{method: "POST", pattern: "/admin/sso/oidc/form", perm: PermSSOWrite, h: s.handleSSOClientForm},
		{method: "GET", pattern: "/admin/sso/oidc/{id}", perm: PermSSORead, h: s.handleSSOClient},
		{method: "GET", pattern: "/admin/sso/oidc/{id}/edit", perm: PermSSOWrite, h: s.handleSSOClientEdit},
		{method: "POST", pattern: "/admin/sso/oidc/{id}/rotate", perm: PermSSOWrite, h: s.handleSSOClientRotate},
		{method: "POST", pattern: "/admin/sso/oidc/{id}/enabled", perm: PermSSOWrite, h: s.handleSSOClientEnabled},
		{method: "POST", pattern: "/admin/sso/oidc/{id}/delete", perm: PermSSOWrite, h: s.handleSSOClientDelete},
		{method: "GET", pattern: "/admin/sso/saml", perm: PermSSORead, h: s.handleSSOSPs},
		{method: "GET", pattern: "/admin/sso/saml/new", perm: PermSSOWrite, h: s.handleSSOSPNew},
		{method: "POST", pattern: "/admin/sso/saml/import", perm: PermSSOWrite, h: s.handleSSOSPImport, maxBody: maxMetadataUpload + 64<<10},
		{method: "POST", pattern: "/admin/sso/saml/form", perm: PermSSOWrite, h: s.handleSSOSPForm, maxBody: 256 << 10},
		{method: "GET", pattern: "/admin/sso/saml/sp", perm: PermSSORead, h: s.handleSSOSP},
		{method: "GET", pattern: "/admin/sso/saml/sp/edit", perm: PermSSOWrite, h: s.handleSSOSPEdit},
		{method: "POST", pattern: "/admin/sso/saml/sp/enabled", perm: PermSSOWrite, h: s.handleSSOSPEnabled},
		{method: "POST", pattern: "/admin/sso/saml/sp/delete", perm: PermSSOWrite, h: s.handleSSOSPDelete},
		{method: "GET", pattern: "/admin/sso/keys", perm: PermSSORead, h: s.handleSSOKeys},
		{method: "POST", pattern: "/admin/sso/keys/rotate", perm: PermSSOWrite, h: s.handleSSOKeysRotate},
		{method: "GET", pattern: "/admin/sso/keys/saml.pem", perm: PermSSORead, h: s.handleSSOCert},
		{method: "GET", pattern: "/admin/sso/policy", perm: PermSSORead, h: s.handleSSOPolicy},
		{method: "POST", pattern: "/admin/sso/policy", perm: PermSSOWrite, h: s.handleSSOPolicyPost},
		{method: "GET", pattern: "/admin/sso/activity", perm: PermSSORead, h: s.handleSSOActivity},

		// Settings > Branding: the look of the user-facing pages
		// (self-service, and conductor-idp's sign-in pages through its
		// management API). Administrators only; saving and restoring a
		// version need the password and a fresh second factor.
		{method: "GET", pattern: "/admin/branding", perm: PermBranding, h: s.handleBranding},
		{method: "POST", pattern: "/admin/branding", perm: PermBranding, h: s.handleBrandingDraft, maxBody: brandingMaxBody},
		{method: "GET", pattern: "/admin/branding/preview", perm: PermBranding, h: s.handleBrandingPreview},
		{method: "GET", pattern: "/admin/branding/preview.css", perm: PermBranding, h: s.handleBrandingPreviewCSS},
		{method: "GET", pattern: "/admin/branding/draft-asset", perm: PermBranding, h: s.handleBrandingDraftAsset},
		{method: "POST", pattern: "/admin/branding/save", perm: PermBranding, h: s.handleBrandingSave},
		{method: "POST", pattern: "/admin/branding/discard", perm: PermBranding, h: s.handleBrandingDiscard},
		{method: "POST", pattern: "/admin/branding/push", perm: PermBranding, h: s.handleBrandingPush},
		{method: "GET", pattern: "/admin/branding/versions", perm: PermBranding, h: s.handleBrandingVersions},
		{method: "POST", pattern: "/admin/branding/revert", perm: PermBranding, h: s.handleBrandingRevert},

		// Settings > E-mail: the relay as configured (never its password),
		// the queue, the log and a test message. Administrators only.
		{method: "GET", pattern: "/admin/settings/mail", perm: PermSettings, h: s.handleMailSettings},
		{method: "POST", pattern: "/admin/settings/mail/test", perm: PermSettings, h: s.handleMailTest},
		// Settings > Passwords: invitations, reset by e-mail, notifications.
		{method: "GET", pattern: "/admin/settings/passwords", perm: PermSettings, h: s.handlePasswordSettings},
		{method: "POST", pattern: "/admin/settings/passwords", perm: PermSettings, h: s.handlePasswordSettingsPost},

		// WebAuthn related origins (other sites that may use conductor's
		// security keys), when configured.
		{method: "GET", pattern: "/.well-known/webauthn", perm: PermPublic, h: s.handleWellKnownWebAuthn},

		{method: "GET", pattern: "/admin/audit", perm: PermAuditRead, h: s.handleAudit},
		{method: "GET", pattern: "/admin/audit/export", perm: PermAuditRead, h: s.handleAuditExport},
		{method: "GET", pattern: "/admin/domain", perm: PermDomainRead, h: s.handleDomain},
	}
}
