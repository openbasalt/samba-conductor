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
		{method: "GET", pattern: "/signin/2fa", perm: PermPreAuth, stages: []stage{stageMFA}, h: s.handleMFAPage},
		{method: "POST", pattern: "/signin/2fa", perm: PermPreAuth, stages: []stage{stageMFA}, h: s.handleMFA},
		{method: "GET", pattern: "/signin/enroll", perm: PermPreAuth, stages: []stage{stageEnroll}, h: s.handleEnrollPage},
		{method: "POST", pattern: "/signin/enroll", perm: PermPreAuth, stages: []stage{stageEnroll}, h: s.handleEnroll},
		{method: "GET", pattern: "/signin/enroll/qr.png", perm: PermPreAuth, stages: []stage{stageEnroll}, h: s.handleEnrollQR},
		{method: "POST", pattern: "/signout", perm: PermPreAuth, stages: allStages, h: s.handleSignout},

		// Self-service.
		{method: "GET", pattern: "/{$}", perm: PermSelf, h: s.handleRoot},
		{method: "GET", pattern: "/me", perm: PermSelf, h: s.handleMe},
		{method: "GET", pattern: "/me/edit", perm: PermSelf, h: s.handleMeEditPage},
		{method: "POST", pattern: "/me/edit", perm: PermSelf, h: s.handleMeEdit},
		{method: "GET", pattern: "/me/password", perm: PermSelf, h: s.handleMePasswordPage},
		{method: "POST", pattern: "/me/password", perm: PermSelf, h: s.handleMePassword},
		{method: "GET", pattern: "/me/security", perm: PermSelf, h: s.handleSecurity},
		{method: "GET", pattern: "/me/recovery-codes", perm: PermSelf, h: s.handleRecoveryCodes},
		{method: "GET", pattern: "/me/2fa/enroll", perm: PermSelf, h: s.handleSelfEnrollStart},
		{method: "POST", pattern: "/me/2fa/enroll", perm: PermSelf, h: s.handleSelfEnroll},
		{method: "GET", pattern: "/me/2fa/qr.png", perm: PermSelf, h: s.handleSelfQR},
		{method: "POST", pattern: "/me/2fa/disable", perm: PermSelf, h: s.handleSelfDisable},
		{method: "POST", pattern: "/me/2fa/recovery-codes", perm: PermSelf, h: s.handleNewRecoveryCodes},
		{method: "POST", pattern: "/me/sessions/signout-all", perm: PermSelf, h: s.handleSignoutEverywhere},

		// Previews awaiting confirmation; each operation re-checks its own
		// permission (pendingOp.perm) before showing or applying.
		{method: "GET", pattern: "/confirm/{id}", perm: PermSelf, h: s.handleConfirmPage},
		{method: "POST", pattern: "/confirm/{id}", perm: PermSelf, h: s.handleConfirm},
		{method: "POST", pattern: "/confirm/{id}/cancel", perm: PermSelf, h: s.handleCancel},

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

		{method: "GET", pattern: "/admin/audit", perm: PermAuditRead, h: s.handleAudit},
		{method: "GET", pattern: "/admin/audit/export", perm: PermAuditRead, h: s.handleAuditExport},
		{method: "GET", pattern: "/admin/domain", perm: PermDomainRead, h: s.handleDomain},
	}
}
