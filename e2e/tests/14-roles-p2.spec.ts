import { test, expect, env, shot, signInMFA, csrfOf, navTo, openNav } from './helpers';

// Role limits on the P2 pages: the auditor reads everything and writes
// nothing; helpdesk sees lockouts and health (and may act on its
// delegated accounts) but no DNS, GPO, policy or bulk import.
test.describe.serial('roles on the P2 pages', () => {
  test('auditor: read-only DNS, GPO, policy, lockouts, health', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'auditor.user', env.userPassword);
    await navTo(page, 'dns');
    await expect(page.getByTestId('dns-link-new-zone')).toHaveCount(0);
    await page.goto('/admin/dns/zones/apps.conductor.test');
    await expect(page.getByTestId('dns-table-records')).toBeVisible();
    await expect(page.getByTestId('dns-btn-add')).toHaveCount(0);
    await expect(page.getByTestId('dns-link-edit-mail-a')).toHaveCount(0);
    await shot(page, info, '14-auditor-dns');
    await navTo(page, 'gpo');
    await expect(page.getByTestId('gpo-link-new')).toHaveCount(0);
    await page.getByTestId('gpo-link-container-people').click();
    await expect(page.getByTestId('gpc-table-links')).toBeVisible();
    await expect(page.getByTestId('gpc-btn-link')).toHaveCount(0);
    await navTo(page, 'policy');
    await expect(page.getByTestId('policy-link-edit')).toHaveCount(0);
    // AD shows fine-grained policies to administrators only (default ACL).
    await expect(page.getByTestId('policy-text-pso-hidden')).toBeVisible();
    await page.goto('/admin/users?q=user0101');
    await page.getByTestId('users-link-user0101').click();
    await page.getByTestId('user-link-policy').click();
    await expect(page.getByTestId('effective-text-source')).toBeVisible();
    await navTo(page, 'lockouts');
    await expect(page.getByTestId('sel-form')).toHaveCount(0);
    await navTo(page, 'health');
    await expect(page.getByTestId('health-link-export')).toBeVisible();
    await expect(page.getByTestId('nav-link-bulk')).toHaveCount(0);

    // Forged writes with a valid CSRF token are refused by role.
    const csrf = await csrfOf(page);
    for (const [path, form] of [
      ['/admin/dns/zones/apps.conductor.test/records/new', { name: 'x', type: 'A', data: '192.0.2.1' }],
      ['/admin/dns/new', { name: 'evil.test', partition: 'DomainDnsZones' }],
      ['/admin/gpo/new', { name: 'evil' }],
      ['/admin/gpo/inheritance', { dn: 'OU=Lab,DC=lab,DC=conductor,DC=test', block: '1' }],
      ['/admin/policy/edit', { min_length: '1' }],
      ['/admin/users/selected', { action: 'unlock', sel: '00112233-4455-6677-8899-aabbccddeeff' }],
      ['/admin/bulk/upload', { kind: 'import-create' }],
    ] as [string, Record<string, string>][]) {
      const r = await page.request.post(path, { form: { csrf, ...form }, maxRedirects: 0 });
      expect(r.status(), path).toBe(403);
    }
    for (const p of ['/admin/bulk', '/admin/dns/new', '/admin/gpo/new', '/admin/policy/edit', '/admin/policy/pso/new']) {
      const r = await page.goto(p);
      expect(r!.status(), p).toBe(403);
    }
  });

  test('helpdesk: lockouts and health with actions; no DNS, GPO, policy, bulk', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'helpdesk.user', env.helpdeskPassword);
    await expect(page.getByTestId('nav-link-dns')).toHaveCount(0);
    await expect(page.getByTestId('nav-link-gpo')).toHaveCount(0);
    await expect(page.getByTestId('nav-link-policy')).toHaveCount(0);
    await expect(page.getByTestId('nav-link-bulk')).toHaveCount(0);
    // Groups with nothing the role can use are not rendered at all.
    await expect(page.getByTestId('nav-group-network')).toHaveCount(0);
    await expect(page.getByTestId('nav-group-policies')).toHaveCount(0);
    await expect(page.getByTestId('nav-group-audit')).toHaveCount(0);
    await expect(page.getByTestId('nav-group-operations')).toHaveCount(1);
    await navTo(page, 'lockouts');
    await openNav(page);
    await expect(page.getByTestId('nav-link-lockouts')).toHaveAttribute('aria-current', 'page');
    await expect(page.getByTestId('lockouts-table').or(page.getByTestId('lockouts-text-none'))).toBeVisible();
    await navTo(page, 'health');
    // The never-signed-in tab always has accounts (the selection form is
    // shown with a non-empty list only).
    await page.getByTestId('health-link-never').click();
    await expect(page.getByTestId('sel-form')).toBeVisible();
    // Only the helpdesk actions are offered.
    const options = await page.getByTestId('sel-select-action').locator('option').allInnerTexts();
    expect(options).toEqual(['Unlock', 'Enable', 'Disable', 'Reset password (random)']);
    await shot(page, info, '14-helpdesk-health');
    for (const p of ['/admin/dns', '/admin/gpo', '/admin/policy', '/admin/bulk', '/admin/users/00112233-4455-6677-8899-aabbccddeeff/policy']) {
      const r = await page.goto(p);
      expect(r!.status(), p).toBe(403);
    }
    await page.goto('/admin/health');
    const csrf = await csrfOf(page);
    for (const action of ['delete', 'move', 'group_add']) {
      const r = await page.request.post('/admin/users/selected', { form: { csrf, action, sel: '00112233-4455-6677-8899-aabbccddeeff' }, maxRedirects: 0 });
      expect(r.status(), action).toBe(403);
    }
    // A protected account is refused for helpdesk before AD is asked.
    await page.goto('/admin/users?q=lab.admin');
    await page.getByTestId('sel-check-lab-admin').check();
    await page.getByTestId('sel-select-action').selectOption('unlock');
    await page.getByTestId('sel-btn-go').click();
    await page.getByTestId('sel-btn-preview').click();
    await expect(page.getByTestId('bulk-text-error')).toContainText('protected');
  });
});
