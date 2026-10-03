import { test, expect, env, shot, signInMFA, apply, navTo, openNav, csrfOf } from './helpers';

// Backups (P3). The lab snapshot conductor-p3 has conductor-backup on dc1
// with one backup uploaded to MinIO and one restore drill that passed on the
// drill host. Administrators see everything and may act (with
// re-authentication); auditors read; helpdesk has no access.
const reauth = (info: any) => ({ info, user: 'lab.admin', password: env.adminPassword });

test.describe.serial('backups', () => {
  test('administrator: status, back up now with re-authentication', async ({ page }, info) => {
    test.setTimeout(420_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'backups');
    await openNav(page);
    await expect(page.getByTestId('nav-link-backups')).toHaveAttribute('aria-current', 'page');
    await expect(page.getByTestId('backups-table')).toBeVisible();
    await expect(page.locator('[data-e2e^="backups-row-"]').first()).toBeVisible();
    // The snapshot's drill passed and measured a restore time.
    await expect(page.getByTestId('drills-badge-passed').first()).toBeVisible();
    await expect(page.getByTestId('backups-text-rto')).not.toHaveText('—');
    await expect(page.getByTestId('backups-text-rpo')).not.toHaveText('—');
    await expect(page.getByTestId('backups-list-recipients').locator('li')).toHaveCount(2);
    await expect(page.getByTestId('backups-list-destinations')).toContainText('minio');
    // No secret anywhere on the page.
    const html = await page.content();
    expect(html).not.toMatch(/AGE-SECRET-KEY|cbsigkey1:|secret_access_key/);
    await shot(page, info, '15-backups');

    await page.getByTestId('backups-btn-run').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('backup.trigger');
    await expect(page.getByTestId('confirm-text-preview')).toContainText('action: backup');
    await apply(page, { reauth: reauth(info), screenshot: [info, '15-backups-confirm'] });
    await expect(page).toHaveURL(/\/admin\/backups$/);
    await expect(page.getByTestId('flash-ok')).toBeVisible();

    // conductor-backup.path starts the run; the new backup shows up as
    // requested by the administrator and verified in both destinations.
    const mine = page.locator('[data-e2e^="backups-row-"]').filter({ hasText: 'lab.admin' });
    // Status OK plus both destinations OK: three "OK" badges in the row.
    await expect
      .poll(
        async () => {
          await page.reload();
          return await mine.first().locator('.badge-ok').count();
        },
        { timeout: 300_000, intervals: [5_000] },
      )
      .toBeGreaterThanOrEqual(3);
    await expect(mine.first()).toContainText('minio');
    await expect(mine.first()).toContainText('local');
    await shot(page, info, '15-backups-after');
  });

  test('administrator: run drill now and edit the policy', async ({ page }, info) => {
    test.setTimeout(300_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto('/admin/backups');
    await page.getByTestId('backups-btn-drill').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('action: drill');
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('backups-pending-drill').first()).toBeVisible();

    await page.getByTestId('backups-link-config').click();
    await expect(page.getByTestId('backupcfg-input-daily')).toHaveValue('7');
    // Invalid: alert threshold below the 24 h interval.
    await page.getByTestId('backupcfg-input-max-age').fill('12');
    await page.getByTestId('backupcfg-btn-preview').click();
    await expect(page.getByTestId('form-text-error')).toBeVisible();
    await page.getByTestId('backupcfg-input-max-age').fill('26');
    await page.getByTestId('backupcfg-input-daily').fill('8');
    await shot(page, info, '15-backups-config');
    await page.getByTestId('backupcfg-btn-preview').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('retention.daily: 7 -> 8');
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('backups-text-retention')).toContainText('8 daily');
    // Back to the default.
    await page.getByTestId('backups-link-config').click();
    await page.getByTestId('backupcfg-input-daily').fill('7');
    await page.getByTestId('backupcfg-btn-preview').click();
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('backups-text-retention')).toContainText('7 daily');
  });

  test('auditor: read-only', async ({ page }, info) => {
    test.setTimeout(180_000);
    await signInMFA(page, info, 'auditor.user', env.userPassword);
    await navTo(page, 'backups');
    await expect(page.getByTestId('backups-table')).toBeVisible();
    await expect(page.getByTestId('drills-table')).toBeVisible();
    await expect(page.getByTestId('backups-btn-run')).toHaveCount(0);
    await expect(page.getByTestId('backups-btn-drill')).toHaveCount(0);
    await expect(page.getByTestId('backups-link-config')).toHaveCount(0);
    await shot(page, info, '15-backups-auditor');
    const csrf = await csrfOf(page);
    for (const path of ['/admin/backups/run', '/admin/backups/drill', '/admin/backups/config']) {
      const r = await page.request.post(path, { form: { csrf, daily: '1' }, maxRedirects: 0 });
      expect(r.status(), path).toBe(403);
    }
    const r = await page.goto('/admin/backups/config');
    expect(r!.status()).toBe(403);
  });

  test('helpdesk: no access', async ({ page }, info) => {
    test.setTimeout(120_000);
    await signInMFA(page, info, 'helpdesk.user', env.helpdeskPassword);
    await openNav(page);
    await expect(page.getByTestId('nav-link-backups')).toHaveCount(0);
    for (const p of ['/admin/backups', '/admin/backups/config']) {
      const r = await page.goto(p);
      expect(r!.status(), p).toBe(403);
    }
  });
});
