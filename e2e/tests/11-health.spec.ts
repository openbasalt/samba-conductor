import * as fs from 'node:fs';
import { test, expect, env, shot, signInMFA, freshCode, navTo } from './helpers';

test.describe.serial('lockouts and account health', () => {
  test('lockouts across both DCs; unlock selected', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'lockouts');
    const table = page.getByTestId('lockouts-table');
    await expect(table).toContainText('dc1.lab.conductor.test');
    await expect(table).toContainText('dc2.lab.conductor.test');
    await expect(page.getByTestId('lockouts-badge-locked-locked-user')).toBeVisible();
    // Bad-password counters are per DC: the lock was made against one DC.
    await expect(page.getByTestId('lockouts-row-locked-user')).toContainText('3 failed');
    await shot(page, info, '11-lockouts');

    await page.getByTestId('sel-check-locked-user').check();
    await page.getByTestId('sel-select-action').selectOption('unlock');
    await page.getByTestId('sel-btn-go').click();
    await expect(page.getByTestId('sel-text-names')).toHaveText('locked.user');
    await page.getByTestId('sel-btn-preview').click();
    await expect(page.getByTestId('job-text-status')).toHaveText(/Waiting/);
    await expect(page.getByTestId('job-table-rows')).toContainText('lockoutTime');
    await shot(page, info, '11-job-preview');
    await page.getByTestId('job-btn-apply').click();
    await expect(page.getByTestId('job-text-status')).toHaveText('Finished', { timeout: 30_000 });
    await expect(page.getByTestId('job-text-row-status-locked-user')).toHaveText('Applied');
    // The unlock is written on every DC (no waiting for replication) and the
    // report names each one.
    await expect(page.getByTestId('job-table-rows')).toContainText('dc1.lab.conductor.test: applied');
    await expect(page.getByTestId('job-table-rows')).toContainText('dc2.lab.conductor.test: applied');
    await page.goto('/admin/lockouts');
    await expect(page.getByTestId('lockouts-badge-locked-locked-user')).toHaveCount(0);
  });

  test('health lists, CSV export and a password reset of selected accounts', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'health');
    // Expiring within 365 days covers the 20-day PSO whatever the date.
    await page.goto('/admin/health?kind=expiring&days=365');
    const expiring = await page.getByTestId('health-row-user0101').count();
    if (expiring === 0) {
      await page.goto('/admin/health?kind=expired');
    }
    await expect(page.getByTestId('health-row-user0101')).toBeVisible();
    await expect(page.getByTestId('health-row-user0102')).toBeVisible();
    await shot(page, info, '11-health-expiring');

    await page.getByTestId('health-link-stale').click();
    await expect(page.getByTestId('health-row-stale-user')).toBeVisible();
    await page.getByTestId('health-link-disabled').click();
    await expect(page.getByTestId('health-row-disabled-user')).toBeVisible();
    await page.getByTestId('health-link-never').click();
    await expect(page.getByTestId('health-row-user0001')).toBeVisible();
    await shot(page, info, '11-health-never');

    // CSV export (formula-safe cells), audited.
    const resp = await page.request.get('/admin/health/export.csv?kind=disabled');
    expect(resp.status()).toBe(200);
    expect(resp.headers()['content-type']).toContain('text/csv');
    const csv = await resp.text();
    expect(csv.split('\n')[0]).toBe('username,display_name,email,dn,enabled,locked,password_last_set,password_expires,last_logon,created');
    expect(csv).toContain('disabled.user');

    // Reset two passwords at once: random passwords shown once.
    await page.goto('/admin/users?q=user055');
    await page.getByTestId('sel-check-user0551').check();
    await page.getByTestId('sel-check-user0552').check();
    await page.getByTestId('sel-select-action').selectOption('reset');
    await page.getByTestId('sel-btn-go').click();
    await expect(page.getByTestId('sel-check-must-change')).toBeChecked();
    await page.getByTestId('sel-btn-preview').click();
    await expect(page.getByTestId('job-table-rows')).toContainText('unicodePwd: <redacted>');
    await page.getByTestId('job-btn-apply').click();
    await expect(page.getByTestId('job-text-status')).toHaveText('Finished', { timeout: 30_000 });
    await expect(page.getByTestId('job-text-password')).toHaveCount(2);
    await shot(page, info, '11-job-passwords');
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByTestId('job-link-passwords').click()]);
    const body = fs.readFileSync(await download.path(), 'utf8');
    expect(body.trim().split('\n')).toHaveLength(3);
    // Shown once: gone after the download.
    await page.reload();
    await expect(page.getByTestId('job-text-password')).toHaveCount(0);
    const again = await page.request.get(page.url() + '/passwords.csv');
    expect(again.status()).toBe(410);
  });

  test('deleting selected accounts needs the typed count and re-authentication', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto('/admin/users?q=user0601');
    await page.getByTestId('sel-check-user0601').check();
    await page.getByTestId('sel-select-action').selectOption('delete');
    await page.getByTestId('sel-btn-go').click();
    await page.getByTestId('sel-input-confirm').fill('2');
    await page.getByTestId('sel-btn-preview').click();
    await expect(page.getByTestId('form-text-error')).toBeVisible();
    await page.getByTestId('sel-input-confirm').fill('1');
    await page.getByTestId('sel-btn-preview').click();
    await expect(page.getByTestId('confirm-text-reauth')).toBeVisible();
    await page.getByTestId('confirm-input-password').fill(env.adminPassword);
    await page.getByTestId('confirm-input-code').fill(await freshCode(info, 'lab.admin'));
    await page.getByTestId('job-btn-apply').click();
    await expect(page.getByTestId('job-text-status')).toHaveText('Finished', { timeout: 30_000 });
    await expect(page.getByTestId('job-text-row-status-user0601')).toHaveText('Applied');
    await page.goto('/admin/users?q=user0601');
    await expect(page.getByTestId('users-row-user0601')).toHaveCount(0);
  });
});
