import { test, expect, env, shot, signInMFA } from './helpers';

// Only in the lab's missed-schedule test (planning/lab/backup-failure-tests.sh
// stale-setup, an hour later): E2E_STALE=1 E2E_NO_RESET=1. The dashboard
// shows the backup banner; the Backups page lists the alerts.
test.describe.serial('backups: missed schedule', () => {
  test.skip(!process.env.E2E_STALE, 'only with E2E_STALE=1');
  test('dashboard banner and alerts', async ({ page }, info) => {
    test.setTimeout(120_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto('/admin/backups');
    await expect(page.getByTestId('backups-alert-stale')).toBeVisible();
    await shot(page, info, '16-backups-alerts');
    await page.goto('/admin');
    await expect(page.getByTestId('dashboard-alert-backups')).toBeVisible();
    await expect(page.getByTestId('dashboard-alert-backup-stale')).toBeVisible();
    await shot(page, info, '16-dashboard-backup-banner');
    await page.getByTestId('dashboard-link-backups').click();
    await expect(page).toHaveURL(/\/admin\/backups$/);
  });
});
