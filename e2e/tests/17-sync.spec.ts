import * as path from 'node:path';
import { test, expect, env, shot, signInMFA, apply, navTo, openNav, gotoStable, csrfOf } from './helpers';
import type { Page, TestInfo } from '@playwright/test';

// Google Workspace sync (P5b). The lab snapshot conductor-p5b has
// conductor-sync on dc1 behind its management API (socket activation) and
// the fake Directory API on dc1's loopback; run-lab.sh copies the fake's
// service account key to .auth/. No real Google Workspace is involved.
const reauth = (info: TestInfo) => ({ info, user: 'lab.admin', password: env.adminPassword });
const keyFile = path.join(__dirname, '..', '.auth', 'fake-sa-key.json');

// waitRun follows a job page until it lands on the run page.
async function waitRun(page: Page, timeout = 300_000) {
  await expect(page).toHaveURL(/\/admin\/sync\/runs\/\d+$/, { timeout });
  await expect(page.getByTestId('sync-run-title')).toBeVisible();
}

async function confirmation(page: Page): Promise<string> {
  return (await page.getByTestId('sync-run-text-confirmation').innerText()).trim();
}

test.describe.serial('google workspace sync', () => {
  test('setup: key, tenant, connection test, scope, org units, templates, review', async ({ page }, info) => {
    test.setTimeout(600_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'sync');
    await openNav(page);
    await expect(page.getByTestId('nav-link-sync')).toHaveAttribute('aria-current', 'page');
    await expect(page.getByTestId('sync-card-unconfigured')).toBeVisible();
    await shot(page, info, '17-sync-unconfigured');
    await page.getByTestId('sync-link-setup-start').click();

    // 1. Google: the key (write only, re-authentication), the tenant, a test.
    await page.getByTestId('sync-setup-input-key').setInputFiles(keyFile);
    await page.getByTestId('sync-setup-btn-key').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('client_email: sync@project.iam.gserviceaccount.com');
    expect(await page.content()).not.toContain('PRIVATE KEY');
    await apply(page, { reauth: reauth(info), screenshot: [info, '17-sync-key-confirm'] });
    await expect(page.getByTestId('sync-setup-key-current')).toContainText('sync@project.iam.gserviceaccount.com');
    expect(await page.content()).not.toContain('PRIVATE KEY');
    await page.getByTestId('sync-setup-input-subject').fill('admin@lab.example.com');
    await page.getByTestId('sync-setup-input-domains').fill('lab.example.com');
    await page.getByTestId('sync-setup-btn-save-google').click();
    await page.getByTestId('sync-setup-btn-test').click();
    await expect(page.getByTestId('sync-setup-test-ad-ok')).toBeVisible();
    await expect(page.getByTestId('sync-setup-test-google-ok')).toBeVisible();
    await shot(page, info, '17-sync-setup-google');
    await page.getByTestId('sync-setup-btn-next-google').click();

    // 2. Who: members of All Staff (nested groups count).
    await expect(page).toHaveURL(/step=scope/);
    await page.getByTestId('sync-setup-input-group-q').fill('All Staff');
    await page.getByTestId('sync-setup-btn-group-search').click();
    await page.getByTestId('sync-setup-btn-include-all-staff').click();
    await expect(page.getByTestId('sync-setup-list-include')).toContainText('All Staff');
    await shot(page, info, '17-sync-setup-scope');
    await page.getByTestId('sync-setup-btn-next-scope').click();

    // 3. Org units: Finance by group (priority 10), Engineering by OU.
    await expect(page).toHaveURL(/step=mapping/);
    await page.getByTestId('sync-setup-input-group-q').fill('Finance');
    await page.getByTestId('sync-setup-btn-group-search').click();
    await page.getByTestId('sync-setup-input-rule-target-finance').fill('/Finance');
    await page.getByTestId('sync-setup-btn-add-rule-finance').click();
    await page.getByTestId('sync-setup-select-rule-ou').selectOption({ label: 'Lab / People / Engineering' });
    await page.getByTestId('sync-setup-input-ou-target').fill('/Staff/Engineering');
    await page.getByTestId('sync-setup-btn-add-ou-rule').click();
    await expect(page.getByTestId('sync-setup-table-rules')).toContainText('/Finance');
    await expect(page.getByTestId('sync-setup-table-rules')).toContainText('/Staff/Engineering');
    await shot(page, info, '17-sync-setup-mapping');
    await page.getByTestId('sync-setup-btn-next-mapping').click();

    // 4. E-mail templates, previewed against real AD users.
    await expect(page).toHaveURL(/step=templates/);
    await page.getByTestId('sync-setup-input-attr-title').fill('{title}');
    await page.getByTestId('sync-setup-input-preview-q').fill('user0004');
    await page.getByTestId('sync-setup-btn-preview').click();
    await expect(page.getByTestId('sync-setup-preview-email-user0004')).toHaveText('user0004@lab.example.com');
    await expect(page.getByTestId('sync-setup-preview-user0004')).toContainText('/Finance');
    await shot(page, info, '17-sync-setup-preview');
    await page.getByTestId('sync-setup-btn-next-templates').click();

    // 5. Safety: the defaults. 6. Review and save (re-authentication).
    await expect(page).toHaveURL(/step=safety/);
    await expect(page.getByTestId('sync-setup-input-max-suspends')).toHaveValue('10');
    await page.getByTestId('sync-setup-btn-next-safety').click();
    await expect(page).toHaveURL(/step=review/);
    await expect(page.getByTestId('sync-setup-review-changes')).toContainText('scope.include_groups');
    await expect(page.getByTestId('sync-setup-review-changes')).toContainText('mapping.org_units');
    await page.getByTestId('sync-setup-input-comment').fill('e2e: first setup');
    await shot(page, info, '17-sync-setup-review');
    await page.getByTestId('sync-setup-btn-save').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('config.update');
    await apply(page, { reauth: reauth(info) });
    await expect(page).toHaveURL(/\/admin\/sync\/config$/);
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('sync-config-history-1')).toContainText('conductor:lab.admin');
    await expect(page.getByTestId('sync-config-include')).toContainText('All Staff');
    await shot(page, info, '17-sync-config');
  });

  test('mode, plan, typed confirmation and the first apply', async ({ page }, info) => {
    test.setTimeout(600_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'sync');
    await page.getByTestId('sync-btn-mode-apply').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('mode: dry-run -> apply');
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('sync-text-mode')).toHaveText('Apply');

    await page.getByTestId('sync-btn-plan').click();
    await waitRun(page, 180_000);
    // The first sync is far beyond max_creates: applying needs the override.
    await expect(page.getByTestId('sync-run-limit-exceeded-max-creates')).toBeVisible();
    await expect(page.getByTestId('sync-run-tab-create')).toBeVisible();
    await expect(page.getByTestId('sync-run-table-groups')).toContainText('All Staff');
    await expect(page.getByTestId('sync-run-table-groups')).toContainText('Finance');
    await expect(page.getByTestId('sync-run-table-ops')).toContainText('@lab.example.com');
    await shot(page, info, '17-sync-plan');
    const typed = await confirmation(page);
    expect(typed).toMatch(/^override [0-9a-f]{8}$/);
    // A confirmation that does not match is refused.
    await page.getByTestId('sync-run-input-confirm').fill('apply ' + typed.slice('override '.length));
    await page.getByTestId('sync-run-btn-apply').click();
    await expect(page.getByTestId('flash-error')).toBeVisible();
    await page.getByTestId('sync-run-input-confirm').fill(typed);
    await page.getByTestId('sync-run-btn-apply').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('override_limits: true');
    await apply(page, { reauth: reauth(info), screenshot: [info, '17-sync-apply-confirm'] });
    if (page.url().includes('/jobs/')) {
      await expect(page.getByTestId('sync-job-card')).toBeVisible();
      await shot(page, info, '17-sync-job');
    }
    await waitRun(page);
    await expect(page.getByTestId('sync-run-title').getByTestId('sync-badge-applied')).toBeVisible();
    await expect(page.getByTestId('sync-run-failed')).toHaveText('0');
    await shot(page, info, '17-sync-applied');
  });

  test('a mass exclusion blocks the scheduled run; override; history', async ({ page }, info) => {
    test.setTimeout(600_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    // Exclude the 500 members of Support.
    await gotoStable(page, '/admin/sync/setup?step=scope');
    await page.getByTestId('sync-setup-input-group-q').fill('Support');
    await page.getByTestId('sync-setup-btn-group-search').click();
    await page.getByTestId('sync-setup-btn-exclude-support').click();
    await expect(page.getByTestId('sync-setup-list-exclude')).toContainText('Support');
    await gotoStable(page, '/admin/sync/setup?step=review');
    await expect(page.getByTestId('sync-setup-review-changes')).toContainText('scope.exclude_groups');
    await page.getByTestId('sync-setup-btn-save').click();
    await apply(page, { reauth: reauth(info) });

    // Run now with the scheduled rules: blocked, nothing written.
    await navTo(page, 'sync');
    await page.getByTestId('sync-btn-run-now').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('scheduled: true');
    await apply(page, { reauth: reauth(info) });
    await waitRun(page, 180_000);
    await expect(page.getByTestId('sync-run-alert-blocked')).toBeVisible();
    await expect(page.getByTestId('sync-run-violation-max-suspends')).toBeVisible();
    await expect(page.getByTestId('sync-run-tab-suspend')).toContainText('500');
    await shot(page, info, '17-sync-blocked');
    await navTo(page, 'sync');
    await expect(page.locator('[data-e2e^="sync-alert-blocked-"]')).toHaveCount(1);
    await shot(page, info, '17-sync-overview-blocked');

    // The override: typed confirmation bound to the blocked plan.
    await page.locator('[data-e2e^="sync-link-blocked-"]').click();
    await expect(page.getByTestId('sync-run-override-warning')).toBeVisible();
    await page.getByTestId('sync-run-input-confirm').fill(await confirmation(page));
    await page.getByTestId('sync-run-btn-apply').click();
    await expect(page.getByTestId('confirm-text-warning')).toBeVisible();
    await apply(page, { reauth: reauth(info) });
    await waitRun(page);
    await expect(page.getByTestId('sync-run-title').getByTestId('sync-badge-applied')).toBeVisible();
    await expect(page.getByTestId('sync-run-done')).toHaveText('500');

    // History, filtered; the overview no longer shows the blocked run.
    await navTo(page, 'sync-runs');
    await expect(page.getByTestId('sync-runs-table')).toBeVisible();
    await page.getByTestId('sync-runs-select-status').selectOption('blocked');
    await page.getByTestId('sync-runs-btn-filter').click();
    await expect(page.locator('[data-e2e^="sync-runs-row-"]')).toHaveCount(1);
    await page.getByTestId('sync-runs-select-status').selectOption('');
    await page.getByTestId('sync-runs-btn-filter').click();
    await shot(page, info, '17-sync-history');
    await navTo(page, 'sync');
    await expect(page.locator('[data-e2e^="sync-alert-blocked-"]')).toHaveCount(0);
    await expect(page.getByTestId('sync-text-links')).not.toHaveText('0');
    await shot(page, info, '17-sync-overview');
    await navTo(page, 'dashboard');
    await expect(page.getByTestId('dashboard-card-sync')).toBeVisible();
  });

  test('auditor and helpdesk: no access', async ({ page }, info) => {
    test.setTimeout(180_000);
    await signInMFA(page, info, 'auditor.user', env.userPassword);
    await openNav(page);
    await expect(page.getByTestId('nav-link-sync')).toHaveCount(0);
    for (const p of ['/admin/sync', '/admin/sync/runs', '/admin/sync/setup', '/admin/sync/config']) {
      const r = await page.goto(p);
      expect(r!.status(), p).toBe(403);
    }
    const csrf = await csrfOf(page);
    for (const p of ['/admin/sync/plan', '/admin/sync/run-now', '/admin/sync/mode']) {
      const r = await page.request.post(p, { form: { csrf, mode: 'apply' }, maxRedirects: 0 });
      expect(r.status(), p).toBe(403);
    }
  });
});
