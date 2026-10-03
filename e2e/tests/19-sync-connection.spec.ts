import * as path from 'node:path';
import { test, expect, env, shot, signInMFA, apply, gotoStable, csrfOf, rand } from './helpers';
import type { Page, TestInfo } from '@playwright/test';

// Google Workspace sync > Settings > Connection (P5c). Runs after
// 17-sync.spec.ts configured the sync (lab snapshot conductor-p2b:
// conductor-sync on dc1 with the fake Directory API on its loopback).
// Every change: a draft, a connection test of exactly that draft, a preview
// of the changed settings, re-authentication; secrets are write only and no
// page ever contains a secret value.
const reauth = (info: TestInfo) => ({ info, user: 'lab.admin', password: env.adminPassword });
const labCA = path.join(__dirname, '..', '.auth', 'lab-ca.pem');
const CONN = '/admin/sync/config/connection';

async function openConnection(page: Page) {
  await gotoStable(page, '/admin/sync/config');
  await page.getByTestId('sync-config-tab-connection').click();
  await expect(page).toHaveURL(/\/admin\/sync\/config\/connection/);
  await expect(page.getByTestId('sync-conn-form')).toBeVisible();
}

// noSecret fails when the page contains any of the values.
async function noSecret(page: Page, ...values: string[]) {
  const html = await page.content();
  for (const v of values) if (v) expect(html.includes(v), 'a page shows a secret value').toBe(false);
}

test.describe.serial('google workspace sync: connection settings', () => {
  test('a second DC: untested save refused, test, preview, re-authentication, version', async ({ page }, info) => {
    test.setTimeout(300_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await openConnection(page);
    await expect(page.getByTestId('sync-conn-input-realm')).toHaveValue('LAB.CONDUCTOR.TEST');
    await expect(page.getByTestId('sync-conn-secret-state-ad-bind-password')).toHaveText('Configured');
    await expect(page.getByTestId('sync-conn-secret-state-google-service-account-key')).toHaveText('Configured');
    await expect(page.getByTestId('sync-conn-secret-state-alert-webhook-secret')).toHaveText('Not configured');
    await expect(page.getByTestId('sync-conn-text-marker')).toHaveText('conductor-sync');
    await shot(page, info, '19-sync-connection');

    await page.getByTestId('sync-conn-input-dcs').fill('dc1.lab.conductor.test\ndc2.lab.conductor.test');
    await page.getByTestId('sync-conn-input-preferred').fill('dc2.lab.conductor.test');
    await page.getByTestId('sync-conn-input-dns').fill('10.93.0.10\n10.93.0.11');
    // Saving without a test is refused; the draft shows what changes.
    await page.getByTestId('sync-conn-btn-save').click();
    await expect(page.getByTestId('flash-error')).toBeVisible();
    await expect(page.getByTestId('sync-conn-draft-changes')).toContainText('connection.ad.preferred');
    await expect(page.getByTestId('sync-conn-test-needed')).toBeVisible();
    // The test signs in to the preferred DC.
    await page.getByTestId('sync-conn-btn-test').click();
    await expect(page.getByTestId('sync-conn-test-ad-ok')).toBeVisible();
    await expect(page.getByTestId('sync-conn-test-result')).toContainText('dc2.lab.conductor.test');
    await expect(page.getByTestId('sync-conn-test-google-ok')).toBeVisible();
    await shot(page, info, '19-sync-connection-test');
    await page.getByTestId('sync-conn-input-comment').fill('e2e: second DC');
    await page.getByTestId('sync-conn-btn-save').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('connection.ad.dcs');
    await expect(page.getByTestId('confirm-text-preview')).toContainText('connection.ad.preferred');
    await expect(page.getByTestId('confirm-text-warning')).toBeVisible();
    await apply(page, { reauth: reauth(info), screenshot: [info, '19-sync-connection-confirm'] });
    await expect(page).toHaveURL(/\/admin\/sync\/config\/connection/);
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('sync-conn-input-preferred')).toHaveValue('dc2.lab.conductor.test');
    await expect(page.getByTestId('sync-conn-draft')).toHaveCount(0);
    await gotoStable(page, '/admin/sync/config');
    await expect(page.locator('[data-e2e^="sync-config-history-"]').first()).toContainText('e2e: second DC');
  });

  test('the domain CA uploaded and pinned inline', async ({ page }, info) => {
    test.setTimeout(300_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await openConnection(page);
    await expect(page.getByTestId('sync-conn-ca-current')).toContainText('/etc/conductor-sync/domain-ca.pem');
    await page.getByTestId('sync-conn-input-ca-upload').setInputFiles(labCA);
    await page.getByTestId('sync-conn-btn-test').click();
    await expect(page.getByTestId('sync-conn-test-ad-ok')).toBeVisible();
    await expect(page.getByTestId('sync-conn-ca-list')).toContainText('SHA-256');
    await expect(page.getByTestId('sync-conn-draft-changes')).toContainText('connection.ad.ca_pem');
    await page.getByTestId('sync-conn-btn-save').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('certificate(s), sha256');
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('sync-conn-ca-current')).toContainText('Stored in the settings');
    await shot(page, info, '19-sync-connection-ca');
  });

  test('secrets are write only: refused bind password, replace and remove', async ({ page }, info) => {
    test.setTimeout(420_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await openConnection(page);
    // A wrong bind password: AD refuses it, nothing is stored or proposed.
    const wrong = `Wrong-${rand()}-${rand()}`;
    await page.getByTestId('sync-conn-input-secret-ad-bind-password').fill(wrong);
    await page.getByTestId('sync-conn-btn-replace-ad-bind-password').click();
    await expect(page).toHaveURL(/\/admin\/sync\/config\/connection/);
    await expect(page.getByTestId('flash-error')).toBeVisible();
    await noSecret(page, wrong);
    if (env.syncPassword) {
      // The right one: stored encrypted by conductor-sync after a sign-in.
      await page.getByTestId('sync-conn-input-secret-ad-bind-password').fill(env.syncPassword);
      await page.getByTestId('sync-conn-btn-replace-ad-bind-password').click();
      await expect(page.getByTestId('confirm-text-preview')).toContainText('name: ad_bind_password');
      await noSecret(page, env.syncPassword);
      await apply(page, { reauth: reauth(info), screenshot: [info, '19-sync-secret-confirm'] });
      await expect(page.getByTestId('flash-ok')).toBeVisible();
      await expect(page.getByTestId('sync-conn-secret-ad-bind-password')).toContainText('stored encrypted by conductor-sync');
      await expect(page.getByTestId('sync-conn-secret-ad-bind-password')).toContainText('conductor:lab.admin');
      await noSecret(page, env.syncPassword);
      // Removed again: the credential file is used as before.
      await page.getByTestId('sync-conn-btn-remove-ad-bind-password').click();
      await expect(page.getByTestId('confirm-text-warning')).toBeVisible();
      await apply(page, { reauth: reauth(info) });
      await expect(page.getByTestId('sync-conn-secret-ad-bind-password')).toContainText('from a credential file');
    }
    // The webhook HMAC secret: set, shown only as configured, removed.
    const hook = `e2e-hook-${rand()}${rand()}${rand()}`;
    await page.getByTestId('sync-conn-input-secret-alert-webhook-secret').fill(hook);
    await page.getByTestId('sync-conn-btn-replace-alert-webhook-secret').click();
    await noSecret(page, hook);
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('sync-conn-secret-state-alert-webhook-secret')).toHaveText('Configured');
    await noSecret(page, hook);
    await shot(page, info, '19-sync-secrets');
    await page.getByTestId('sync-conn-btn-remove-alert-webhook-secret').click();
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('sync-conn-secret-state-alert-webhook-secret')).toHaveText('Not configured');
  });

  test('the ownership marker: typed confirmation, warning; rollback; a plan still works', async ({ page }, info) => {
    test.setTimeout(420_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await openConnection(page);
    await expect(page.getByTestId('sync-conn-marker-warning')).toBeVisible();
    await page.getByTestId('sync-conn-input-marker').fill('conductor-sync-e2e');
    await page.getByTestId('sync-conn-input-marker-confirm').fill('yes');
    await page.getByTestId('sync-conn-btn-marker').click();
    await expect(page.getByTestId('flash-error')).toContainText('change marker to conductor-sync-e2e');
    await page.getByTestId('sync-conn-input-marker').fill('conductor-sync-e2e');
    await page.getByTestId('sync-conn-input-marker-confirm').fill('change marker to conductor-sync-e2e');
    await page.getByTestId('sync-conn-btn-marker').click();
    await expect(page.getByTestId('confirm-text-warning')).toBeVisible();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('connection.marker: conductor-sync -> conductor-sync-e2e');
    await apply(page, { reauth: reauth(info), screenshot: [info, '19-sync-marker-confirm'] });
    await expect(page.getByTestId('sync-conn-text-marker')).toHaveText('conductor-sync-e2e');

    // Roll back to the version before the marker change.
    await gotoStable(page, '/admin/sync/config');
    await page.locator('[data-e2e^="sync-config-link-rollback-"]').first().click();
    await expect(page.getByTestId('sync-rollback-changes')).toContainText('connection.marker');
    await expect(page.getByTestId('sync-rollback-marker-warning')).toBeVisible();
    await expect(page.getByTestId('sync-rollback-secrets')).toBeVisible();
    await shot(page, info, '19-sync-rollback');
    await page.getByTestId('sync-rollback-input-confirm').fill('change marker to conductor-sync-e2e');
    await page.getByTestId('sync-rollback-btn-submit').click();
    await expect(page.getByTestId('flash-error')).toBeVisible();
    await page.getByTestId('sync-rollback-input-confirm').fill('change marker to conductor-sync');
    await page.getByTestId('sync-rollback-input-comment').fill('e2e: undo the marker');
    await page.getByTestId('sync-rollback-btn-submit').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('config.rollback');
    await apply(page, { reauth: reauth(info) });
    await expect(page).toHaveURL(/\/admin\/sync\/config$/);
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.locator('[data-e2e^="sync-config-history-"]').first()).toContainText('rollback');
    await gotoStable(page, CONN);
    await expect(page.getByTestId('sync-conn-text-marker')).toHaveText('conductor-sync');

    // conductor-sync still reads AD with the stored connection (two DCs,
    // the CA inline): a plan finishes.
    await gotoStable(page, '/admin/sync');
    await page.getByTestId('sync-btn-plan').click();
    await expect(page).toHaveURL(/\/admin\/sync\/runs\/\d+$/, { timeout: 180_000 });
    await expect(page.getByTestId('sync-run-title')).toBeVisible();
    await expect(page.getByTestId('sync-run-title').getByTestId('sync-badge-planned')).toBeVisible();
  });

  test('auditor: no access to the connection settings', async ({ page }, info) => {
    test.setTimeout(180_000);
    await signInMFA(page, info, 'auditor.user', env.userPassword);
    for (const p of [CONN, '/admin/sync/config/rollback?version=1']) {
      const r = await page.goto(p);
      expect(r!.status(), p).toBe(403);
    }
    const csrf = await csrfOf(page);
    for (const p of [CONN, '/admin/sync/config/marker', '/admin/sync/config/secret', '/admin/sync/config/rollback']) {
      const r = await page.request.post(p, { form: { csrf, name: 'alert_webhook_secret', action: 'remove', version: '1' }, maxRedirects: 0 });
      expect(r.status(), p).toBe(403);
    }
  });
});
