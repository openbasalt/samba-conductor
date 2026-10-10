import { Page, TestInfo } from '@playwright/test';
import { test, expect, env, shot, signInMFA, apply, navTo, e2eID } from './helpers';

// Google-first mode (Google Workspace to AD). Needs, on the lab: conductor-sync
// with a [google_first] scope "people" whose Google selection holds at least
// one account, conductor-provisioner delegated on the scope's managed OU, the
// [sync], [provisioner] and [idp] sections in conductor.toml, and:
//   E2E_GF_DOMAIN          the Google domain of the scope (test Cloud Identity domain)
//   E2E_GF_PRIVILEGED_SAM  an account in the managed OU that is privileged in AD
//                          (for example a member of Domain Admins) and selected in Google
//   E2E_GF_MANAGED_USER    the username of an account the mode created (it carries the marker)
// Without E2E_GF_DOMAIN the spec is skipped.
const DOMAIN = process.env.E2E_GF_DOMAIN ?? '';
const PRIVILEGED = process.env.E2E_GF_PRIVILEGED_SAM ?? '';
const MANAGED = process.env.E2E_GF_MANAGED_USER ?? '';
const reauth = (info: TestInfo) => ({ info, user: 'lab.admin', password: env.adminPassword });

// setMode turns the mode on or off from the overview (the preview is confirmed
// with re-authentication).
async function setMode(page: Page, info: TestInfo, on: boolean) {
  await page.goto('/admin/google-first');
  await page.getByTestId('gf-input-domain').fill(DOMAIN);
  const box = page.getByTestId('gf-check-enabled');
  if (on) await box.check();
  else await box.uncheck();
  await page.getByTestId('gf-btn-settings-preview').click();
}

test.describe.serial('Google-first mode', () => {
  test.skip(!DOMAIN, 'E2E_GF_DOMAIN is not set (Google-first lab setup)');

  test('enablement is refused while conductor-idp has a Google SAML application', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await setMode(page, info, false);
    if (page.url().includes('/confirm/')) await apply(page, { reauth: reauth(info) });

    // Register Google Workspace in conductor-idp while the mode is off.
    await navTo(page, 'sso');
    await page.getByTestId('sso-link-new').click();
    await page.getByTestId('sso-link-preset-google-workspace').click();
    await page.getByTestId('sso-input-preset-domain').fill(DOMAIN);
    await page.getByTestId('sso-btn-preset-next').click();
    await page.getByTestId('sso-check-allow-all').check();
    await page.getByTestId('sso-btn-review').click();
    await apply(page, { reauth: reauth(info) });

    // Turning the mode on names the application and saves nothing.
    await setMode(page, info, true);
    await expect(page).toHaveURL(/\/admin\/google-first$/);
    await expect(page.getByTestId('flash-error')).toContainText('Google Workspace');
    await expect(page.getByTestId('gf-p3-refused')).toBeVisible();
    await expect(page.getByTestId('gf-text-state')).not.toHaveText(/^On$/);
    await shot(page, info, '19-gf-p3-refused');

    // Remove the application again.
    await page.goto('/admin/sso/saml/sp?id=' + encodeURIComponent('google.com/a/' + DOMAIN));
    await page.getByTestId('sso-input-sp-delete').fill('Google Workspace (' + DOMAIN + ')');
    await page.getByTestId('sso-btn-sp-delete').click();
    await apply(page, { reauth: reauth(info) });
  });

  test('the mode is turned on and the plan is shown, with the privileged account skipped', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await setMode(page, info, true);
    await expect(page.getByTestId('confirm-text-warning')).toBeVisible();
    await apply(page, { reauth: reauth(info), screenshot: [info, '19-gf-enable-confirm'] });
    await navTo(page, 'google-first');
    await expect(page.getByTestId('gf-text-state')).toHaveText(/On|Ligado/);
    await expect(page.getByTestId('gf-p3-ok')).toBeVisible();
    await page.getByTestId('gf-btn-plan').click();
    await expect(page).toHaveURL(/\/admin\/google-first\/runs\/\d+$/);
    await expect(page.getByTestId('gf-plan-scope-people')).toBeVisible();
    await expect(page.getByTestId('gf-plan-preview-only-people')).toBeVisible();
    await expect(page.getByTestId('gf-plan-limits-people')).toBeVisible();
    if (PRIVILEGED) {
      await expect(page.getByTestId('gf-plan-privileged-people')).toBeVisible();
      await expect(page.getByTestId('gf-plan-skip-privileged-' + e2eID(PRIVILEGED))).toBeVisible();
    }
    // Dry-run: the plan is a preview, the switch to apply needs the typed text.
    await expect(page.getByTestId('gf-plan-form-apply')).toHaveCount(0);
    await expect(page.getByTestId('gf-plan-text-mode-confirmation-people')).toContainText('people ');
    await shot(page, info, '19-gf-plan');
  });

  test('fields Google owns are read only on the edit page', async ({ page }, info) => {
    test.skip(!MANAGED, 'E2E_GF_MANAGED_USER is not set');
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto('/admin/users?q=' + encodeURIComponent(MANAGED));
    await page.getByRole('link', { name: MANAGED, exact: false }).first().click();
    await expect(page.getByTestId('user-text-google-id')).toBeVisible();
    await expect(page.getByTestId('user-text-google-scope')).toContainText('people');
    await page.getByTestId('user-link-edit').click();
    await expect(page.getByTestId('gf-managed-note')).toBeVisible();
    await expect(page.getByTestId('user-edit-managed-mail')).toBeVisible();
    await expect(page.getByTestId('user-edit-input-mail')).toHaveAttribute('readonly', '');
    await expect(page.getByTestId('user-edit-input-description')).not.toHaveAttribute('readonly', '');
    await shot(page, info, '19-gf-managed-fields');

    // A POST that changes a Google-owned field anyway is refused.
    const csrf = await page.locator('input[name="csrf"]').first().inputValue();
    const action = (await page.locator('form[action$="/edit"]').getAttribute('action')) ?? '';
    const r = await page.request.post(action, { form: { csrf, mail: 'someone.else@' + DOMAIN } });
    expect(r.status()).toBe(400);
    expect(await r.text()).toContain('Google');
  });
});
