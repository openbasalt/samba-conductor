import { test, expect, env, shot, signInMFA, apply, rand, navTo } from './helpers';

const reauth = (info: any) => ({ info, user: 'lab.admin', password: env.adminPassword });

test.describe.serial('password policy', () => {
  test('domain policy: view, change with re-authentication, lockout warning', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'policy');
    await expect(page.getByTestId('policy-text-threshold').first()).toHaveText('10');
    await expect(page.getByTestId('policy-text-no-lockout')).toHaveCount(0);
    await expect(page.getByTestId('policy-row-lab-staff-20d')).toBeVisible();
    await shot(page, info, '10-policy');

    await page.getByTestId('policy-link-edit').click();
    await page.getByTestId('policy-input-min-length').fill('8');
    await page.getByTestId('policyedit-btn-preview').click();
    const preview = page.getByTestId('confirm-text-preview');
    await expect(preview).toContainText('# minimum length: 7 -> 8');
    await expect(preview).toContainText('(minPwdLength=7)');
    await apply(page, { reauth: reauth(info), screenshot: [info, '10-policy-preview'] });
    await expect(page.getByTestId('policy-text-min-length').first()).toHaveText('8');

    // Turning lockout off is warned about (and not applied here).
    await page.getByTestId('policy-link-edit').click();
    await page.getByTestId('policy-input-min-length').fill('7');
    await page.getByTestId('policy-input-threshold').fill('0');
    await page.getByTestId('policyedit-btn-preview').click();
    await expect(page.getByTestId('confirm-text-warning')).toContainText('never lock out');
    await shot(page, info, '10-policy-lockout-warning');
    await page.getByTestId('confirm-btn-cancel').click();
    // Restore the length.
    await page.getByTestId('policy-link-edit').click();
    await page.getByTestId('policy-input-min-length').fill('7');
    await page.getByTestId('policyedit-btn-preview').click();
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('policy-text-min-length').first()).toHaveText('7');
  });

  test('fine-grained policy: create, apply, effective policy, remove', async ({ page }, info) => {
    test.setTimeout(300_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    // The seeded 20-day policy is in effect for user0101.
    await page.goto('/admin/users?q=user0101');
    await page.getByTestId('users-link-user0101').click();
    await page.getByTestId('user-link-policy').click();
    await expect(page.getByTestId('effective-link-pso')).toHaveText('lab-staff-20d');
    await expect(page.getByTestId('effective-text-expiry')).toContainText(/expires|expira/);
    await shot(page, info, '10-effective-policy');

    const name = `e2e-pso-${rand()}`;
    await page.goto('/admin/policy/pso/new');
    await page.getByTestId('policyedit-input-name').fill(name);
    await page.getByTestId('policy-input-precedence').fill('5');
    await page.getByTestId('policy-input-min-length').fill('14');
    await page.getByTestId('policyedit-btn-preview').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('objectClass: msDS-PasswordSettings');
    await apply(page, { reauth: reauth(info) });
    await page.getByTestId(`policy-link-pso-${name}`).click();
    await page.getByTestId('pso-input-target').fill('user0301');
    await page.getByTestId('pso-btn-apply').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('add: msDS-PSOAppliesTo');
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('pso-row-user-0301')).toBeVisible();
    await shot(page, info, '10-pso');

    await page.goto('/admin/users?q=user0301');
    await page.getByTestId('users-link-user0301').click();
    await page.getByTestId('user-link-policy').click();
    await expect(page.getByTestId('effective-link-pso')).toHaveText(name);
    await expect(page.getByTestId('policy-text-min-length')).toHaveText('14');

    await page.getByTestId('effective-link-pso').click();
    await page.getByTestId('pso-btn-unapply-user-0301').click();
    await apply(page, { reauth: reauth(info) });
    await page.getByTestId('pso-btn-delete').click();
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId(`policy-link-pso-${name}`)).toHaveCount(0);
  });
});
