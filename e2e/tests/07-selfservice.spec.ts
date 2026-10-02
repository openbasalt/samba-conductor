import { test, expect, env, shot, signIn, signOut, apply, enroll, freshCode, newPassword } from './helpers';

test('self-service profile, password and optional 2FA', async ({ page }, info) => {
  test.setTimeout(240_000);
  const user = info.project.name === 'desktop' ? 'user0011' : 'user0012';
  await signIn(page, user, env.userPassword);
  await expect(page).toHaveURL(/\/me$/);
  // Regular users have no admin navigation.
  await expect(page.getByTestId('nav-link-users')).toHaveCount(0);
  const r = await page.goto('/admin/users');
  expect(r!.status()).toBe(403);

  // Edit the attributes AD lets users write on themselves.
  await page.goto('/me/edit');
  await expect(page.getByTestId('me-edit-input-title')).toHaveCount(0);
  await page.getByTestId('me-edit-input-mobile').fill('+55 11 98888-0000');
  await page.getByTestId('me-edit-input-l').fill('Campinas');
  await page.getByTestId('me-edit-btn-preview').click();
  await expect(page.getByTestId('confirm-text-preview')).toContainText('replace: mobile');
  await apply(page, { screenshot: [info, '07-preview-self-edit'] });
  await expect(page.getByTestId('me-text-mobile')).toHaveText('+55 11 98888-0000');
  await expect(page.getByTestId('me-text-l')).toHaveText('Campinas');
  await shot(page, info, '07-me');

  // Change the password: the current one is required.
  const next = newPassword();
  await page.getByTestId('me-link-password').click();
  await page.getByTestId('me-password-input-current').fill('wrong');
  await page.getByTestId('me-password-input-new').fill(next);
  await page.getByTestId('me-password-input-confirm').fill(next);
  await page.getByTestId('me-password-btn-submit').click();
  await expect(page.getByTestId('form-text-error')).toHaveText(/current password is not correct/);
  await page.getByTestId('me-password-input-current').fill(env.userPassword);
  await page.getByTestId('me-password-input-new').fill(next);
  await page.getByTestId('me-password-input-confirm').fill(next);
  await page.getByTestId('me-password-btn-submit').click();
  await expect(page.getByTestId('flash-ok')).toBeVisible();

  // Optional 2FA: enroll, then it is asked at sign-in.
  await page.getByTestId('me-link-security').click();
  await expect(page.getByTestId('security-text-mfa-off')).toBeVisible();
  await page.getByTestId('security-link-enroll').click();
  await enroll(page, info, user);
  await page.getByTestId('recovery-link-continue').click();
  await page.goto('/me/security');
  await expect(page.getByTestId('security-text-mfa-on')).toBeVisible();
  await shot(page, info, '07-security');
  await signOut(page);
  await signIn(page, user, next);
  await expect(page).toHaveURL(/\/signin\/2fa$/);
  await shot(page, info, '07-signin-2fa');
  await page.getByTestId('mfa-input-code').fill(await freshCode(info, user));
  await page.getByTestId('mfa-btn-submit').click();
  await expect(page).toHaveURL(/\/me$/);

  // Turn it off again (password + code), then sign out everywhere.
  await page.goto('/me/security');
  await page.getByTestId('security-input-disable-password').fill(next);
  await page.getByTestId('security-input-disable-code').fill(await freshCode(info, user));
  await page.getByTestId('security-btn-disable').click();
  await expect(page.getByTestId('security-text-mfa-off')).toBeVisible();
  await page.getByTestId('security-btn-signout-all').click();
  await expect(page.getByTestId('signin-text-notice')).toContainText('All your sessions');
});
