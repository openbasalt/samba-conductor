import { test, expect, env, shot, signIn, signOut, newPassword } from './helpers';

// must.change (pwdLastSet=0, AD 773) and expired.password (AD 532): AD
// proves the password right, conductor asks for it again to change it.
for (const user of ['must.change', 'expired.password']) {
  test(`${user} changes the password with the old one`, async ({ page }, info) => {
    await signIn(page, user, env.userPassword);
    await expect(page).toHaveURL(/\/signin\/password$/);
    await expect(page.getByTestId('signin-password-text-intro')).toContainText(user);
    if (user === 'must.change') await shot(page, info, '02-password-change-required');
    // Nothing else is reachable in this state.
    await page.goto('/me');
    await expect(page).toHaveURL(/\/signin\/password$/);

    const next = newPassword();
    await page.getByTestId('signin-password-input-current').fill('not-the-old-one');
    await page.getByTestId('signin-password-input-new').fill(next);
    await page.getByTestId('signin-password-input-confirm').fill(next);
    await page.getByTestId('signin-password-btn-submit').click();
    await expect(page.getByTestId('form-text-error')).toHaveText(/current password is not correct/);

    await page.getByTestId('signin-password-input-current').fill(env.userPassword);
    await page.getByTestId('signin-password-input-new').fill(next);
    await page.getByTestId('signin-password-input-confirm').fill(next);
    await page.getByTestId('signin-password-btn-submit').click();
    await expect(page).toHaveURL(/\/signin\?m=password_changed$/);
    await expect(page.getByTestId('signin-text-notice')).toContainText('Password changed');

    await signIn(page, user, next);
    await expect(page).toHaveURL(/\/me$/);
    await expect(page.getByTestId('me-text-sam')).toHaveText(user);
    await signOut(page);
  });
}
