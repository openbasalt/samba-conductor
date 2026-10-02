import { test, expect, env, shot, signIn, apply, enroll, newPassword } from './helpers';

test('helpdesk resets and unlocks in its OU, never on an administrator', async ({ page }, info) => {
  test.setTimeout(240_000);
  // Delegated roles enroll 2FA on first sign-in.
  await signIn(page, 'helpdesk.user', env.helpdeskPassword);
  await expect(page).toHaveURL(/\/signin\/enroll$/);
  await enroll(page, info, 'helpdesk.user');
  await page.getByTestId('recovery-link-continue').click();
  await expect(page).toHaveURL(/\/admin\/users$/);
  await expect(page.getByTestId('nav-link-groups')).toHaveCount(0);
  await expect(page.getByTestId('users-link-new')).toHaveCount(0);

  // Reset a password inside OU=People (forces a change by default).
  await page.getByTestId('users-input-search').fill('user0042');
  await page.getByTestId('users-btn-search').click();
  await page.getByTestId('users-link-user0042').click();
  await expect(page.getByTestId('user-link-edit')).toHaveCount(0);
  await page.getByTestId('user-link-reset').click();
  await expect(page.getByTestId('reset-check-must-change')).toBeChecked();
  const pw = newPassword();
  await page.getByTestId('reset-input-new').fill(pw);
  await page.getByTestId('reset-input-confirm').fill(pw);
  await page.getByTestId('reset-btn-preview').click();
  const preview = page.getByTestId('confirm-text-preview');
  await expect(preview).toContainText('unicodePwd: <redacted>');
  await expect(preview).toContainText('pwdLastSet: 0');
  await expect(preview).not.toContainText(pw);
  await apply(page, { screenshot: [info, '05-preview-reset'] });
  await expect(page.getByTestId('flash-ok')).toBeVisible();
  await expect(page.getByTestId('status-badge-must-change')).toBeVisible();

  // Unlock a locked account inside OU=People.
  await page.goto('/admin/users?q=locked.people');
  await page.getByTestId('users-link-locked-people').click();
  await expect(page.getByTestId('status-badge-locked')).toBeVisible();
  await page.getByTestId('user-btn-unlock').click();
  await expect(page.getByTestId('confirm-text-preview')).toContainText('lockoutTime');
  await apply(page);
  await expect(page.getByTestId('status-badge-locked')).toHaveCount(0);

  // Outside the delegated OU, AD itself refuses.
  await page.goto('/admin/users?q=normal.user');
  await page.getByTestId('users-link-normal-user').click();
  await page.getByTestId('user-link-reset').click();
  await page.getByTestId('reset-input-new').fill(pw);
  await page.getByTestId('reset-input-confirm').fill(pw);
  await page.getByTestId('reset-btn-preview').click();
  await apply(page);
  await expect(page.getByTestId('flash-error')).toContainText('refused');

  // A Domain Admin is refused by conductor before AD is asked.
  await page.goto('/admin/users?q=lab.admin');
  await page.getByTestId('users-link-lab-admin').click();
  await expect(page.getByTestId('user-badge-protected')).toBeVisible();
  await page.getByTestId('user-link-reset').click();
  await page.getByTestId('reset-input-new').fill(pw);
  await page.getByTestId('reset-input-confirm').fill(pw);
  await page.getByTestId('reset-btn-preview').click();
  await expect(page.getByTestId('error-text-message')).toContainText('protected');
  await shot(page, info, '05-helpdesk-refused-admin');

  // Pages of other roles are refused.
  for (const p of ['/admin/groups', '/admin/audit', '/admin', '/admin/users/new']) {
    const r = await page.goto(p);
    expect(r!.status(), p).toBe(403);
  }
});
