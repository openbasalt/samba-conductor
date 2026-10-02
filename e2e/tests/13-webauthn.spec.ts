import { CDPSession, Page } from '@playwright/test';
import { test, expect, env, shot, signIn, signInMFA, signOut, freshCode, loadState, saveState } from './helpers';

// WebAuthn with Chromium's virtual authenticator (CDP): a security key
// that is present and verifies the user automatically.
async function virtualKey(page: Page): Promise<CDPSession> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true },
  });
  return client;
}

test.describe.serial('security keys (WebAuthn)', () => {
  test('a user registers a key, then signs in with it', async ({ page }, info) => {
    await virtualKey(page);
    await signIn(page, 'normal.user', env.userPassword);
    await expect(page).toHaveURL(/\/me$/);
    await page.goto('/me/security');
    await expect(page.getByTestId('security-text-no-keys')).toBeVisible();
    // The script is loaded on this page only (CSP nonce + SRI).
    await expect(page.locator('script[src^="/static/webauthn.js"]')).toHaveCount(1);
    await expect(page.getByTestId('key-btn-register')).toBeEnabled();
    await page.getByTestId('key-input-name').fill('E2E key');
    await shot(page, info, '13-security-keys');
    await page.getByTestId('key-btn-register').click();
    // The first key comes with recovery codes (the user had no 2FA).
    await expect(page.getByTestId('recovery-list-codes')).toBeVisible();
    const codes = await page.getByTestId('recovery-text-code').allInnerTexts();
    const st = loadState(info);
    st.passwords['normal.user.recovery'] = codes[0];
    saveState(info, st);
    await page.goto('/me/security');
    await expect(page.getByTestId('security-row-key-e2e-key')).toBeVisible();
    // Every other page stays script-free.
    for (const p of ['/me', '/me/password']) {
      await page.goto(p);
      await expect(page.locator('script')).toHaveCount(0);
    }
    await signOut(page);

    await signIn(page, 'normal.user', env.userPassword);
    await expect(page).toHaveURL(/\/signin\/2fa$/);
    await expect(page.getByTestId('key-btn-use')).toBeEnabled();
    await shot(page, info, '13-signin-key');
    await page.getByTestId('key-btn-use').click();
    await expect(page).toHaveURL(/\/me$/);
    await page.goto('/me/security');
    await expect(page.getByTestId('security-row-key-e2e-key')).not.toContainText('—');
    await signOut(page);
  });

  test('an administrator re-authenticates a protected change with a key', async ({ page }, info) => {
    await virtualKey(page);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto('/me/security');
    await page.getByTestId('key-input-name').fill('Admin key');
    await page.getByTestId('key-btn-register').click();
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('security-row-key-admin-key')).toBeVisible();

    // A change that needs re-authentication (a privileged group), confirmed
    // with the key instead of a TOTP code.
    await page.goto('/admin/users?q=helpdesk.user');
    await page.getByTestId('users-link-helpdesk-user').click();
    await page.getByTestId('user-input-add-group').fill('Backup Operators');
    await page.getByTestId('user-btn-add-group').click();
    await expect(page.getByTestId('confirm-text-reauth')).toBeVisible();
    await page.getByTestId('confirm-link-key').click();
    await expect(page.getByTestId('confirmkey-card')).toBeVisible();
    await page.getByTestId('key-input-password').fill(env.adminPassword);
    await shot(page, info, '13-reauth-key');
    await page.getByTestId('key-btn-use').click();
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('user-row-group-backup-operators')).toBeVisible();
    // Undo, re-authenticating with TOTP this time.
    await page.getByTestId('user-btn-remove-group-backup-operators').click();
    await page.getByTestId('confirm-input-password').fill(env.adminPassword);
    await page.getByTestId('confirm-input-code').fill(await freshCode(info, 'lab.admin'));
    await page.getByTestId('confirm-btn-apply').click();
    await expect(page.getByTestId('user-row-group-backup-operators')).toHaveCount(0);

    // Remove the key: re-authentication with the key itself.
    await page.goto('/me/security');
    await page.getByTestId('security-link-remove-key-admin-key').click();
    await page.getByTestId('key-input-password').fill(env.adminPassword);
    await page.getByTestId('key-btn-use').click();
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('security-row-key-admin-key')).toHaveCount(0);
    await signOut(page);
  });

  test('a wrong key or a cancelled ceremony is refused', async ({ page }, info) => {
    // A fresh virtual authenticator holds no credential for normal.user.
    await virtualKey(page);
    await signIn(page, 'normal.user', env.userPassword);
    await expect(page).toHaveURL(/\/signin\/2fa$/);
    await page.getByTestId('key-btn-use').click();
    await expect(page.getByTestId('key-text-error')).toBeVisible();
    // The recovery code still works.
    const st = loadState(info);
    await page.getByTestId('mfa-input-code').fill(st.passwords['normal.user.recovery']);
    await page.getByTestId('mfa-btn-submit').click();
    await expect(page).toHaveURL(/\/me$/);
  });
});
