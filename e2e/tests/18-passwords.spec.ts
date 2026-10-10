import { Page, TestInfo } from '@playwright/test';
import { test, expect, env, shot, signInMFA, signOut, apply, navTo, rand, newPassword, loadState, saveState, freshCode } from './helpers';

// Invitations and password reset by e-mail. Needs, on the lab: conductor-provisioner
// (planning lab: provisioner-install.sh) delegated on OU=People, [provisioner] and
// [mail] in conductor.toml, the relay being a mailpit sink whose HTTP API is
// E2E_MAILPIT_URL. Without it the spec is skipped.
const MAILPIT = process.env.E2E_MAILPIT_URL ?? '';
const reauth = (info: TestInfo) => ({ info, user: 'lab.admin', password: env.adminPassword });

type MailSummary = { ID: string; Subject: string; To: { Address: string }[]; Created: string };

// mailsTo lists the messages for an address, newest first.
async function mailsTo(page: Page, address: string): Promise<MailSummary[]> {
  const r = await page.request.get(`${MAILPIT}/api/v1/search?query=${encodeURIComponent('to:"' + address + '"')}`);
  expect(r.ok()).toBeTruthy();
  const body = (await r.json()) as { messages: MailSummary[] };
  return body.messages ?? [];
}

// mailText returns the plain text part of a message.
async function mailText(page: Page, id: string): Promise<string> {
  const r = await page.request.get(`${MAILPIT}/api/v1/message/${id}`);
  expect(r.ok()).toBeTruthy();
  return ((await r.json()) as { Text: string }).Text;
}

// waitMail waits for the count-th message to an address whose subject
// matches, and returns its text.
async function waitMail(page: Page, address: string, subject: RegExp, count = 1): Promise<string> {
  let found: MailSummary[] = [];
  await expect
    .poll(async () => {
      found = (await mailsTo(page, address)).filter((m) => subject.test(m.Subject));
      return found.length;
    }, { timeout: 60_000 })
    .toBeGreaterThanOrEqual(count);
  return mailText(page, found[0].ID);
}

// linkIn extracts the path of the one-time link of a message.
function linkIn(text: string): string {
  const m = text.match(/https:\/\/[^\s]+(\/link\/[A-Za-z0-9_-]{43})/);
  expect(m, 'link in the message').not.toBeNull();
  return m![1];
}

// setPasswordSettings saves Settings > Passwords.
async function setPasswordSettings(page: Page, info: TestInfo, opts: { reset: boolean; mfa: 'if-enrolled' | 'always' }) {
  await navTo(page, 'passwords');
  await expect(page.getByTestId('passwords-list-prov')).toBeVisible();
  const reset = page.getByTestId('passwords-check-reset-enabled');
  if ((await reset.isChecked()) !== opts.reset) await reset.click();
  await page.getByTestId('passwords-select-reset-mfa').selectOption(opts.mfa);
  await page.getByTestId('passwords-input-reset-minutes').fill(String(15 + Math.floor(Math.random() * 10)));
  await shot(page, info, '18p-settings-passwords');
  await page.getByTestId('passwords-btn-preview').click();
  await expect(page.getByTestId('confirm-text-preview')).toContainText('before:');
  await apply(page, { reauth: reauth(info) });
  await expect(page.getByTestId('flash-ok')).toBeVisible();
}

async function requestReset(page: Page, identifier: string): Promise<string> {
  await page.goto('/reset');
  await page.getByTestId('reset-input-identifier').fill(identifier);
  await page.getByTestId('reset-btn-submit').click();
  await expect(page.getByTestId('reset-text-sent')).toBeVisible();
  return page.locator('main').innerText();
}

test.describe.serial('invitations and password reset by e-mail', () => {
  test.skip(!MAILPIT, 'E2E_MAILPIT_URL is not set: the lab has no conductor-provisioner and mail sink');
  const sam = `inv${rand()}`;
  const mail = `${sam}@mail.lab.conductor.test`;
  let password = newPassword();

  test('an administrator turns the reset form on and invites a new user', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await setPasswordSettings(page, info, { reset: true, mfa: 'if-enrolled' });

    // A privileged account: the invitation is refused on its page.
    await page.goto('/admin/users?q=lab.admin');
    await page.getByTestId('users-link-lab-admin').click();
    await expect(page.getByTestId('user-text-invite-reason')).toBeVisible();
    await expect(page.getByTestId('user-btn-invite')).toHaveCount(0);

    // A new account in a managed OU, invited instead of given a password.
    await page.goto('/admin/users/new');
    await page.getByTestId('form-select-parent').selectOption({ label: 'Lab / People' });
    await page.getByTestId('user-new-input-sam').fill(sam);
    await page.getByTestId('user-new-input-given').fill('Invited');
    await page.getByTestId('user-new-input-sn').fill('Person');
    await page.getByTestId('user-new-input-mail').fill(mail);
    await page.getByTestId('user-new-check-invite').check();
    await shot(page, info, '18p-user-new-invite');
    await page.getByTestId('user-new-btn-preview').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('invitation');
    await expect(page.getByTestId('confirm-text-preview')).not.toContainText('unicodePwd: ' + password);
    await apply(page);
    await expect(page.getByTestId('flash-ok').first()).toBeVisible();
    await page.goto('/admin/users?q=' + sam);
    await page.getByTestId('users-link-' + sam).click();
    await expect(page.getByTestId('status-badge-disabled')).toBeVisible();
    await expect(page.getByTestId('user-table-tokens')).toBeVisible();
    await expect(page.getByTestId('user-btn-revoke-invite')).toBeVisible();
    await shot(page, info, '18p-user-invited');
    await signOut(page);
  });

  test('the invited person sets the password and enrolls a second factor', async ({ page }, info) => {
    test.setTimeout(240_000);
    const link = linkIn(await waitMail(page, mail, /set your password/i));
    // Opening only validates: twice is fine.
    await page.goto(link);
    await page.goto(link);
    await expect(page.getByTestId('link-btn-start')).toBeVisible();
    await shot(page, info, '18p-link-invite');
    await page.getByTestId('link-btn-start').click();
    await expect(page).toHaveURL(/\/link\/password$/);
    await page.getByTestId('link-input-password').fill(password);
    await page.getByTestId('link-input-confirm').fill(password);
    await page.getByTestId('link-btn-submit').click();
    await expect(page).toHaveURL(/\/link\/enroll$/);
    const secret = (await page.getByTestId('enroll-text-secret').innerText()).trim();
    const st = loadState(info);
    st.secrets[sam] = secret;
    saveState(info, st);
    await page.getByTestId('enroll-input-code').fill(await freshCode(info, sam));
    await page.getByTestId('enroll-btn-submit').click();
    await expect(page.getByTestId('link-text-done')).toBeVisible();
    await expect(page.getByTestId('link-text-code')).toHaveCount(10);
    await page.screenshot({ path: `screenshots/${info.project.name}/18p-link-done.png`, fullPage: true, mask: [page.getByTestId('link-list-codes')] });
    // Used: the same link is now the neutral page.
    await page.goto(link);
    await expect(page.getByTestId('link-text-invalid')).toBeVisible();
    // The account works, and its owner was told about the password.
    await signInMFA(page, info, sam, password);
    await expect(page).toHaveURL(/\/me$/);
    await signOut(page);
    await waitMail(page, mail, /was changed/i);
  });

  test('reset requests get one answer, whoever is asked for', async ({ page }) => {
    const answers = [await requestReset(page, `nobody-${rand()}`), await requestReset(page, 'lab.admin'), await requestReset(page, mail)];
    expect(answers[1]).toBe(answers[0]);
    expect(answers[2]).toBe(answers[0]);
    // Only the eligible account gets a message.
    await waitMail(page, mail, /reset your password/i);
    expect((await mailsTo(page, 'lab.admin@lab.conductor.test')).filter((m) => /reset/i.test(m.Subject))).toHaveLength(0);
  });

  test('a reset asks for the second factor first', async ({ page }, info) => {
    test.setTimeout(240_000);
    const link = linkIn(await waitMail(page, mail, /reset your password/i));
    await page.goto(link);
    await page.getByTestId('link-btn-start').click();
    await expect(page).toHaveURL(/\/link\/2fa$/);
    await shot(page, info, '18p-link-2fa');
    await page.getByTestId('link-input-code').fill('000000');
    await page.getByTestId('link-btn-code').click();
    await expect(page.getByTestId('form-text-error')).toBeVisible();
    await page.getByTestId('link-input-code').fill(await freshCode(info, sam));
    await page.getByTestId('link-btn-code').click();
    await expect(page).toHaveURL(/\/link\/password$/);
    password = newPassword();
    await page.getByTestId('link-input-password').fill(password);
    await page.getByTestId('link-input-confirm').fill(password);
    await page.getByTestId('link-btn-submit').click();
    await expect(page.getByTestId('link-text-done')).toBeVisible();
    await page.goto(link);
    await expect(page.getByTestId('link-text-invalid')).toBeVisible();
    await waitMail(page, mail, /was changed/i, 2);
    await signInMFA(page, info, sam, password);
    await expect(page).toHaveURL(/\/me$/);
    await signOut(page);
  });

  test('revoked and unknown links show the same neutral page', async ({ page }, info) => {
    test.setTimeout(240_000);
    await requestReset(page, sam);
    const before = (await mailsTo(page, mail)).filter((m) => /reset/i.test(m.Subject)).length;
    const link = linkIn(await waitMail(page, mail, /reset your password/i, before));
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto('/admin/users?q=' + sam);
    await page.getByTestId('users-link-' + sam).click();
    await page.getByTestId('user-btn-revoke-reset').click();
    await apply(page);
    await signOut(page);
    await page.goto(link);
    const revoked = await page.getByTestId('link-card-invalid').innerText();
    await page.goto('/link/' + 'A'.repeat(43));
    expect(await page.getByTestId('link-card-invalid').innerText()).toBe(revoked);
    await page.goto('/link/short');
    expect(await page.getByTestId('link-card-invalid').innerText()).toBe(revoked);
    await shot(page, info, '18p-link-invalid');
  });

  test('a user adds a recovery address', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, sam, password);
    await navTo(page, 'security');
    await page.getByTestId('security-link-recovery-email').click();
    const alt = `alt-${sam}@mail.lab.conductor.test`;
    await page.getByTestId('recovery-input-address').fill(alt);
    await page.getByTestId('recovery-input-password').fill(password);
    await page.getByTestId('recovery-input-mfa').fill(await freshCode(info, sam));
    await page.getByTestId('recovery-btn-send').click();
    const code = (await waitMail(page, alt, /verification code/i)).match(/\b\d{6}\b/)![0];
    await page.getByTestId('recovery-input-code').fill(code);
    await page.getByTestId('recovery-btn-verify').click();
    await expect(page.getByTestId('recovery-text-current')).toContainText('@mail.lab.conductor.test');
    await expect(page.getByTestId('recovery-text-blocked')).toBeVisible();
    await shot(page, info, '18p-recovery-address');
    await signOut(page);
  });

  test('cleanup: the administrator turns the reset form off', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await setPasswordSettings(page, info, { reset: false, mfa: 'if-enrolled' });
    await signOut(page);
  });
});
