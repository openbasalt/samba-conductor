import { Page, TestInfo } from '@playwright/test';
import { test, expect, env, shot, signIn, signInMFA, enroll, freshCode, loadState, gotoStable } from './helpers';

// A user's Attributes tab (every readable attribute, secrets hidden) and,
// when [ui] advanced_attribute_edit is on, the restricted editor. The
// spec enrolls lab.admin and helpdesk.user itself when an earlier spec of
// the run has not (it can run alone with E2E_GREP).

async function adminIn(page: Page, info: TestInfo) {
  if (loadState(info).secrets['lab.admin']) {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
  } else {
    const u = new URL(env.adminEnrollURL);
    await page.goto(u.pathname + u.search);
    await page.getByTestId('signin-input-username').fill('lab.admin');
    await page.getByTestId('signin-input-password').fill(env.adminPassword);
    await page.getByTestId('signin-btn-submit').click();
    await enroll(page, info, 'lab.admin');
    await page.getByTestId('recovery-link-continue').click();
  }
  await expect(page).toHaveURL(/\/admin$/);
}

async function helpdeskIn(page: Page, info: TestInfo) {
  if (loadState(info).secrets['helpdesk.user']) {
    await signInMFA(page, info, 'helpdesk.user', env.helpdeskPassword);
  } else {
    await signIn(page, 'helpdesk.user', env.helpdeskPassword);
    await expect(page).toHaveURL(/\/signin\/enroll$/);
    await enroll(page, info, 'helpdesk.user');
    await page.getByTestId('recovery-link-continue').click();
  }
  await expect(page).toHaveURL(/\/admin\/users$/);
}

// openUser opens a user's overview from the users list and returns its path.
async function openUser(page: Page, sam: string): Promise<string> {
  await gotoStable(page, '/admin/users?q=' + sam);
  await page.getByTestId('users-link-' + sam).click();
  await expect(page.getByTestId('user-text-name')).toContainText(sam);
  return new URL(page.url()).pathname;
}

// confirm applies a previewed change, re-authenticating when asked (the
// second factor is not recent, or the account is protected).
async function confirm(page: Page, info: TestInfo) {
  await expect(page).toHaveURL(/\/confirm\//);
  await expect(page.getByTestId('confirm-text-preview')).toBeVisible();
  if (await page.getByTestId('confirm-text-reauth').isVisible()) {
    await page.getByTestId('confirm-input-password').fill(env.adminPassword);
    await page.getByTestId('confirm-input-code').fill(await freshCode(info, 'lab.admin'));
  }
  await page.getByTestId('confirm-btn-apply').click();
}

async function editAttrs(page: Page, path: string, values: Record<string, string>) {
  await gotoStable(page, path + '/attributes/edit');
  for (const [name, v] of Object.entries(values)) {
    await page.getByTestId('attrs-input-' + name.toLowerCase()).fill(v);
  }
  await page.getByTestId('attrs-btn-preview').click();
}

const secretAttrs = ['unicodepwd', 'dbcspwd', 'supplementalcredentials', 'ntpwdhistory', 'lmpwdhistory', 'userpassword', 'ntsecuritydescriptor'];
// A per-run UID range, far from the seeded and system ranges.
const uidBase = 300000 + Math.floor(Math.random() * 100000) * 10;
let userPath = '';

test.describe.serial('user attributes', () => {
  test('administrator: Attributes tab, known attributes, no secrets', async ({ page }, info) => {
    await adminIn(page, info);
    userPath = await openUser(page, 'user0042');
    await expect(page.getByTestId('user-tab-overview')).toHaveAttribute('aria-current', 'page');
    await page.getByTestId('user-tab-attributes').click();
    await expect(page).toHaveURL(/\/attributes$/);
    await expect(page.getByTestId('user-tab-attributes')).toHaveAttribute('aria-current', 'page');
    const table = page.getByTestId('attrs-table');
    await expect(table).toBeVisible();
    await expect(page.getByTestId('attrs-row-samaccountname')).toContainText('user0042');
    await expect(page.getByTestId('attrs-row-objectsid')).toContainText(/S-1-5-21-\d+-\d+-\d+-\d+/);
    await expect(page.getByTestId('attrs-row-objectguid')).toContainText(/[0-9a-f]{8}-[0-9a-f]{4}-/);
    await expect(page.getByTestId('attrs-row-objectclass')).toContainText('user');
    await expect(page.getByTestId('attrs-row-whencreated')).toBeVisible();
    for (const a of secretAttrs) {
      // Samba never returns them; were it to, only a "hidden" badge shows.
      const row = page.getByTestId('attrs-row-' + a);
      if ((await row.count()) > 0) await expect(page.getByTestId('attrs-hidden-' + a)).toBeVisible();
    }
    await expect(table).not.toContainText(/unicodePwd|supplementalCredentials/i);
    // No horizontal scrolling, also on a phone: long values wrap.
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
    await shot(page, info, '21-attributes');
  });

  test('helpdesk: no Attributes tab, 403 on its URL', async ({ page }, info) => {
    expect(userPath).not.toBe('');
    await helpdeskIn(page, info);
    await openUser(page, 'user0042');
    await expect(page.getByTestId('user-tab-attributes')).toHaveCount(0);
    const res = await gotoStable(page, userPath + '/attributes');
    expect(res?.status()).toBe(403);
    const edit = await gotoStable(page, userPath + '/attributes/edit');
    expect(edit?.status()).toBe(403);
  });

  test('administrator: restricted editor with preview, audit and refusals', async ({ page }, info) => {
    test.setTimeout(240_000);
    await adminIn(page, info);
    const path = await openUser(page, 'user0043');
    await page.getByTestId('user-tab-attributes').click();
    if ((await page.getByTestId('attrs-link-edit').count()) === 0) {
      // [ui] advanced_attribute_edit is off: the editor does not exist.
      const res = await gotoStable(page, path + '/attributes/edit');
      expect(res?.status()).toBe(404);
      test.info().annotations.push({ type: 'skipped', description: 'advanced_attribute_edit is off on this lab' });
      return;
    }
    const uid1 = String(uidBase + 1);
    const uid2 = String(uidBase + 2);

    await page.getByTestId('attrs-link-edit').click();
    await expect(page.getByTestId('attrs-edit-text-warning')).toBeVisible();
    await shot(page, info, '21-attributes-edit');
    await page.getByTestId('attrs-input-loginshell').fill('/bin/bash');
    await page.getByTestId('attrs-input-uidnumber').fill(uid1);
    await page.getByTestId('attrs-btn-preview').click();
    let preview = page.getByTestId('confirm-text-preview');
    await expect(preview).toContainText('replace: loginShell');
    await expect(preview).toContainText('uidNumber: ' + uid1);
    await confirm(page, info);
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('attrs-row-loginshell')).toContainText('/bin/bash');
    await expect(page.getByTestId('attrs-row-uidnumber')).toContainText(uid1);

    // Old and new values in the preview and the audit.
    await editAttrs(page, path, { loginShell: '/bin/zsh', uidNumber: uid2 });
    preview = page.getByTestId('confirm-text-preview');
    await expect(preview).toContainText('loginShell: /bin/bash -> /bin/zsh');
    await expect(preview).toContainText(`uidNumber: ${uid1} -> ${uid2}`);
    await expect(preview).toContainText(`(loginShell=/bin/bash)`);
    await shot(page, info, '21-attributes-preview');
    await confirm(page, info);
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('attrs-row-loginshell')).toContainText('/bin/zsh');
    await gotoStable(page, '/admin/audit?action=user.attributes_update');
    await expect(page.getByTestId('audit-table')).toContainText('user.attributes_update');
    await expect(page.getByTestId('audit-table')).toContainText('loginShell: /bin/bash -> /bin/zsh');
    await expect(page.getByTestId('audit-table')).toContainText(`uidNumber: ${uid1} -> ${uid2}`);

    // Refusals, shown per field before any preview.
    await editAttrs(page, path, { uidNumber: '0' });
    await expect(page.getByTestId('attrs-error-uidnumber')).toBeVisible();
    await expect(page).not.toHaveURL(/\/confirm\//);
    await editAttrs(page, path, { loginShell: 'bin/sh' });
    await expect(page.getByTestId('attrs-error-loginshell')).toContainText('absolute');
    await editAttrs(page, path, { loginShell: '/bin/../etc/shadow' });
    await expect(page.getByTestId('attrs-error-loginshell')).toBeVisible();
    await shot(page, info, '21-attributes-refused');
    // Another account may not take a UID already in use.
    const other = await openUser(page, 'user0044');
    await editAttrs(page, other, { uidNumber: uid2 });
    await expect(page.getByTestId('attrs-error-uidnumber')).toContainText(uid2);
    await expect(page).not.toHaveURL(/\/confirm\//);
  });
});
