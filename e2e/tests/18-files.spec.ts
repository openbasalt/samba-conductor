import * as fs from 'node:fs';
import * as path from 'node:path';
import { test, expect, env, shot, signInMFA, apply, navTo, openNav, gotoStable } from './helpers';
import type { Page, TestInfo } from '@playwright/test';

// File servers (P2b). The lab snapshot conductor-p2b has fs1, a Samba
// member file server joined to the domain with conductor-files installed
// and not enrolled; run-lab.sh makes a one-time enrollment code on fs1
// (E2E_FILES_CODE) and runs an SMB watcher on the lab host: a test writes a
// request file into .auth/ and the watcher answers with smbclient run from
// dc2 against fs1 as a lab user (passwords never reach the browser).
const reauth = (info: TestInfo) => ({ info, user: 'lab.admin', password: env.adminPassword });
const share = 'e2e-eng';
const authDir = path.join(__dirname, '..', '.auth');

type SMBResult = { rc: number; out: string };

// smb asks the watcher to run smbclient on dc2 against fs1 as a lab user.
// op: "ls" (list), "write" (upload a file named e2e-<user>.txt, then list),
// "hold" (keep a session open for about 25 s, answered at once).
async function smb(info: TestInfo, user: string, op: 'ls' | 'write' | 'hold', name = share): Promise<SMBResult> {
  const id = `${info.project.name}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const res = path.join(authDir, `smb-res-${id}.json`);
  fs.writeFileSync(path.join(authDir, `smb-req-${id}.json`), JSON.stringify({ share: name, user, op }), { mode: 0o600 });
  for (let i = 0; i < 240; i++) {
    if (fs.existsSync(res)) {
      const r = JSON.parse(fs.readFileSync(res, 'utf8')) as SMBResult;
      fs.unlinkSync(res);
      return r;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('the SMB watcher did not answer (run through e2e/run-lab.sh)');
}

async function serverPage(page: Page) {
  await navTo(page, 'files');
  await page.getByTestId('files-link-server-fs1-lab-conductor-test').click();
  await expect(page.getByTestId('files-server-title')).toHaveText('fs1.lab.conductor.test');
}

test.describe.serial('file servers', () => {
  test('enroll fs1 with a one-time code', async ({ page }, info) => {
    const code = process.env.E2E_FILES_CODE ?? '';
    test.skip(!code, 'E2E_FILES_CODE is set by run-lab.sh');
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'files');
    await openNav(page);
    await expect(page.getByTestId('nav-link-files')).toHaveAttribute('aria-current', 'page');
    await expect(page.getByTestId('files-card-empty')).toBeVisible();
    await page.getByTestId('files-link-new').click();
    // A malformed code is refused before anything is sent.
    await page.getByTestId('files-input-address').fill('fs1.lab.conductor.test');
    await page.getByTestId('files-input-code').fill('cfe1.not-a-code');
    await page.getByTestId('files-btn-enroll').click();
    await expect(page.getByTestId('form-text-error')).toBeVisible();
    await page.getByTestId('files-input-code').fill(code);
    await shot(page, info, '18-files-enroll');
    await page.getByTestId('files-btn-enroll').click();
    const agentPin = 'sha256:' + code.split('.')[2];
    await expect(page.getByTestId('confirm-text-preview')).toContainText('address: fs1.lab.conductor.test:7443');
    await expect(page.getByTestId('confirm-text-preview')).toContainText(agentPin);
    expect(await page.getByTestId('confirm-text-preview').innerText()).not.toContain(code.split('.')[1]);
    await apply(page, { reauth: reauth(info), screenshot: [info, '18-files-enroll-confirm'] });
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('files-server-title')).toHaveText('fs1.lab.conductor.test');
    await expect(page.getByTestId('files-server-state').getByTestId('files-badge-ready')).toBeVisible();
    await expect(page.getByTestId('files-text-agent-pin')).toHaveText(agentPin);
    await expect(page.getByTestId('files-list-checks')).toContainText('include = registry');
    await shot(page, info, '18-files-server');
    await navTo(page, 'files');
    await expect(page.getByTestId('files-row-fs1-lab-conductor-test').getByTestId('files-badge-ready')).toBeVisible();
    await shot(page, info, '18-files-servers');
  });

  test('create a share for Engineering: reachable by members only', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await serverPage(page);
    await page.getByTestId('files-link-new-share').click();

    // 1. Folder: a new folder below the root.
    await expect(page).toHaveURL(/step=folder/);
    await expect(page.getByTestId('files-wizard-browse-path')).toContainText('/srv/shares');
    await page.getByTestId('files-wizard-input-name').fill(share);
    await page.getByTestId('files-wizard-input-comment').fill('Engineering documents');
    await page.getByTestId('files-wizard-input-newdir').fill(share);
    await shot(page, info, '18-files-wizard-folder');
    await page.getByTestId('files-wizard-btn-folder').click();

    // 2. Access: Engineering may modify.
    await expect(page).toHaveURL(/step=access/);
    await expect(page.getByTestId('files-wizard-path')).toContainText('/srv/shares/' + share);
    await page.getByTestId('files-wizard-input-group-q').fill('Engineering');
    await page.getByTestId('files-wizard-btn-group-search').click();
    await page.getByTestId('files-wizard-select-add-engineering').selectOption('modify');
    await page.getByTestId('files-wizard-btn-add-engineering').click();
    await expect(page.getByTestId('files-wizard-table-access')).toContainText('Engineering');
    await shot(page, info, '18-files-wizard-access');
    await page.getByTestId('files-wizard-btn-access-next').click();

    // 3. Options, then the agent's exact plan.
    await expect(page).toHaveURL(/step=options/);
    await expect(page.getByTestId('files-wizard-check-browseable')).toBeChecked();
    await expect(page.getByTestId('files-wizard-check-shadow')).toBeDisabled();
    await page.getByTestId('files-wizard-check-recycle').check();
    await shot(page, info, '18-files-wizard-options');
    await page.getByTestId('files-wizard-btn-review').click();
    await expect(page).toHaveURL(/\/confirm\//);
    await expect(page.getByTestId('files-plan')).toBeVisible();
    await expect(page.getByTestId('files-plan-commands')).toContainText(`net conf import /var/lib/conductor-files/import/${share}.conf ${share}`);
    await expect(page.getByTestId('files-plan-commands')).toContainText('samba-tool ntacl set --use-s3fs');
    await expect(page.getByTestId('files-plan-commands')).toContainText(`sharesec ${share} --replace=`);
    await expect(page.getByTestId('files-plan-section')).toContainText('recycle:repository = .recycle/%U');
    await expect(page.getByTestId('files-diff-nt').locator('.diff-add')).toContainText(['LAB\\Engineering']);
    await expect(page.getByTestId('confirm-text-preview')).toContainText('digest: ');
    await apply(page, { reauth: reauth(info), screenshot: [info, '18-files-share-confirm'] });
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('files-share-title')).toContainText(share);
    await expect(page.getByTestId('files-table-nt-acl')).toContainText('LAB\\Engineering');
    await expect(page.getByTestId('files-table-share-acl')).toContainText('Change');
    await shot(page, info, '18-files-share');

    // From the network: an Engineering member writes, a Sales member is refused.
    const eng = await smb(info, 'user0001', 'write');
    expect(eng.out).toContain('e2e-user0001.txt');
    expect(eng.rc).toBe(0);
    const sales = await smb(info, 'user0002', 'ls');
    expect(sales.out).toContain('NT_STATUS_ACCESS_DENIED');
  });

  test('live sessions are visible', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await serverPage(page);
    expect((await smb(info, 'user0001', 'hold')).rc).toBe(0);
    await page.getByTestId('files-tab-sessions').click();
    await expect(async () => {
      await page.getByTestId('files-link-sessions-refresh').click();
      await expect(page.getByTestId('files-session-row-lab-user0001')).toBeVisible({ timeout: 1000 });
    }).toPass({ timeout: 20_000 });
    await expect(page.getByTestId(`files-connection-row-${share}`)).toBeVisible();
    await shot(page, info, '18-files-sessions');
  });

  test('change access: Engineering read-only, Sales modify', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await serverPage(page);
    await page.getByTestId(`files-link-share-${share}`).click();
    await page.getByTestId('files-link-edit-share').click();
    await expect(page).toHaveURL(/step=access/);
    await page.getByTestId('files-wizard-select-level-lab-engineering').selectOption('read');
    await page.getByTestId('files-wizard-btn-level-lab-engineering').click();
    await page.getByTestId('files-wizard-input-group-q').fill('Sales');
    await page.getByTestId('files-wizard-btn-group-search').click();
    await page.getByTestId('files-wizard-btn-add-sales').click();
    await expect(page.getByTestId('files-wizard-table-access')).toContainText('Sales');
    await page.getByTestId('files-wizard-btn-access-next').click();
    await page.getByTestId('files-wizard-btn-review').click();
    await expect(page.getByTestId('confirm-text-warning')).toBeVisible();
    await expect(page.getByTestId('files-diff-share').locator('.diff-del')).toContainText(['LAB\\Engineering']);
    await expect(page.getByTestId('files-diff-share').locator('.diff-add')).toHaveCount(2);
    await apply(page, { reauth: reauth(info), screenshot: [info, '18-files-share-edit-confirm'] });
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('files-share-access')).toContainText('Sales');

    const sales = await smb(info, 'user0002', 'write');
    expect(sales.out).toContain('e2e-user0002.txt');
    const eng = await smb(info, 'user0001', 'write');
    expect(eng.out).toContain('e2e-user0001.txt'); // still listed (read)
    expect(eng.out).toContain('NT_STATUS_ACCESS_DENIED'); // but no longer writable
  });

  test('auditors read, helpdesk does not see file servers', async ({ page }, info) => {
    await signInMFA(page, info, 'auditor.user', env.userPassword);
    await serverPage(page);
    await expect(page.getByTestId('files-link-new-share')).toHaveCount(0);
    await expect(page.getByTestId('files-btn-remove-server')).toHaveCount(0);
    await page.getByTestId(`files-link-share-${share}`).click();
    await expect(page.getByTestId('files-link-edit-share')).toHaveCount(0);
    expect((await gotoStable(page, '/admin/files/new'))?.status()).toBe(403);
    await page.context().clearCookies();
    await signInMFA(page, info, 'helpdesk.user', env.helpdeskPassword);
    await openNav(page);
    await expect(page.getByTestId('nav-link-files')).toHaveCount(0);
    expect((await gotoStable(page, '/admin/files'))?.status()).toBe(403);
  });

  test('remove the share (folder kept), then the server', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await serverPage(page);
    await page.getByTestId(`files-link-share-${share}`).click();
    await page.getByTestId('files-btn-remove-share').click();
    await expect(page.getByTestId('confirm-text-warning')).toContainText(`/srv/shares/${share}`);
    await expect(page.getByTestId('files-plan-commands')).toContainText(`net conf delshare ${share}`);
    await apply(page, { reauth: reauth(info), screenshot: [info, '18-files-share-remove-confirm'] });
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId(`files-share-row-${share}`)).toHaveCount(0);
    const gone = await smb(info, 'user0002', 'ls');
    expect(gone.out).toContain('NT_STATUS_BAD_NETWORK_NAME');

    // Revoke: the agent drops conductor's key, conductor forgets the server.
    await page.getByTestId('files-btn-remove-server').click();
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('files-card-empty')).toBeVisible();
  });
});
