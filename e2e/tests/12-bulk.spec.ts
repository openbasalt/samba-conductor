import * as fs from 'node:fs';
import { test, expect, env, shot, signInMFA, freshCode, rand, navTo } from './helpers';

const createHeader = 'username,first_name,last_name,display_name,email,description,ou,groups,must_change_password,enabled';
const updateHeader = 'username,display_name,email,description,title,department,company,telephone,mobile,office,enabled,ou,add_groups,remove_groups';

async function upload(page: any, kind: 'create' | 'update', csv: string) {
  await page.goto('/admin/bulk');
  await page.getByTestId(`bulk-input-${kind}-file`).setInputFiles({ name: `${kind}.csv`, mimeType: 'text/csv', buffer: Buffer.from(csv) });
  await page.getByTestId(`bulk-btn-${kind}`).click();
}

async function applyJob(page: any, info: any) {
  await expect(page.getByTestId('confirm-text-reauth')).toBeVisible();
  await page.getByTestId('confirm-input-password').fill(env.adminPassword);
  await page.getByTestId('confirm-input-code').fill(await freshCode(info, 'lab.admin'));
  await page.getByTestId('job-btn-apply').click();
  await expect(page.getByTestId('job-text-status')).toHaveText('Finished', { timeout: 60_000 });
}

test.describe.serial('bulk operations', () => {
  const tag = rand();
  const users = [1, 2, 3].map((i) => `e2e${tag}${i}`);

  test('invalid files are rejected as a whole, nothing applied', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'bulk');
    await expect(page.getByTestId('bulk-text-create-columns')).toHaveText(createHeader);
    await shot(page, info, '12-bulk');
    // Wrong header.
    await upload(page, 'create', 'user,first\r\nx,y\r\n');
    await expect(page.getByTestId('bulk-text-errors')).toBeVisible();
    // Unknown OU, unknown group and a duplicate, all reported together.
    await upload(page, 'create', [createHeader,
      `${users[0]},A,B,,,,Lab/Nowhere,,yes,yes`,
      `${users[1]},A,B,,,,Lab/People/Sales,No Such Group,yes,yes`,
      `${users[2]},A,B,,,,Lab/People/Sales,,yes,yes`,
      `${users[2]},A,B,,,,Lab/People/Sales,,yes,yes`].join('\r\n'));
    await expect(page.getByTestId('bulk-text-error')).toHaveCount(3);
    await shot(page, info, '12-bulk-errors');
    await page.goto(`/admin/users?q=e2e${tag}`);
    await expect(page.getByTestId('users-text-empty')).toBeVisible();
  });

  test('create users from CSV: full preview, apply, report, passwords once', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    const csv = [createHeader, ...users.map((u, i) => `${u},E2E,User ${i},E2E User ${tag} ${i},${u}@lab.conductor.test,bulk test,Lab/People/Sales,Sales,yes,yes`)].join('\r\n');
    await upload(page, 'create', csv);
    const rows = page.getByTestId('job-table-rows');
    await expect(rows).toContainText('changetype: add');
    await expect(rows).toContainText('unicodePwd: <redacted>');
    await expect(rows).toContainText('add: member');
    await shot(page, info, '12-bulk-preview');
    await applyJob(page, info);
    await expect(page.getByTestId('job-text-counts')).toContainText('3 applied');
    await expect(page.getByTestId('job-text-password')).toHaveCount(3);
    await shot(page, info, '12-bulk-result');
    const report = await page.request.get(page.url() + '/report.csv');
    expect((await report.text()).match(/,ok,/g)).toHaveLength(3);
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByTestId('job-link-passwords').click()]);
    expect(fs.readFileSync(await download.path(), 'utf8').trim().split('\n')).toHaveLength(4);
    await page.goto(`/admin/users?q=e2e${tag}`);
    for (const u of users) await expect(page.getByTestId(`users-row-${u}`)).toBeVisible();
  });

  test('update users from CSV: attributes, disable, group, move', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    const csv = [updateHeader,
      `${users[0]},,,,Engineer,,,,,,,,Support,`,
      `${users[1]},,,(clear),,,,,,,no,,,Sales`,
      `${users[2]},,,,,,,,,,,Lab/People/Support,,`].join('\r\n');
    await upload(page, 'update', csv);
    const rows = page.getByTestId('job-table-rows');
    await expect(rows).toContainText('replace: title');
    await expect(rows).toContainText('delete: member');
    await expect(rows).toContainText('changetype: moddn');
    await applyJob(page, info);
    await expect(page.getByTestId('job-text-counts')).toContainText('3 applied');
    await page.goto(`/admin/users?q=${users[1]}`);
    await expect(page.getByTestId(`users-row-${users[1]}`)).toContainText('Disabled');
    await page.goto(`/admin/users?q=${users[2]}`);
    await page.getByTestId(`users-link-${users[2]}`).click();
    await expect(page.getByTestId('user-text-dn')).toContainText('OU=Support,OU=People');
  });

  test('clean up: delete the created users (selected, typed count)', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto(`/admin/users?q=e2e${tag}`);
    for (const u of users) await page.getByTestId(`sel-check-${u}`).check();
    await page.getByTestId('sel-select-action').selectOption('delete');
    await page.getByTestId('sel-btn-go').click();
    await page.getByTestId('sel-input-confirm').fill('3');
    await page.getByTestId('sel-btn-preview').click();
    await applyJob(page, info);
    await expect(page.getByTestId('job-text-counts')).toContainText('3 applied');
  });
});
