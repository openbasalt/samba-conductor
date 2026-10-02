import { test, expect, env, shot, signIn, enroll, csrfOf, navTo } from './helpers';
import * as fs from 'node:fs';

test('auditor sees everything and changes nothing', async ({ page }, info) => {
  await signIn(page, 'auditor.user', env.userPassword);
  await expect(page).toHaveURL(/\/signin\/enroll$/);
  await enroll(page, info, 'auditor.user');
  await page.getByTestId('recovery-link-continue').click();
  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.getByTestId('dashboard-table-audit')).toBeVisible();

  await navTo(page, 'groups');
  await expect(page.getByTestId('groups-link-new')).toHaveCount(0);
  await page.getByTestId('groups-input-search').fill('Engineering Leads');
  await page.getByTestId('groups-btn-search').click();
  await page.getByTestId('groups-link-engineering-leads').click();
  // Nested view: parent and child groups.
  await expect(page.getByTestId('group-link-parent-engineering')).toBeVisible();
  await expect(page.getByTestId('group-link-nested-platform-team')).toBeVisible();
  await expect(page.getByTestId('group-btn-delete')).toHaveCount(0);
  await shot(page, info, '06-group-nested');

  await page.goto('/admin/users?q=user0007');
  await page.getByTestId('users-link-user0007').click();
  await expect(page.getByTestId('user-link-reset')).toHaveCount(0);
  await expect(page.getByTestId('user-btn-disable')).toHaveCount(0);
  const userURL = page.url();

  // A forged write with a valid CSRF token is still refused by role.
  const csrf = await csrfOf(page);
  const r = await page.request.post(userURL + '/disable', { form: { csrf }, maxRedirects: 0 });
  expect(r.status()).toBe(403);

  await navTo(page, 'ous');
  await expect(page.getByTestId('ous-link-people')).toBeVisible();
  await expect(page.getByTestId('ous-input-new-name')).toHaveCount(0);
  await navTo(page, 'computers');
  await expect(page.getByTestId('computers-link-ws0001')).toBeVisible();

  await navTo(page, 'audit');
  await page.getByTestId('audit-input-action').fill('signin.');
  await page.getByTestId('audit-btn-filter').click();
  await expect(page.getByTestId('audit-table')).toContainText('signin.failure');
  await shot(page, info, '06-audit');
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByTestId('audit-link-export').click()]);
  const lines = fs.readFileSync(await download.path(), 'utf8').trim().split('\n');
  expect(lines.length).toBeGreaterThan(5);
  for (const l of lines) {
    const ev = JSON.parse(l);
    expect(ev.action.startsWith('signin.')).toBeTruthy();
    expect(ev.hash).toMatch(/^[0-9a-f]{64}$/);
  }
  await navTo(page, 'domain');
  await expect(page.getByTestId('domain-text-forest')).toContainText('2016');
});
