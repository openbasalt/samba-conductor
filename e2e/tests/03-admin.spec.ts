import { test, expect, env, shot, signIn, signInMFA, signOut, enroll, navTo, openNav } from './helpers';

test.describe.serial('administrator', () => {
  test('forced 2FA enrollment through the one-time link', async ({ page }, info) => {
    const u = new URL(env.adminEnrollURL);
    await page.goto(u.pathname + u.search);
    await expect(page.getByTestId('signin-text-enroll')).toBeVisible();
    await page.getByTestId('signin-input-username').fill('lab.admin');
    await page.getByTestId('signin-input-password').fill(env.adminPassword);
    await page.getByTestId('signin-btn-submit').click();
    await expect(page).toHaveURL(/\/signin\/enroll$/);
    // No admin page before enrollment.
    await page.goto('/admin');
    await expect(page).toHaveURL(/\/signin\/enroll$/);
    await enroll(page, info, 'lab.admin', '03-admin-enroll');
    await shot(page, info, '03-recovery-codes');
    await page.getByTestId('recovery-link-continue').click();
    await expect(page).toHaveURL(/\/admin$/);
    await signOut(page);
    // Enrolled now: the next sign-in asks for a code, link or not.
    await page.goto(u.pathname + u.search);
    await signIn(page, 'lab.admin', env.adminPassword);
    await expect(page).toHaveURL(/\/signin\/2fa$/);
  });

  test('dashboard, users with server-side search and paging', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await expect(page).toHaveURL(/\/admin$/);
    await expect(page.getByTestId('dashboard-text-users')).toHaveText(/^2[5-9]\d\d$/);
    await expect(page.getByTestId('dashboard-link-locked-locked-user')).toBeVisible();
    // Grouped sidebar: every group for an administrator, the current page marked.
    await openNav(page);
    for (const g of ['overview', 'directory', 'policies', 'network', 'operations', 'audit', 'account']) {
      await expect(page.getByTestId('nav-group-' + g)).toBeVisible();
    }
    await expect(page.getByTestId('nav-link-dashboard')).toHaveAttribute('aria-current', 'page');
    await expect(page.getByTestId('nav-link-security')).toBeVisible();
    await shot(page, info, '03-dashboard');

    await navTo(page, 'users');
    await expect(page.getByTestId('users-table')).toBeVisible();
    await expect(page.getByTestId('pager-link-next')).toBeVisible();
    await page.getByTestId('pager-link-next').click();
    await expect(page.getByTestId('pager-text-page')).toHaveText('Page 2');
    await page.getByTestId('users-input-search').fill('user01');
    await page.getByTestId('users-btn-search').click();
    await expect(page.getByTestId('users-row-user0100')).toBeVisible();
    await expect(page.getByTestId('users-row-user0001')).toHaveCount(0);
    await shot(page, info, '03-users');
    await page.getByTestId('users-select-status').selectOption('locked');
    await page.getByTestId('users-input-search').fill('');
    await page.getByTestId('users-btn-search').click();
    await expect(page.getByTestId('users-row-locked-user')).toBeVisible();
    await page.getByTestId('users-link-locked-user').click();
    await expect(page.getByTestId('status-badge-locked')).toBeVisible();
    await shot(page, info, '03-user-locked');
  });

  test('domain information through conductor-helper', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'domain');
    await expect(page.getByTestId('domain-text-helper')).toBeVisible();
    await expect(page.getByTestId('domain-text-domain')).toContainText('2016');
    await expect(page.getByTestId('domain-list-dcs')).toContainText('DC1');
    await expect(page.getByTestId('domain-list-dcs')).toContainText('DC2');
    await expect(page.getByTestId('domain-table-fsmo')).toContainText('PdcEmulationMasterRole');
    await shot(page, info, '03-domain');
  });
});
