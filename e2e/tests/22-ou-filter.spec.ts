import { Page } from '@playwright/test';
import { test, expect, env, shot, signInMFA, gotoStable } from './helpers';

// The container picker of the Users, Groups and Computers lists: the
// search is limited to the chosen OU's subtree, the choice travels as ?ou=
// and survives the text filter, and a container that is not offered falls
// back to the entire domain with a notice.

// ouValue returns the DN of the picker option whose label (indented with
// no-break spaces) is name.
async function ouValue(page: Page, list: string, name: string): Promise<string> {
  const opt = page.getByTestId(`${list}-select-ou`).locator('option', { hasText: new RegExp(`^\\s*${name}$`) });
  await expect(opt).toHaveCount(1);
  return (await opt.getAttribute('value')) ?? '';
}

test.describe.serial('container filter', () => {
  test('administrator: users, groups and computers of one container', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);

    // Users: the seed spreads user0001.. over five department OUs in turn,
    // user0002 and user0007 are in Sales, user0001 in Engineering.
    await gotoStable(page, '/admin/users');
    await expect(page.getByTestId('users-select-ou')).toHaveValue('');
    const sales = await ouValue(page, 'users', 'Sales');
    expect(sales).toMatch(/^OU=Sales,OU=People,OU=Lab,/i);
    await page.getByTestId('users-select-ou').selectOption(sales);
    await page.getByTestId('users-input-search').fill('user000');
    await page.getByTestId('users-btn-search').click();
    await expect(page).toHaveURL(/[?&]ou=/);
    await expect(page.getByTestId('users-row-user0002')).toBeVisible();
    await expect(page.getByTestId('users-row-user0007')).toBeVisible();
    await expect(page.getByTestId('users-row-user0001')).toHaveCount(0);
    await expect(page.getByTestId('users-select-ou')).toHaveValue(sales);
    await expect(page.getByTestId('users-input-search')).toHaveValue('user000');
    await shot(page, info, '22-ou-users');

    // The OU above it holds every department.
    const people = await ouValue(page, 'users', 'People');
    await gotoStable(page, '/admin/users?q=user000&ou=' + encodeURIComponent(people));
    await expect(page.getByTestId('users-row-user0001')).toBeVisible();
    await expect(page.getByTestId('users-row-user0002')).toBeVisible();
    await expect(page.getByTestId('users-row-lab-admin')).toHaveCount(0);

    // A container that is not offered: the entire domain, with a notice.
    await gotoStable(page, '/admin/users?q=lab.admin&ou=' + encodeURIComponent('OU=Nowhere,DC=example,DC=com'));
    await expect(page.getByTestId('users-text-ou-unavailable')).toBeVisible();
    await expect(page.getByTestId('users-select-ou')).toHaveValue('');
    await expect(page.getByTestId('users-row-lab-admin')).toBeVisible();
    // A filter is not a container either.
    await gotoStable(page, '/admin/users?ou=' + encodeURIComponent('(objectClass=*)'));
    await expect(page.getByTestId('users-text-ou-unavailable')).toBeVisible();

    // Groups: the built-in CN=Users container is offered next to the OUs.
    await gotoStable(page, '/admin/groups');
    const builtin = await ouValue(page, 'groups', 'Users');
    expect(builtin).toMatch(/^CN=Users,DC=/i);
    await page.getByTestId('groups-select-ou').selectOption(builtin);
    await page.getByTestId('groups-btn-search').click();
    await expect(page.getByTestId('groups-row-domain-admins')).toBeVisible();
    await expect(page.getByTestId('groups-row-big-group')).toHaveCount(0);
    const groups = await ouValue(page, 'groups', 'Groups');
    await page.getByTestId('groups-select-ou').selectOption(groups);
    await page.getByTestId('groups-btn-search').click();
    await expect(page.getByTestId('groups-row-big-group')).toBeVisible();
    await expect(page.getByTestId('groups-row-domain-admins')).toHaveCount(0);
    await shot(page, info, '22-ou-groups');

    // Computers: the workstations' OU leaves the domain controllers out.
    await gotoStable(page, '/admin/computers');
    const ws = await ouValue(page, 'computers', 'Workstations');
    await page.getByTestId('computers-select-ou').selectOption(ws);
    await page.getByTestId('computers-btn-search').click();
    await expect(page.getByTestId('computers-link-ws0001')).toBeVisible();
    await expect(page.getByTestId('computers-link-dc1')).toHaveCount(0);
  });
});
