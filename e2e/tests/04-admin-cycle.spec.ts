import { test, expect, env, shot, signInMFA, apply, rand, newPassword, e2eID } from './helpers';

// A full create / edit / move / delete cycle, every write through its
// preview; privileged changes need password + TOTP again.
test('create, edit, move and delete with previews', async ({ page }, info) => {
  test.setTimeout(300_000);
  const tag = `${info.project.name[0]}${rand()}`;
  const ou = `E2E ${tag}`;
  const sub = `Sub ${tag}`;
  const sam = `e2e.${tag}`;
  const group = `E2E Group ${tag}`;
  const reauth = { info, user: 'lab.admin', password: env.adminPassword };
  await signInMFA(page, info, 'lab.admin', env.adminPassword);

  // OU at the domain root, then a child OU.
  await page.goto('/admin/ous');
  await page.getByTestId('ous-input-new-name').fill(ou);
  await page.getByTestId('ous-input-new-description').fill('created by the e2e suite');
  await page.getByTestId('ous-btn-new').click();
  await expect(page.getByTestId('confirm-text-preview')).toContainText('objectClass: organizationalUnit');
  await apply(page, { screenshot: [info, '04-preview-create-ou'] });
  await expect(page.getByTestId('flash-ok')).toBeVisible();
  await page.getByTestId(`ous-link-${e2eID(ou)}`).click();
  await page.getByTestId('ou-input-child').fill(sub);
  await page.getByTestId('ou-btn-child').click();
  await apply(page);
  await expect(page.getByTestId(`ous-link-${e2eID(sub)}`)).toBeVisible();
  await shot(page, info, '04-ous');

  // User in the new OU.
  const pw = newPassword();
  await page.goto('/admin/users/new');
  await page.getByTestId('form-select-parent').selectOption({ label: ou });
  await page.getByTestId('user-new-input-given').fill('Erin');
  await page.getByTestId('user-new-input-sn').fill(`Test ${tag}`);
  await page.getByTestId('user-new-input-sam').fill(sam);
  await page.getByTestId('user-new-input-mail').fill(`${sam}@lab.conductor.test`);
  await page.getByTestId('user-new-input-password').fill(pw);
  await page.getByTestId('user-new-input-confirm').fill(pw);
  await page.getByTestId('user-new-btn-preview').click();
  const preview = page.getByTestId('confirm-text-preview');
  await expect(preview).toContainText(`sAMAccountName: ${sam}`);
  await expect(preview).toContainText('unicodePwd: <redacted>');
  await expect(preview).not.toContainText(pw);
  await apply(page, { screenshot: [info, '04-preview-create-user'] });
  await page.getByTestId(`users-link-${e2eID(sam)}`).click();
  await expect(page.getByTestId('status-badge-must-change')).toBeVisible();
  const userURL = page.url();

  // Edit attributes from the allowlist.
  await page.getByTestId('user-link-edit').click();
  await page.getByTestId('user-edit-input-title').fill('QA Engineer');
  await page.getByTestId('user-edit-input-telephonenumber').fill('+55 11 5555-0101');
  await page.getByTestId('user-edit-btn-preview').click();
  await expect(page.getByTestId('confirm-text-preview')).toContainText('replace: title');
  await apply(page);
  await expect(page.getByTestId('user-text-title')).toHaveText('QA Engineer');

  // Group in the OU, user as member (from the group page).
  await page.goto('/admin/groups/new');
  await page.getByTestId('form-select-parent').selectOption({ label: ou });
  await page.getByTestId('group-new-input-name').fill(group);
  await page.getByTestId('group-new-btn-preview').click();
  await expect(page.getByTestId('confirm-text-preview')).toContainText('groupType: -2147483646');
  await apply(page);
  await page.getByTestId(`groups-link-${e2eID(group)}`).click();
  await page.getByTestId('group-input-add-member').fill(sam);
  await page.getByTestId('group-btn-add-member').click();
  await expect(page.getByTestId('confirm-text-preview')).toContainText('add: member');
  await apply(page);
  await expect(page.getByTestId('group-table-members')).toContainText(`Erin Test ${tag}`);
  await shot(page, info, '04-group');

  // Domain Admins membership needs re-authentication, both ways.
  await page.goto(userURL);
  await page.getByTestId('user-input-add-group').fill('Domain Admins');
  await page.getByTestId('user-btn-add-group').click();
  await expect(page.getByTestId('confirm-text-warning')).toBeVisible();
  await shot(page, info, '04-preview-reauth');
  // Wrong password: refused, nothing applied.
  await page.getByTestId('confirm-input-password').fill('wrong-password');
  await page.getByTestId('confirm-input-code').fill('000000');
  await page.getByTestId('confirm-btn-apply').click();
  await expect(page.getByTestId('form-text-error')).toBeVisible();
  await apply(page, { reauth });
  await expect(page.getByTestId('user-row-group-domain-admins')).toBeVisible();
  await expect(page.getByTestId('user-badge-protected')).toBeVisible();
  await page.getByTestId('user-btn-remove-group-domain-admins').click();
  await apply(page, { reauth });
  await expect(page.getByTestId('user-row-group-domain-admins')).toHaveCount(0);

  // Disable / enable, then move to the child OU.
  await page.getByTestId('user-btn-disable').click();
  await expect(page.getByTestId('confirm-text-preview')).toContainText('userAccountControl');
  await apply(page);
  await expect(page.getByTestId('status-badge-disabled')).toBeVisible();
  await page.getByTestId('user-btn-enable').click();
  await apply(page);
  await expect(page.getByTestId('status-badge-enabled')).toBeVisible();
  await page.getByTestId('user-link-move').click();
  await page.getByTestId('form-select-parent').selectOption({ label: `${ou} / ${sub}` });
  await page.getByTestId('move-btn-preview').click();
  await expect(page.getByTestId('confirm-text-preview')).toContainText('changetype: moddn');
  await apply(page);
  await expect(page.getByTestId('user-text-dn')).toContainText(`OU=${sub},OU=${ou}`);
  await shot(page, info, '04-user');

  // Rename the child OU.
  await page.goto('/admin/ous');
  await page.getByTestId(`ous-link-${e2eID(sub)}`).click();
  await page.getByTestId('ou-input-rename').fill(`${sub} renamed`);
  await page.getByTestId('ou-btn-rename').click();
  await apply(page);
  await expect(page.getByTestId(`ous-link-${e2eID(sub + ' renamed')}`)).toBeVisible();

  // Computers: disable/enable WS0002, move WS0003 into the OU and delete it.
  await page.goto('/admin/computers?q=WS0002');
  await page.getByTestId('computers-link-ws0002').click();
  await page.getByTestId('computer-btn-disable').click();
  await apply(page);
  await expect(page.getByTestId('computer-badge-disabled')).toBeVisible();
  await page.getByTestId('computer-btn-enable').click();
  await apply(page);
  await expect(page.getByTestId('computer-badge-enabled')).toBeVisible();
  await page.goto('/admin/computers?q=WS0003');
  await page.getByTestId('computers-link-ws0003').click();
  await page.getByTestId('form-select-parent').selectOption({ label: ou });
  await page.getByTestId('computer-btn-move').click();
  await apply(page);
  await expect(page.getByTestId('computer-text-dn')).toContainText(`OU=${ou}`);
  await page.getByTestId('computer-btn-delete').click();
  await expect(page.getByTestId('confirm-text-preview')).toContainText('changetype: delete');
  await apply(page);
  await expect(page.getByTestId('flash-ok')).toBeVisible();
  // Domain controllers are not managed here.
  await page.goto('/admin/computers?q=DC1');
  await page.getByTestId('computers-link-dc1').click();
  await expect(page.getByTestId('computer-text-dc-protected')).toBeVisible();

  // The OU is not empty yet: no delete button.
  await page.goto('/admin/ous');
  await page.getByTestId(`ous-link-${e2eID(ou)}`).click();
  await expect(page.getByTestId('ou-text-not-empty')).toBeVisible();

  // Delete everything again.
  await page.goto(userURL);
  await page.getByTestId('user-btn-delete').click();
  await expect(page.getByTestId('confirm-text-warning')).toBeVisible();
  await apply(page);
  await page.goto(`/admin/groups?q=${encodeURIComponent(group)}`);
  await page.getByTestId(`groups-link-${e2eID(group)}`).click();
  await page.getByTestId('group-btn-delete').click();
  await apply(page);
  await page.goto('/admin/ous');
  await page.getByTestId(`ous-link-${e2eID(sub + ' renamed')}`).click();
  await page.getByTestId('ou-btn-delete').click();
  await apply(page);
  await page.getByTestId(`ous-link-${e2eID(ou)}`).click();
  await page.getByTestId('ou-btn-delete').click();
  await apply(page);
  await expect(page.getByTestId(`ous-link-${e2eID(ou)}`)).toHaveCount(0);

  // Everything above is in the audit log.
  await page.getByTestId('nav-link-audit').click();
  await page.getByTestId('audit-input-target').fill(tag);
  await page.getByTestId('audit-btn-filter').click();
  await expect(page.getByTestId('audit-table')).toContainText('ou.create');
  await expect(page.getByTestId('audit-table')).toContainText('user.create');
  await expect(page.getByTestId('audit-table')).toContainText('group.add_member');
  await expect(page.getByTestId('audit-table')).toContainText('ou.delete');
  await shot(page, info, '04-audit');
});
