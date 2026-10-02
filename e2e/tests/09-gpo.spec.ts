import { test, expect, env, shot, signInMFA, apply, rand, navTo } from './helpers';

test.describe.serial('Group Policy', () => {
  test('GPOs and links; settings editing is out of scope', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'gpo');
    await expect(page.getByTestId('gpo-text-scope')).toBeVisible();
    await expect(page.getByTestId('gpo-row-lab-baseline')).toContainText('Enforced');
    await expect(page.getByTestId('gpo-text-unlinked-lab-unlinked')).toBeVisible();
    await expect(page.getByTestId('gpo-row-lab-disabled-link')).toContainText('Link disabled');
    await shot(page, info, '09-gpo-list');
    await page.getByTestId('gpo-link-lab-baseline').click();
    await expect(page.getByTestId('gpo-text-id')).toHaveText(/^\{[0-9A-F-]{36}\}$/);
    await expect(page.getByTestId('gpo-text-settings-note')).toContainText('RSAT');
    // A linked GPO cannot be deleted.
    await expect(page.getByTestId('gpo-text-delete-linked')).toBeVisible();
    await shot(page, info, '09-gpo-view');
  });

  test('link, enforce, disable, reorder, unlink, block inheritance', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto('/admin/gpo');
    await page.getByTestId('gpo-link-lab-unlinked').click();
    await page.getByTestId('gpo-select-link').selectOption({ label: 'lab.conductor.test / Lab / Special' });
    await page.getByTestId('gpo-btn-link').click();
    const preview = page.getByTestId('confirm-text-preview');
    await expect(preview).toContainText('replace: gPLink');
    await expect(preview).toContainText('(!(gPLink=*))');
    await apply(page);
    await expect(page.getByTestId('gpo-link-container-special')).toBeVisible();
    await page.getByTestId('gpo-link-container-special').click();
    await expect(page.getByTestId('gpc-text-order-lab-unlinked')).toHaveText('1');

    // A second link gets the lowest precedence (order 2), then moves up.
    await page.getByTestId('gpc-select-gpo').selectOption({ label: 'Lab People Policy' });
    await page.getByTestId('gpc-btn-link').click();
    await apply(page);
    await expect(page.getByTestId('gpc-text-order-lab-people-policy')).toHaveText('2');
    await page.getByTestId('gpc-btn-up-lab-people-policy').click();
    await expect(preview).toContainText('link order 1:');
    await apply(page);
    await expect(page.getByTestId('gpc-text-order-lab-people-policy')).toHaveText('1');
    await page.getByTestId('gpc-btn-enforce-lab-unlinked').click();
    await apply(page);
    await expect(page.getByTestId('gpc-badge-enforced-lab-unlinked')).toBeVisible();
    await page.getByTestId('gpc-btn-disable-lab-unlinked').click();
    await apply(page);
    await expect(page.getByTestId('gpc-badge-disabled-lab-unlinked')).toBeVisible();
    await page.getByTestId('gpc-btn-block').click();
    await expect(preview).toContainText('gPOptions: 1');
    await apply(page);
    await expect(page.getByTestId('gpc-badge-blocked')).toBeVisible();
    await shot(page, info, '09-gpo-container');
    await page.getByTestId('gpc-btn-allow').click();
    await apply(page);
    await page.getByTestId('gpc-btn-unlink-lab-unlinked').click();
    await apply(page);
    await page.getByTestId('gpc-btn-unlink-lab-people-policy').click();
    await apply(page);
    await expect(page.getByTestId('gpc-text-none')).toBeVisible();
  });

  test('create and delete a GPO with the user own ticket', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    const name = `E2E GPO ${rand()}`;
    await page.goto('/admin/gpo/new');
    await page.getByTestId('gponew-input-name').fill(name);
    await page.getByTestId('gponew-btn-preview').click();
    const preview = page.getByTestId('confirm-text-preview');
    await expect(preview).toContainText('samba-tool gpo create');
    await expect(preview).toContainText('--use-kerberos=required --use-krb5-ccache=');
    await expect(preview).toContainText(`-- '${name}'`);
    await apply(page, { screenshot: [info, '09-gpo-create-preview'] });
    await expect(page.getByTestId('flash-ok')).toContainText(name);
    const id = e2eName(name);
    await page.getByTestId(`gpo-link-${id}`).click();
    await expect(page.getByTestId('gpo-text-not-linked')).toBeVisible();
    await page.getByTestId('gpo-btn-delete').click();
    await expect(preview).toContainText('samba-tool gpo del');
    await apply(page, { reauth: { info, user: 'lab.admin', password: env.adminPassword } });
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId(`gpo-link-${id}`)).toHaveCount(0);
  });
});

function e2eName(v: string): string {
  return v.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}
