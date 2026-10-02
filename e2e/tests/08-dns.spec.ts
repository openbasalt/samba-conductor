import { test, expect, env, shot, signInMFA, apply, rand, navTo } from './helpers';

test.describe.serial('DNS', () => {
  test('zones and records; AD records are read-only', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'dns');
    await expect(page.getByTestId('dns-table-zones')).toBeVisible();
    // DCs are discovered from the directory, never configured by name.
    await expect(page.getByTestId('dns-text-dcs')).toContainText('dc1.lab.conductor.test');
    await expect(page.getByTestId('dns-text-dcs')).toContainText('dc2.lab.conductor.test');
    await expect(page.getByTestId('dns-badge-ad-lab-conductor-test')).toBeVisible();
    await expect(page.getByTestId('dns-badge-ad-msdcs-lab-conductor-test')).toBeVisible();
    await expect(page.getByTestId('dns-row-apps-conductor-test')).toBeVisible();
    await expect(page.getByTestId('dns-row-0-93-10-in-addr-arpa')).toBeVisible();
    await shot(page, info, '08-dns-zones');

    // The AD zone: locator and DC records are AD-managed, intranet is not.
    await page.getByTestId('dns-link-zone-lab-conductor-test').click();
    await expect(page.getByTestId('dns-badge-ad-zone')).toBeVisible();
    await expect(page.getByTestId('dns-btn-zone-delete')).toHaveCount(0);
    await page.getByTestId('dns-input-search').fill('_ldap._tcp');
    await page.getByTestId('dns-btn-search').click();
    await expect(page.getByTestId('dns-badge-protected-ldap-tcp-srv').first()).toBeVisible();
    await expect(page.getByTestId('dns-btn-delete-ldap-tcp-srv')).toHaveCount(0);
    await page.getByTestId('dns-input-search').fill('dc');
    await page.getByTestId('dns-btn-search').click();
    await expect(page.getByTestId('dns-badge-protected-dc1-a')).toBeVisible();
    await page.getByTestId('dns-input-search').fill('intranet');
    await page.getByTestId('dns-btn-search').click();
    await expect(page.getByTestId('dns-text-data-intranet-a')).toHaveText('10.93.0.60');
    await expect(page.getByTestId('dns-link-edit-intranet-a')).toBeVisible();
    await shot(page, info, '08-dns-ad-zone');

    // A forward zone with more than one page of names.
    await page.goto('/admin/dns/zones/apps.conductor.test');
    await expect(page.getByTestId('dns-text-data-app-cname')).toHaveText('www.apps.conductor.test');
    await page.getByTestId('pager-link-next').click();
    await expect(page.getByTestId('pager-text-page')).toHaveText('Page 2');
    await expect(page.getByTestId('dns-text-data-www-aaaa')).toHaveText('2001:db8::50');
  });

  test('create a zone, add/edit/delete records, delete the zone', async ({ page }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    const zone = `e2e-${rand()}.test`;
    await page.goto('/admin/dns');
    await page.getByTestId('dns-link-new-zone').click();
    await page.getByTestId('dnsnew-input-name').fill(zone);
    await page.getByTestId('dnsnew-btn-preview').click();
    const preview = page.getByTestId('confirm-text-preview');
    await expect(preview).toContainText(`dn: DC=${zone},CN=MicrosoftDNS,DC=DomainDnsZones`);
    await expect(preview).toContainText('# dNSProperty: zone type: primary');
    // SOA and NS name the DC conductor is connected to (discovered).
    await expect(preview).toContainText(/# dnsRecord: SOA dc[12]\.lab\.conductor\.test hostmaster\./);
    await apply(page, { screenshot: [info, '08-dns-zone-preview'] });
    await expect(page.getByTestId('dns-text-zone')).toHaveText(zone);

    // Add an A record: the preview shows the decoded record and the SOA bump.
    await page.getByTestId('dns-input-name').fill('www');
    await page.getByTestId('dns-select-type').selectOption('A');
    await page.getByTestId('dns-input-data').fill('192.0.2.10');
    await page.getByTestId('dns-input-ttl').fill('600');
    await page.getByTestId('dns-btn-add').click();
    await expect(preview).toContainText('# zone serial 1 -> 2');
    await expect(preview).toContainText('# dnsRecord: A 192.0.2.10 (ttl 600)');
    await apply(page, { screenshot: [info, '08-dns-record-preview'] });
    await expect(page.getByTestId('dns-text-data-www-a')).toHaveText('192.0.2.10');

    // Edit: the old value is deleted by its exact bytes, the new one added.
    await page.getByTestId('dns-link-edit-www-a').click();
    await page.getByTestId('dnsrec-input-data').fill('192.0.2.11');
    await page.getByTestId('dnsrec-btn-preview').click();
    await expect(preview).toContainText('delete: dnsRecord');
    await expect(preview).toContainText('# dnsRecord: A 192.0.2.10 (ttl 600)');
    await expect(preview).toContainText('# dnsRecord: A 192.0.2.11 (ttl 600)');
    await apply(page);
    await expect(page.getByTestId('dns-text-data-www-a')).toHaveText('192.0.2.11');

    // More types; invalid data is refused before any preview.
    for (const [name, type, data] of [['@', 'MX', `10 mail.${zone}`], ['@', 'TXT', 'v=spf1 -all'], ['app', 'CNAME', `www.${zone}`],
      ['_http._tcp', 'SRV', `0 5 80 www.${zone}`]]) {
      await page.getByTestId('dns-input-name').fill(name);
      await page.getByTestId('dns-select-type').selectOption(type);
      await page.getByTestId('dns-input-data').fill(data);
      await page.getByTestId('dns-btn-add').click();
      await apply(page);
      await expect(page.getByTestId('flash-ok')).toBeVisible();
    }
    await page.getByTestId('dns-input-name').fill('bad');
    await page.getByTestId('dns-select-type').selectOption('A');
    await page.getByTestId('dns-input-data').fill('not-an-address');
    await page.getByTestId('dns-btn-add').click();
    await expect(page.getByTestId('flash-error')).toBeVisible();
    await page.goto(`/admin/dns/zones/${zone}`);
    await shot(page, info, '08-dns-records');

    await page.getByTestId('dns-btn-delete-app-cname').click();
    await expect(preview).toContainText('changetype: delete');
    await apply(page);
    await expect(page.getByTestId('dns-text-data-app-cname')).toHaveCount(0);

    // Delete the zone: typed name, then re-authentication.
    await page.getByTestId('dns-input-zone-confirm').fill('wrong.test');
    await page.getByTestId('dns-btn-zone-delete').click();
    await expect(page.getByTestId('flash-error')).toBeVisible();
    await page.getByTestId('dns-input-zone-confirm').fill(zone);
    await page.getByTestId('dns-btn-zone-delete').click();
    await expect(preview).toContainText('control: 1.2.840.113556.1.4.805 true');
    await apply(page, { reauth: { info, user: 'lab.admin', password: env.adminPassword } });
    await expect(page.getByTestId(`dns-row-${zone.replace(/[^a-z0-9]+/g, '-')}`)).toHaveCount(0);
  });

  test('a reverse zone from a network, with a PTR record', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto('/admin/dns/new');
    await page.getByTestId('dnsnew-input-network').fill('198.51.100.0/24');
    await page.getByTestId('dnsnew-btn-preview').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('DC=100.51.198.in-addr.arpa,CN=MicrosoftDNS');
    await apply(page);
    await expect(page.getByTestId('dns-text-zone')).toHaveText('100.51.198.in-addr.arpa');
    await page.getByTestId('dns-input-name').fill('5');
    await page.getByTestId('dns-select-type').selectOption('PTR');
    await page.getByTestId('dns-input-data').fill('host5.apps.conductor.test');
    await page.getByTestId('dns-btn-add').click();
    await apply(page);
    await expect(page.getByTestId('dns-text-data-5-ptr')).toHaveText('host5.apps.conductor.test');
    await page.getByTestId('dns-input-zone-confirm').fill('100.51.198.in-addr.arpa');
    await page.getByTestId('dns-btn-zone-delete').click();
    await apply(page, { reauth: { info, user: 'lab.admin', password: env.adminPassword } });
    await expect(page).toHaveURL(/\/admin\/dns$/);
  });
});
