import { Page, TestInfo } from '@playwright/test';
import { Resolver } from 'node:dns/promises';
import { test, expect, env, shot, signInMFA, enroll, loadState, apply, rand, e2eID } from './helpers';

// TXT records typed one string per line (issue #46): the add form shows a
// multi-line field when TXT is selected (no script: the stylesheet swaps
// the fields), the preview shows the quoted strings as they are stored,
// and the edit form shows them one per line again. The record is then
// read from the DNS service of both DCs. It is left in the test zone: the
// lab is reset before each project. The spec enrolls lab.admin itself when
// an earlier spec of the run has not (it can run alone with E2E_GREP).

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

// txtAt returns the strings of the TXT record of name that the DNS server
// at ip answers and whose first string is first (null until it does).
async function txtAt(ip: string, name: string, first: string): Promise<string[] | null> {
  const r = new Resolver({ timeout: 3000, tries: 1 });
  r.setServers([ip]);
  try {
    return (await r.resolveTxt(name)).find((rec) => rec[0] === first) ?? null;
  } catch {
    return null;
  }
}

// quote renders a string the way the record data shows it.
const quote = (s: string) => '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';

test.describe.serial('DNS TXT records, one string per line', () => {
  test('add a multi-line DKIM record, preview the split, edit it as lines', async ({ page }, info) => {
    test.setTimeout(300_000);
    await adminIn(page, info);
    const zone = 'apps.conductor.test';
    const name = `s${rand()}._domainkey`;
    const row = `${e2eID(name)}-txt`;
    const preview = page.getByTestId('confirm-text-preview');
    const summary = page.getByTestId('confirm-text-summary');

    // A key line longer than 255 bytes, a line with quotes and a backslash,
    // and trailing blank lines (ignored).
    const key = ('p2=' + 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA'.repeat(8)).slice(0, 300);
    const typed = ['v=DKIM1; h=sha256; k=rsa;', 'p=abcdef', 'ghijklmnop', key, 'note "x" \\ y', '', ''].join('\n');
    const strings = ['v=DKIM1; h=sha256; k=rsa;', 'p=abcdef', 'ghijklmnop', key.slice(0, 255), key.slice(255), 'note "x" \\ y'];
    const stored = strings.map(quote).join(' ');

    await page.goto(`/admin/dns/zones/${zone}`);
    // A one-line field for A records; the multi-line one replaces it for TXT.
    await page.getByTestId('dns-select-type').selectOption('A');
    await expect(page.getByTestId('dns-input-data')).toBeVisible();
    await expect(page.getByTestId('dns-input-txt')).toBeHidden();
    await page.getByTestId('dns-input-name').fill(name);
    await page.getByTestId('dns-select-type').selectOption('TXT');
    await expect(page.getByTestId('dns-input-data')).toBeHidden();
    await expect(page.getByTestId('dns-input-txt')).toBeVisible();
    await page.getByTestId('dns-input-txt').fill(typed);
    await shot(page, info, '23-dns-txt-form');
    await page.getByTestId('dns-btn-add').click();

    // The preview shows the strings exactly as stored: one per line, the
    // 300-byte line split at 255, quotes and backslash escaped.
    await expect(summary).toContainText(stored);
    await expect(preview).toContainText(`# dnsRecord: TXT ${stored} (ttl 3600)`);
    // The long strings wrap: the page does not scroll sideways.
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await apply(page, { screenshot: [info, '23-dns-txt-preview'] });
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId(`dns-text-data-${row}`)).toHaveText(stored);

    // The edit form shows one string per line, unquoted.
    await page.getByTestId(`dns-link-edit-${row}`).click();
    const field = page.getByTestId('dnsrec-input-data');
    await expect(field).toHaveValue(strings.join('\n'));
    await shot(page, info, '23-dns-txt-edit');
    // Saved unchanged, nothing would change.
    await page.getByTestId('dnsrec-btn-preview').click();
    await expect(page.getByTestId('flash-error')).toContainText('Nothing would change.');

    // Change one line: the preview names the old and the new strings.
    await page.goto(`/admin/dns/zones/${zone}?q=${name}`);
    await page.getByTestId(`dns-link-edit-${row}`).click();
    const changed = strings.map((s) => (s === 'p=abcdef' ? 'p=abcdeg' : s));
    await field.fill(changed.join('\r\n'));
    await page.getByTestId('dnsrec-btn-preview').click();
    await expect(summary).toContainText(`${stored} → ${changed.map(quote).join(' ')}`);
    await apply(page);
    await expect(page.getByTestId(`dns-text-data-${row}`)).toHaveText(changed.map(quote).join(' '));

    // Both DCs answer the record with the same strings (dc2 once AD has
    // replicated it).
    const fqdn = `${name}.${zone}`;
    for (const ip of ['10.93.0.10', '10.93.0.11']) {
      await expect.poll(() => txtAt(ip, fqdn, changed[0]), { timeout: 180_000, intervals: [2_000, 5_000] }).toEqual(changed);
    }
  });
});
