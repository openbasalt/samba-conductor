import { test as base, expect, Page, TestInfo } from '@playwright/test';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Secrets come from the environment set by run-lab.sh (read on server-home
// from the lab secrets file); they are never printed.
export const env = {
  userPassword: required('E2E_USER_PASSWORD'),
  adminPassword: required('E2E_ADMIN_PASSWORD'),
  helpdeskPassword: required('E2E_HELPDESK_PASSWORD'),
  adminEnrollURL: required('E2E_ADMIN_ENROLL_URL'),
};

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set (run through e2e/run-lab.sh)`);
  return v;
}

// ---- state shared between spec files of one project run ----

type State = { secrets: Record<string, string>; lastStep: Record<string, number>; passwords: Record<string, string> };

function stateFile(info: TestInfo): string {
  return path.join(__dirname, '..', '.auth', `state-${info.project.name}.json`);
}

export function loadState(info: TestInfo): State {
  try {
    return JSON.parse(fs.readFileSync(stateFile(info), 'utf8'));
  } catch {
    return { secrets: {}, lastStep: {}, passwords: {} };
  }
}

export function saveState(info: TestInfo, s: State) {
  fs.mkdirSync(path.dirname(stateFile(info)), { recursive: true, mode: 0o700 });
  fs.writeFileSync(stateFile(info), JSON.stringify(s), { mode: 0o600 });
}

// ---- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ----

function base32Decode(s: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    value = (value << 5) | alphabet.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function totpAt(secret: string, step: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const off = h[h.length - 1] & 0xf;
  const v = (h.readUInt32BE(off) & 0x7fffffff) % 1_000_000;
  return v.toString().padStart(6, '0');
}

const step = () => Math.floor(Date.now() / 30_000);

// freshCode returns a code for a step the server has not seen for this user
// yet (conductor refuses a replayed step), waiting for the next step if
// needed.
export async function freshCode(info: TestInfo, user: string): Promise<string> {
  const st = loadState(info);
  const secret = st.secrets[user];
  if (!secret) throw new Error(`no TOTP secret recorded for ${user}`);
  while (step() <= (st.lastStep[user] ?? 0)) {
    await new Promise((r) => setTimeout(r, 1000));
  }
  const s = step();
  st.lastStep[user] = s;
  saveState(info, st);
  return totpAt(secret, s);
}

// ---- page helpers ----

export const test = base.extend<{ cspGuard: void }>({
  // Every test fails on a CSP violation or a page error.
  cspGuard: [
    async ({ page }, use) => {
      const problems: string[] = [];
      page.on('console', (m) => {
        if (/Content Security Policy|Refused to (load|apply|execute|frame)/i.test(m.text())) problems.push(m.text());
      });
      page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
      await use();
      expect(problems, 'CSP violations / page errors').toEqual([]);
    },
    { auto: true },
  ],
});
export { expect };

export function shotPath(info: TestInfo, name: string): string {
  return path.join(__dirname, '..', 'screenshots', info.project.name, `${name}.png`);
}

// shot saves a full-page screenshot; TOTP secrets, QR codes and recovery
// codes are always masked.
export async function shot(page: Page, info: TestInfo, name: string) {
  const mask = [page.getByTestId('enroll-text-secret'), page.getByTestId('enroll-img-qr'), page.getByTestId('recovery-list-codes'),
    page.getByTestId('user-text-enroll-link')];
  await page.screenshot({ path: shotPath(info, name), fullPage: true, mask });
}

export async function signIn(page: Page, user: string, password: string) {
  await page.goto('/signin');
  await page.getByTestId('signin-input-username').fill(user);
  await page.getByTestId('signin-input-password').fill(password);
  await page.getByTestId('signin-btn-submit').click();
}

// enroll completes the 2FA enrollment page and records the secret.
export async function enroll(page: Page, info: TestInfo, user: string, screenshot?: string) {
  await expect(page.getByTestId('enroll-img-qr')).toBeVisible();
  const secret = (await page.getByTestId('enroll-text-secret').innerText()).trim();
  const st = loadState(info);
  st.secrets[user] = secret;
  saveState(info, st);
  if (screenshot) await shot(page, info, screenshot);
  await page.getByTestId('enroll-input-code').fill(await freshCode(info, user));
  await page.getByTestId('enroll-btn-submit').click();
  await expect(page.getByTestId('recovery-list-codes')).toBeVisible();
  await expect(page.getByTestId('recovery-text-code')).toHaveCount(10);
}

// signInMFA signs in a user who already enrolled.
export async function signInMFA(page: Page, info: TestInfo, user: string, password: string) {
  await signIn(page, user, password);
  await expect(page).toHaveURL(/\/signin\/2fa$/);
  await page.getByTestId('mfa-input-code').fill(await freshCode(info, user));
  await page.getByTestId('mfa-btn-submit').click();
}

// openNav opens the phone "Menu" (a native <details>, no JavaScript) when the
// sidebar is collapsed; on desktop the sidebar is always open.
export async function openNav(page: Page) {
  const menu = page.getByTestId('nav-btn-menu');
  if (await menu.isVisible()) {
    const open = await page.locator('details.sidenav-box').evaluate((d) => (d as HTMLDetailsElement).open);
    if (!open) await menu.click();
  }
}

// navTo clicks a sidebar link (opening the phone menu first).
export async function navTo(page: Page, name: string) {
  await openNav(page);
  await page.getByTestId('nav-link-' + name).click();
}

export async function signOut(page: Page) {
  await openNav(page);
  await page.getByTestId('nav-btn-signout').click();
  await expect(page).toHaveURL(/\/signin/);
}

// apply confirms a previewed change, re-authenticating when asked.
export async function apply(page: Page, opts?: { reauth?: { info: TestInfo; user: string; password: string }; screenshot?: [TestInfo, string] }) {
  await expect(page).toHaveURL(/\/confirm\//);
  await expect(page.getByTestId('confirm-text-preview')).toBeVisible();
  if (opts?.screenshot) await shot(page, opts.screenshot[0], opts.screenshot[1]);
  if (opts?.reauth) {
    await expect(page.getByTestId('confirm-text-reauth')).toBeVisible();
    await page.getByTestId('confirm-input-password').fill(opts.reauth.password);
    await page.getByTestId('confirm-input-code').fill(await freshCode(opts.reauth.info, opts.reauth.user));
  }
  await page.getByTestId('confirm-btn-apply').click();
}

export function rand(): string {
  return crypto.randomBytes(3).toString('hex');
}

export function newPassword(): string {
  return `E2e-${crypto.randomBytes(6).toString('base64url')}-9x`;
}

// e2eID mirrors the server's data-e2e suffix normalization.
export function e2eID(v: string): string {
  return v.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'x';
}

// csrfOf reads the CSRF token of the current page (any form carries it).
export async function csrfOf(page: Page): Promise<string> {
  return (await page.locator('input[name="csrf"]').first().getAttribute('value')) ?? '';
}
