import * as crypto from 'node:crypto';
import { CDPSession, Page, TestInfo, request as pwRequest } from '@playwright/test';
import { test, expect, env, shot, signIn, signInMFA, signOut, apply, navTo, openNav, loadState, saveState, freshCode } from './helpers';

// Single sign-on (P4b). The lab snapshot conductor-p4b has conductor-idp on
// dc1 (https://dc1.lab.conductor.test:9444) with its management API for
// conductor and conductor's second factor (mfa.backend = "conductor");
// run-lab.sh runs the example SAML SP on http://localhost:8000. The OIDC
// relying party is this browser: its redirect URI (http://localhost:5556)
// is intercepted.
const IDP = 'https://dc1.lab.conductor.test:9444';
const RP = 'http://localhost:5556/callback';
const SP = 'http://localhost:8000';
const reauth = (info: TestInfo) => ({ info, user: 'lab.admin', password: env.adminPassword });

async function virtualKey(page: Page): Promise<CDPSession> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true },
  });
  return client;
}

// pickGroup searches the directory in an SSO form and allows a group.
async function pickGroup(page: Page, name: string) {
  await page.getByTestId('sso-input-group-search').fill(name);
  await page.getByTestId('sso-btn-group-search').click();
  await page.getByTestId('sso-btn-allow-' + name.toLowerCase().replace(/[^a-z0-9]+/g, '-')).click();
  await expect(page.getByTestId('sso-list-group')).toContainText(name);
}

function b64url(b: Buffer): string {
  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

test.describe.serial('single sign-on (conductor-idp)', () => {
  test('an administrator registers an OpenID Connect app from a preset; the secret is shown once', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await navTo(page, 'sso');
    await openNav(page);
    await expect(page.getByTestId('nav-link-sso')).toHaveAttribute('aria-current', 'page');
    await expect(page.getByTestId('sso-text-issuer')).toHaveText(IDP);
    await expect(page.getByTestId('sso-text-mfa-backend')).toBeVisible();
    await shot(page, info, '20-sso-overview');

    await page.getByTestId('sso-link-new').click();
    await expect(page.getByTestId('sso-preset-google-workspace')).toBeVisible();
    await shot(page, info, '20-sso-presets');
    await page.getByTestId('sso-link-preset-generic-oidc').click();
    await page.getByTestId('sso-input-preset-redirect-uri').fill(RP);
    await page.getByTestId('sso-btn-preset-next').click();
    await expect(page.getByTestId('sso-text-preset')).toBeVisible();
    await page.getByTestId('sso-input-client-name').fill('E2E App');
    await page.getByTestId('sso-check-scope-groups').check();
    await page.getByTestId('sso-check-require-mfa').check();
    await page.getByTestId('sso-select-groups-claim').selectOption('names');
    await pickGroup(page, 'Engineering');
    // The claims a real user would get (the draft is validated too).
    await page.getByTestId('sso-input-preview-user').fill('user0001');
    await page.getByTestId('sso-btn-preview').click();
    await expect(page.getByTestId('sso-preview-allowed')).toBeVisible();
    await expect(page.getByTestId('sso-preview-groups')).toContainText('Engineering');
    await expect(page.getByTestId('sso-preview-email')).toContainText('user0001@');
    await shot(page, info, '20-sso-client-form');
    await page.getByTestId('sso-btn-review').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('conductor-idp client.create');
    await expect(page.getByTestId('confirm-text-preview')).toContainText(RP);
    await apply(page, { reauth: reauth(info), screenshot: [info, '20-sso-client-confirm'] });

    await expect(page.getByTestId('sso-text-secret-once')).toBeVisible();
    const clientID = (await page.getByTestId('sso-text-client-id').innerText()).trim();
    const secret = (await page.getByTestId('sso-text-client-secret').innerText()).trim();
    expect(secret).toMatch(/^cidp_cs_/);
    await page.screenshot({ path: `screenshots/${info.project.name}/20-sso-secret-once.png`, fullPage: true,
      mask: [page.getByTestId('sso-text-client-secret')] });
    const st = loadState(info);
    st.passwords['sso.client'] = clientID;
    st.passwords['sso.secret'] = secret;
    saveState(info, st);
    // Shown once: the same page again is gone.
    const once = page.url();
    await page.getByTestId('sso-link-secret-done').click();
    await expect(page.getByTestId('sso-text-client-title')).toContainText('E2E App');
    await expect(page.getByTestId('sso-list-client-groups')).toContainText('Engineering');
    await shot(page, info, '20-sso-client');
    const again = await page.goto(once);
    expect(again?.status()).toBe(404);
    expect(await page.content()).not.toContain(secret);
  });

  test('the consent note and session lifetimes are set from the panel', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto('/admin/sso/policy');
    await expect(page.getByTestId('sso-text-mfa-shared')).toBeVisible();
    await page.getByTestId('sso-input-policy-idle').fill('45');
    await page.getByTestId('sso-input-consent-en').fill('E2E: the data stays in the company.');
    await shot(page, info, '20-sso-policy');
    await page.getByTestId('sso-btn-policy-save').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText('session_idle_minutes: 60 -> 45');
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('flash-ok')).toBeVisible();
    await expect(page.getByTestId('sso-text-policy-version')).toContainText('1');
  });

  test('a user signs in to the app with a passkey registered in conductor', async ({ page }, info) => {
    const st = loadState(info);
    const clientID = st.passwords['sso.client'], secret = st.passwords['sso.secret'];
    expect(clientID).toBeTruthy();
    await virtualKey(page);
    // The key is registered in conductor (the user's first second factor).
    await signIn(page, 'user0006', env.userPassword);
    await expect(page).toHaveURL(/\/me$/);
    await page.goto('/me/security');
    await page.getByTestId('key-input-name').fill('Laptop');
    await page.getByTestId('key-btn-register').click();
    await expect(page.getByTestId('recovery-list-codes')).toBeVisible();
    await signOut(page);

    // The app (the browser) starts an authorization with PKCE.
    // The redirect to the app is followed by the browser (route handlers
    // do not see redirects): read the code from the request itself, and
    // answer the app's URL so the page settles.
    let code = '';
    page.on('request', (r) => {
      if (r.url().startsWith(RP)) code = new URL(r.url()).searchParams.get('code') ?? code;
    });
    await page.route('http://localhost:5556/**', (route) => route.fulfill({ status: 200, contentType: 'text/plain', body: 'relying party' }));
    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
    const q = new URLSearchParams({ client_id: clientID, redirect_uri: RP, response_type: 'code', scope: 'openid profile email groups',
      state: 'e2e-state', nonce: 'e2e-nonce', code_challenge: challenge, code_challenge_method: 'S256' });
    await page.goto(`${IDP}/authorize?${q}`);
    await expect(page.getByTestId('signin-input-username')).toBeVisible();
    await expect(page.getByTestId('flow-text-app')).toContainText('E2E App');
    await page.getByTestId('signin-input-username').fill('user0006');
    await page.getByTestId('signin-input-password').fill(env.userPassword);
    await page.getByTestId('signin-btn-submit').click();
    // The app requires a second factor: conductor's passkey, at the IdP.
    await expect(page.getByTestId('key-btn-use')).toBeEnabled();
    await expect(page.locator('script[src^="/static/webauthn.js"]')).toHaveCount(1);
    await shot(page, info, '20-sso-idp-passkey');
    await page.getByTestId('key-btn-use').click();
    // A third-party app: consent, with the note from the panel.
    await expect(page.getByTestId('consent-text-note')).toContainText('E2E: the data stays in the company.');
    await shot(page, info, '20-sso-idp-consent');
    await page.getByTestId('consent-btn-allow').click();
    await expect.poll(() => code).not.toBe('');

    const api = await pwRequest.newContext();
    const resp = await api.post(`${IDP}/oauth/token`, {
      form: { grant_type: 'authorization_code', code, redirect_uri: RP, code_verifier: verifier },
      headers: { Authorization: 'Basic ' + Buffer.from(`${clientID}:${secret}`).toString('base64') },
    });
    expect(resp.status()).toBe(200);
    const tok = await resp.json();
    const claims = JSON.parse(Buffer.from(tok.id_token.split('.')[1], 'base64url').toString());
    expect(claims.preferred_username).toBe('user0006');
    expect(claims.groups).toContain('Engineering');
    expect(claims.amr).toContain('mfa');
    expect(claims.nonce).toBe('e2e-nonce');
    await api.dispose();
  });

  test('a SAML app from its metadata: sign-in, then single logout from the app', async ({ page, browser }, info) => {
    test.setTimeout(240_000);
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    const api = await pwRequest.newContext();
    const md = await (await api.get(`${SP}/saml/metadata`)).text();
    await api.dispose();
    expect(md).toContain('SingleLogoutService');
    await page.goto('/admin/sso/saml/new');
    await page.getByTestId('sso-input-metadata-xml').fill(md);
    await page.getByTestId('sso-btn-import').click();
    await expect(page.getByTestId('sso-input-sp-slo')).toHaveValue(`${SP}/saml/slo`);
    await expect(page.getByTestId('sso-text-sign-cert')).toBeVisible();
    await page.getByTestId('sso-input-sp-name').fill('Example SP');
    await page.getByTestId('sso-select-nameid-format').selectOption('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
    await page.getByTestId('sso-select-nameid-source').selectOption('username');
    await page.getByTestId('sso-input-sp-attributes').fill('uid=username\nmail=email\nmemberOf=groups');
    await pickGroup(page, 'Engineering');
    await page.getByTestId('sso-input-preview-user').fill('user0016');
    await page.getByTestId('sso-btn-preview').click();
    await expect(page.getByTestId('sso-preview-nameid')).toHaveText('user0016');
    await shot(page, info, '20-sso-sp-form');
    await page.getByTestId('sso-btn-review').click();
    await expect(page.getByTestId('confirm-text-preview')).toContainText(`single_logout: ${SP}/saml/slo`);
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('sso-text-sp-slo')).toContainText(`${SP}/saml/slo`);
    await shot(page, info, '20-sso-sp');

    // A user signs in to the SP through the IdP, in a fresh browser.
    const ctx = await browser.newContext({ ignoreHTTPSErrors: false });
    const u = await ctx.newPage();
    await u.goto(`${SP}/`);
    await expect(u.getByTestId('signin-input-username')).toBeVisible();
    await u.getByTestId('signin-input-username').fill('user0016');
    await u.getByTestId('signin-input-password').fill(env.userPassword);
    await u.getByTestId('signin-btn-submit').click();
    await u.getByTestId('saml-btn-continue').click();
    await expect(u.getByTestId('sp-text-nameid')).toHaveText('user0016');
    // Single logout started at the SP (signed HTTP-Redirect request): the
    // IdP ends its session without asking and answers the SP.
    await u.getByTestId('sp-link-logout').click();
    await expect(u.getByTestId('sp-text-signed-out')).toBeVisible();
    await u.goto(`${IDP}/`);
    await expect(u.getByTestId('signin-input-username')).toBeVisible();
    await ctx.close();
  });

  test("an administrator signs in at the IdP with conductor's authenticator code", async ({ page }, info) => {
    await page.goto(`${IDP}/login`);
    await page.getByTestId('signin-input-username').fill('lab.admin');
    await page.getByTestId('signin-input-password').fill(env.adminPassword);
    await page.getByTestId('signin-btn-submit').click();
    // Administrators always need a second factor; the code is conductor's.
    await page.getByTestId('mfa-input-code').fill(await freshCode(info, 'lab.admin'));
    await page.getByTestId('mfa-btn-submit').click();
    await expect(page.getByTestId('home-text-username')).toContainText('lab.admin');
    await expect(page.getByTestId('home-link-admin')).toBeVisible();
    await shot(page, info, '20-sso-idp-home');
  });

  test('keys, activity and the audit chain', async ({ page }, info) => {
    await signInMFA(page, info, 'lab.admin', env.adminPassword);
    await page.goto('/admin/sso/keys');
    await expect(page.getByTestId('sso-table-keys-oidc').locator('tbody tr')).toHaveCount(1);
    await page.getByTestId('sso-btn-rotate-oidc').click();
    await apply(page, { reauth: reauth(info) });
    await expect(page.getByTestId('sso-table-keys-oidc').locator('tbody tr')).toHaveCount(2);
    await shot(page, info, '20-sso-keys');
    const pem = await page.request.get('/admin/sso/keys/saml.pem');
    expect(await pem.text()).toContain('BEGIN CERTIFICATE');

    await navTo(page, 'sso-activity');
    await page.getByTestId('sso-select-days').selectOption('1');
    await page.getByTestId('sso-btn-days').click();
    await expect(page.getByTestId('sso-table-activity-apps')).toContainText('E2E App');
    await expect(page.getByTestId('sso-table-activity-apps')).toContainText('Example SP');
    await page.getByTestId('sso-link-verify').click();
    await expect(page.getByTestId('sso-alert-chain-ok')).toBeVisible();
    await expect(page.getByTestId('sso-table-audit')).toContainText('api.client.create');
    await shot(page, info, '20-sso-activity');
    await signOut(page);
  });

  test('helpdesk never reaches the section', async ({ page }, info) => {
    await signInMFA(page, info, 'helpdesk.user', env.helpdeskPassword);
    await expect(page).not.toHaveURL(/\/signin/);
    await openNav(page);
    await expect(page.getByTestId('nav-group-sso')).toHaveCount(0);
    const r = await page.goto('/admin/sso');
    expect(r?.status()).toBe(403);
  });
});
