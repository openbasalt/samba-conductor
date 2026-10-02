import { test, expect, env, shot, signIn } from './helpers';

test.describe('anonymous visitor and sign-in failures', () => {
  test('sign-in page, theme, language and security headers', async ({ page }, info) => {
    const resp = await page.goto('/signin');
    const h = resp!.headers();
    expect(h['content-security-policy']).toContain("script-src 'none'");
    expect(h['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(h['strict-transport-security']).toContain('max-age=');
    expect(h['referrer-policy']).toBe('no-referrer');
    expect(h['x-content-type-options']).toBe('nosniff');
    await expect(page.getByTestId('signin-input-username')).toBeVisible();
    await shot(page, info, '01-signin');
    await page.getByTestId('footer-link-theme-dark').click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await shot(page, info, '01-signin-dark');
    await page.getByTestId('footer-link-lang-pt-br').click();
    await expect(page.getByTestId('signin-btn-submit')).toHaveText('Entrar');
    await shot(page, info, '01-signin-pt-br');
    await page.getByTestId('footer-link-lang-en').click();
    await page.getByTestId('footer-link-theme-system').click();
    await expect(page.getByTestId('signin-btn-submit')).toHaveText('Sign in');
    // The session cookie may only ever be a __Host- cookie.
    const cookies = await page.context().cookies();
    for (const c of cookies.filter((c) => c.name.startsWith('__Host-'))) {
      expect(c.secure && c.httpOnly && c.sameSite === 'Strict' && c.path === '/').toBeTruthy();
    }
  });

  test('anonymous access is limited to sign-in and static assets', async ({ page, request }) => {
    for (const p of ['/', '/me', '/admin', '/admin/users', '/admin/audit', '/admin/domain', '/me/security']) {
      await page.goto(p);
      await expect(page, p).toHaveURL(/\/signin$/);
    }
    expect((await request.get('/static/app.css')).status()).toBe(200);
    // A state-changing request without a session/CSRF token is refused.
    const r = await request.post('/me/edit', { form: { mobile: 'x' }, maxRedirects: 0 });
    expect(r.status()).toBe(403);
    const r2 = await request.post('/signin', { form: { username: 'normal.user', password: 'x' }, maxRedirects: 0 });
    expect(r2.status()).toBe(403);
  });

  test('refused sign-ins get the right message', async ({ page }, info) => {
    const cases: [string, string, RegExp][] = [
      ['normal.user', 'definitely-wrong', /Wrong username or password/],
      ['no.such.user', 'whatever', /Wrong username or password/],
      ['locked.user', env.userPassword, /locked/],
      ['disabled.user', env.userPassword, /disabled/],
      ['expired.account', env.userPassword, /expired/],
    ];
    for (const [user, pw, msg] of cases) {
      await signIn(page, user, pw);
      await expect(page.getByTestId('form-text-error'), user).toHaveText(msg);
      await expect(page).toHaveURL(/\/signin$/);
    }
    await shot(page, info, '01-signin-expired-account');
  });

  test('an administrator without 2FA needs an enrollment link', async ({ page }) => {
    await signIn(page, 'lab.admin', env.adminPassword);
    await expect(page.getByTestId('form-text-error')).toContainText('enrollment link');
    await page.goto('/admin');
    await expect(page).toHaveURL(/\/signin$/);
  });

  test('per-account rate limit stops before AD locks the account', async ({ page }, info) => {
    const user = info.project.name === 'desktop' ? 'user0999' : 'user0998';
    for (let i = 0; i < 5; i++) {
      await signIn(page, user, `wrong-${i}`);
      await expect(page.getByTestId('form-text-error')).toHaveText(/Wrong username or password/);
    }
    await signIn(page, user, env.userPassword);
    await expect(page.getByTestId('form-text-error')).toHaveText(/Too many failed attempts/);
    await shot(page, info, '01-signin-rate-limited');
  });
});
