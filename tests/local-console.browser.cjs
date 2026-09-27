// @ts-check
const assert = require('node:assert/strict');
const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({headless: true, args: ['--no-sandbox']});
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.setRequestInterception(true);
    page.on('request', request => {
      if (request.url().startsWith('https://accounts.google.com/')) {
        void request.respond({status: 200, contentType: 'application/javascript', body:
          'window.google={accounts:{id:{initialize(){},renderButton(host){host.textContent="Google sign-in"},prompt(){},cancel(){},disableAutoSelect(){}}}};'});
      } else void request.continue();
    });
    await page.goto(`http://localhost:${process.env.TAUTH_LOCAL_WEB_PORT || 8081}/app/`);
    await page.waitForFunction(() => document.querySelector('#notice')?.textContent === 'Sign in to manage your tenants.');
    assert.equal(await page.title(), 'TAuth · Tenant workspace');
    const origins = await page.evaluate(async () => {
      const {Client} = await import('/app/client.js');
      const accepted = ['http://localhost:8082', 'http://127.0.0.1:8082', 'http://[::1]:8082', 'https://api.example.com'];
      const rejected = ['http://example.com', 'http://localhost.example.com', 'http://127.0.0.2', 'https://example.com/path'];
      return accepted.every(origin => new Client(origin).origin === origin) && rejected.every(origin => {
        try { new Client(origin); return false; } catch { return true; }
      });
    });
    assert.equal(origins, true);
    assert.deepEqual(errors, []);
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
