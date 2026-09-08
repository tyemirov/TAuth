// @ts-check
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const https = require("node:https");
const puppeteer = require("puppeteer");

function post(url, form) {
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method: "POST", rejectUnauthorized: false, headers: { "Content-Type": "application/x-www-form-urlencoded" } }, response => {
      let body = "";
      response.on("data", chunk => { body += chunk; });
      response.on("end", () => resolve({ status: response.statusCode, body }));
      response.on("error", reject);
    });
    request.on("error", reject);
    request.end(form.toString());
  });
}

test("GitHub cross-site login reaches OAuth consent with Strict session cookies", { timeout: 90000 }, async (suite) => {
  const fixture = spawn("make", ["--no-print-directory", "test-github-oauth-browser-server"], {
    cwd: require("node:path").join(__dirname, ".."),
    env: { ...process.env, TAUTH_GITHUB_OAUTH_BROWSER_FIXTURE: "1" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const exit = new Promise(resolve => fixture.once("exit", resolve));
  let logs = "";
  const config = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`OAuth fixture startup failed: ${logs}`)), 45000);
    fixture.on("error", reject);
    fixture.on("exit", code => { clearTimeout(timeout); reject(new Error(`OAuth fixture exited ${code}: ${logs}`)); });
    fixture.stderr.on("data", chunk => { logs += chunk; });
    fixture.stdout.on("data", chunk => {
      logs += chunk;
      const match = logs.match(/GITHUB_OAUTH_BROWSER_FIXTURE (\{[^\n]+\})/);
      if (match) { clearTimeout(timeout); resolve(JSON.parse(match[1])); }
    });
  });
  suite.after(async () => { await post(`${config.issuer}/test/shutdown`, new URLSearchParams()); await exit; });
  const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--ignore-certificate-errors"],
    ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
  });
  suite.after(() => browser.close());
  const page = await browser.newPage();
  let consentPolicy = "";
  page.on("response", response => {
    if (new URL(response.url()).pathname === "/oauth/consent" && response.request().method() === "GET" && response.status() === 200) {
      consentPolicy = response.headers()["content-security-policy"];
    }
  });
  await page.setRequestInterception(true);
  page.on("request", request => {
    const url = new URL(request.url());
    if (url.hostname === "github.com" && url.pathname === "/login/oauth/authorize") {
      void request.respond({ status: 302, headers: { location: config.provider + url.pathname + url.search } });
    } else if (request.url().startsWith(config.redirectURI + "?")) {
      void request.respond({ status: 200, contentType: "text/html", body: "<!doctype html><title>Resource client authorized</title>Authorization complete" });
    } else { void request.continue(); }
  });
  await page.goto(config.authorize);
  await Promise.all([page.waitForNavigation(), page.click('a[href*="/auth/github/start"]')]);
  assert.equal(new URL(page.url()).origin, config.provider);
  assert.notEqual(new URL(page.url()).hostname, new URL(config.issuer).hostname);
  await Promise.all([page.waitForNavigation({ waitUntil: "networkidle0" }), page.click("#github-approve")]);
  assert.equal(new URL(page.url()).pathname, "/oauth/consent", "GitHub login returned to the login page instead of consent");
  assert.match(await page.content(), /verified GitHub user ID/);
  assert.ok(consentPolicy.includes(`form-action 'self' ${new URL(config.redirectURI).origin};`));
  assert.equal(consentPolicy.includes("*"), false);
  const cookies = await browser.defaultBrowserContext().cookies();
  for (const name of ["app_session_demo", "app_refresh_demo"]) {
    const cookie = cookies.find(candidate => candidate.name === name);
    assert.ok(cookie, `missing ${name}`);
    assert.equal(cookie.sameSite, "Strict");
    assert.equal(cookie.secure, true);
    assert.equal(cookie.httpOnly, true);
  }
  await page.evaluate(() => {
    window["blockedDirectives"] = [];
    document.addEventListener("securitypolicyviolation", event => window["blockedDirectives"].push(event.effectiveDirective));
  });
  try {
    await Promise.all([page.waitForNavigation({ timeout: 10000 }), page.click('button[name="decision"][value="approve"]')]);
  } catch (error) {
    const directives = await page.evaluate(() => window["blockedDirectives"]);
    assert.deepEqual(directives, [], "consent redirect blocked by CSP");
    throw error;
  }
  const destination = new URL(page.url());
  assert.equal(destination.searchParams.get("state"), "cross-site-state");
  const code = destination.searchParams.get("code");
  assert.ok(code);
  const response = await post(config.issuer + "/oauth/token", new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: "b".repeat(43), client_id: config.clientID, resource: config.resource }));
  assert.equal(response.status, 200);
  const tokens = JSON.parse(response.body);
  assert.equal(tokens.token_type, "Bearer");
  assert.ok(tokens.refresh_token);
});
