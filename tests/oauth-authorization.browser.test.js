// @ts-check
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");

let puppeteer = null;
try {
  puppeteer = require("puppeteer");
} catch (_error) {
  puppeteer = null;
}

const chromiumExecutable = process.env.CHROMIUM_PATH || "";
const configuredServerBinary = process.env.TAUTH_BROWSER_TEST_SERVER || "";
const repositoryRoot = path.join(__dirname, "..");
let serverBinary = configuredServerBinary;
let serverBuildDirectory = "";

if (!puppeteer) {
  test.skip("OAuth authorization uses TAuth login and consent pages", () => {});
} else {
  test.before(async () => {
    if (serverBinary) {
      await fs.access(serverBinary);
      return;
    }
    serverBuildDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "tauth-oauth-browser-build-"));
    serverBinary = path.join(serverBuildDirectory, "tauth-test-server");
    execFileSync("go", ["build", "-o", serverBinary, "./cmd/server"], { cwd: repositoryRoot });
  });

  test.after(async () => {
    if (serverBuildDirectory) {
      await fs.rm(serverBuildDirectory, { recursive: true, force: true });
    }
  });

  for (const callbackLocation of ["same-origin", "cross-origin"]) {
    test(`OAuth authorization uses TAuth login and consent pages (${callbackLocation} callback)`, { timeout: 60000 },
      (testingHandle) => runAuthorizationScenario(testingHandle, callbackLocation));
  }

  async function runAuthorizationScenario(testingHandle, callbackLocation) {
    /** @type {import("node:child_process").ChildProcess | null} */
    let server = null;
    /** @type {import("puppeteer").Browser | null} */
    let browser = null;
    const port = await reservePort();
    const issuer = `http://127.0.0.1:${port}`;
    const resource = `${issuer}/protected-resource`;
    let callbackOrigin = issuer;
    if (callbackLocation === "cross-origin") {
      const callbackServer = http.createServer((_request, response) => {
        response.writeHead(200, { "Content-Type": "text/html" });
        response.end("<!doctype html><title>OAuth client</title><p>Callback received</p>");
      });
      await new Promise((resolve) => callbackServer.listen(0, "127.0.0.1", resolve));
      testingHandle.after(() => new Promise((resolve, reject) => callbackServer.close((error) => error ? reject(error) : resolve())));
      const address = callbackServer.address();
      assert.ok(address && typeof address === "object");
      callbackOrigin = `http://127.0.0.1:${address.port}`;
      assert.notEqual(callbackOrigin, issuer);
    }
    const redirectUri = `${callbackOrigin}/client/callback`;
    const temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "tauth-oauth-browser-"));
    testingHandle.after(async () => {
      /** @type {Promise<void>[]} */
      const cleanupTasks = [];
      if (browser) {
        cleanupTasks.push(closeBrowser(browser));
      }
      if (server) {
        cleanupTasks.push(terminateChildProcess(server));
      }
      const cleanupResults = await Promise.allSettled(cleanupTasks);
      await fs.rm(temporaryDirectory, { recursive: true, force: true });
      const cleanupErrors = cleanupResults
        .filter((result) => result.status === "rejected")
        .map((result) => result.reason instanceof Error ? result.reason : new Error(String(result.reason)));
      if (cleanupErrors.length > 0) {
        throw new AggregateError(cleanupErrors, "OAuth browser test cleanup failed");
      }
    }, { timeout: 15000 });

    const { privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const keyBase64 = Buffer.from(privateKey).toString("base64");
    const configPath = path.join(temporaryDirectory, "config.yaml");
    await fs.writeFile(configPath, oauthConfig({ issuer, resource, redirectUri, keyBase64 }), { mode: 0o600 });

    let serverLogs = "";
    const serverProcess = spawn(serverBinary, ["--config", configPath], {
      cwd: repositoryRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
    server = serverProcess;
    serverProcess.stdout.on("data", (chunk) => { serverLogs += chunk.toString(); });
    serverProcess.stderr.on("data", (chunk) => { serverLogs += chunk.toString(); });
    await waitForHealth(`${issuer}/health`, serverProcess);

    const launchOptions = { headless: "new", args: ["--no-sandbox", "--disable-setuid-sandbox"] };
    if (chromiumExecutable) {
      launchOptions.executablePath = chromiumExecutable;
    }
    const launchedBrowser = await puppeteer.launch(launchOptions);
    browser = launchedBrowser;
    const page = await launchedBrowser.newPage();
    const policyErrors = [];
    page.on("console", (message) => {
      if (message.type() === "error" && /form-action/.test(message.text())) {
        policyErrors.push(message.text());
      }
    });
    await page.setRequestInterception(true);
    let googleLoginCount = 0;
    let rejectGoogleLogin = false;
    let observeGoogleRequest = () => {};
    /** @type {Promise<void> | null} */
    let googleLoginGate = null;
    let consentSubmissionCount = 0;
    /** @param {import("puppeteer").HTTPRequest} request */
    const interceptGoogleScript = async (request) => {
      if (request.method() === "POST" && new URL(request.url()).pathname === "/oauth/consent" ) {
        consentSubmissionCount += 1;
      }
      if (request.method() === "POST" && new URL(request.url()).pathname === "/oauth/login" && googleLoginGate) {
        googleLoginCount += 1;
        observeGoogleRequest();
        await googleLoginGate;
        if (rejectGoogleLogin) {
          await request.respond({ status: 500, contentType: "application/json", body: '{"error":"server_error"}' });
          return;
        }
      }
      if (request.url() === "https://accounts.google.com/gsi/client") {
        await request.respond({
          status: 200,
          contentType: "application/javascript",
          body: "window.google={accounts:{id:{initialize:function(options){window.__tauthGoogleCallback=options.callback;},renderButton:function(element){element.textContent='Continue with Google';}}}};",
        });
        return;
      }
      await request.continue();
    };
    page.on("request", interceptGoogleScript);

    let reportConsentState = (_state) => {};
    await page.exposeFunction("reportConsentState", (state) => reportConsentState(state));
    const submitConsent = async (decision) => {
      const consentResponse = await page.reload({ waitUntil: "domcontentloaded" });
      assert.doesNotMatch(consentResponse.headers()["content-security-policy"], /accounts\.google\.com/, "Consent must not enable provider scripts or frames");
      const observed = new Promise((resolve) => { reportConsentState = resolve; });
      await page.evaluate(() => {
        document.addEventListener("submit", (event) => {
          const form = event.target;
          const state = {
            status: document.querySelector('[role="status"]')?.textContent || "",
            disabled: Array.from(form.querySelectorAll("button")).every((button) => button.disabled),
            decisions: new FormData(form, event.submitter).getAll("decision"),
            duplicatePrevented: false,
          };
          const duplicate = new SubmitEvent("submit", { bubbles: true, cancelable: true, submitter: event.submitter });
          form.dispatchEvent(duplicate);
          state.duplicatePrevented = duplicate.defaultPrevented;
          void window.reportConsentState(state);
        }, { once: true });
      });
      const countBefore = consentSubmissionCount;
      await Promise.all([
        page.waitForNavigation({ waitUntil: "domcontentloaded" }),
        page.click(`button[value="${decision}"]`),
      ]);
      const state = await observed;
      assert.equal(state.status, decision === "approve" ? "Connecting…" : "Cancelling…");
      assert.equal(state.disabled, true);
      assert.deepEqual(state.decisions, [decision]);
      assert.equal(state.duplicatePrevented, true);
      assert.equal(consentSubmissionCount, countBefore + 1);
    };

    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    const authorize = new URL(`${issuer}/oauth/authorize`);
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: "browser-test-client",
      redirect_uri: redirectUri,
      resource,
      scope: "resource:use",
      state: "browser-state",
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();
    await page.goto(authorize.href, { waitUntil: "domcontentloaded" });
    assert.equal(await page.$eval("h1", (node) => node.textContent), "Log in");
    assert.match(await page.$eval("main", (node) => node.textContent || ""), /Browser Test Client/);
    await page.waitForFunction(() => document.querySelector("#google-login")?.textContent === "Continue with Google");
    assert.doesNotMatch(await page.content(), /access_token|refresh_token|PRIVATE KEY/);

    // Keep another login page open while this page establishes the shared session.
    const googlePage = await launchedBrowser.newPage();
    await googlePage.setRequestInterception(true);
    googlePage.on("request", interceptGoogleScript);
    await googlePage.goto(authorize.href, { waitUntil: "load" });
    await googlePage.waitForFunction(() => typeof window.__tauthGoogleCallback === "function");
    const pendingGoogleURL = new URL(googlePage.url());

    await page.bringToFront();
    await page.type('input[name="email"]', "browser@example.com");
    await page.type('input[name="password"]', "browser-test-password");
    await Promise.all([
      page.waitForNavigation({ waitUntil: "domcontentloaded" }),
      page.click('button[type="submit"]'),
    ]);
    assert.match(page.url(), new RegExp(`^${escapeRegExp(issuer)}/oauth/consent\\?request=`), await page.content());
    assert.equal(await page.$eval("h1", (node) => node.textContent), "Authorize access");
    const consentText = await page.$eval("main", (node) => node.textContent || "");
    assert.match(consentText, /Browser Test Client/);
    assert.match(consentText, /Browser Resource/);
    assert.match(consentText, /Use the browser test resource/);
    assert.doesNotMatch(await page.content(), /access_token|refresh_token|PRIVATE KEY|password/);

    await googlePage.bringToFront();
    /** @type {() => void} */
    let releaseGoogleLogin = () => {};
    googleLoginGate = new Promise((resolve) => { releaseGoogleLogin = resolve; });
    rejectGoogleLogin = true;
    const rejectedRequest = new Promise((resolve) => { observeGoogleRequest = resolve; });
    await googlePage.evaluate(() => { void window.__tauthGoogleCallback({ credential: "unused-token-with-existing-session" }); });
    await rejectedRequest;
    assert.equal(await googlePage.$eval("h1", (node) => node.textContent), "Signing in…", "Account selection must replace the stale login dialog with progress");
    assert.equal(await googlePage.$eval("#login-controls", (node) => node.hidden), true);
    assert.equal(await googlePage.$eval('[role="status"]', (node) => node.textContent), "Please wait while we sign you in.");
    await googlePage.evaluate(() => { void window.__tauthGoogleCallback({ credential: "duplicate-callback" }); });
    releaseGoogleLogin();
    await googlePage.waitForFunction(() => !document.querySelector("#google-error")?.hidden);
    assert.equal(googleLoginCount, 1, "Only one credential request may be active");
    assert.equal(await googlePage.$eval("h1", (node) => node.textContent), "Log in");
    assert.equal(await googlePage.$eval("#login-controls", (node) => node.hidden), false);
    rejectGoogleLogin = false;
    googleLoginGate = null;
    const googleResponsePromise = googlePage.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/oauth/login");
    await googlePage.evaluate(async () => {
      await window.__tauthGoogleCallback({ credential: "unused-token-with-existing-session" });
    });
    const googleResponse = await googleResponsePromise;
    assert.equal(googleResponse.status(), 200, "Existing-session Google login must return JSON instead of an HTML redirect");
    assert.match(googleResponse.headers()["content-type"], /application\/json/);
    assert.equal(googleResponse.headers()["cache-control"], "no-store");
    await googlePage.waitForFunction(() => window.location.pathname === "/oauth/consent");
    assert.equal(new URL(googlePage.url()).searchParams.get("request"), pendingGoogleURL.searchParams.get("request"));
    assert.equal(await googlePage.$eval("h1", (node) => node.textContent), "Authorize access");
    assert.doesNotMatch(await googlePage.content(), /Google authentication was not accepted/);
    await googlePage.goBack({ waitUntil: "domcontentloaded" });
    assert.equal(googlePage.url(), "about:blank", "Accepted login must replace the login history entry");

    await page.bringToFront();
    await submitConsent("approve");
    const callback = new URL(page.url());
    assert.equal(callback.origin + callback.pathname, redirectUri);
    assert.equal(callback.searchParams.get("state"), "browser-state");
    assert.equal(callback.searchParams.get("iss"), issuer);
    const code = callback.searchParams.get("code");
    assert.ok(code);
    assert.equal(callback.searchParams.has("access_token"), false);
    assert.equal(callback.searchParams.has("refresh_token"), false);

    const tokenResponse = await fetch(`${issuer}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: "browser-test-client",
        resource,
        code_verifier: verifier,
      }),
    });
    assert.equal(tokenResponse.status, 200);
    const tokens = await tokenResponse.json();
    assert.equal(tokens.token_type, "Bearer");
    assert.ok(tokens.access_token);
    assert.ok(tokens.refresh_token);
    const browserStorage = await page.evaluate(() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
      body: document.body.textContent || "",
    }));
    assert.deepEqual(browserStorage.local, []);
    assert.deepEqual(browserStorage.session, []);
    assert.equal(browserStorage.body.includes(tokens.access_token), false);
    assert.equal(browserStorage.body.includes(tokens.refresh_token), false);
    assert.equal(serverLogs.includes(code), false);
    assert.equal(serverLogs.includes(tokens.access_token), false);
    assert.equal(serverLogs.includes(tokens.refresh_token), false);

    // A fresh browser session must retain the server-side grant for this account.
    await page.deleteCookie(...await page.cookies(issuer));
    const freshLoginResponse = await page.goto(authorize.href, { waitUntil: "load" });
    assert.equal(await page.$eval("h1", (node) => node.textContent), "Log in");
    await page.type('input[name="email"]', "browser@example.com");
    await page.type('input[name="password"]', "wrong-password");
    const [rejectedLoginResponse] = await Promise.all([
      page.waitForNavigation({ waitUntil: "domcontentloaded" }),
      page.click('button[type="submit"]'),
    ]);
    assert.equal(rejectedLoginResponse.status(), 401);
    assert.match(await page.$eval('[role="alert"]', (node) => node.textContent), /Authentication was not accepted/);
    await page.type('input[name="email"]', "browser@example.com");
    await page.type('input[name="password"]', "browser-test-password");
    try {
      await Promise.all([
        page.waitForNavigation({ waitUntil: "domcontentloaded" }),
        page.click('button[type="submit"]'),
      ]);
    } finally {
      assert.deepEqual(policyErrors, [], "Password login callback must not be blocked by CSP");
    }
    const freshCallback = new URL(page.url());
    assert.equal(freshCallback.origin + freshCallback.pathname, redirectUri, "Fresh login must reuse the existing exact consent grant");
    assert.ok(freshCallback.searchParams.get("code"));
    assert.notEqual(freshCallback.searchParams.get("code"), code);
    assert.equal(freshCallback.searchParams.get("state"), "browser-state");
    assert.equal(freshCallback.searchParams.get("iss"), issuer);
    for (const response of [freshLoginResponse, rejectedLoginResponse]) {
      const formAction = response.headers()["content-security-policy"].split(";").find((directive) => directive.trim().startsWith("form-action ")).trim();
      assert.equal(formAction, `form-action 'self' ${callbackOrigin}`);
    }
    const freshTokenResponse = await fetch(`${issuer}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: freshCallback.searchParams.get("code"),
        client_id: "browser-test-client",
        resource,
        code_verifier: verifier,
      }),
    });
    assert.equal(freshTokenResponse.status, 200, "Fresh login code must support PKCE exchange");

    const revokeResponse = await fetch(`${issuer}/oauth/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: tokens.refresh_token, client_id: "browser-test-client" }),
    });
    assert.equal(revokeResponse.status, 200);
    await page.goto(authorize.href, { waitUntil: "domcontentloaded" });
    assert.equal(await page.$eval("h1", (node) => node.textContent), "Authorize access");
    await submitConsent("deny");
    const deniedCallback = new URL(page.url());
    assert.equal(deniedCallback.origin + deniedCallback.pathname, redirectUri);
    assert.equal(deniedCallback.searchParams.get("error"), "access_denied");
    assert.equal(deniedCallback.searchParams.has("code"), false);
    assert.equal(deniedCallback.searchParams.get("state"), "browser-state");
  }
}

function oauthConfig({ issuer, resource, redirectUri, keyBase64 }) {
  return `server:
  listen_addr: "${new URL(issuer).host}"
  database_url: ""
oauth:
  enabled: true
  allow_insecure_http: true
  issuer: "${issuer}"
  authorization_endpoint: "${issuer}/oauth/authorize"
  token_endpoint: "${issuer}/oauth/token"
  revocation_endpoint: "${issuer}/oauth/revoke"
  jwks_uri: "${issuer}/oauth/jwks"
  login_endpoint: "${issuer}/oauth/login"
  consent_endpoint: "${issuer}/oauth/consent"
  authorization_request_ttl: "5m"
  authorization_code_ttl: "1m"
  active_signing_key_id: "browser-key"
  signing_keys:
    - id: "browser-key"
      private_key_base64: "${keyBase64}"
  client_metadata:
    request_timeout: "1s"
    maximum_bytes: 5120
    minimum_cache_ttl: "1s"
    maximum_cache_ttl: "1h"
tenants:
  - id: "browser"
    display_name: "Browser"
    tenant_origins: ["${issuer}"]
    google_web_client_id: "browser-test.apps.googleusercontent.com"
    password_auth:
      enabled: true
      users:
        - email: "browser@example.com"
          display_name: "Browser User"
          password_hash: "$2y$10$ltWv5bbEUshywNhX.G4Df.h/LG44DWrEDxCwlpv6iaQa03m.7ISCm"
    oauth:
      enabled: true
      access_token_ttl: "1m"
      refresh_token_ttl: "1h"
      consent_ttl: "30m"
      allow_client_metadata_documents: false
      resources:
        - identifier: "${resource}"
          display_name: "Browser Resource"
          scopes:
            - identifier: "resource:use"
              display_name: "Use resource"
              description: "Use the browser test resource."
      clients:
        - id: "browser-test-client"
          display_name: "Browser Test Client"
          application_type: "native"
          redirect_uris: ["${redirectUri}"]
          grants:
            - resource: "${resource}"
              scopes: ["resource:use"]
    jwt_signing_key: "browser-session-signing-key-with-sufficient-entropy"
    session_cookie_name: "app_session_browser"
    refresh_cookie_name: "app_refresh_browser"
    session_ttl: "15m"
    refresh_ttl: "1h"
    nonce_ttl: "5m"
    allow_insecure_http: true
`;
}

async function reservePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitForHealth(address, server) {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (server.exitCode !== null) {
      throw new Error(`TAuth exited before health was ready: ${server.exitCode}`);
    }
    try {
      const response = await fetch(address);
      if (response.status === 200) {
        return;
      }
    } catch (_error) {
      // The listener is still starting.
    }
    await delay(100);
  }
  throw new Error("TAuth health endpoint did not become ready");
}

/**
 * @param {import("node:child_process").ChildProcess} childProcess
 */
async function terminateChildProcess(childProcess) {
  if (processExited(childProcess)) {
    return;
  }
  const gracefulExit = waitForProcessExit(childProcess);
  childProcess.kill("SIGTERM");
  if (await settlesWithin(gracefulExit, 5000)) {
    return;
  }
  const forcedExit = waitForProcessExit(childProcess);
  childProcess.kill("SIGKILL");
  if (!await settlesWithin(forcedExit, 5000)) {
    throw new Error(`Child process ${childProcess.pid || "unknown"} did not exit after SIGKILL`);
  }
}

/**
 * @param {import("puppeteer").Browser} browser
 */
async function closeBrowser(browser) {
  const closeResult = browser.close().then(() => null, (error) => error);
  if (await settlesWithin(closeResult, 5000)) {
    const closeError = await closeResult;
    if (closeError) {
      throw closeError;
    }
    return;
  }

  const browserProcess = browser.process();
  if (browserProcess && !processExited(browserProcess)) {
    const forcedExit = waitForProcessExit(browserProcess);
    browserProcess.kill("SIGKILL");
    if (!await settlesWithin(forcedExit, 5000)) {
      throw new Error(`Browser process ${browserProcess.pid || "unknown"} did not exit after SIGKILL`);
    }
  }
  if (browser.isConnected()) {
    const disconnectResult = browser.disconnect().then(() => null, (error) => error);
    if (!await settlesWithin(disconnectResult, 1000)) {
      throw new Error("Browser did not disconnect after SIGKILL");
    }
    const disconnectError = await disconnectResult;
    if (disconnectError) {
      throw disconnectError;
    }
  }
}

/**
 * @param {import("node:child_process").ChildProcess} childProcess
 */
function processExited(childProcess) {
  return childProcess.exitCode !== null || childProcess.signalCode !== null;
}

/**
 * @param {import("node:child_process").ChildProcess} childProcess
 * @returns {Promise<void>}
 */
function waitForProcessExit(childProcess) {
  if (processExited(childProcess)) {
    return Promise.resolve();
  }
  return new Promise((resolve) => childProcess.once("exit", () => resolve()));
}

/**
 * @param {Promise<unknown>} promise
 * @param {number} milliseconds
 */
async function settlesWithin(promise, milliseconds) {
  let timeoutHandle;
  const timeoutResult = new Promise((resolve) => {
    timeoutHandle = setTimeout(() => resolve(false), milliseconds);
  });
  try {
    return await Promise.race([
      promise.then(() => true, () => true),
      timeoutResult,
    ]);
  } finally {
    clearTimeout(timeoutHandle);
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
