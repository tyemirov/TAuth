// @ts-check
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
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

  test("OAuth authorization uses TAuth login and consent pages", { timeout: 60000 }, async (testingHandle) => {
    /** @type {import("node:child_process").ChildProcess | null} */
    let server = null;
    /** @type {import("puppeteer").Browser | null} */
    let browser = null;
    const port = await reservePort();
    const issuer = `http://127.0.0.1:${port}`;
    const resource = `${issuer}/protected-resource`;
    const redirectUri = `${issuer}/client/callback`;
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
    await page.setRequestInterception(true);
    page.on("request", (request) => {
      if (request.url() === "https://accounts.google.com/gsi/client") {
        request.respond({
          status: 200,
          contentType: "application/javascript",
          body: "window.google={accounts:{id:{initialize:function(options){window.__tauthGoogleCallback=options.callback;},renderButton:function(element){element.textContent='Continue with Google';}}}};",
        }).catch(() => {});
        return;
      }
      request.continue().catch(() => {});
    });

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

    await Promise.all([
      page.waitForNavigation({ waitUntil: "domcontentloaded" }),
      page.click('button[value="approve"]'),
    ]);
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
  });
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
