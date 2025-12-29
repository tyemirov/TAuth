// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const { startDemoServer } = require("./support/demoServer");
const { delay } = require("./support/delay");

let puppeteer = null;
try {
  puppeteer = require("puppeteer");
} catch (primaryError) {
  try {
    puppeteer = require("puppeteer-core");
  } catch (_secondaryError) {
    puppeteer = null;
  }
}

const chromiumExecutable = process.env.CHROMIUM_PATH || "";
const GIS_SCRIPT_URL = "https://accounts.google.com/gsi/client";

function buildDemoConfigScript(baseUrl) {
  const payload = {
    baseUrl,
    googleClientId: "demo-client-id",
    tenantId: "mpr-sites",
  };
  return `// @ts-check\n'use strict';\n\nconst DEMO_CONFIG = Object.freeze(${JSON.stringify(
    payload,
    null,
    2,
  )});\n\nwindow.__TAUTH_DEMO_CONFIG = DEMO_CONFIG;\n`;
}

const GIS_STUB_SOURCE =
  "window.google={accounts:{id:{initialize:function(){},renderButton:function(container){if(container&&container.setAttribute){container.setAttribute('data-gis-rendered','true');}},prompt:function(){}}}};";

if (!puppeteer) {
  test.skip("demo header signs out and clears auth state", () => {});
} else {
  test("demo header signs out and clears auth state", async (t) => {
    const server = await startDemoServer();
    t.after(() => server.close());

    const launchOptions = {
      headless: "new",
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    };
    if (chromiumExecutable) {
      launchOptions.executablePath = chromiumExecutable;
    }
    const browser = await puppeteer.launch(launchOptions);
    t.after(() => browser.close());

    const page = await browser.newPage();
    await page.setRequestInterception(true);
    page.on("request", (request) => {
      const requestUrl = request.url();
      if (requestUrl === GIS_SCRIPT_URL) {
        request.respond({
          status: 200,
          contentType: "application/javascript; charset=utf-8",
          body: GIS_STUB_SOURCE,
        });
        return;
      }
      if (requestUrl.endsWith("/demo-config.js")) {
        request.respond({
          status: 200,
          contentType: "application/javascript; charset=utf-8",
          body: buildDemoConfigScript(server.baseUrl),
        });
        return;
      }
      request.continue();
    });

    await page.goto(`${server.baseUrl}/demo`, { waitUntil: "networkidle0" });

    await page.waitForSelector("mpr-header#demo-header header.mpr-header", {
      timeout: 5000,
    });
    await page.waitForFunction(
      () => Boolean(window.__TAUTH_AUTH_CLIENT_READY__),
      { timeout: 5000 },
    );
    await page.evaluate(async () => {
      if (window.__TAUTH_AUTH_CLIENT_READY__) {
        await window.__TAUTH_AUTH_CLIENT_READY__;
      }
    });

    const initialAuthenticated = await page.evaluate(() => {
      const headerRoot = document.querySelector(
        "mpr-header#demo-header header.mpr-header",
      );
      return headerRoot ? headerRoot.classList.contains("mpr-header--authenticated") : null;
    });
    assert.equal(initialAuthenticated, false);

    const profile = await page.evaluate(async () => {
      if (typeof window.requestNonce !== "function") {
        throw new Error("requestNonce is not available");
      }
      if (typeof window.exchangeGoogleCredential !== "function") {
        throw new Error("exchangeGoogleCredential is not available");
      }
      const nonce = await window.requestNonce();
      return window.exchangeGoogleCredential({
        credential: "demo-credential",
        nonceToken: nonce,
      });
    });

    assert.equal(profile.user_email, "demo@example.com");

    await page.waitForFunction(() => {
      const headerRoot = document.querySelector(
        "mpr-header#demo-header header.mpr-header",
      );
      return headerRoot && headerRoot.classList.contains("mpr-header--authenticated");
    }, { timeout: 5000 });

    await page.click('mpr-header#demo-header [data-mpr-header="sign-out-button"]');
    await delay(50);

    await page.waitForFunction(() => {
      const headerRoot = document.querySelector(
        "mpr-header#demo-header header.mpr-header",
      );
      return headerRoot && !headerRoot.classList.contains("mpr-header--authenticated");
    }, { timeout: 5000 });

    const statusText = await page.evaluate(() => {
      const statusHost = document.querySelector("[data-demo-auth-status]");
      return statusHost ? statusHost.textContent || "" : "";
    });
    assert.match(statusText, /Signed out/i);
  });
}
