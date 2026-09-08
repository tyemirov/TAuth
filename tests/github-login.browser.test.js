// @ts-check
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const puppeteer = require("puppeteer");

test("GitHub browser redirect, popup, and message boundaries", { timeout: 90000 }, async (suite) => {
  const fixture = spawn("make", ["--no-print-directory", "test-github-browser-server"], {
    cwd: require("node:path").join(__dirname, ".."),
    env: { ...process.env, TAUTH_GITHUB_BROWSER_FIXTURE: "1" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const fixtureExit = new Promise((resolve) => fixture.once("exit", resolve));
  let logs = "";
  const issuer = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`GitHub fixture startup failed: ${logs}`)), 45000);
    fixture.on("error", reject);
    fixture.on("exit", (code) => { clearTimeout(timeout); reject(new Error(`GitHub fixture exited ${code}: ${logs}`)); });
    fixture.stderr.on("data", (chunk) => { logs += chunk.toString(); });
    fixture.stdout.on("data", (chunk) => {
      logs += chunk.toString();
      const match = logs.match(/GITHUB_BROWSER_FIXTURE (https:\/\/[^\s]+)/);
      if (match) { clearTimeout(timeout); resolve(match[1]); }
    });
  });
  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox", "--ignore-certificate-errors"],
    ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
  });
  suite.after(async () => { await browser.close(); await new Promise((resolve, reject) => {
    const request = require("node:https").request(`${issuer}/test/shutdown`, { method: "POST", rejectUnauthorized: false }, response => { response.resume(); response.on("end", resolve); });
    request.on("error", reject); request.end();
  }); await fixtureExit; });

  await suite.test("full-page login restores the authenticated profile", async () => {
    const context = await browser.createBrowserContext();
    try {
      const page = await context.newPage();
      await page.goto(`${issuer}/test/app`);
      assert.equal(await page.evaluate(() => typeof window["startGitHubLogin"]), "function");
      await page.click("#redirect");
      await page.waitForFunction(() => document.querySelector("#profile").textContent.includes("private@example.com"));
      assert.equal(new URL(page.url()).pathname, "/test/app");
    } finally { await context.close(); }
  });

  await suite.test("popup restores the profile without navigation or credential messages", async () => {
    const context = await browser.createBrowserContext();
    try {
      const page = await context.newPage();
      await page.goto(`${issuer}/test/app`);
      await page.evaluate(() => { window["messages"] = []; window.addEventListener("message", event => window["messages"].push(event.data)); });
      assert.equal(await page.evaluate(() => typeof window["startGitHubLogin"]), "function");
      await page.click("#popup");
      await page.waitForFunction(() => document.querySelector("#profile").textContent.includes("private@example.com"));
      const messages = await page.evaluate(() => window["messages"]);
      const completion = messages.find((message) => message.type === "tauth:github");
      assert.deepEqual(Object.keys(completion).sort(), ["correlation", "status", "type"]);
      assert.equal(completion.status, "complete");
      assert.equal(page.url(), `${issuer}/test/app`);
    } finally { await context.close(); }
  });

  await suite.test("a popup return on another approved origin is rejected before login", async () => {
    const context = await browser.createBrowserContext();
    try {
      const page = await context.newPage();
      await page.goto(`${issuer}/test/app`);
      await page.evaluate(() => {
        const open = window.open.bind(window);
        window["popupCalls"] = 0;
        window.open = (...args) => { window["popupCalls"]++; return open(...args); };
      });
      await page.click("#popup-other-origin");
      await page.waitForFunction(() => document.querySelector("#error").textContent.length > 0);
      assert.equal(await page.evaluate(() => window["popupCalls"]), 0, "invalid popup started authentication");
      assert.equal(await page.$eval("#error", element => element.textContent), "tauth.github_invalid_popup_origin");
      const session = await page.evaluate(async () => {
        const response = await fetch("/auth/session", { credentials: "include", headers: { "X-TAuth-Tenant": "github" } });
        return { status: response.status, body: await response.text() };
      });
      assert.deepEqual(session, { status: 204, body: "" });
      const result = await page.evaluate(() => {
        let error = "";
        try { window["getGitHubLoginUrl"]({ mode: "popup", returnTo: "https://other.example.com/done" }); }
        catch (failure) { error = failure.message; }
        return { error, redirect: window["getGitHubLoginUrl"]({ mode: "redirect", returnTo: "https://other.example.com/done" }) };
      });
      assert.equal(result.error, "tauth.github_invalid_popup_origin");
      assert.equal(new URL(result.redirect).searchParams.get("return_to"), "https://other.example.com/done");
    } finally { await context.close(); }
  });

  await suite.test("blocked popups report a clear error", async () => {
    const context = await browser.createBrowserContext();
    try {
      const page = await context.newPage();
      await page.goto(`${issuer}/test/app`);
      await page.evaluate(() => { window.open = () => null; });
      assert.equal(await page.evaluate(() => typeof window["startGitHubLogin"]), "function");
      await page.click("#popup");
      await page.waitForFunction(() => document.querySelector("#error").textContent.includes("popup_blocked"));
    } finally { await context.close(); }
  });

  await suite.test("forged messages are ignored and a closed popup reports failure", async () => {
    const context = await browser.createBrowserContext();
    try {
      const page = await context.newPage();
      await page.goto(`${issuer}/test/app`);
      await page.evaluate(() => {
        const open = window.open.bind(window);
        window.open = (url) => {
          window["correlation"] = new URL(String(url)).searchParams.get("correlation");
          window["popup"] = open("about:blank");
          return window["popup"];
        };
      });
      assert.equal(await page.evaluate(() => typeof window["startGitHubLogin"]), "function");
      await page.click("#popup");
      await page.evaluate(() => {
        const data = { type: "tauth:github", status: "complete", correlation: window["correlation"] };
        window.dispatchEvent(new MessageEvent("message", { origin: "https://foreign.example", source: window["popup"], data }));
        window.dispatchEvent(new MessageEvent("message", { origin: location.origin, source: window, data }));
        window.dispatchEvent(new MessageEvent("message", { origin: location.origin, source: window["popup"], data: { ...data, correlation: "wrong" } }));
        window["popup"].close();
      });
      await page.waitForFunction(() => document.querySelector("#error").textContent.includes("popup_closed"));
      assert.equal(await page.$eval("#profile", (element) => element.textContent), "");
    } finally { await context.close(); }
  });
});
