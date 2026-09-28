// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const puppeteer = require("puppeteer");
const https = require("node:https");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const googleScript = `window.google={accounts:{id:{initialize(config){this.config=config;},renderButton(host,options){const button=document.createElement('button');button.id='fixture-google-login';button.textContent='G';button.setAttribute('aria-label','Continue with Google');button.style.cssText='width:100%;padding:0;min-width:0;height:30px';button.onclick=()=>{options.click_listener?.();this.config.callback({state:options.state,credential:'eyJhbGciOiJSUzI1NiJ9.'+btoa(JSON.stringify({aud:this.config.client_id,iss:'https://accounts.google.com',sub:window.fixtureSubject||'owner',email:window.fixtureSubject?'other@example.com':'vtyemirov@gmail.com',email_verified:true,iat:Math.floor(Date.now()/1000),name:'Browser owner',nonce:this.config.nonce})).replaceAll('=','').replaceAll('+','-').replaceAll('/','_')+'.fixture-signature'});};host.replaceChildren(button);},prompt(){},cancel(){},disableAutoSelect(){}}}};`;

test(
  "owner workspace uses the real management service",
  { timeout: 60000 },
  async (t) => {
    const browser = await puppeteer.launch({
      headless: true,
      args: [
        "--no-sandbox",
        "--no-proxy-server",
        "--ignore-certificate-errors",
        "--host-resolver-rules=MAP *.tauth.test 127.0.0.1, MAP *.customer.test 127.0.0.1",
      ],
    });
    t.after(() => browser.close());
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    t.after(async () => {
      if (errors.length) console.error(errors.join("\n"));
    });
    page.on("console", (message) => {
      if (message.type() === "error") console.error(message.text());
    });
    await page.evaluateOnNewDocument(() => {
      document.addEventListener("mpr-ui:auth:error", (e) =>
        console.error(JSON.stringify(e.detail)),
      );
    });
    await page.setRequestInterception(true);
    let holdNextRead = false,
      heldRead = null,
      holdNextRename = false,
      heldRename = null,
      holdNextSave = false,
      failNextSave = false,
      heldSave = null;
    page.on("request", (request) => {
      if (
        holdNextRead &&
        request.method() === "GET" &&
        request.url().endsWith("/configuration")
      ) {
        holdNextRead = false;
        heldRead = request;
        return;
      }
      if (holdNextRename && request.method() === "PATCH") {
        holdNextRename = false;
        heldRename = request;
        return;
      }
      if (
        request.method() === "PUT" &&
        request.url().endsWith("/configuration")
      ) {
        if (failNextSave) {
          failNextSave = false;
          void request.abort("failed");
          return;
        }
        if (holdNextSave) {
          holdNextSave = false;
          heldSave = request;
          return;
        }
      }
      if (request.url().startsWith("https://accounts.google.com/")) {
        void request.respond({
          status: 200,
          contentType: "text/javascript",
          body: googleScript,
        });
      } else void request.continue();
    });
    for (const destination of [
      {
        fragment: "app=z-fixture-app",
        app: "z-fixture-app",
        tenant: "another-app-browser",
        section: "configuration",
      },
      {
        fragment: "tenant=unnamed-browser&section=integration",
        app: "fixture-app",
        tenant: "unnamed-browser",
        section: "integration",
      },
    ]) {
      await page.goto(
        process.env.TAUTH_CONSOLE_URL + "#" + destination.fragment,
      );
      await page.waitForSelector("#fixture-google-login", { visible: true });
      await page.waitForFunction(
        () =>
          document.getElementById("notice").textContent ===
          "Sign in to manage your tenants.",
      );
      assert.equal(
        await page.evaluate(() => location.hash),
        "#" + destination.fragment,
      );
      await page.click("#fixture-google-login");
      await page.waitForFunction(
        (id) => document.getElementById("tenant-id").textContent === id,
        {},
        destination.tenant,
      );
      assert.equal(
        await page.$eval(
          '[data-app][aria-expanded="true"]',
          (node) => node.dataset.app,
        ),
        destination.app,
      );
      assert.equal(
        await page.$eval(
          '[data-section][aria-current="page"]',
          (node) => node.dataset.section,
        ),
        destination.section,
      );
      await page.evaluate(() => logout());
      await page.waitForSelector("#signed-out:not([hidden])");
      assert.equal(await page.evaluate(() => location.hash), "");
      await page.goto("about:blank");
    }
    await page.goto(process.env.TAUTH_CONSOLE_URL);
    assert.equal(await page.title(), "TAuth · Tenant workspace");
    await page.waitForSelector("#fixture-google-login", {
      visible: true,
      timeout: 10000,
    });
    await page.screenshot({ path: "/tmp/tauth-console-login.png" });
    await page.click("#fixture-google-login");

    await page.waitForSelector("#workspace:not([hidden])", { timeout: 10000 });
    await page.waitForSelector(
      '[data-app="fixture-app"][aria-expanded="true"]',
    );
    assert.deepEqual(
      await page.$$eval("[data-app]", (nodes) =>
        nodes.map((node) => ({
          name: node.querySelector(".app-name").textContent,
          count: node.querySelector(".tenant-count").textContent,
        })),
      ),
      [
        { name: "Fixture app", count: "2" },
        { name: "Other App", count: "1" },
      ],
    );
    await page.click('[data-app="z-fixture-app"]');
    await page.waitForSelector('[data-tenant="another-app-browser"]');
    await page.click('[data-app="fixture-app"]');
    await page.waitForSelector('[data-tenant="imported-browser"]');
    const dimensions = await page.evaluate(() => ({
      width: document.querySelector("main").getBoundingClientRect().width,
      row: document.querySelector("[data-app]").getBoundingClientRect().height,
      control: document.querySelector("#create-app").getBoundingClientRect()
        .height,
    }));
    assert.ok(dimensions.width <= 1180);
    assert.ok(dimensions.row <= 36);
    assert.ok(dimensions.control <= 34);
    assert.equal(
      await page.$eval("#authentication-toggle", (node) => node.tagName),
      "BUTTON",
    );
    assert.equal(await page.$(".tenant-actions"), null);
    assert.equal(
      await page.$eval("#rename", (node) => node.getAttribute("aria-label")),
      "Rename tenant",
    );
    assert.equal(
      await page.$eval("#rename-app", (node) =>
        node.getAttribute("aria-label"),
      ),
      "Rename App",
    );
    assert.equal(
      await page.$$eval("mpr-header a", (nodes) =>
        nodes.some((node) => node.textContent === "Documentation"),
      ),
      false,
    );
    assert.equal(
      await page.$$eval("mpr-footer a", (nodes) =>
        nodes.some((node) => node.textContent === "Documentation"),
      ),
      true,
    );
    assert.deepEqual(
      await page.$$eval("#sections button", (nodes) =>
        nodes.map((node) => node.textContent),
      ),
      ["Configuration", "Integration"],
    );
    assert.equal(
      await page.$eval("#session-settings", (node) => node.open),
      false,
    );
    await page.focus("#session-settings summary");
    await page.keyboard.press("Enter");
    await page.waitForSelector("#session-ttl", { visible: true });
    await page.keyboard.press("Enter");
    assert.equal(
      await page.$eval("#session-settings", (node) => node.open),
      false,
    );

    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "Imported application",
    );
    assert.equal(await page.$eval("#notice", (node) => node.textContent), "");
    assert.equal(await page.$eval("#notice", (node) => node.hidden), true);
    assert.equal(
      await page.$eval("#tenant-state", (node) => node.textContent),
      "Authentication unavailable",
    );
    assert.equal(
      await page.$eval(
        "#authentication-toggle",
        (node) => getComputedStyle(node).borderTopWidth,
      ),
      "1px",
    );
    assert.match(
      await page.$eval("#next-step", (node) => node.textContent),
      /no active configuration/,
    );
    assert.doesNotMatch(
      await page.$eval("#next-step", (node) => node.textContent),
      /Complete the application settings/,
    );
    await page.screenshot({ path: "/tmp/tauth-authentication-status.png" });
    await page.click("#rename-app");
    assert.equal(await page.$("dialog[open]"), null);
    await page.waitForSelector("#edited-name", { visible: true });
    assert.equal(await page.$("#save-status"), null);
    assert.equal(await page.$("#new-environment"), null);
    assert.equal(
      await page.$eval(
        "#name-editor",
        (node) =>
          node.parentElement ===
          document.getElementById("selected-app-name").parentElement,
      ),
      true,
    );
    await page.screenshot({ path: "/tmp/tauth-i221-inline-name.png" });
    assert.equal(await page.$("#rename-environment"), null);
    assert.equal(
      await page.$eval("#edited-name", (node) =>
        node.getAttribute("aria-label"),
      ),
      "App name",
    );
    holdNextRename = true;
    const invalidAppRename = page.waitForRequest(
      (request) =>
        request.method() === "PATCH" &&
        request.url().endsWith("/apps/fixture-app"),
    );
    await page.$eval("#edited-name", (node) => {
      node.value = "";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await invalidAppRename;
    await page.$eval("#edited-name", (node) => {
      node.value = "Renamed Fixture";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await heldRename.continue();
    await page.waitForFunction(
      () =>
        document.getElementById("selected-app-name").textContent ===
        "Renamed Fixture",
    );
    assert.equal(
      await page.$eval(
        '[data-app="fixture-app"] .app-name',
        (node) => node.textContent,
      ),
      "Renamed Fixture",
    );
    assert.equal(
      await page.$eval("#tenant-name", (node) => node.textContent),
      "Imported application",
    );
    await page.keyboard.press("Escape");
    assert.equal(
      await page.evaluate(() => document.activeElement.id),
      "rename-app",
    );
    await page.reload();
    await page.waitForFunction(
      () =>
        document.getElementById("selected-app-name").textContent ===
        "Renamed Fixture",
    );
    await page.click("#rename-app");
    await page.$eval("#edited-name", (node) => {
      node.value = "";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.waitForFunction(
      () =>
        document.getElementById("edited-name").getAttribute("aria-invalid") ===
        "true",
    );
    await page.keyboard.press("Escape");
    await page.waitForSelector("#edited-name", { visible: true });
    assert.equal(await page.$("dialog[open]"), null);
    assert.equal(await page.$eval("#edited-name", (node) => node.value), "");
    await page.$eval("#edited-name", (node) => {
      node.value = "Fixture app";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.waitForFunction(
      () =>
        document.getElementById("selected-app-name").textContent ===
        "Fixture app",
    );
    await page.keyboard.press("Escape");
    assert.equal(await page.$("#open-admin"), null);
    await page.waitForSelector('[data-mpr-user-action="admin"]');
    await page.click('[data-mpr-user="trigger"]');
    await page.waitForSelector('[data-mpr-user-action="admin"]', {
      visible: true,
    });
    assert.equal(await page.$eval("#admin-dialog", (node) => node.open), false);
    await page.screenshot({ path: "/tmp/tauth-avatar-menu.png" });
    await page.click('[data-mpr-user-action="admin"]');
    await page.waitForSelector("#admin-dialog[open]");
    await page.waitForFunction(() =>
      document
        .querySelector("#account-list")
        ?.textContent.includes("vtyemirov@gmail.com"),
    );
    assert.equal(
      await page.$eval("#accounts-status", (node) => node.textContent),
      "1 account",
    );
    await page.keyboard.press("Escape");
    assert.equal(await page.$eval("#admin-dialog", (node) => node.open), false);
    await page.waitForFunction(
      () =>
        document.querySelector('[data-mpr-user="trigger"]') ===
        document.activeElement,
    );
    assert.equal(
      await page.$$eval("button", (nodes) =>
        nodes.some((node) =>
          /^(save|refresh|reload)\b/i.test(node.textContent.trim()),
        ),
      ),
      false,
    );
    assert.deepEqual(
      await page.$$eval("[data-tenant]", (nodes) =>
        nodes.map((node) => node.textContent),
      ),
      ["Imported application", "unnamed-browser"],
    );
    await page.click('[data-tenant="unnamed-browser"]');
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "unnamed-browser",
    );
    assert.equal(
      await page.$eval("#tenant-id", (node) => node.textContent),
      "unnamed-browser",
    );
    await page.screenshot({ path: "/tmp/tauth-tenant-labels.png" });
    await page.click('[data-tenant="imported-browser"]');
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "Imported application",
    );
    // The imported tenant uses the same settings and protected export UI.
    await page.click("[data-section=configuration]");
    await page.$eval("#frontend-origins", (node) => {
      node.value = "http://localhost:9391";
    });
    await page.type("#api-base", "http://localhost:9392");
    await page.click("#local-development");
    await page.$eval("#configuration", (node) =>
      node.dispatchEvent(new Event("input", { bubbles: true })),
    );
    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
    );
    await page.click("[data-section=configuration]");
    assert.equal(
      await page.evaluate(async (api) => {
        const response = await fetch(
          api + "/api/management/tenants/imported-browser",
          { credentials: "include" },
        );
        return (await response.json()).active_revision;
      }, process.env.TAUTH_CONSOLE_API),
      2,
    );
    await page.click("[data-section=integration]");
    await page.waitForSelector("#integration-ready:not([hidden])");
    assert.ok(
      (
        await page.$eval("#browser-example", (node) => node.textContent)
      ).includes("imported-browser"),
    );
    await page.click("#export-session-key");
    await page.waitForSelector("#reauth-google #fixture-google-login", {
      visible: true,
    });
    await page.click("#reauth-google #fixture-google-login");
    await page.waitForSelector("#export-key-panel:not([hidden])");
    assert.equal(
      await page.$eval("#export-key", (node) => node.textContent),
      Buffer.from("imported-browser-signing-key").toString("base64"),
    );
    await page.click("#dismiss-export");
    await page.click("[data-section=configuration]");
    assert.equal(
      await page.$eval(
        '[data-app][aria-expanded="true"]',
        (node) => node.dataset.app,
      ),
      "fixture-app",
    );
    await page.click("#create-app");
    await page.type("#app-name", "Separate App");
    await page.click("#confirm-app");
    await page.waitForFunction(
      () =>
        document.querySelector('[data-app][aria-expanded="true"] .app-name')
          ?.textContent === "Separate App",
    );
    assert.equal(
      await page.$$eval("[data-tenant]", (nodes) => nodes.length),
      0,
    );
    assert.equal(
      await page.$eval("#tenant-detail", (node) => node.hidden),
      true,
    );
    await page.click("#rename-empty-app");
    await page.$eval("#edited-name", (node) => {
      node.value = "Separate renamed App";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.click("#empty-title");
    await page.waitForFunction(
      () =>
        document.getElementById("empty-app-name").textContent ===
        "Separate renamed App",
    );
    await page.waitForSelector("#name-editor", { hidden: true });
    await chooseApp(page, "fixture-app");
    await page.waitForSelector('[data-tenant="imported-browser"]');
    await page.click("[data-create]");
    assert.equal(
      await page.$eval("#confirm-tenant", (node) => node.disabled),
      true,
    );
    await page.type("#new-name", "Browser application");
    assert.equal(
      await page.$eval("#confirm-tenant", (node) => node.disabled),
      true,
    );
    await page.type("#new-origin", "http://localhost:9491");
    assert.equal(
      await page.$eval("#confirm-tenant", (node) => node.disabled),
      true,
    );
    await page.type(
      "#new-google-client",
      "browser-app-client.apps.googleusercontent.com",
    );
    await page.screenshot({ path: "/tmp/tauth-three-field-create.png" });
    assert.equal(
      await page.$eval("#confirm-tenant", (node) => node.disabled),
      false,
    );
    await page.click("#confirm-tenant");
    await page
      .waitForFunction(
        () =>
          document.getElementById("tenant-name").textContent ===
          "Browser application",
        { timeout: 5000 },
      )
      .catch(async () => {
        throw new Error(
          await page.$eval("#notice", (node) => node.textContent),
        );
      });
    const tenantID = await page.$eval("#tenant-id", (node) => node.textContent);
    assert.equal(
      await page.$eval("#tenant-state", (node) => node.textContent),
      "Authentication active",
    );
    assert.equal(await page.$("#activate"), null);
    await page.click("[data-section=configuration]");
    assert.equal(
      await page.$eval("#frontend-origins", (node) => node.value),
      "http://localhost:9491",
    );
    await page.type("#api-base", "http://localhost:9492");
    await page.screenshot({
      path: "/tmp/tauth-console-workspace.png",
      fullPage: true,
    });
    await page.$eval("#configuration", (node) =>
      node.dispatchEvent(new Event("input", { bubbles: true })),
    );

    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
      { timeout: 5000 },
    );
    await page.click("[data-section=configuration]");
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-state").textContent ===
        "Authentication active",
    );
    await page.reload();
    await page.waitForFunction(
      (id) => document.getElementById("tenant-id").textContent === id,
      {},
      tenantID,
    );
    assert.equal(
      await page.$eval("#tenant-state", (node) => node.textContent),
      "Authentication active",
    );
    await page.click("[data-section=configuration]");
    holdNextSave = true;
    const waitingSave = page.waitForRequest(
      (request) =>
        request.method() === "PUT" && request.url().endsWith("/configuration"),
    );
    await page.$eval("#session-ttl", (node) => {
      node.value = "20m";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await waitingSave;
    await page.$eval("#session-ttl", (node) => {
      node.value = "25m";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await heldSave.continue();
    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
      { timeout: 10000 },
    );
    assert.equal(await page.$eval("#session-ttl", (node) => node.value), "25m");
    failNextSave = true;
    await page.$eval("#session-ttl", (node) => {
      node.value = "15m";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.waitForFunction(
      () => document.querySelector("#field-error").textContent !== "",
    );
    assert.equal(await page.$eval("#session-ttl", (node) => node.value), "15m");
    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
      { timeout: 10000 },
    );
    // A late error for invalid input must not strand its corrected successor.
    holdNextSave = true;
    const invalidSave = page.waitForRequest(
      (request) =>
        request.method() === "PUT" && request.url().endsWith("/configuration"),
    );
    await page.$eval("#session-ttl", (node) => {
      node.value = "2h";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await invalidSave;
    await page.$eval("#session-ttl", (node) => {
      node.value = "18m";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await heldSave.continue();
    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
      { timeout: 10000 },
    );
    assert.equal(await page.$eval("#session-ttl", (node) => node.value), "18m");
    holdNextSave = true;
    const limitedSave = page.waitForRequest(
      (request) =>
        request.method() === "PUT" && request.url().endsWith("/configuration"),
    );
    await page.$eval("#session-ttl", (node) => {
      node.value = "19m";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await limitedSave;
    await rateLimit(heldSave);
    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
      { timeout: 10000 },
    );
    assert.equal(await page.$eval("#session-ttl", (node) => node.value), "19m");
    await page.$eval("#session-settings", (node) => {
      node.open = false;
    });
    await page.$eval("#session-ttl", (node) => (node.value = "2h"));
    await page.$eval("#configuration", (node) =>
      node.dispatchEvent(new Event("input", { bubbles: true })),
    );
    await page.waitForFunction(() =>
      document
        .getElementById("field-error")
        .textContent.includes("session ttl invalid"),
    );
    assert.equal(await page.$eval("#session-ttl", (node) => node.value), "2h");
    assert.equal(
      await page.$eval("#session-settings", (node) => node.open),
      true,
    );
    assert.equal(
      await page.evaluate(() => document.activeElement.id),
      "session-ttl",
    );
    await page.click("#session-settings summary");
    await page.$eval("#session-ttl", (node) => (node.value = "15m"));
    const concurrentStatus = await page.evaluate(
      async ({ api, id }) => {
        const path = api + "/api/management/tenants/" + id + "/configuration";
        const response = await fetch(path, { credentials: "include" });
        const current = await response.json();
        const body = {
          google_web_client_id: "concurrent-client",
          frontend_origins: current.frontend_origins,
          api_base_url: current.api_base_url,
          local_development: current.local_development,
          session_ttl: current.session_ttl,
          refresh_ttl: current.refresh_ttl,
        };
        return (
          await fetch(path, {
            method: "PUT",
            credentials: "include",
            headers: {
              "Content-Type": "application/json",
              "X-TAuth-CSRF": "1",
              "If-Match": response.headers.get("ETag"),
            },
            body: JSON.stringify(body),
          })
        ).status;
      },
      { api: process.env.TAUTH_CONSOLE_API, id: tenantID },
    );
    assert.equal(concurrentStatus, 200);
    // A lifetime-only edit preserves the client ID accepted from another session.
    await page.$eval("#session-ttl", (node) => {
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
    );
    assert.equal(
      await page.$eval("#google-client", (node) => node.value),
      "concurrent-client",
    );

    holdNextRead = true;
    const waitingRead = page.waitForRequest(
      (request) =>
        request.method() === "GET" && request.url().endsWith("/configuration"),
    );
    await page.$eval("#google-client", (node) => {
      node.value = "my-unsaved-client";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await waitingRead;
    const competingStatus = await page.evaluate(
      async ({ api, id }) => {
        const path = api + "/api/management/tenants/" + id + "/configuration";
        const response = await fetch(path, { credentials: "include" });
        const current = await response.json();
        const body = {
          google_web_client_id: "another-session-client",
          frontend_origins: current.frontend_origins,
          api_base_url: current.api_base_url,
          local_development: current.local_development,
          session_ttl: current.session_ttl,
          refresh_ttl: current.refresh_ttl,
        };
        return (
          await fetch(path, {
            method: "PUT",
            credentials: "include",
            headers: {
              "Content-Type": "application/json",
              "X-TAuth-CSRF": "1",
              "If-Match": response.headers.get("ETag"),
            },
            body: JSON.stringify(body),
          })
        ).status;
      },
      { api: process.env.TAUTH_CONSOLE_API, id: tenantID },
    );
    assert.equal(competingStatus, 200);
    await page.$eval("#google-client", (node) => {
      node.value = "my-newer-client";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await heldRead.continue();
    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
      { timeout: 10000 },
    );
    assert.equal(
      await page.$eval("#google-client", (node) => node.value),
      "my-newer-client",
    );
    assert.equal(await page.$eval("#session-ttl", (node) => node.value), "15m");
    // Return the client to the value used by the later customer integration.
    await page.$eval("#google-client", (node) => {
      node.value = "concurrent-client";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
    );
    await page.setViewport({ width: 1440, height: 900 });
    await page.click('[data-section="configuration"]');
    await page.screenshot({
      path: "/tmp/tauth-i221-desktop.png",
      fullPage: true,
    });
    const formHeight = await page.$eval(
      "#configuration",
      (node) => node.getBoundingClientRect().height,
    );
    assert.ok(formHeight < 550);
    await page.setViewport({ width: 390, height: 844 });
    await page.screenshot({
      path: "/tmp/tauth-i221-mobile.png",
      fullPage: true,
    });
    await page.click('[data-mpr-user="trigger"]');
    await page.click('[data-mpr-user-action="admin"]');
    await page.waitForSelector("#admin-dialog[open]");
    assert.equal(
      await page.$eval(
        "#admin-dialog",
        (node) => node.getBoundingClientRect().right <= innerWidth,
      ),
      true,
    );
    await page.click("#admin-dialog [data-close]");
    await page.waitForFunction(
      () =>
        document.querySelector('[data-mpr-user="trigger"]') ===
        document.activeElement,
    );
    await page.click(`[data-tenant="${"unnamed-browser"}"]`);
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "unnamed-browser",
    );

    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
      true,
    );
    await page.click(`[data-tenant="${"imported-browser"}"]`);
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "Imported application",
    );
    await page.click(`[data-tenant="${tenantID}"]`);
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "Browser application",
    );
    // Delay a real response at the fetch boundary, then switch tenants.
    await page.evaluate(() => {
      const original = window.fetch;
      window.fixtureOriginalFetch = original;
      window.fetch = async (...args) => {
        const response = await original(...args);
        if (String(args[0]).endsWith("/imported-browser/configuration")) {
          window.fixtureHeld = true;
          await new Promise((resolve) => (window.fixtureRelease = resolve));
        }
        return response;
      };
    });
    await page.click(`[data-tenant="${"imported-browser"}"]`);
    await page.waitForFunction(() => window.fixtureHeld === true);
    await page.click(`[data-tenant="${tenantID}"]`);
    await page.waitForFunction(
      (id) => document.getElementById("tenant-id").textContent === id,
      {},
      tenantID,
    );
    await page.evaluate(() => {
      window.fixtureRelease();
      window.fetch = window.fixtureOriginalFetch;
    });
    await page.waitForFunction(
      (id) => document.getElementById("tenant-id").textContent === id,
      {},
      tenantID,
    );
    await page.waitForSelector("#tenant-detail:not([hidden])");
    await page.click("[data-section=configuration]");
    await page.click("#rename");
    await page.focus("#edited-name");
    await page.keyboard.press("Escape");
    assert.equal(
      await page.evaluate(() => document.activeElement.id),
      "rename",
    );
    await page.click("#rename");
    // A background update must preserve the inline input and untouched environment.
    const metadataStatus = await page.evaluate(
      async ({ api, id }) => {
        const path = api + "/api/management/tenants/" + id;
        const current = await fetch(path, { credentials: "include" });
        return (
          await fetch(path, {
            method: "PATCH",
            credentials: "include",
            headers: {
              "Content-Type": "application/json",
              "X-TAuth-CSRF": "1",
              "If-Match": current.headers.get("ETag"),
            },
            body: JSON.stringify({
              name: "Remote name",
              environment: "remote-environment",
            }),
          })
        ).status;
      },
      { api: process.env.TAUTH_CONSOLE_API, id: tenantID },
    );
    assert.equal(metadataStatus, 200);
    await page.evaluate(() => window.dispatchEvent(new Event("focus")));
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent === "Remote name",
    );
    await page.focus("#edited-name");
    await page.keyboard.press("End");
    holdNextRename = true;
    const waitingRename = page.waitForRequest(
      (request) => request.method() === "PATCH",
    );
    await page.keyboard.type(" renam");
    await waitingRename;
    await page.keyboard.type("ed");
    await page.keyboard.press("Escape");
    assert.deepEqual(Object.keys(JSON.parse(heldRename.postData())), ["name"]);
    await heldRename.continue();
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "Browser application renamed",
    );
    const renamed = await page.evaluate(
      async ({ api, id }) =>
        (
          await fetch(api + "/api/management/tenants/" + id, {
            credentials: "include",
          })
        ).json(),
      { api: process.env.TAUTH_CONSOLE_API, id: tenantID },
    );
    assert.equal(renamed.environment, "remote-environment");
    await page.click("#rename");
    holdNextRename = true;
    const invalidRename = page.waitForRequest(
      (request) => request.method() === "PATCH",
    );
    await page.$eval("#edited-name", (node) => {
      node.value = "";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await invalidRename;
    await page.$eval("#edited-name", (node) => {
      node.value = "Browser application renamed";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await heldRename.continue();
    await page.waitForFunction(
      () =>
        document.querySelector("#name-editor").getAttribute("aria-busy") ===
          "false" && document.querySelector("#name-error").textContent === "",
      { timeout: 10000 },
    );
    holdNextRename = true;
    const limitedRename = page.waitForRequest(
      (request) => request.method() === "PATCH",
    );
    await page.$eval("#edited-name", (node) => {
      node.value = "Browser application renamed again";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await limitedRename;
    await rateLimit(heldRename);
    await page.waitForFunction(
      () =>
        document.querySelector("#name-editor").getAttribute("aria-busy") ===
          "false" && document.querySelector("#name-error").textContent === "",
      { timeout: 10000 },
    );
    const savedMetadata = await page.evaluate(
      async ({ api, id }) =>
        (
          await fetch(api + "/api/management/tenants/" + id, {
            credentials: "include",
          })
        ).json(),
      { api: process.env.TAUTH_CONSOLE_API, id: tenantID },
    );
    assert.equal(savedMetadata.name, "Browser application renamed again");
    assert.equal(savedMetadata.environment, "remote-environment");
    await page.keyboard.press("Escape");
    await page.click("[data-section=configuration]");
    await page.$eval(
      "#frontend-origins",
      (node, value) => (node.value = value),
      process.env.TAUTH_CUSTOMER_FRONTEND,
    );
    await page.$eval(
      "#api-base",
      (node, value) => (node.value = value),
      process.env.TAUTH_CUSTOMER_API,
    );
    await page.click("#local-development");
    await page.$eval("#configuration", (node) =>
      node.dispatchEvent(new Event("input", { bubbles: true })),
    );
    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
    );
    await page.click("[data-section=configuration]");
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-state").textContent ===
        "Authentication active",
    );
    await page.click("[data-section=integration]");
    await page.waitForSelector("#integration-ready:not([hidden])");
    await page.click("#export-session-key");
    await page.waitForSelector("#reauth-google #fixture-google-login", {
      visible: true,
    });
    await page.click("#reauth-google #fixture-google-login");
    await page.waitForSelector("#export-key-panel:not([hidden])");
    const exportedKey = await page.$eval(
      "#export-key",
      (node) => node.textContent,
    );
    const publicHTML = await page.$eval(
      "#browser-example",
      (node) => node.textContent,
    );
    const backend = JSON.parse(
      await page.$eval("#backend-example", (node) => node.textContent),
    );
    assert.equal(publicHTML.includes(exportedKey), false);
    await operator("/__customer-config", {
      tenant_id: tenantID,
      session_cookie_name: backend.TAUTH_SESSION_COOKIE,
      session_key_base64: exportedKey,
      browser_html: publicHTML,
    });
    await page.click("#dismiss-export");
    await page.waitForFunction(
      () => document.getElementById("export-key").textContent === "",
    );
    assert.ok(exportedKey.length > 30);
    assert.ok(publicHTML.includes("https://tauth.mprlab.com/tauth.js"));
    const app = await browser.newPage();
    app.on("pageerror", (error) =>
      console.error("application error", error.message),
    );
    app.on("console", (message) => {
      if (message.type() === "error")
        console.error("application console", message.text());
    });
    await app.evaluateOnNewDocument(
      () => (window.fixtureSubject = "application-user"),
    );
    await app.setRequestInterception(true);
    app.on("request", (request) => {
      if (request.url().startsWith("https://accounts.google.com/"))
        void request.respond({
          status: 200,
          contentType: "text/javascript",
          body: googleScript,
        });
      else if (request.url() === "https://tauth.mprlab.com/tauth.js")
        void request.respond({
          status: 200,
          contentType: "text/javascript",
          body: fs.readFileSync(
            path.join(__dirname, "../web/tauth.js"),
            "utf8",
          ),
        });
      else void request.continue();
    });
    const refreshes = [];
    app.on("request", (request) => {
      if (request.url().endsWith("/auth/refresh"))
        refreshes.push(request.url());
    });
    await app.goto(process.env.TAUTH_CUSTOMER_FRONTEND);
    await app
      .waitForSelector("#fixture-google-login", {
        visible: true,
        timeout: 5000,
      })
      .catch(async () => {
        throw new Error("Application bootstrap failed: " + (await app.title()));
      });
    await app.click("#fixture-google-login");
    await app.waitForFunction(() => getCurrentUser() !== null);
    const protectedStatus = () =>
      app.evaluate(
        async (api) =>
          (await fetch(api + "/private", { credentials: "include" })).status,
        process.env.TAUTH_CUSTOMER_API,
      );
    assert.equal(await protectedStatus(), 200);
    const cookies = await app.cookies(process.env.TAUTH_CUSTOMER_API + "/auth");
    const session = cookies.find(
      (cookie) => cookie.name === backend.TAUTH_SESSION_COOKIE,
    );
    const refresh = cookies.find((cookie) => cookie.path === "/auth");
    assert.equal(session.domain, "api.customer.test");
    assert.equal(session.httpOnly, true);
    assert.equal(session.secure, true);
    assert.equal(refresh.domain, "api.customer.test");
    assert.equal(refresh.httpOnly, true);
    assert.equal(refresh.secure, true);
    assert.equal(
      cookies.some((cookie) => cookie.domain.startsWith(".")),
      false,
    );
    await operator("/__expire-session", {});
    const beforeRefresh = refreshes.length;
    assert.equal(
      await app.evaluate(
        async (api) => (await apiFetch(api + "/private")).status,
        process.env.TAUTH_CUSTOMER_API,
      ),
      200,
    );
    assert.ok(refreshes.length > beforeRefresh);
    await operator("/__restart", {});
    assert.equal(
      await app.evaluate(
        async ({ api, id }) =>
          (
            await fetch(api + "/auth/refresh", {
              method: "POST",
              credentials: "include",
              headers: { "X-TAuth-Tenant": id },
            })
          ).status,
        { api: process.env.TAUTH_CUSTOMER_API, id: tenantID },
      ),
      204,
    );
    assert.equal(await protectedStatus(), 200);
    const currentCookies = await app.cookies(process.env.TAUTH_CUSTOMER_API);
    const currentSession = currentCookies.find(
      (cookie) => cookie.name === backend.TAUTH_SESSION_COOKIE,
    );
    const header = Buffer.from(
      JSON.stringify({ alg: "HS256", typ: "JWT" }),
    ).toString("base64url");
    const claims = Buffer.from(
      JSON.stringify({
        iss: "tauth",
        sub: "other-user",
        tenant_id: "wrong-tenant",
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
      }),
    ).toString("base64url");
    const unsigned = header + "." + claims;
    const forged =
      unsigned +
      "." +
      crypto
        .createHmac("sha256", Buffer.from(exportedKey, "base64"))
        .update(unsigned)
        .digest("base64url");
    await app.setCookie({ ...currentSession, value: forged });
    assert.equal(await protectedStatus(), 403);
    await app.setCookie(currentSession);
    assert.equal(
      await operatorStatus(
        process.env.TAUTH_CUSTOMER_API.replace(
          "api.customer.test",
          "127.0.0.1",
        ) + "/private",
        { Origin: "https://denied.customer.test" },
      ),
      403,
    );
    assert.equal(
      await app.evaluate(
        (key) =>
          JSON.stringify({
            local: { ...localStorage },
            session: { ...sessionStorage },
            url: location.href,
          }).includes(key),
        exportedKey,
      ),
      false,
    );
    await app.click("#logout");
    await app.waitForFunction(() => getCurrentUser() === null);
    assert.equal(await protectedStatus(), 401);
    await app.close();
    await page.click("#run-setup-check");
    await page.waitForFunction(() =>
      document.getElementById("setup-result").textContent.includes("succeeded"),
    );
    const checkEvidence = await page.$eval(
      "#setup-result",
      (node) => node.textContent,
    );
    assert.ok(checkEvidence.includes("/auth/nonce: passed (200)"));
    await page.reload();
    await page.waitForFunction(() =>
      document.getElementById("setup-result").textContent.includes("succeeded"),
    );
    // Tenant selection closes the export and rejects a late Google callback.
    await page.click("#export-session-key");
    await page.waitForSelector("#reauth-google #fixture-google-login", {
      visible: true,
    });
    await page.evaluate(() => {
      window.fixtureLateCallback = google.accounts.id.config.callback;
    });
    await page.click("#reauth-google #fixture-google-login");
    await page.waitForSelector("#export-key-panel:not([hidden])");
    await page.evaluate(() => {
      location.hash = "tenant=imported-browser&section=integration";
    });
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-id").textContent === "imported-browser",
    );
    assert.equal(
      await page.$eval("#export-key", (node) => node.textContent),
      "",
    );
    assert.equal(
      await page.$eval("#export-dialog", (node) => node.open),
      false,
    );
    await page.evaluate(() =>
      window.fixtureLateCallback({ credential: "stale" }),
    );
    assert.equal(
      await page.$eval("#export-key", (node) => node.textContent),
      "",
    );
    await page.evaluate((id) => {
      location.hash = "tenant=" + id + "&section=integration";
    }, tenantID);
    await page.waitForFunction(
      (id) => document.getElementById("tenant-id").textContent === id,
      {},
      tenantID,
    );
    await page.click("[data-section=configuration]");
    await page.click("#authentication-toggle");
    await page.keyboard.press("Escape");
    assert.equal(
      await page.$eval("#suspend-dialog", (node) => node.open),
      false,
    );
    await page.click("#authentication-toggle");
    await page.click("#confirm-suspend");
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-state").textContent ===
        "Authentication suspended",
    );
    assert.match(
      await page.$eval("#next-step", (node) => node.textContent),
      /not accepting sign-ins/,
    );
    assert.equal(
      await page.$eval("#authentication-toggle", (node) =>
        node.getAttribute("aria-label"),
      ),
      "Resume authentication",
    );
    await page.focus("#authentication-toggle");
    await page.keyboard.press("Enter");
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-state").textContent ===
        "Authentication active",
    );
    assert.equal(
      await page.$eval("#authentication-toggle", (node) =>
        node.getAttribute("aria-label"),
      ),
      "Pause authentication",
    );
    // Release the fixture origin before the second owner configures its customer app.
    await page.click("#authentication-toggle");
    await page.click("#confirm-suspend");
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-state").textContent ===
        "Authentication suspended",
    );
    await page.click("[data-mpr-user=trigger]");
    await Promise.all([
      page.waitForNavigation({ waitUntil: "domcontentloaded" }),
      page.click("[data-mpr-user=logout]"),
    ]);
    await page.waitForSelector("#signed-out:not([hidden])");
    await page.waitForFunction(
      () => document.getElementById("tenant-id").textContent === "",
    );
    assert.equal(await page.$eval("#new-name", (node) => node.value), "");
    await page.evaluate(() => (window.fixtureSubject = "second-owner"));
    await page.waitForSelector("#fixture-google-login", { visible: true });
    await page.click("#fixture-google-login");
    await page.waitForSelector("#workspace:not([hidden])");
    await page.waitForSelector("#empty:not([hidden])");
    assert.equal(
      await page.$$eval("[data-tenant]", (nodes) => nodes.length),
      0,
    );
    assert.equal(await page.$$eval("[data-app]", (nodes) => nodes.length), 0);
    await page.click("#create-app");
    await page.type("#app-name", "Second owner App");
    await page.click("#confirm-app");
    await page.waitForFunction(
      () =>
        document.querySelector('[data-app][aria-expanded="true"] .app-name')
          ?.textContent === "Second owner App",
    );
    await page.click("[data-create]");
    await page.type("#new-name", "Second owner application");
    await page.type("#new-origin", "http://localhost:9599");
    await page.type(
      "#new-google-client",
      "second-app-google.apps.googleusercontent.com",
    );
    await page.click("#confirm-tenant");
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "Second owner application",
    );
    const otherID = await page.$eval("#tenant-id", (node) => node.textContent);
    assert.notEqual(otherID, tenantID);
    await page.click("[data-section=configuration]");
    assert.equal(await page.$('[data-mpr-user-action="admin"]'), null);
    await page.evaluate(() =>
      document.querySelector("mpr-user").dispatchEvent(
        new CustomEvent("mpr-user:menu-item", {
          bubbles: true,
          detail: { action: "admin" },
        }),
      ),
    );
    assert.equal(await page.$eval("#admin-dialog", (node) => node.open), false);
    await page.$eval("#google-client", (node) => {
      node.value = "second-app-google";
      node.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.click("[data-section=configuration]");
    await page.$eval(
      "#frontend-origins",
      (node, value) => {
        node.value = value;
      },
      process.env.TAUTH_CUSTOMER_FRONTEND,
    );
    await page.click("#local-development");
    await page.type("#api-base", process.env.TAUTH_CUSTOMER_API);
    await page.$eval("#configuration", (node) =>
      node.dispatchEvent(new Event("input", { bubbles: true })),
    );
    await page.waitForFunction(
      () =>
        document.getElementById("configuration").getAttribute("aria-busy") ===
          "false" && document.getElementById("field-error").textContent === "",
    );
    await page.click("[data-section=configuration]");
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-state").textContent ===
        "Authentication active",
    );
    await page.click("[data-section=integration]");
    await page.waitForSelector("#integration-ready:not([hidden])");
    await page.click("#export-session-key");
    await page.waitForSelector("#reauth-google #fixture-google-login", {
      visible: true,
    });
    await page.click("#reauth-google #fixture-google-login");
    await page.waitForSelector("#export-key-panel:not([hidden])");
    const otherKey = await page.$eval(
      "#export-key",
      (node) => node.textContent,
    );
    assert.notEqual(otherKey, exportedKey);
    const otherBackend = JSON.parse(
      await page.$eval("#backend-example", (node) => node.textContent),
    );
    await operator("/__customer-config", {
      tenant_id: otherID,
      session_cookie_name: otherBackend.TAUTH_SESSION_COOKIE,
      session_key_base64: otherKey,
      browser_html: await page.$eval(
        "#browser-example",
        (node) => node.textContent,
      ),
    });
    const otherApp = await browser.newPage();
    otherApp.on("pageerror", (error) => errors.push(error.message));
    await otherApp.setRequestInterception(true);
    otherApp.on("request", (request) => {
      if (request.url().startsWith("https://accounts.google.com/"))
        void request.respond({
          status: 200,
          contentType: "text/javascript",
          body: googleScript,
        });
      else if (request.url() === "https://tauth.mprlab.com/tauth.js")
        void request.respond({
          status: 200,
          contentType: "text/javascript",
          body: fs.readFileSync(
            path.join(__dirname, "../web/tauth.js"),
            "utf8",
          ),
        });
      else void request.continue();
    });
    await otherApp.goto(process.env.TAUTH_CUSTOMER_FRONTEND);
    await otherApp.waitForSelector("#fixture-google-login", { visible: true });
    await otherApp.click("#fixture-google-login");
    await otherApp.waitForFunction(() => getCurrentUser() !== null);
    assert.equal(
      await otherApp.evaluate(
        async (api) => (await apiFetch(api + "/private")).status,
        process.env.TAUTH_CUSTOMER_API,
      ),
      200,
    );
    await otherApp.close();
    // Log out through the public helper while the exported key is displayed.
    await page.evaluate(() => logout());
    await page.waitForSelector("#signed-out:not([hidden])");
    assert.equal(
      await page.$eval("#export-key", (node) => node.textContent),
      "",
    );
    await page.reload();
    await page.waitForSelector("#fixture-google-login", { visible: true });
    await page.click("#fixture-google-login");
    await page.waitForSelector("#workspace:not([hidden])");
    await chooseApp(page, "fixture-app");
    await page.waitForFunction(
      () => document.querySelectorAll("[data-tenant]").length === 3,
    );
    assert.equal(
      await page.$$eval(
        "[data-tenant]",
        (nodes, id) =>
          nodes.some((node) => node.getAttribute("data-tenant") === id),
        otherID,
      ),
      false,
    );
    assert.deepEqual(errors, []);
  },
);

async function operator(resource, body) {
  return new Promise((resolve, reject) => {
    const request = https.request(
      process.env.TAUTH_BROWSER_OPERATOR_URL + resource,
      {
        method: "POST",
        rejectUnauthorized: false,
        headers: { "Content-Type": "application/json" },
      },
      (response) => {
        response.resume();
        response.on("end", () =>
          response.statusCode === 204
            ? resolve()
            : reject(
                new Error("Operator fixture failed: " + response.statusCode),
              ),
        );
      },
    );
    request.on("error", reject);
    request.end(JSON.stringify(body));
  });
}
async function operatorStatus(url, headers) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { rejectUnauthorized: false, headers }, (response) => {
        response.resume();
        response.on("end", () => resolve(response.statusCode));
      })
      .on("error", reject);
  });
}

async function rateLimit(request) {
  await request.respond({
    status: 429,
    contentType: "application/json",
    headers: {
      "Access-Control-Allow-Origin": new URL(process.env.TAUTH_CONSOLE_URL)
        .origin,
      "Access-Control-Allow-Credentials": "true",
    },
    body: JSON.stringify({
      code: "management.rate_limited",
      message: "Too many changes. Retry shortly.",
      request_id: "rate-limit-fixture",
    }),
  });
}

async function chooseApp(page, id) {
  const selector = `[data-app="${id}"]`;
  if (
    (await page.$eval(selector, (node) =>
      node.getAttribute("aria-expanded"),
    )) !== "true"
  )
    await page.click(selector);
}
