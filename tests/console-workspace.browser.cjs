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
    page.on("request", (request) => {
      if (request.url().startsWith("https://accounts.google.com/")) {
        void request.respond({
          status: 200,
          contentType: "text/javascript",
          body: googleScript,
        });
      } else void request.continue();
    });
    await page.goto(process.env.TAUTH_CONSOLE_URL);
    assert.equal(await page.title(), "TAuth · Tenant workspace");
    await page.waitForSelector("#fixture-google-login", {
      visible: true,
      timeout: 10000,
    });
    await page.screenshot({ path: "/tmp/tauth-console-login.png" });
    await page.click("#fixture-google-login");

    await page.waitForSelector("#workspace:not([hidden])", { timeout: 10000 });
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "Imported application",
    );
    await page.waitForSelector("#admin-accounts:not([hidden])");
    await page.click("#refresh-accounts");
    await page.waitForFunction(() =>
      document
        .querySelector("#account-list")
        ?.textContent.includes("vtyemirov@gmail.com"),
    );
    // The imported tenant uses the same settings and protected export UI.
    await page.click("[data-section=domains]");
    await page.$eval("#frontend-origins", (node) => {
      node.value = "http://localhost:9391";
    });
    await page.type("#api-base", "http://localhost:9392");
    await page.click("#local-development");
    await page.click("#save");
    await page.waitForFunction(() =>
      document.getElementById("notice").textContent.startsWith("Draft saved"),
    );
    await page.click("[data-section=overview]");
    await page.click("#activate");
    await page.waitForFunction(
      () => document.getElementById("active-revision").textContent === "2",
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
    await page.click("[data-section=overview]");
    await page.click("[data-create]");
    await page.type("#new-name", "Browser application");
    await page.type("#new-environment", "development");
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
    assert.equal(await page.$eval("#activate", (node) => node.disabled), true);
    await page.click("[data-section=signin]");
    await page.type("#google-client", "browser-app-client");
    await page.click("[data-section=domains]");
    await page.type("#frontend-origins", "http://localhost:9491");
    await page.type("#api-base", "http://localhost:9492");
    await page.click("#local-development");
    await page.screenshot({
      path: "/tmp/tauth-console-workspace.png",
      fullPage: true,
    });
    await page.click("#save");

    await page.waitForFunction(
      () =>
        document.getElementById("notice").textContent.startsWith("Draft saved"),
      { timeout: 5000 },
    );
    await page.click("[data-section=overview]");
    await page.click("#activate");
    await page.waitForFunction(
      () => document.getElementById("tenant-state").textContent === "active",
    );
    await page.reload();
    await page.waitForFunction(
      (id) => document.getElementById("tenant-id").textContent === id,
      {},
      tenantID,
    );
    assert.equal(
      await page.$eval("#tenant-state", (node) => node.textContent),
      "active",
    );
    await page.click("[data-section=settings]");
    await page.$eval("#session-ttl", (node) => (node.value = "2h"));
    await page.click("#save");
    await page.waitForFunction(() =>
      document
        .getElementById("field-error")
        .textContent.includes("session ttl invalid"),
    );
    assert.equal(await page.$eval("#session-ttl", (node) => node.value), "2h");
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
    await page.click("#save");
    await page.waitForSelector("#reload:not([hidden])");
    assert.equal(await page.$eval("#session-ttl", (node) => node.value), "15m");
    await page.click("#reload");
    await page.waitForFunction(
      () =>
        document.getElementById("google-client").value === "concurrent-client",
    );
    await page.setViewport({ width: 390, height: 844 });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
      true,
    );
    await page.select("#tenant-select", "imported-browser");
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "Imported application",
    );
    await page.select("#tenant-select", tenantID);
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
    await page.select("#tenant-select", "imported-browser");
    await page.waitForFunction(() => window.fixtureHeld === true);
    await page.select("#tenant-select", tenantID);
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
    await page.click("[data-section=settings]");
    await page.click("#rename");
    await page.focus("#new-name");
    await page.keyboard.press("Escape");
    assert.equal(
      await page.evaluate(() => document.activeElement.id),
      "rename",
    );
    await page.click("#rename");
    await page.focus("#new-name");
    await page.keyboard.press("End");
    await page.keyboard.type(" renamed");
    await page.keyboard.press("Enter");
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "Browser application renamed",
    );
    await page.click("[data-section=domains]");
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
    await page.click("#save");
    await page.waitForFunction(() =>
      document.getElementById("notice").textContent.startsWith("Draft saved"),
    );
    await verifyCustomerDomains(page);
    await page.click("[data-section=overview]");
    await page.click("#activate");
    await page.waitForFunction(
      () =>
        document.getElementById("active-revision").textContent ===
        document.getElementById("draft-revision").textContent,
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
    await page.click("[data-section=settings]");
    await page.click("#suspend");
    await page.keyboard.press("Escape");
    assert.equal(
      await page.$eval("#suspend-dialog", (node) => node.open),
      false,
    );
    await page.click("#suspend");
    await page.click("#confirm-suspend");
    await page.waitForFunction(
      () => document.getElementById("tenant-state").textContent === "suspended",
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
    await page.click(".mobile-selector [data-create]");
    await page.type("#new-name", "Second owner application");
    await page.click("#confirm-tenant");
    await page.waitForFunction(
      () =>
        document.getElementById("tenant-name").textContent ===
        "Second owner application",
    );
    const otherID = await page.$eval("#tenant-id", (node) => node.textContent);
    assert.notEqual(otherID, tenantID);
    await page.click("[data-section=signin]");
    assert.equal(
      await page.$eval("#admin-accounts", (node) => node.hidden),
      true,
    );
    await page.type("#google-client", "second-app-google");
    await page.click("[data-section=domains]");
    await page.type("#frontend-origins", process.env.TAUTH_CUSTOMER_FRONTEND);
    await page.type("#api-base", process.env.TAUTH_CUSTOMER_API);
    await page.click("#save");
    await page.waitForFunction(() =>
      document.getElementById("notice").textContent.startsWith("Draft saved"),
    );
    await verifyCustomerDomains(page);
    await page.click("[data-section=overview]");
    await page.click("#activate");
    await page.waitForFunction(
      () => document.getElementById("tenant-state").textContent === "active",
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
    await page.waitForFunction(
      () => document.querySelectorAll("[data-tenant]").length === 2,
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

async function verifyCustomerDomains(page) {
  for (let index = 0; index < 2; index++) {
    const buttons = await page.$$("#proof-actions button");
    await buttons[index].click();
    await page.waitForFunction(
      (count) => document.querySelectorAll("#proofs li").length === count,
      {},
      index + 1,
    );
  }
  const records = await page.$$eval("#proofs li pre", (nodes) =>
    nodes.map((node) => {
      const lines = node.textContent.split("\n");
      return { Name: lines[0].slice(4), Value: lines[1] };
    }),
  );
  for (const record of records)
    await page.evaluate(async (value) => {
      const response = await fetch("/__dns", {
        method: "POST",
        body: JSON.stringify(value),
      });
      if (!response.ok) throw new Error("DNS publication failed");
    }, record);
  for (let index = 0; index < 2; index++) {
    const buttons = await page.$$("#proofs li button");
    await buttons[index].click();
    await page.waitForFunction(
      (count) =>
        [...document.querySelectorAll("#proofs strong")].filter((node) =>
          node.textContent.includes("verified"),
        ).length === count,
      {},
      index + 1,
    );
  }
}
