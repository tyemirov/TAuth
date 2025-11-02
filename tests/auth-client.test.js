const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const path = require("node:path");
const fs = require("node:fs/promises");
const puppeteer = require("puppeteer-core");

const CHROMIUM_EXECUTABLE =
  process.env.CHROMIUM_PATH || "/usr/bin/chromium-browser";

function createScenario(options) {
  return {
    meQueue: [...(options.meQueue || [])],
    refreshQueue: [...(options.refreshQueue || [])],
    logoutStatus: options.logoutStatus ?? 204,
    counts: {
      me: 0,
      refresh: 0,
      logout: 0,
    },
  };
}

async function startScenarioServer(scenario) {
  const scriptPath = path.join(__dirname, "..", "web", "auth-client.js");
  const authClientScript = await fs.readFile(scriptPath, "utf8");

  let baseUrl = "";

  const server = http.createServer((request, response) => {
    const { url: requestUrl, method } = request;
    if (requestUrl === "/auth-client.js") {
      response.writeHead(200, {
        "Content-Type": "text/javascript",
        "Cache-Control": "no-store",
      });
      response.end(authClientScript);
      return;
    }

    if (requestUrl === "/me" && method === "GET") {
      scenario.counts.me += 1;
      const payload =
        scenario.meQueue.shift() ||
        scenario.meQueue[scenario.meQueue.length - 1] || { status: 401 };
      response.writeHead(payload.status, {
        "Content-Type": "application/json",
      });
      response.end(JSON.stringify(payload.body || {}));
      return;
    }

    if (requestUrl === "/auth/refresh" && method === "POST") {
      scenario.counts.refresh += 1;
      const payload =
        scenario.refreshQueue.shift() ||
        scenario.refreshQueue[scenario.refreshQueue.length - 1] || {
          status: 401,
        };
      response.writeHead(payload.status, {
        "Content-Type": "application/json",
      });
      response.end(JSON.stringify(payload.body || {}));
      return;
    }

    if (requestUrl === "/auth/logout" && method === "POST") {
      scenario.counts.logout += 1;
      response.writeHead(scenario.logoutStatus, {
        "Content-Type": "application/json",
      });
      response.end("{}");
      return;
    }

    if (requestUrl === "/app" && method === "GET") {
      const html = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Auth Client Harness</title>
    <script src="/auth-client.js"></script>
  </head>
  <body>
    <script>
      window.eventLog = [];
      initAuthClient({
        baseUrl: "${baseUrl}",
        onAuthenticated(profile) {
          window.eventLog.push({ type: "authenticated", profile });
        },
        onUnauthenticated() {
          window.eventLog.push({ type: "unauthenticated" });
        }
      });
    </script>
  </body>
</html>`;
      response.writeHead(200, { "Content-Type": "text/html" });
      response.end(html);
      return;
    }

    response.writeHead(404);
    response.end();
  });

  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });

  return {
    server,
    baseUrl,
  };
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function launchBrowser() {
  return puppeteer.launch({
    headless: true,
    executablePath: CHROMIUM_EXECUTABLE,
    args: ["--no-sandbox", "--disable-gpu", "--remote-allow-origins=*"],
  });
}

function waitForEventCount(page, expected) {
  return page.waitForFunction(
    (count) => window.eventLog && window.eventLog.length >= count,
    {},
    expected,
  );
}

test(
  "auth client dispatches authenticated and unauthenticated events",
  { concurrency: false },
  async (t) => {
    const scenario = createScenario({
      meQueue: [
        {
          status: 200,
          body: {
            user_id: "user-123",
            user_email: "user@example.com",
            display: "Demo User",
          },
        },
      ],
      logoutStatus: 204,
    });
    const { server, baseUrl } = await startScenarioServer(scenario);
    t.after(async () => {
      await closeServer(server);
    });

    const browser = await launchBrowser();
    t.after(async () => {
      await browser.close();
    });

    const page = await browser.newPage();
    await page.goto(`${baseUrl}/app`, { waitUntil: "networkidle0" });
    await waitForEventCount(page, 1);

    const initialEvents = await page.evaluate(() => window.eventLog);
    assert.equal(initialEvents.length, 1);
    assert.equal(initialEvents[0].type, "authenticated");
    assert.deepEqual(initialEvents[0].profile, {
      user_id: "user-123",
      user_email: "user@example.com",
      display: "Demo User",
    });

    await page.evaluate(() => logout());
    await waitForEventCount(page, 2);
    const eventsAfterLogout = await page.evaluate(() => window.eventLog);
    assert.equal(eventsAfterLogout.length, 2);
    assert.equal(eventsAfterLogout[1].type, "unauthenticated");
    assert.equal(scenario.counts.logout, 1);
  },
);

test(
  "auth client refreshes once before authenticating",
  { concurrency: false },
  async (t) => {
    const scenario = createScenario({
      meQueue: [
        { status: 401 },
        {
          status: 200,
          body: {
            user_id: "user-456",
            user_email: "second@example.com",
            display: "Second User",
          },
        },
      ],
      refreshQueue: [{ status: 204 }],
    });
    const { server, baseUrl } = await startScenarioServer(scenario);
    t.after(async () => {
      await closeServer(server);
    });

    const browser = await launchBrowser();
    t.after(async () => {
      await browser.close();
    });

    const page = await browser.newPage();
    await page.goto(`${baseUrl}/app`, { waitUntil: "networkidle0" });
    await waitForEventCount(page, 1);
    const events = await page.evaluate(() => window.eventLog);
    assert.equal(events.length, 1);
    assert.equal(events[0].type, "authenticated");
    assert.equal(scenario.counts.refresh, 1);
    assert.equal(scenario.counts.me, 2);
  },
);

test(
  "auth client surfaces unauthenticated when refresh fails",
  { concurrency: false },
  async (t) => {
    const scenario = createScenario({
      meQueue: [{ status: 401 }],
      refreshQueue: [{ status: 401 }],
    });
    const { server, baseUrl } = await startScenarioServer(scenario);
    t.after(async () => {
      await closeServer(server);
    });

    const browser = await launchBrowser();
    t.after(async () => {
      await browser.close();
    });

    const page = await browser.newPage();
    await page.goto(`${baseUrl}/app`, { waitUntil: "networkidle0" });
    await waitForEventCount(page, 1);
    const events = await page.evaluate(() => window.eventLog);
    assert.equal(events.length, 1);
    assert.equal(events[0].type, "unauthenticated");
    assert.equal(scenario.counts.refresh, 1);
  },
);
