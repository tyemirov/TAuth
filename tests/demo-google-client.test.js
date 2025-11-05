const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(__dirname, "..", "web", "demo.html");
const HARDCODED_CLIENT_ID =
  "991677581607-r0dj8q6irjagipali0jpca7nfp8sfj9r.apps.googleusercontent.com";

test("demo loads dynamic config instead of hard-coding Google client ID", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes('<script src="/demo/config.js"></script>'),
    "Expected demo to pull runtime configuration from the server",
  );
  assert.ok(
    !html.includes(HARDCODED_CLIENT_ID),
    "Expected demo to rely on runtime configuration for the Google client ID",
  );
  assert.ok(
    html.includes("window.__TAUTH_DEMO_CONFIG || {}"),
    "Expected demo to read runtime configuration from the injected script",
  );
  assert.ok(
    html.includes("const demoBaseUrl") && html.includes("fetch(withBase") && html.includes("baseUrl: demoBaseUrl"),
    "Expected demo JavaScript to route API calls through the configured base URL",
  );
});
