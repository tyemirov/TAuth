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
    html.includes('id="googleButtonHost"'),
    "Expected demo to expose a container for the GIS button",
  );
  assert.ok(
    html.includes("accounts.renderButton(host"),
    "Expected demo JavaScript to initialize the GIS button programmatically",
  );
});
