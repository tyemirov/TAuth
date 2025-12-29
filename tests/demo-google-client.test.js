// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(
  __dirname,
  "..",
  "examples",
  "tauth-demo",
  "index.html",
);
test("demo renders mpr-ui header wiring for tauth.js", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes("mpr-ui.css"),
    "Expected demo to load the mpr-ui stylesheet",
  );
  assert.ok(
    html.includes("<mpr-header"),
    "Expected demo to declare the mpr-ui header element",
  );
  assert.ok(
    html.includes('login-path="/auth/google"'),
    "Expected demo to declare the login endpoint on the header",
  );
  assert.ok(
    html.includes('nonce-path="/auth/nonce"'),
    "Expected demo to declare the nonce endpoint on the header",
  );
  assert.ok(
    html.includes('logout-path="/auth/logout"'),
    "Expected demo to declare the logout endpoint on the header",
  );
});
