// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(__dirname, "..", "web", "demo.html");
test("demo renders GIS sign-in wiring for tauth.js", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes(
      'src="https://accounts.google.com/gsi/client"',
    ),
    "Expected demo to load the Google Identity Services script",
  );
  assert.ok(
    html.includes('id="googleSignInContainer"'),
    "Expected demo to declare the Google sign-in container",
  );
  assert.ok(
    html.includes('id="headerLogoutButton"'),
    "Expected demo to declare the header sign-out button",
  );
  assert.ok(
    html.includes('src="/tauth.js"'),
    "Expected demo to load tauth.js",
  );
});
