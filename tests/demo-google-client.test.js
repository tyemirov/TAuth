// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(
  __dirname,
  "fixtures",
  "tauth-demo",
  "index.html",
);
test("demo renders vendor-neutral auth controls for tauth.js", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes('rel="stylesheet" href="./demo.css"'),
    "Expected demo to load its local stylesheet",
  );
  assert.ok(
    html.includes('<header id="demo-header"'),
    "Expected demo to declare the native header element",
  );
  assert.ok(
    html.includes("data-demo-google-signin"),
    "Expected demo to declare the Google Sign-In host",
  );
  assert.ok(
    html.includes("data-demo-sign-out"),
    "Expected demo to declare the sign-out control",
  );
});
