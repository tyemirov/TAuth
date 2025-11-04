const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(__dirname, "..", "web", "demo.html");

test("demo integrates mpr-ui footer component declaratively", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  const hasMprFooter = html.includes('x-data="MPRUI.mprFooter(');
  assert.ok(
    hasMprFooter,
    "Expected demo to expose the footer via mprFooter Alpine factory",
  );
});
