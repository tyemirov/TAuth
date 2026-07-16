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

test("demo uses self-contained semantic layout styling", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes('<main class="demo-shell">'),
    "Expected demo to render the local content shell",
  );
  assert.ok(
    html.includes('<header id="demo-header"'),
    "Expected demo to render a semantic header",
  );
});
