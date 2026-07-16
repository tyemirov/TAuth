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

test("demo renders the static footer content", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes('<footer id="page-footer"'),
    "Expected demo to declare the semantic footer element",
  );
  assert.ok(
    html.includes("TAuth demonstration"),
    "Expected footer copy to identify the neutral demonstration",
  );
});
