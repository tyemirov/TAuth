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
    html.includes("<mpr-footer"),
    "Expected demo to declare the mpr-ui footer element",
  );
  assert.ok(
    html.includes("Built by Marco Polo Research Lab"),
    "Expected footer copy to include the organization name",
  );
});
