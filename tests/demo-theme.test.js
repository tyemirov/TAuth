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

test("demo uses mpr-ui layout components for styling", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes("<mpr-band"),
    "Expected demo to render the mpr-ui band component",
  );
  assert.ok(
    html.includes("<mpr-header"),
    "Expected demo to render the mpr-ui header component",
  );
});
