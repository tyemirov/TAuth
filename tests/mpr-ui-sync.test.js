const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

test("embedded mpr-ui asset stays in sync with tools source", async () => {
  const sourcePath = path.join(__dirname, "..", "tools", "mpr-ui", "mpr-ui.js");
  const embeddedPath = path.join(__dirname, "..", "web", "mpr-ui.js");
  const [source, embedded] = await Promise.all([
    fs.readFile(sourcePath, "utf8"),
    fs.readFile(embeddedPath, "utf8"),
  ]);
  assert.equal(
    embedded,
    source,
    "web/mpr-ui.js must match tools/mpr-ui/mpr-ui.js so the embedded asset stays current",
  );
});
