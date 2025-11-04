const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(__dirname, "..", "web", "demo.html");

test("demo integrates mpr-ui footer component declaratively", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes(
      'import "https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@main/footer.js?module";',
    ),
    "Expected demo to load the footer module from the CDN",
  );
  assert.ok(
    html.includes('x-data="mprFooter({'),
    "Expected demo to expose the footer via the mprFooter Alpine factory",
  );
  assert.ok(
    html.includes('"themeToggle": {') || html.includes("themeToggle: {"),
    "Expected footer configuration to provide theme toggle options",
  );
});
