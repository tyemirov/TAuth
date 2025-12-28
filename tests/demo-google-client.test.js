// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(__dirname, "..", "web", "demo.html");
test("demo renders mpr-ui header/footer with GIS popup wiring", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes(
      'src="https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@3.1.0/mpr-ui.js"',
    ),
    "Expected demo to load the mpr-ui bundle via CDN",
  );
  assert.ok(
    html.includes('<mpr-header id="siteHeader"></mpr-header>'),
    "Expected demo to declare the mpr-ui header element",
  );
  assert.ok(
    html.includes("const GOOGLE_CLIENT_ID"),
    "Expected demo to define the canonical Google client ID",
  );
  assert.ok(
    html.includes('headerHost.setAttribute("auth-config"'),
    "Expected demo to configure the mpr-ui header auth settings",
  );
  assert.ok(
    html.includes('headerHost.setAttribute("site-id"'),
    "Expected demo to set the Google client ID on the mpr-ui header",
  );
});
