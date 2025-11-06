const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(__dirname, "..", "web", "demo.html");

test("demo integrates mpr-ui footer component declaratively", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes(
      'src="https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@0.0.5/mpr-ui.js"',
    ),
    "Expected demo to load the mpr-ui bundle via CDN",
  );
  assert.ok(
    html.includes("MPRUI.renderFooter") && html.includes("MPRUI.renderSiteHeader"),
    "Expected demo to configure both the mpr-ui footer and site header",
  );
  assert.ok(
    html.includes('prefixText: "Built by"') && html.includes('"Marco Polo Research Lab"'),
    "Expected footer configuration to include Built by Marco Polo Research Lab copy",
  );
  assert.ok(
    html.includes('inputId: "public-theme-toggle"'),
    "Expected footer theme toggle to expose the public theme toggle input",
  );
  assert.ok(
    html.includes('src="/static/mpr-sites.js"'),
    "Expected demo to load the shared sites script",
  );
  assert.ok(
    html.includes("tauth-demo-theme"),
    "Expected demo script to configure persistent theme storage",
  );
});
