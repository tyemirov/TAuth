// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(__dirname, "..", "web", "demo.html");

test("demo integrates mpr-ui footer component declaratively", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes(
      'src="https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@3.1.0/mpr-ui.js"',
    ),
    "Expected demo to load the mpr-ui bundle via CDN",
  );
  assert.ok(
    html.includes('<mpr-footer id="landing-footer"'),
    "Expected demo to declare the mpr-ui footer element",
  );
  assert.ok(
    html.includes('footerHost.setAttribute("prefix-text"') &&
      html.includes('"Built by"'),
    "Expected footer configuration to include Built by copy",
  );
  assert.ok(
    html.includes('inputId: "public-theme-toggle"'),
    "Expected footer theme toggle to expose the public theme toggle input",
  );
  assert.ok(
    html.includes('footerHost.setAttribute("theme-config"'),
    "Expected footer to configure the shared theme toggle",
  );
  assert.ok(
    html.includes('footerHost.setAttribute("links"'),
    "Expected footer to configure the site catalog links",
  );
  assert.ok(
    html.includes('src="/mpr-sites.js"'),
    "Expected demo to load the shared sites script",
  );
  assert.ok(
    html.includes("tauth-demo-theme"),
    "Expected demo script to configure persistent theme storage",
  );
});
