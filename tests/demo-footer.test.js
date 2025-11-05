const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(__dirname, "..", "web", "demo.html");

test("demo integrates mpr-ui footer component declaratively", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes(
      '<script defer src="https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@main/footer.js"></script>',
    ),
    "Expected demo to load the mpr-ui footer bundle via CDN",
  );
  assert.ok(
    html.includes("window.mprFooter = window.MPRUI && window.MPRUI.mprFooter;"),
    "Expected demo to expose the mprFooter Alpine factory from the global namespace",
  );
  assert.ok(
    html.includes('data-mpr-footer-config='),
    "Expected footer markup to embed mpr-footer configuration JSON",
  );
  assert.ok(
    html.includes('Built by') && html.includes('Marco Polo Research Lab'),
    "Expected footer to include the Built by Marco Polo Research Lab copy",
  );
  assert.ok(
    html.includes('footer-menu dropup'),
    "Expected footer menu wrapper to declare the dropup styling",
  );
  assert.ok(
    html.includes('footer-theme-toggle form-check form-switch m-0'),
    "Expected footer theme toggle to reuse the LoopAware form-switch styling",
  );
  assert.ok(
    html.includes('id="public-theme-toggle"'),
    "Expected footer theme toggle input id to match public theme storage wiring",
  );
  assert.ok(
    html.includes('href="https://mprlab.com"'),
    "Expected footer link catalogue to include the LoopAware product list",
  );
});
