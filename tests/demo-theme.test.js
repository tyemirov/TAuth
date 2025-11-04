const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEMO_HTML_PATH = path.join(__dirname, "..", "web", "demo.html");

test("demo exposes data-theme aware styling for layout panels", async () => {
  const html = await fs.readFile(DEMO_HTML_PATH, "utf8");
  assert.ok(
    html.includes('body[data-bs-theme="dark"]'),
    "Expected demo to declare dark-theme selectors on the body element",
  );
  assert.ok(
    html.includes('body[data-bs-theme="dark"] .demo-card'),
    "Expected demo to style key components when the dark theme is active",
  );
});
