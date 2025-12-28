// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const fileSystem = require("node:fs/promises");
const pathModule = require("node:path");

const DEMO_INDEX_PATH = pathModule.join(
  __dirname,
  "..",
  "examples",
  "tauth-demo",
  "index.html",
);
const DEMO_CONFIG_PATH = pathModule.join(
  __dirname,
  "..",
  "examples",
  "tauth-demo",
  "tauth-config.js",
);
const MPR_UI_SCRIPT_PATTERN = /<script[^>]+mpr-ui\.js/;

test("tauth demo loads mpr-ui via config bootstrap", async () => {
  const html = await fileSystem.readFile(DEMO_INDEX_PATH, "utf8");
  assert.ok(
    html.includes('<script defer src="./tauth-config.js"></script>'),
    "Expected demo to load tauth-config.js",
  );
  assert.ok(
    html.includes(
      'href="https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@latest/mpr-ui.css"',
    ),
    "Expected demo to load mpr-ui styles from CDN",
  );
  assert.ok(
    !MPR_UI_SCRIPT_PATTERN.test(html),
    "Expected demo to inject the mpr-ui bundle after config",
  );

  const configSource = await fileSystem.readFile(DEMO_CONFIG_PATH, "utf8");
  assert.ok(
    configSource.includes("/demo/config.json"),
    "Expected demo config to fetch JSON config from TAuth",
  );
  assert.ok(
    configSource.includes("mpr-ui@latest/mpr-ui.js"),
    "Expected demo config to inject the mpr-ui bundle from CDN",
  );
  assert.ok(
    configSource.includes("data-tenant-id"),
    "Expected demo config to set the tenant id for tauth.js",
  );
});
