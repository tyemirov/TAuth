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
const DEMO_LOCAL_CONFIG_PATH = pathModule.join(
  __dirname,
  "..",
  "examples",
  "tauth-demo",
  "demo-config.js",
);

test("tauth demo loads local config and mpr-ui bootstrap scripts", async () => {
  const html = await fileSystem.readFile(DEMO_INDEX_PATH, "utf8");
  assert.ok(
    html.includes('<script defer src="./demo-config.js"></script>'),
    "Expected demo to load the local demo-config.js",
  );
  assert.ok(
    html.includes('<script defer src="./tauth-config.js"></script>'),
    "Expected demo to load tauth-config.js",
  );
  assert.ok(
    html.includes("mpr-ui.css"),
    "Expected demo to load mpr-ui CSS",
  );
  assert.ok(
    html.includes("<mpr-header"),
    "Expected demo to render the mpr-ui header element",
  );
  assert.ok(
    html.includes("<mpr-footer"),
    "Expected demo to render the mpr-ui footer element",
  );

  const configSource = await fileSystem.readFile(DEMO_CONFIG_PATH, "utf8");
  assert.ok(
    configSource.includes("window.__TAUTH_DEMO_CONFIG"),
    "Expected demo config to read the local demo config",
  );
  assert.ok(
    configSource.includes("data-tenant-id"),
    "Expected demo config to set the tenant id for tauth.js",
  );
  assert.ok(
    configSource.includes("__TAUTH_AUTH_CLIENT_READY__"),
    "Expected demo config to expose an auth client readiness handle",
  );
  assert.ok(
    configSource.includes("mpr-ui@latest/mpr-ui.js"),
    "Expected demo config to load the mpr-ui bundle from the CDN",
  );
  assert.ok(
    configSource.includes("accounts.google.com/gsi/client"),
    "Expected demo config to load the Google Identity Services script",
  );

  const localConfigSource = await fileSystem.readFile(
    DEMO_LOCAL_CONFIG_PATH,
    "utf8",
  );
  assert.ok(
    localConfigSource.includes("window.__TAUTH_DEMO_CONFIG"),
    "Expected local demo config to expose window.__TAUTH_DEMO_CONFIG",
  );
});
