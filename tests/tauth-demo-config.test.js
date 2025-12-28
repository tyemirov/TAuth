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
const DEMO_AUTH_UI_PATH = pathModule.join(
  __dirname,
  "..",
  "examples",
  "tauth-demo",
  "auth-ui.js",
);

test("tauth demo loads local config and auth bootstrap scripts", async () => {
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
    html.includes('<script defer src="./auth-ui.js"></script>'),
    "Expected demo to load the auth UI bootstrap script",
  );
  assert.ok(
    html.includes('https://accounts.google.com/gsi/client'),
    "Expected demo to load the Google Identity Services script",
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

  const authUiSource = await fileSystem.readFile(DEMO_AUTH_UI_PATH, "utf8");
  assert.ok(
    authUiSource.includes("__TAUTH_AUTH_CLIENT_READY__"),
    "Expected demo auth UI to wait for the auth client readiness handle",
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
