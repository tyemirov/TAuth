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
const DEMO_ENV_TEMPLATE_PATH = pathModule.join(
  __dirname,
  "..",
  "examples",
  "tauth-demo",
  ".env.tauth.example",
);
const DEMO_TENANT_CONFIG_PATH = pathModule.join(
  __dirname,
  "..",
  "examples",
  "tauth-demo",
  "config.yaml",
);
const DEMO_LOCAL_CONFIG_PATH = pathModule.join(
  __dirname,
  "..",
  "examples",
  "tauth-demo",
  "demo-config.js",
);
const DEMO_FRONTEND_ORIGINS = Object.freeze([
  "http://localhost:8080",
  "http://127.0.0.1:8080",
]);

const DEMO_FRONTEND_ORIGIN_TEST_CASES = Object.freeze(
  DEMO_FRONTEND_ORIGINS.map((origin) => ({
    origin,
    tenantMessage: `Expected demo tenant config to allow ${origin}`,
    corsMessage: `Expected demo env to allow CORS from ${origin}`,
  })),
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
    html.includes('rel="stylesheet" href="./demo.css"'),
    "Expected demo to load the local demo.css stylesheet",
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
  assert.ok(
    configSource.includes("AUTH_CLIENT_CACHE_BUSTER_PARAM"),
    "Expected demo config to define an auth-client cache buster",
  );
  assert.ok(
    configSource.includes("Date.now"),
    "Expected demo config to include a cache-busting timestamp",
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

test("tauth demo tenant config allows the frontend origins", async () => {
  const tenantConfigSource = await fileSystem.readFile(
    DEMO_TENANT_CONFIG_PATH,
    "utf8",
  );

  for (const testCase of DEMO_FRONTEND_ORIGIN_TEST_CASES) {
    assert.ok(
      tenantConfigSource.includes(testCase.origin),
      testCase.tenantMessage,
    );
  }
});

test("tauth demo env enables CORS for the frontend origins", async () => {
  const envConfigSource = await fileSystem.readFile(
    DEMO_ENV_TEMPLATE_PATH,
    "utf8",
  );

  for (const testCase of DEMO_FRONTEND_ORIGIN_TEST_CASES) {
    assert.ok(
      envConfigSource.includes(testCase.origin),
      testCase.corsMessage,
    );
  }
});
