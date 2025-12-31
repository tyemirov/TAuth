// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const fileSystem = require("node:fs/promises");
const pathModule = require("node:path");

const DEMO_CONFIG_PATH = pathModule.join(
  __dirname,
  "fixtures",
  "tauth-demo",
  "config.yaml",
);
const DEMO_ENV_TEMPLATE_PATH = pathModule.join(
  __dirname,
  "fixtures",
  "tauth-demo",
  ".env.tauth.example",
);
const MULTI_TENANT_CONFIG_PATH = pathModule.join(
  __dirname,
  "..",
  "examples",
  "multi-tenant",
  "config.yaml",
);
const MULTI_TENANT_CONFIG_EXAMPLE_PATH = pathModule.join(
  __dirname,
  "..",
  "examples",
  "multi-tenant",
  "config.yaml.example",
);
const DOC_PATHS = Object.freeze([
  pathModule.join(__dirname, "..", "README.md"),
  pathModule.join(__dirname, "..", "ARCHITECTURE.md"),
  pathModule.join(__dirname, "..", "docs", "usage.md"),
  pathModule.join(__dirname, "..", "docs", "migration.md"),
]);

const CORS_EXCEPTION_KEY = "cors_allowed_origin_exceptions";
const CORS_EXCEPTION_ENV = "TAUTH_CORS_EXCEPTION_1";
const GIS_ORIGIN = "https://accounts.google.com";

async function assertConfigIncludesExceptions(filePath) {
  const source = await fileSystem.readFile(filePath, "utf8");
  assert.ok(
    source.includes(CORS_EXCEPTION_KEY),
    `Expected ${filePath} to declare ${CORS_EXCEPTION_KEY}`,
  );
  assert.ok(
    source.includes(CORS_EXCEPTION_ENV),
    `Expected ${filePath} to reference ${CORS_EXCEPTION_ENV}`,
  );
}

test("example configs declare CORS exception origins", async () => {
  await assertConfigIncludesExceptions(DEMO_CONFIG_PATH);
  await assertConfigIncludesExceptions(MULTI_TENANT_CONFIG_PATH);
  await assertConfigIncludesExceptions(MULTI_TENANT_CONFIG_EXAMPLE_PATH);

  const envSource = await fileSystem.readFile(DEMO_ENV_TEMPLATE_PATH, "utf8");
  assert.ok(
    envSource.includes(CORS_EXCEPTION_ENV),
    "Expected demo env template to include a CORS exception variable",
  );
  assert.ok(
    envSource.includes(GIS_ORIGIN),
    "Expected demo env template to include the GIS origin",
  );
});

test("docs mention CORS exception origins for GIS", async () => {
  const sources = await Promise.all(
    DOC_PATHS.map((docPath) => fileSystem.readFile(docPath, "utf8")),
  );
  const combined = sources.join("\n");
  assert.ok(
    combined.includes(CORS_EXCEPTION_KEY),
    "Expected docs to mention cors_allowed_origin_exceptions",
  );
  assert.ok(
    combined.includes(GIS_ORIGIN),
    "Expected docs to mention the GIS origin",
  );
});
