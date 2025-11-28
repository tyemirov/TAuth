const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs/promises");
const vm = require("node:vm");

async function loadAuthClient(fetchImpl, broadcastSink) {
  const scriptPath = path.join(__dirname, "..", "web", "auth-client.js");
  const source = await fs.readFile(scriptPath, "utf8");

  const context = {
    fetch: fetchImpl,
    console,
    setTimeout,
    clearTimeout,
    Promise,
    URL,
    Request: global.Request,
    Headers: global.Headers,
    BroadcastChannel: class {
      constructor() {}
      postMessage(message) {
        if (broadcastSink) {
          broadcastSink.push(message);
        }
      }
    },
  };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(source, context);
  return context;
}

function createResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  };
}

function createFetchWithQueue(sequence) {
  const calls = [];
  const queue = [...sequence];
  const fetchImpl = async (requestUrl, options = {}) => {
    const next = queue.shift();
    if (!next) {
      throw new Error(`unexpected fetch call to ${requestUrl}`);
    }
    const headers = Object.assign({}, options.headers || {});
    calls.push({
      url: requestUrl,
      method: (options.method || "GET").toUpperCase(),
      headers,
      body: options.body,
    });
    if (typeof next === "function") {
      return next(requestUrl, options);
    }
    return createResponse(next.status, next.body);
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

function assertHeader(call, headerName, expectedValue) {
  assert.equal(
    call.headers && call.headers[headerName],
    expectedValue,
    `expected ${headerName} header`,
  );
}

test("auth client authenticates when /me succeeds", async () => {
  const profile = {
    user_id: "user-123",
    user_email: "user@example.com",
    display: "Demo User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([{ status: 200, body: profile }]);
  const events = [];
  const context = await loadAuthClient(fetch, events);

  let authenticatedProfile = null;
  let unauthenticatedCount = 0;

  await context.initAuthClient({
    baseUrl: "https://example.com",
    onAuthenticated(received) {
      authenticatedProfile = received;
    },
    onUnauthenticated() {
      unauthenticatedCount += 1;
    },
  });

  assert.deepEqual(authenticatedProfile, profile);
  assert.equal(unauthenticatedCount, 0);
  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0].url, "https://example.com/me");
  assertHeader(fetch.calls[0], "X-Client", "mprlab-ui");
  assert.deepEqual(events, []);
});

test("auth client attempts refresh before authenticating", async () => {
  const profile = {
    user_id: "user-456",
    user_email: "second@example.com",
    display: "Second User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 401, body: {} },
    { status: 204, body: {} },
    { status: 200, body: profile },
  ]);
  const events = [];
  const context = await loadAuthClient(fetch, events);

  let authenticatedProfile = null;
  await context.initAuthClient({
    baseUrl: "https://example.com",
    onAuthenticated(received) {
      authenticatedProfile = received;
    },
    onUnauthenticated() {
      throw new Error("should not surface unauthenticated after refresh");
    },
  });

  assert.deepEqual(authenticatedProfile, profile);
  assert.equal(fetch.calls.length, 3);
  assert.equal(fetch.calls[0].url, "https://example.com/me");
  assert.equal(fetch.calls[1].url, "https://example.com/auth/refresh");
  assert.equal(fetch.calls[2].url, "https://example.com/me");
  assertHeader(fetch.calls[0], "X-Client", "mprlab-ui");
  assertHeader(fetch.calls[1], "X-Requested-With", "XMLHttpRequest");
  assertHeader(fetch.calls[2], "X-Client", "mprlab-ui");
  assert.deepEqual(events, ["refreshed"]);
});

test("auth client surfaces unauthenticated when refresh fails", async () => {
  const fetch = createFetchWithQueue([
    { status: 401, body: {} },
    { status: 401, body: {} },
  ]);
  const events = [];
  const context = await loadAuthClient(fetch, events);

  let authenticatedCount = 0;
  let unauthenticatedCount = 0;

  await context.initAuthClient({
    baseUrl: "https://example.com",
    onAuthenticated() {
      authenticatedCount += 1;
    },
    onUnauthenticated() {
      unauthenticatedCount += 1;
    },
  });

  assert.equal(authenticatedCount, 0);
  assert.equal(unauthenticatedCount, 1);
  assert.equal(fetch.calls.length, 2);
  assert.equal(fetch.calls[0].url, "https://example.com/me");
  assert.equal(fetch.calls[1].url, "https://example.com/auth/refresh");
  assertHeader(fetch.calls[0], "X-Client", "mprlab-ui");
  assertHeader(fetch.calls[1], "X-Requested-With", "XMLHttpRequest");
  assert.deepEqual(events, []);
});

test("auth client attaches tenant header when configured", async () => {
  const profile = {
    user_id: "user-tenant",
    user_email: "tenant@example.com",
    display: "Tenant User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([{ status: 200, body: profile }]);
  const context = await loadAuthClient(fetch, []);

  await context.initAuthClient({
    baseUrl: "https://example.com",
    tenantId: "tenant-123",
    onAuthenticated() {},
    onUnauthenticated() {},
  });

  assertHeader(fetch.calls[0], "X-TAuth-Tenant", "tenant-123");
});

test("apiFetch retries with tenant header", async () => {
  const profile = {
    user_id: "user-tenant",
    user_email: "tenant@example.com",
    display: "Tenant User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: profile },
    function () {
      return createResponse(401, {});
    },
    function () {
      return createResponse(204, {});
    },
    function () {
      return createResponse(200, {});
    },
  ]);
  const context = await loadAuthClient(fetch, []);
  await context.initAuthClient({
    baseUrl: "https://example.com",
    tenantId: "tenant-abc",
    onAuthenticated() {},
    onUnauthenticated() {},
  });

  const response = await context.apiFetch("https://example.com/api/data", {
    method: "GET",
  });
  assert.equal(response.status, 200);
  assert.equal(fetch.calls.length, 4);
  assertHeader(fetch.calls[1], "X-TAuth-Tenant", "tenant-abc");
  assertHeader(fetch.calls[2], "X-TAuth-Tenant", "tenant-abc");
  assertHeader(fetch.calls[3], "X-TAuth-Tenant", "tenant-abc");
});
