// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs/promises");
const vm = require("node:vm");

function restoreHintKey(baseUrl, tenantId = "") {
  return `tauth.restore.v1:${encodeURIComponent(baseUrl)}:${encodeURIComponent(tenantId)}`;
}

function createStorage(initialEntries = {}) {
  const data = { ...initialEntries };
  return {
    data,
    getItem(key) {
      return Object.prototype.hasOwnProperty.call(data, key) ? data[key] : null;
    },
    setItem(key, value) {
      data[key] = String(value);
    },
    removeItem(key) {
      delete data[key];
    },
  };
}

async function loadAuthClient(fetchImpl, broadcastSink, options = {}) {
  const scriptPath = path.join(__dirname, "..", "web", "tauth.js");
  const source = await fs.readFile(scriptPath, "utf8");
  const resolvedOptions = options || {};
  const resolvedTenantId = resolvedOptions.tenantId;
  const resolvedOrigin =
    resolvedOptions.locationOrigin || "https://ui.example.com";

  const broadcastChannels = [];
  class BroadcastChannel {
    constructor() {
      this.messageListeners = [];
      this.onmessage = null;
      broadcastChannels.push(this);
    }

    addEventListener(eventName, handler) {
      if (eventName !== "message") {
        return;
      }
      this.messageListeners.push(handler);
    }

    removeEventListener(eventName, handler) {
      if (eventName !== "message") {
        return;
      }
      const listenerIndex = this.messageListeners.indexOf(handler);
      if (listenerIndex >= 0) {
        this.messageListeners.splice(listenerIndex, 1);
      }
    }

    postMessage(message) {
      if (broadcastSink) {
        broadcastSink.push(message);
      }
      for (const channel of broadcastChannels) {
        if (channel === this) {
          continue;
        }
        channel.__dispatch(message);
      }
    }

    __dispatch(message) {
      const event = { data: message };
      if (typeof this.onmessage === "function") {
        this.onmessage(event);
      }
      for (const handler of this.messageListeners) {
        handler(event);
      }
    }
  }

  const context = {
    fetch: fetchImpl,
    console,
    setTimeout,
    clearTimeout,
    Promise,
    URL,
    Request: global.Request,
    Headers: global.Headers,
    BroadcastChannel,
  };
  context.location = { origin: resolvedOrigin };
  context.document = {
    currentScript: {
      getAttribute(attributeName) {
        if (attributeName === "data-tenant-id") {
          return resolvedTenantId || "";
        }
        return null;
      },
    },
    documentElement: {
      getAttribute(attributeName) {
        return null;
      },
    },
  };
  const localStorage = createStorage(resolvedOptions.storage || {});
  context.localStorage = localStorage;
  context.__localStorageData = localStorage.data;
  if (typeof resolvedTenantId === "string") {
    context.__TAUTH_TENANT_ID__ = resolvedTenantId;
  }
  context.window = context;
  context.window.location = context.location;
  context.__dispatchBroadcast = function dispatchBroadcast(message) {
    for (const channel of broadcastChannels) {
      channel.__dispatch(message);
    }
  };
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

function assertMissingHeader(call, headerName) {
  assert.equal(
    call.headers && call.headers[headerName],
    undefined,
    `expected ${headerName} header to be omitted`,
  );
}

test("auth client treats first logged-out visit as anonymous without auth probes", async () => {
  const fetch = createFetchWithQueue([]);
  const context = await loadAuthClient(fetch, []);

  let unauthenticatedCount = 0;
  await context.initAuthClient({
    baseUrl: "https://example.com",
    onAuthenticated() {
      throw new Error("should not authenticate without a restore hint");
    },
    onUnauthenticated() {
      unauthenticatedCount += 1;
    },
  });

  assert.equal(unauthenticatedCount, 1);
  assert.equal(context.getCurrentUser(), null);
  assert.equal(context.getAuthState(), "anonymous");
  assert.equal(fetch.calls.length, 0);
});

test("auth client restores from /me when a restore hint exists", async () => {
  const profile = {
    user_id: "hinted-user",
    user_email: "hinted@example.com",
    display: "Hinted User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([{ status: 200, body: profile }]);
  const context = await loadAuthClient(fetch, [], {
    storage: {
      [restoreHintKey("https://example.com")]: "1",
    },
  });

  let authenticatedProfile = null;
  await context.initAuthClient({
    baseUrl: "https://example.com",
    onAuthenticated(received) {
      authenticatedProfile = received;
    },
    onUnauthenticated() {
      throw new Error("should restore from hint");
    },
  });

  assert.deepEqual(authenticatedProfile, profile);
  assert.equal(context.getAuthState(), "authenticated");
  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0].url, "https://example.com/me");
  assert.equal(context.__localStorageData[restoreHintKey("https://example.com")], "1");
});

test("auth client passive bootstrap preserves restore hints for later pages", async () => {
  const fetch = createFetchWithQueue([]);
  const context = await loadAuthClient(fetch, [], {
    storage: {
      [restoreHintKey("https://example.com")]: "1",
    },
  });

  let unauthenticatedCount = 0;
  await context.initAuthClient({
    baseUrl: "https://example.com",
    bootstrapMode: "passive",
    onAuthenticated() {
      throw new Error("passive bootstrap should not authenticate");
    },
    onUnauthenticated() {
      unauthenticatedCount += 1;
    },
  });

  assert.equal(unauthenticatedCount, 1);
  assert.equal(context.getAuthState(), "anonymous");
  assert.equal(fetch.calls.length, 0);
  assert.equal(context.__localStorageData[restoreHintKey("https://example.com")], "1");
});

test("auth client refreshes hinted expired sessions once", async () => {
  const profile = {
    user_id: "refresh-user",
    user_email: "refresh@example.com",
    display: "Refresh User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 401, body: {} },
    { status: 204, body: {} },
    { status: 200, body: profile },
  ]);
  const events = [];
  const context = await loadAuthClient(fetch, events, {
    storage: {
      [restoreHintKey("https://example.com")]: "1",
    },
  });

  await context.initAuthClient({
    baseUrl: "https://example.com",
    onAuthenticated() {},
    onUnauthenticated() {
      throw new Error("should refresh hinted session");
    },
  });

  assert.equal(context.getAuthState(), "authenticated");
  assert.equal(fetch.calls.length, 3);
  assert.equal(fetch.calls[0].url, "https://example.com/me");
  assert.equal(fetch.calls[1].url, "https://example.com/auth/refresh");
  assert.equal(fetch.calls[2].url, "https://example.com/me");
  assert.deepEqual(events, ["refreshed"]);
});

test("auth client clears restore hints when hinted refresh is unauthenticated", async () => {
  const fetch = createFetchWithQueue([
    { status: 401, body: {} },
    { status: 401, body: {} },
  ]);
  const context = await loadAuthClient(fetch, [], {
    storage: {
      [restoreHintKey("https://example.com")]: "1",
    },
  });

  let unauthenticatedCount = 0;
  await context.initAuthClient({
    baseUrl: "https://example.com",
    onAuthenticated() {
      throw new Error("should not authenticate");
    },
    onUnauthenticated() {
      unauthenticatedCount += 1;
    },
  });

  assert.equal(unauthenticatedCount, 1);
  assert.equal(context.getAuthState(), "anonymous");
  assert.equal(fetch.calls.length, 2);
  assert.equal(context.__localStorageData[restoreHintKey("https://example.com")], undefined);
});

test("auth client reports hinted profile service errors", async () => {
  const fetch = createFetchWithQueue([{ status: 403, body: {} }]);
  const context = await loadAuthClient(fetch, [], {
    storage: {
      [restoreHintKey("https://example.com")]: "1",
    },
  });

  const errors = [];
  await context.initAuthClient({
    baseUrl: "https://example.com",
    onAuthenticated() {
      throw new Error("should not authenticate");
    },
    onUnauthenticated() {
      throw new Error("should report an auth error instead");
    },
    onAuthError(error) {
      errors.push(error);
    },
  });

  assert.equal(fetch.calls.length, 1);
  assert.equal(context.getAuthState(), "error");
  assert.equal(errors.length, 1);
  assert.equal(errors[0].message, "tauth.profile_error");
  assert.equal(errors[0].status, 403);
});

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
    bootstrapMode: "eager",
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
  assertMissingHeader(fetch.calls[0], "X-Client");
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
    bootstrapMode: "eager",
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
  assertMissingHeader(fetch.calls[0], "X-Client");
  assertHeader(fetch.calls[1], "X-Requested-With", "XMLHttpRequest");
  assertMissingHeader(fetch.calls[2], "X-Client");
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
    bootstrapMode: "eager",
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
  assertMissingHeader(fetch.calls[0], "X-Client");
  assertHeader(fetch.calls[1], "X-Requested-With", "XMLHttpRequest");
  assert.deepEqual(events, []);
});

test("auth client clears cached profile when session refresh fails", async () => {
  const profile = {
    user_id: "cached-user",
    user_email: "cached@example.com",
    display: "Cached User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: profile },
    { status: 401, body: {} },
    { status: 401, body: {} },
  ]);
  const context = await loadAuthClient(fetch, []);

  let unauthenticatedCount = 0;

  await context.initAuthClient({
    baseUrl: "https://example.com",
    bootstrapMode: "eager",
    onAuthenticated() {},
    onUnauthenticated() {
      unauthenticatedCount += 1;
    },
  });

  assert.deepEqual(context.getCurrentUser(), profile);

  await context.initAuthClient({
    baseUrl: "https://example.com",
    bootstrapMode: "eager",
    onAuthenticated() {},
    onUnauthenticated() {
      unauthenticatedCount += 1;
    },
  });

  assert.equal(unauthenticatedCount, 1);
  assert.equal(context.getCurrentUser(), null);
  assert.equal(fetch.calls.length, 3);
  assert.equal(fetch.calls[1].url, "https://example.com/me");
  assert.equal(fetch.calls[2].url, "https://example.com/auth/refresh");
});

test("auth client omits tenant header when tenant id is unset", async () => {
  const fetch = createFetchWithQueue([
    { status: 401, body: {} },
    { status: 401, body: {} },
  ]);
  const events = [];
  const context = await loadAuthClient(fetch, events, {
    locationOrigin: "http://ui-origin.localhost",
  });

  await context.initAuthClient({
    baseUrl: "https://auth.example.com",
    bootstrapMode: "eager",
    onAuthenticated() {},
    onUnauthenticated() {},
  });

  assert.equal(fetch.calls.length, 2);
  assertMissingHeader(fetch.calls[0], "X-TAuth-Tenant");
  assertMissingHeader(fetch.calls[1], "X-TAuth-Tenant");
});

test("auth client rejects missing baseUrl", async () => {
  const fetch = createFetchWithQueue([{ status: 200, body: {} }]);
  const context = await loadAuthClient(fetch, []);

  await assert.rejects(
    context.initAuthClient({
      onAuthenticated() {},
      onUnauthenticated() {},
    }),
    /tauth\.missing_base_url/,
  );
  assert.equal(fetch.calls.length, 0);
});

test("auth client exposes endpoint map for core routes", async () => {
  const fetch = createFetchWithQueue([
    {
      status: 200,
      body: {
        user_id: "endpoint-user",
        user_email: "endpoint@example.com",
        display: "Endpoint User",
        roles: ["user"],
      },
    },
  ]);
  const context = await loadAuthClient(fetch, []);

  await context.initAuthClient({
    baseUrl: "https://auth.example.com",
    onAuthenticated() {},
    onUnauthenticated() {},
  });

  const endpoints = context.getAuthEndpoints();
  const expected = {
    baseUrl: "https://auth.example.com",
    meUrl: "https://auth.example.com/me",
    refreshUrl: "https://auth.example.com/auth/refresh",
    logoutUrl: "https://auth.example.com/auth/logout",
    nonceUrl: "https://auth.example.com/auth/nonce",
    googleUrl: "https://auth.example.com/auth/google",
  };

  for (const [key, value] of Object.entries(expected)) {
    assert.equal(endpoints[key], value, `expected ${key} endpoint`);
  }
});

test("auth client requests nonce via helper", async () => {
  const profile = {
    user_id: "nonce-user",
    user_email: "nonce@example.com",
    display: "Nonce User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: profile },
    { status: 200, body: { nonce: "nonce-123" } },
  ]);
  const context = await loadAuthClient(fetch, []);

  await context.initAuthClient({
    baseUrl: "https://auth.example.com",
    tenantId: "tenant-alpha",
    bootstrapMode: "eager",
    onAuthenticated() {},
    onUnauthenticated() {},
  });

  const nonceToken = await context.requestNonce();

  assert.equal(nonceToken, "nonce-123");
  assert.equal(fetch.calls.length, 2);
  const nonceCall = fetch.calls[1];
  assert.equal(nonceCall.url, "https://auth.example.com/auth/nonce");
  assert.equal(nonceCall.method, "POST");
  assertHeader(nonceCall, "Content-Type", "application/json");
  assertHeader(nonceCall, "X-Requested-With", "XMLHttpRequest");
  assertHeader(nonceCall, "X-TAuth-Tenant", "tenant-alpha");
});

test("auth client nonce helper rejects non-200 responses", async () => {
  const profile = {
    user_id: "nonce-error-user",
    user_email: "nonce-error@example.com",
    display: "Nonce Error",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: profile },
    { status: 500, body: { error: "server_error" } },
  ]);
  const context = await loadAuthClient(fetch, []);

  await context.initAuthClient({
    baseUrl: "https://auth.example.com",
    bootstrapMode: "eager",
  });

  await assert.rejects(
    context.requestNonce(),
    /tauth\.nonce_failed/,
  );
});

test("auth client nonce helper rejects invalid JSON payloads", async () => {
  const profile = {
    user_id: "nonce-invalid-user",
    user_email: "nonce-invalid@example.com",
    display: "Nonce Invalid",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: profile },
    () => ({
      ok: true,
      status: 200,
      async json() {
        throw new Error("invalid_json");
      },
    }),
  ]);
  const context = await loadAuthClient(fetch, []);

  await context.initAuthClient({
    baseUrl: "https://auth.example.com",
    bootstrapMode: "eager",
  });

  await assert.rejects(
    context.requestNonce(),
    /tauth\.nonce_invalid/,
  );
});

test("auth client exchanges Google credential and updates profile", async () => {
  const initialProfile = {
    user_id: "initial-user",
    user_email: "initial@example.com",
    display: "Initial User",
    roles: ["user"],
  };
  const exchangedProfile = {
    user_id: "exchanged-user",
    user_email: "exchanged@example.com",
    display: "Exchanged User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: initialProfile },
    { status: 200, body: exchangedProfile },
  ]);
  const context = await loadAuthClient(fetch, []);

  const authenticatedProfiles = [];
  await context.initAuthClient({
    baseUrl: "https://auth.example.com",
    bootstrapMode: "eager",
    onAuthenticated(profile) {
      authenticatedProfiles.push(profile);
    },
    onUnauthenticated() {
      throw new Error("should authenticate");
    },
  });

  const responseProfile = await context.exchangeGoogleCredential({
    credential: "google-token",
    nonceToken: "nonce-456",
  });

  assert.deepEqual(responseProfile, exchangedProfile);
  assert.deepEqual(context.getCurrentUser(), exchangedProfile);
  assert.equal(authenticatedProfiles.length, 2);
  assert.deepEqual(authenticatedProfiles[1], exchangedProfile);

  assert.equal(fetch.calls.length, 2);
  const exchangeCall = fetch.calls[1];
  assert.equal(exchangeCall.url, "https://auth.example.com/auth/google");
  assert.equal(exchangeCall.method, "POST");
  assertHeader(exchangeCall, "Content-Type", "application/json");
  assertHeader(exchangeCall, "X-Requested-With", "XMLHttpRequest");
  assert.equal(
    exchangeCall.body,
    JSON.stringify({
      google_id_token: "google-token",
      nonce_token: "nonce-456",
    }),
  );
});

test("auth client exchanges password credentials and updates profile", async () => {
  const profile = {
    user_id: "email:user@example.com",
    user_email: "user@example.com",
    display: "Password User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: profile },
  ]);
  const context = await loadAuthClient(fetch, [], {
    tenantId: "tenant-alpha",
  });
  await context.initAuthClient({
    baseUrl: "https://auth.example.com",
    onUnauthenticated() {},
  });

  const received = await context.exchangePasswordCredential({
    email: "user@example.com",
    password: "correct horse battery staple",
  });

  assert.deepEqual(received, profile);
  assert.deepEqual(context.getCurrentUser(), profile);
  const exchangeCall = fetch.calls[0];
  assert.equal(exchangeCall.url, "https://auth.example.com/auth/password/login");
  assert.equal(exchangeCall.method, "POST");
  assertHeader(exchangeCall, "Content-Type", "application/json");
  assertHeader(exchangeCall, "X-Requested-With", "XMLHttpRequest");
  assertHeader(exchangeCall, "X-TAuth-Tenant", "tenant-alpha");
  assert.deepEqual(JSON.parse(exchangeCall.body), {
    email: "user@example.com",
    password: "correct horse battery staple",
  });
});

test("auth client exchange helper surfaces server error codes", async () => {
  const profile = {
    user_id: "exchange-error-user",
    user_email: "exchange-error@example.com",
    display: "Exchange Error",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: profile },
    { status: 401, body: { error: "auth.login.invalid_nonce" } },
  ]);
  const context = await loadAuthClient(fetch, []);

  await context.initAuthClient({
    baseUrl: "https://auth.example.com",
    bootstrapMode: "eager",
  });

  await assert.rejects(
    context.exchangeGoogleCredential({
      credential: "google-token",
      nonceToken: "nonce-456",
    }),
    /auth\.login\.invalid_nonce/,
  );
});

test("auth client exchange helper rejects invalid JSON payloads", async () => {
  const profile = {
    user_id: "exchange-invalid-user",
    user_email: "exchange-invalid@example.com",
    display: "Exchange Invalid",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: profile },
    () => ({
      ok: true,
      status: 200,
      async json() {
        throw new Error("invalid_json");
      },
    }),
  ]);
  const context = await loadAuthClient(fetch, []);

  await context.initAuthClient({
    baseUrl: "https://auth.example.com",
    bootstrapMode: "eager",
  });

  await assert.rejects(
    context.exchangeGoogleCredential({
      credential: "google-token",
      nonceToken: "nonce-456",
    }),
    /tauth\.exchange_failed/,
  );
});

test("initAuthClient attaches tenant override header when configured", async () => {
  const profile = {
    user_id: "tenant-user",
    user_email: "tenant@example.com",
    display: "Tenant User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([{ status: 200, body: profile }]);
  const context = await loadAuthClient(fetch);

  await context.initAuthClient({
    baseUrl: "https://tenant.example.com",
    tenantId: "demo-tenant",
    bootstrapMode: "eager",
    onAuthenticated() {},
    onUnauthenticated() {
      throw new Error("should authenticate");
    },
  });

  assert.equal(fetch.calls.length, 1);
  const headers = fetch.calls[0].headers || {};
  assert.equal(headers["X-TAuth-Tenant"], "demo-tenant");
});

test("apiFetch sends tenant header during refresh cycle only", async () => {
  const fetch = createFetchWithQueue([
    { status: 401, body: {} }, // init /me
    { status: 401, body: {} }, // init refresh
    { status: 401, body: {} }, // apiFetch initial attempt
    { status: 204, body: {} }, // refresh
    { status: 200, body: {} }, // retry
  ]);
  const context = await loadAuthClient(fetch);

  await context.initAuthClient({
    baseUrl: "https://tenant.example.com",
    tenantId: "tenant-blue",
    bootstrapMode: "eager",
    onUnauthenticated() {},
  });

  fetch.calls.length = 0;

  await context.apiFetch("https://tenant.example.com/resource", { method: "GET" });

  assert.equal(fetch.calls.length, 3);
  const initialCallHeaders = fetch.calls[0].headers || {};
  assert.equal(initialCallHeaders["X-TAuth-Tenant"], undefined);

  const refreshCall = fetch.calls[1];
  assert.equal(refreshCall.url, "https://tenant.example.com/auth/refresh");
  assert.equal(refreshCall.headers["X-TAuth-Tenant"], "tenant-blue");

  const retryCallHeaders = fetch.calls[2].headers || {};
  assert.equal(retryCallHeaders["X-TAuth-Tenant"], undefined);
});

test("initAuthClient uses detected tenant id when option omitted", async () => {
  const profile = {
    user_id: "detected-user",
    user_email: "detected@example.com",
    display: "Detected User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([{ status: 200, body: profile }]);
  const context = await loadAuthClient(fetch, [], {
    tenantId: "script-tenant",
  });

  await context.initAuthClient({
    baseUrl: "https://tenant.example.com",
    bootstrapMode: "eager",
    onAuthenticated() {},
    onUnauthenticated() {
      throw new Error("should authenticate with detected tenant");
    },
  });

  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0].headers["X-TAuth-Tenant"], "script-tenant");
});

test("setAuthTenantId before init configures tenant header", async () => {
  const profile = {
    user_id: "pref-user",
    user_email: "pref@example.com",
    display: "Preferred User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([{ status: 200, body: profile }]);
  const context = await loadAuthClient(fetch);

  context.setAuthTenantId("pref-tenant");
  await context.initAuthClient({
    baseUrl: "https://tenant.example.com",
    bootstrapMode: "eager",
    onAuthenticated() {},
    onUnauthenticated() {
      throw new Error("should authenticate with preferred tenant");
    },
  });

  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0].headers["X-TAuth-Tenant"], "pref-tenant");
});

test("setAuthTenantId after init updates future auth requests", async () => {
  const profile = {
    user_id: "switch-user",
    user_email: "switch@example.com",
    display: "Switch User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: profile },
    { status: 204, body: {} },
  ]);
  const context = await loadAuthClient(fetch);

  await context.initAuthClient({
    baseUrl: "https://tenant.example.com",
    tenantId: "tenant-one",
    bootstrapMode: "eager",
    onAuthenticated() {},
    onUnauthenticated() {},
  });
  assert.equal(fetch.calls[0].headers["X-TAuth-Tenant"], "tenant-one");

  context.setAuthTenantId("tenant-two");
  await context.logout();

  assert.equal(fetch.calls.length, 2);
  assert.equal(fetch.calls[1].url, "https://tenant.example.com/auth/logout");
  assert.equal(fetch.calls[1].headers["X-TAuth-Tenant"], "tenant-two");
});

test("auth client syncs profile on refreshed broadcast", async () => {
  const firstProfile = {
    user_id: "initial-user",
    user_email: "initial@example.com",
    display: "Initial User",
    roles: ["user"],
  };
  const refreshedProfile = {
    user_id: "refreshed-user",
    user_email: "refreshed@example.com",
    display: "Refreshed User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([
    { status: 200, body: firstProfile },
    { status: 200, body: refreshedProfile },
  ]);
  const context = await loadAuthClient(fetch);

  const authenticatedProfiles = [];
  await context.initAuthClient({
    baseUrl: "https://example.com",
    bootstrapMode: "eager",
    onAuthenticated(profile) {
      authenticatedProfiles.push(profile);
    },
    onUnauthenticated() {
      throw new Error("should stay authenticated");
    },
  });

  context.__dispatchBroadcast("refreshed");
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.equal(authenticatedProfiles.length, 2);
  assert.deepEqual(authenticatedProfiles[1], refreshedProfile);
  assert.equal(fetch.calls.length, 2);
});

test("auth client clears state when peer refresh lacks a profile", async () => {
  const fetchResponses = [
    { status: 401, body: {} },
    { status: 401, body: {} },
    { status: 401, body: {} },
  ];
  const fetchCalls = [];
  let dispatchBroadcast = function () {};
  let callCount = 0;
  const fetch = async (requestUrl, options = {}) => {
    callCount += 1;
    fetchCalls.push({
      url: requestUrl,
      method: options.method || "GET",
      headers: options.headers || {},
      credentials: options.credentials,
    });
    const response = fetchResponses[callCount - 1];
    if (!response) {
      throw new Error("unexpected fetch call in test");
    }
    if (callCount === 2) {
      setTimeout(function () {
        dispatchBroadcast("refreshed");
      }, 0);
    }
    return createResponse(response.status, response.body);
  };
  const context = await loadAuthClient(fetch);
  dispatchBroadcast = function (message) {
    context.__dispatchBroadcast(message);
  };

  let unauthenticatedCount = 0;
  await context.initAuthClient({
    baseUrl: "https://example.com",
    bootstrapMode: "eager",
    onAuthenticated() {
      throw new Error("should not authenticate with missing profile");
    },
    onUnauthenticated() {
      unauthenticatedCount += 1;
    },
  });

  assert.equal(unauthenticatedCount, 1);
  assert.equal(context.getCurrentUser(), null);
  assert.equal(fetchCalls.length, 3);
});

test("auth client clears state on logged_out broadcast", async () => {
  const profile = {
    user_id: "logout-user",
    user_email: "logout@example.com",
    display: "Logout User",
    roles: ["user"],
  };
  const fetch = createFetchWithQueue([{ status: 200, body: profile }]);
  const context = await loadAuthClient(fetch);

  let unauthenticatedCount = 0;
  await context.initAuthClient({
    baseUrl: "https://example.com",
    bootstrapMode: "eager",
    onAuthenticated() {},
    onUnauthenticated() {
      unauthenticatedCount += 1;
    },
  });

  context.__dispatchBroadcast("logged_out");
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.equal(unauthenticatedCount, 1);
  assert.equal(context.getCurrentUser(), null);
  assert.equal(fetch.calls.length, 1);
});
