const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const path = require("node:path");
const fs = require("node:fs/promises");

const MPR_UI_CDN_URL =
  "https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@main/auth-header.js";
const LOCAL_ASSET_PATH = path.join(__dirname, "..", "web", "mpr-ui.js");

let cachedLocalAssetPromise = null;

async function loadLocalAsset() {
  if (!cachedLocalAssetPromise) {
    cachedLocalAssetPromise = fs.readFile(LOCAL_ASSET_PATH, "utf8");
  }
  return cachedLocalAssetPromise;
}

async function createCdnFetchStub() {
  const scriptSource = await loadLocalAsset();
  return async (url) => {
    if (url !== MPR_UI_CDN_URL) {
      throw new Error(`unexpected CDN request to ${url}`);
    }
    return {
      ok: true,
      status: 200,
      async text() {
        return scriptSource;
      },
    };
  };
}

class ClassList {
  constructor(element) {
    this.element = element;
    this.set = new Set();
  }
  add(...tokens) {
    tokens.forEach((token) => this.set.add(token));
    this.element.className = Array.from(this.set).join(" ");
  }
  remove(...tokens) {
    tokens.forEach((token) => this.set.delete(token));
    this.element.className = Array.from(this.set).join(" ");
  }
}

function dataAttributeToKey(name) {
  return name
    .slice(5)
    .split("-")
    .map((segment, index) =>
      index === 0
        ? segment
        : segment.charAt(0).toUpperCase() + segment.slice(1),
    )
    .join("");
}

class StubElement {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.className = "";
    this.classList = new ClassList(this);
    this.dataset = {};
    this.attributes = {};
    this.textContent = "";
    this.hidden = false;
    this.eventListeners = new Map();
    this.innerHTMLValue = "";
  }

  appendChild(child) {
    this.children.push(child);
    child.parentNode = this;
    return child;
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
    if (name.startsWith("data-")) {
      const key = dataAttributeToKey(name);
      this.dataset[key] = String(value);
    }
  }

  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }

  removeAttribute(name) {
    delete this.attributes[name];
    if (name.startsWith("data-")) {
      const key = dataAttributeToKey(name);
      delete this.dataset[key];
    }
  }

  addEventListener(type, handler) {
    if (!this.eventListeners.has(type)) {
      this.eventListeners.set(type, []);
    }
    this.eventListeners.get(type).push(handler);
  }

  dispatchEvent(event) {
    const handlers = this.eventListeners.get(event.type) || [];
    handlers.forEach((handler) => handler.call(this, event));
    if (event.bubbles && this.parentNode) {
      this.parentNode.dispatchEvent(event);
    }
    return true;
  }

  set innerHTML(value) {
    this.innerHTMLValue = value;
    this.children = [];
  }

  get innerHTML() {
    return this.innerHTMLValue;
  }
}

class StubDocument {
  createElement(tagName) {
    return new StubElement(tagName);
  }
}

class StubCustomEvent {
  constructor(type, options = {}) {
    this.type = type;
    this.detail = options.detail;
    this.bubbles = Boolean(options.bubbles);
  }
}

async function loadAuthHeader(options = {}) {
  const resolvedOptions = options || {};
  const defaultScriptPath = LOCAL_ASSET_PATH;

  let source = null;
  if (resolvedOptions.useLocalAsset !== false) {
    const scriptPath = resolvedOptions.scriptPath || defaultScriptPath;
    try {
      source = await fs.readFile(scriptPath, "utf8");
    } catch (error) {
      if (!error || error.code !== "ENOENT") {
        throw error;
      }
    }
  }

  if (source === null) {
    const cdnFetch = resolvedOptions.cdnFetch || globalThis.fetch;
    if (typeof cdnFetch !== "function") {
      throw new Error("fetch API required to load mpr-ui auth header from CDN");
    }
    const response = await cdnFetch(MPR_UI_CDN_URL);
    if (!response || typeof response.text !== "function") {
      throw new Error("invalid response when loading mpr-ui auth header");
    }
    if (response.ok === false) {
      throw new Error(
        `failed to load mpr-ui auth header from CDN (status ${response.status})`,
      );
    }
    source = await response.text();
  }

  const rootElement = resolvedOptions.rootElement || new StubElement("div");
  const events = [];

  const fetchImpl =
    typeof resolvedOptions.fetch === "function" ? resolvedOptions.fetch : undefined;

  const context = {
    document: new StubDocument(),
    CustomEvent: StubCustomEvent,
    console,
    fetch: fetchImpl,
    setTimeout,
    clearTimeout,
  };
  context.window = context;
  context.window.MPRUI = {};
  context.window.google = resolvedOptions.google;
  context.window.initAuthClient = resolvedOptions.initAuthClient;
  context.window.CustomEvent = StubCustomEvent;
  context.window.HTMLElement = StubElement;
  context.HTMLElement = StubElement;
  if (fetchImpl) {
    context.window.fetch = fetchImpl;
  }

  vm.createContext(context);
  vm.runInContext(source, context);

  const eventsCollector = events;
  rootElement.addEventListener("mpr-ui:auth:authenticated", (event) => {
    eventsCollector.push({ type: event.type, detail: event.detail });
  });
  rootElement.addEventListener("mpr-ui:auth:unauthenticated", (event) => {
    eventsCollector.push({ type: event.type, detail: event.detail });
  });
  rootElement.addEventListener("mpr-ui:auth:error", (event) => {
    eventsCollector.push({ type: event.type, detail: event.detail });
  });

  return {
    context,
    rootElement,
    events,
  };
}

function createFetchStub(responses) {
  const calls = [];
  const queue = [...responses];
  const fetchStub = async (url, options = {}) => {
    const descriptor = queue.shift();
    if (!descriptor) {
      throw new Error(`unexpected fetch call to ${url}`);
    }
    calls.push({
      url,
      method: (options.method || "GET").toUpperCase(),
      body: options.body ? JSON.parse(options.body) : undefined,
    });
    if (descriptor.url && descriptor.url !== url) {
      throw new Error(
        `expected fetch to ${descriptor.url} but received ${url}`,
      );
    }
    const expectedMethod = (descriptor.method || "GET").toUpperCase();
    if (expectedMethod !== (options.method || "GET").toUpperCase()) {
      throw new Error(
        `expected method ${expectedMethod} for ${url}, got ${options.method}`,
      );
    }
    if (descriptor.status >= 200 && descriptor.status < 300) {
      return {
        ok: true,
        status: descriptor.status,
        async json() {
          return descriptor.body || {};
        },
      };
    }
    return {
      ok: false,
      status: descriptor.status,
      async json() {
        return descriptor.body || {};
      },
    };
  };
  fetchStub.calls = calls;
  return fetchStub;
}

test("mpr-ui header handles credential exchange and logout", async () => {
  const loginProfile = {
    user_id: "google:sub-xyz",
    user_email: "header-user@example.com",
    display: "Header User",
    avatar_url: "https://example.com/avatar.png",
    roles: ["user"],
  };

  const fetch = createFetchStub([
    {
      url: "https://auth.example.com/auth/nonce",
      method: "POST",
      status: 200,
      body: { nonce: "nonce-123" },
    },
    {
      url: "https://auth.example.com/auth/google",
      method: "POST",
      status: 200,
      body: loginProfile,
    },
    {
      url: "https://auth.example.com/auth/logout",
      method: "POST",
      status: 204,
      body: {},
    },
  ]);

  const initAuthCalls = [];
  const initAuthBehaviours = [
    (options) => {
      initAuthCalls.push("unauthenticated");
      options.onUnauthenticated();
      return Promise.resolve();
    },
    (options) => {
      initAuthCalls.push("authenticated");
      options.onAuthenticated(loginProfile);
      return Promise.resolve();
    },
    (options) => {
      initAuthCalls.push("after-logout");
      options.onUnauthenticated();
      return Promise.resolve();
    },
  ];

  const initAuthClient = (options) => {
    const handler = initAuthBehaviours.shift();
    if (!handler) {
      throw new Error("initAuthClient invoked more times than expected");
    }
    return handler(options);
  };

  const googleStub = {
    accounts: {
      id: {
        promptCalls: 0,
        prompt() {
          googleStub.accounts.id.promptCalls += 1;
        },
      },
    },
  };

  const { context, rootElement, events } = await loadAuthHeader({
    cdnFetch: await createCdnFetchStub(),
    fetch,
    google: googleStub,
    initAuthClient,
  });

  const controller = context.MPRUI.createAuthHeader(rootElement, {
    baseUrl: "https://auth.example.com",
    siteName: "Demo",
    siteLink: "/demo",
  });

  assert.equal(controller.state.status, "unauthenticated");
  assert.equal(rootElement.getAttribute("data-user-id"), null);

  await controller.handleCredential({ credential: "token-123" });
  assert.equal(fetch.calls.length, 2);
  assert.equal(fetch.calls[0].url, "https://auth.example.com/auth/nonce");
  assert.deepEqual(fetch.calls[1].url, "https://auth.example.com/auth/google");
  assert.deepEqual(fetch.calls[1].body, {
    google_id_token: "token-123",
    nonce_token: "nonce-123",
  });

  assert.equal(controller.state.status, "authenticated");
  assert.equal(
    rootElement.getAttribute("data-user-id"),
    "google:sub-xyz",
  );
  assert.equal(
    rootElement.getAttribute("data-user-email"),
    "header-user@example.com",
  );
  assert.equal(
    rootElement.getAttribute("data-user-display"),
    "Header User",
  );
  assert.equal(
    rootElement.getAttribute("data-user-avatar-url"),
    "https://example.com/avatar.png",
  );

  await controller.signOut();
  assert.equal(fetch.calls.length, 3);
  assert.equal(fetch.calls[2].url, "https://auth.example.com/auth/logout");
  assert.equal(controller.state.status, "unauthenticated");
  assert.equal(rootElement.getAttribute("data-user-id"), null);

  assert.deepEqual(initAuthCalls, [
    "unauthenticated",
    "authenticated",
    "after-logout",
  ]);
  assert.deepEqual(
    events.map((event) => event.type),
    [
      "mpr-ui:auth:unauthenticated",
      "mpr-ui:auth:authenticated",
      "mpr-ui:auth:unauthenticated",
    ],
  );
});

test("mpr-ui header surfaces error when credential missing", async () => {
  const fetch = createFetchStub([]);
  const initAuthClient = (options) => {
    options.onUnauthenticated();
    return Promise.resolve();
  };
  const googleStub = {
    accounts: {
      id: {
        prompt() {},
      },
    },
  };

  const { context, rootElement, events } = await loadAuthHeader({
    cdnFetch: await createCdnFetchStub(),
    fetch,
    google: googleStub,
    initAuthClient,
  });

  const controller = context.MPRUI.createAuthHeader(rootElement, {});

  controller.handleCredential({});
  assert.equal(events.length, 2);
  assert.equal(events[0].type, "mpr-ui:auth:unauthenticated");
  assert.equal(events[1].type, "mpr-ui:auth:error");
  assert.equal(
    events[1].detail.code,
    "mpr-ui.auth.missing_credential",
  );
  assert.equal(fetch.calls.length, 0);
});

test("mpr-ui header loads from CDN when local asset disabled", async () => {
  let cdnCalls = 0;
  const cdnFetch = await createCdnFetchStub();
  const cdnFetchSpy = async (url) => {
    cdnCalls += 1;
    return cdnFetch(url);
  };

  const { context } = await loadAuthHeader({
    useLocalAsset: false,
    cdnFetch: cdnFetchSpy,
  });

  assert.equal(typeof context.MPRUI.createAuthHeader, "function");
  assert.equal(cdnCalls, 1);
});
