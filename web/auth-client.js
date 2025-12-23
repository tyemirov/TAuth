// @ts-check
/* @mprlab/auth-client */
(function () {
  /**
   * @typedef {Record<string, unknown>} UserProfile
   */

  /**
   * @typedef {Object} AuthClientOptions
   * @property {string} baseUrl
   * @property {string} meEndpoint
   * @property {string} nonceEndpoint
   * @property {string} googleEndpoint
   * @property {string} refreshEndpoint
   * @property {string} logoutEndpoint
   * @property {string} tenantId
   * @property {(profile: UserProfile) => void} onAuthenticated
   * @property {() => void} onUnauthenticated
   */

  /**
   * @typedef {Object} AuthClientInitOptions
   * @property {string=} baseUrl
   * @property {string=} meEndpoint
   * @property {string=} nonceEndpoint
   * @property {string=} googleEndpoint
   * @property {string=} refreshEndpoint
   * @property {string=} logoutEndpoint
   * @property {string=} tenantId
   * @property {(profile: UserProfile) => void=} onAuthenticated
   * @property {() => void=} onUnauthenticated
   */

  /**
   * @typedef {Object} AuthEndpointMap
   * @property {string} baseUrl
   * @property {string} meUrl
   * @property {string} nonceUrl
   * @property {string} googleUrl
   * @property {string} refreshUrl
   * @property {string} logoutUrl
   */

  /**
   * @typedef {Object} PendingRequest
   * @property {(value: Response | PromiseLike<Response>) => void} resolve
   * @property {(reason?: unknown) => void} reject
   * @property {() => Promise<Response>} executorFunction
   */

  /** @type {AuthClientOptions} */
  var defaultOptions = {
    baseUrl: "/",
    meEndpoint: "/me",
    nonceEndpoint: "/auth/nonce",
    googleEndpoint: "/auth/google",
    refreshEndpoint: "/auth/refresh",
    logoutEndpoint: "/auth/logout",
    tenantId: "",
    onAuthenticated: function onAuthenticatedDefault(userProfile) {},
    onUnauthenticated: function onUnauthenticatedDefault() {},
  };

  /** @type {{ options: AuthClientOptions | null, userProfile: UserProfile | null, isRefreshing: boolean, pendingRequests: PendingRequest[], broadcastChannel: BroadcastChannel | null, tenantId: string, originHint: string, baseUrlHint: string }} */
  var runtime = {
    options: null,
    userProfile: null,
    isRefreshing: false,
    pendingRequests: [],
    broadcastChannel: null,
    tenantId: "",
    originHint: "",
    baseUrlHint: "",
  };

  function detectInitialTenantId() {
    if (typeof window !== "undefined") {
      var globalTenantId = window["__TAUTH_TENANT_ID__"];
      if (typeof globalTenantId === "string") {
        return globalTenantId.trim();
      }
    }
    if (typeof document !== "undefined") {
      var currentScript = document.currentScript;
      if (currentScript && typeof currentScript.getAttribute === "function") {
        var dataValue = currentScript.getAttribute("data-tenant-id");
        if (dataValue) {
          return dataValue.trim();
        }
      }
      if (
        document.documentElement &&
        typeof document.documentElement.getAttribute === "function"
      ) {
        var attrValue = document.documentElement.getAttribute(
          "data-tauth-tenant-id",
        );
        if (attrValue) {
          return attrValue.trim();
        }
      }
    }
    return "";
  }

  function parseOriginFromUrl(urlValue) {
    if (!urlValue || typeof URL !== "function") {
      return "";
    }
    var baseOrigin = runtime.originHint || detectOriginHint();
    try {
      if (baseOrigin) {
        return new URL(urlValue, baseOrigin).origin;
      }
      return new URL(urlValue).origin;
    } catch (error) {
      return "";
    }
  }

  function detectOriginHint() {
    if (
      typeof window !== "undefined" &&
      window.location &&
      typeof window.location.origin === "string"
    ) {
      return window.location.origin;
    }
    if (
      typeof globalThis !== "undefined" &&
      globalThis.location &&
      typeof globalThis.location.origin === "string"
    ) {
      return globalThis.location.origin;
    }
    return "";
  }

  function detectInitialBaseUrl() {
    if (typeof window !== "undefined") {
      var globalBaseUrl = window["__TAUTH_BASE_URL__"];
      if (typeof globalBaseUrl === "string" && globalBaseUrl.trim()) {
        return globalBaseUrl.trim();
      }
    }

    if (typeof document !== "undefined") {
      var currentScript = document.currentScript;
      var dataBaseUrl = "";
      var scriptSrc = "";

      if (currentScript && typeof currentScript.getAttribute === "function") {
        var dataValue = currentScript.getAttribute("data-base-url");
        if (dataValue) {
          dataBaseUrl = dataValue.trim();
        }
        var scriptValue = currentScript.getAttribute("src");
        if (scriptValue) {
          scriptSrc = scriptValue;
        }
      }

      if (dataBaseUrl) {
        return dataBaseUrl;
      }

      if (
        document.documentElement &&
        typeof document.documentElement.getAttribute === "function"
      ) {
        var documentValue = document.documentElement.getAttribute(
          "data-tauth-base-url",
        );
        if (documentValue) {
          return documentValue.trim();
        }
      }

      var parsedOrigin = parseOriginFromUrl(scriptSrc);
      if (parsedOrigin) {
        return parsedOrigin;
      }
    }
    return "";
  }

  runtime.originHint = detectOriginHint();
  runtime.baseUrlHint = detectInitialBaseUrl();
  setTenantId(detectInitialTenantId());
  runtime.options = normalizeOptions({});

  /**
   * @param {string} value
   */
  function setTenantId(value) {
    var normalized = typeof value === "string" ? value.trim() : "";
    runtime.tenantId = normalized;
    if (runtime.options) {
      runtime.options.tenantId = normalized;
    }
  }

  function joinUrl(baseUrl, path) {
    if (baseUrl.endsWith("/") && path.startsWith("/")) {
      return baseUrl.slice(0, -1) + path;
    }
    return baseUrl + path;
  }

  var tenantHeaderName = "X-TAuth-Tenant";

  function queueWhileRefreshing(executorFunction) {
    return new Promise(function (resolve, reject) {
      runtime.pendingRequests.push({
        resolve: resolve,
        reject: reject,
        executorFunction: executorFunction,
      });
    });
  }

  function flushPendingRequests(errorObject) {
    var list = runtime.pendingRequests;
    runtime.pendingRequests = [];
    for (var index = 0; index < list.length; index++) {
      var item = list[index];
      if (errorObject) {
        item.reject(errorObject);
      } else {
        item.executorFunction().then(item.resolve).catch(item.reject);
      }
    }
  }

  function setUserProfile(userProfile) {
    runtime.userProfile = userProfile;
  }

  /**
   * @returns {UserProfile | null}
   */
  function getCurrentUser() {
    return runtime.userProfile;
  }

  /**
   * @returns {AuthEndpointMap}
   */
  function getAuthEndpoints() {
    var options = runtime.options || normalizeOptions({});
    return {
      baseUrl: options.baseUrl,
      meUrl: joinUrl(options.baseUrl, options.meEndpoint),
      nonceUrl: joinUrl(options.baseUrl, options.nonceEndpoint),
      googleUrl: joinUrl(options.baseUrl, options.googleEndpoint),
      refreshUrl: joinUrl(options.baseUrl, options.refreshEndpoint),
      logoutUrl: joinUrl(options.baseUrl, options.logoutEndpoint),
    };
  }

  function ensureBroadcastChannel() {
    if (!runtime.broadcastChannel && typeof BroadcastChannel !== "undefined") {
      runtime.broadcastChannel = new BroadcastChannel("auth");
    }
  }

  function broadcast(message) {
    ensureBroadcastChannel();
    if (runtime.broadcastChannel) {
      runtime.broadcastChannel.postMessage(message);
    }
  }

  /**
   * @param {AuthClientInitOptions} passed
   * @returns {AuthClientOptions}
   */
  function normalizeOptions(passed) {
    var options = Object.assign({}, defaultOptions, passed || {});
    var hasExplicitBaseUrl =
      passed && Object.prototype.hasOwnProperty.call(passed, "baseUrl");
    var baseUrlCandidate =
      hasExplicitBaseUrl && typeof passed.baseUrl === "string"
        ? passed.baseUrl.trim()
        : "";
    if (hasExplicitBaseUrl) {
      options.baseUrl = baseUrlCandidate || runtime.baseUrlHint || "/";
    } else {
      options.baseUrl = runtime.baseUrlHint || options.baseUrl || "/";
    }
    var providedTenant = options.tenantId;
    if (providedTenant === undefined || providedTenant === null) {
      options.tenantId = runtime.tenantId || "";
    } else {
      options.tenantId = String(providedTenant).trim();
      if (!options.tenantId && runtime.tenantId) {
        options.tenantId = runtime.tenantId;
      }
    }
    runtime.tenantId = options.tenantId || "";
    return options;
  }

  function currentTenantId() {
    if (runtime.options && runtime.options.tenantId) {
      return runtime.options.tenantId;
    }
    return runtime.tenantId;
  }

  function resolveTenantHeaderValue() {
    var explicitTenant = currentTenantId();
    if (explicitTenant) {
      return explicitTenant;
    }
    if (runtime.originHint) {
      return runtime.originHint;
    }
    var detected = detectOriginHint();
    if (detected) {
      runtime.originHint = detected;
      return detected;
    }
    return "";
  }

  function withTenantHeader(headers) {
    var combined = Object.assign({}, headers || {});
    var headerValue = resolveTenantHeaderValue();
    if (headerValue) {
      combined[tenantHeaderName] = headerValue;
    }
    return combined;
  }

  /**
   * @param {AuthClientInitOptions} passed
   * @returns {Promise<void>}
   */
  async function initAuthClient(passed) {
    runtime.options = normalizeOptions(passed);
    try {
      var meResponse = await fetch(
        joinUrl(runtime.options.baseUrl, runtime.options.meEndpoint),
        {
          method: "GET",
          credentials: "include",
          headers: withTenantHeader({ "X-Client": "mprlab-ui" }),
        },
      );
      if (meResponse.ok) {
        var profile = await meResponse.json();
        setUserProfile(profile);
        runtime.options.onAuthenticated(profile);
        return;
      }
      var refreshResponse = await fetch(
        joinUrl(runtime.options.baseUrl, runtime.options.refreshEndpoint),
        {
          method: "POST",
          credentials: "include",
          headers: withTenantHeader({ "X-Requested-With": "XMLHttpRequest" }),
        },
      );
      if (refreshResponse.ok || refreshResponse.status === 204) {
        broadcast("refreshed");
        var retryResponse = await fetch(
          joinUrl(runtime.options.baseUrl, runtime.options.meEndpoint),
          {
            method: "GET",
            credentials: "include",
            headers: withTenantHeader({ "X-Client": "mprlab-ui" }),
          },
        );
        if (retryResponse.ok) {
          var profileAfter = await retryResponse.json();
          setUserProfile(profileAfter);
          runtime.options.onAuthenticated(profileAfter);
          return;
        }
      }
      setUserProfile(null);
      runtime.options.onUnauthenticated();
    } catch (initializationError) {
      setUserProfile(null);
      runtime.options.onUnauthenticated();
    }
  }

  /**
   * @param {string} inputUrl
   * @param {RequestInit=} initOptions
   * @returns {Promise<Response>}
   */
  async function apiFetch(inputUrl, initOptions) {
    var merged = Object.assign({}, initOptions || {});
    merged.credentials = "include";
    merged.headers = Object.assign(
      { "X-Client": "mprlab-ui" },
      merged.headers || {},
    );
    var execute = function () {
      return fetch(inputUrl, merged);
    };

    var firstResponse = await execute();
    if (firstResponse.status !== 401) {
      return firstResponse;
    }
    if (runtime.isRefreshing) {
      return queueWhileRefreshing(execute);
    }
    runtime.isRefreshing = true;
    try {
      var refreshResponse = await fetch(
        joinUrl(runtime.options.baseUrl, runtime.options.refreshEndpoint),
        {
          method: "POST",
          credentials: "include",
          headers: withTenantHeader({ "X-Requested-With": "XMLHttpRequest" }),
        },
      );
      if (refreshResponse.ok || refreshResponse.status === 204) {
        broadcast("refreshed");
        var retryResponse = await execute();
        flushPendingRequests(null);
        return retryResponse;
      } else {
        flushPendingRequests(new Error("refresh_failed"));
        return firstResponse;
      }
    } finally {
      runtime.isRefreshing = false;
    }
  }

  /**
   * @returns {Promise<void>}
   */
  async function logout() {
    try {
      await fetch(
        joinUrl(runtime.options.baseUrl, runtime.options.logoutEndpoint),
        {
          method: "POST",
          credentials: "include",
          headers: withTenantHeader({ "X-Requested-With": "XMLHttpRequest" }),
        },
      );
    } catch (ignore) {}
    setUserProfile(null);
    broadcast("logged_out");
    if (
      runtime.options &&
      typeof runtime.options.onUnauthenticated === "function"
    ) {
      runtime.options.onUnauthenticated();
    }
  }

  if (typeof window !== "undefined") {
    window["initAuthClient"] = initAuthClient;
    window["apiFetch"] = apiFetch;
    window["getCurrentUser"] = getCurrentUser;
    window["getAuthEndpoints"] = getAuthEndpoints;
    window["logout"] = logout;
    window["setAuthTenantId"] = setTenantId;
  }
})();
