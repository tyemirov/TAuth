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
   * @property {string} baseUrl
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
   * @typedef {Object} GoogleCredentialExchange
   * @property {string} credential
   * @property {string} nonceToken
   */

  /**
   * @typedef {Object} PendingRequest
   * @property {(value: Response | PromiseLike<Response>) => void} resolve
   * @property {(reason?: unknown) => void} reject
   * @property {() => Promise<Response>} executorFunction
   */

  /** @type {AuthClientOptions} */
  var defaultOptions = {
    baseUrl: "",
    meEndpoint: "/me",
    nonceEndpoint: "/auth/nonce",
    googleEndpoint: "/auth/google",
    refreshEndpoint: "/auth/refresh",
    logoutEndpoint: "/auth/logout",
    tenantId: "",
    onAuthenticated: function onAuthenticatedDefault(userProfile) {},
    onUnauthenticated: function onUnauthenticatedDefault() {},
  };

  /** @type {{ options: AuthClientOptions | null, userProfile: UserProfile | null, isRefreshing: boolean, pendingRequests: PendingRequest[], broadcastChannel: BroadcastChannel | null, broadcastListeners: Array<(event: MessageEvent) => void>, broadcastListenerAttached: boolean, broadcastHandlerAttached: boolean, profileSyncPromise: Promise<UserProfile | null> | null, tenantId: string, originHint: string }} */
  var runtime = {
    options: null,
    userProfile: null,
    isRefreshing: false,
    pendingRequests: [],
    broadcastChannel: null,
    broadcastListeners: [],
    broadcastListenerAttached: false,
    broadcastHandlerAttached: false,
    profileSyncPromise: null,
    tenantId: "",
    originHint: "",
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

  runtime.originHint = detectOriginHint();
  setTenantId(detectInitialTenantId());

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

  /**
   * @param {string} rawValue
   * @param {string} errorCode
   * @returns {string}
   */
  function requireNonEmptyString(rawValue, errorCode) {
    var normalized = typeof rawValue === "string" ? rawValue.trim() : "";
    if (!normalized) {
      throw new Error(errorCode);
    }
    return normalized;
  }

  /**
   * @param {GoogleCredentialExchange} input
   * @returns {{ credential: string, nonceToken: string }}
   */
  function normalizeGoogleCredentialInput(input) {
    if (!input || typeof input !== "object") {
      throw new Error("tauth.missing_credential");
    }
    var credential = requireNonEmptyString(
      input.credential,
      "tauth.missing_credential",
    );
    var nonceToken = requireNonEmptyString(
      input.nonceToken,
      "tauth.missing_nonce_token",
    );
    return { credential: credential, nonceToken: nonceToken };
  }

  var tenantHeaderName = "X-TAuth-Tenant";
  var broadcastChannelName = "auth";
  var broadcastEventRefreshed = "refreshed";
  var broadcastEventLoggedOut = "logged_out";
  var broadcastWaitTimeoutMs = 360;

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

  function applyAuthenticatedProfile(profile) {
    setUserProfile(profile);
    if (
      runtime.options &&
      typeof runtime.options.onAuthenticated === "function"
    ) {
      runtime.options.onAuthenticated(profile);
    }
  }

  function applyUnauthenticated() {
    setUserProfile(null);
    if (
      runtime.options &&
      typeof runtime.options.onUnauthenticated === "function"
    ) {
      runtime.options.onUnauthenticated();
    }
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
    var options = requireOptions();
    return {
      baseUrl: options.baseUrl,
      meUrl: joinUrl(options.baseUrl, options.meEndpoint),
      nonceUrl: joinUrl(options.baseUrl, options.nonceEndpoint),
      googleUrl: joinUrl(options.baseUrl, options.googleEndpoint),
      refreshUrl: joinUrl(options.baseUrl, options.refreshEndpoint),
      logoutUrl: joinUrl(options.baseUrl, options.logoutEndpoint),
    };
  }

  /**
   * @returns {Promise<string>}
   */
  async function requestNonce() {
    var endpoints = getAuthEndpoints();
    var response = await fetch(endpoints.nonceUrl, {
      method: "POST",
      credentials: "include",
      headers: withTenantHeader({
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
      }),
    });
    if (!response.ok) {
      throw new Error("tauth.nonce_failed");
    }
    var payload;
    try {
      payload = await response.json();
    } catch (error) {
      throw new Error("tauth.nonce_invalid");
    }
    if (
      !payload ||
      typeof payload.nonce !== "string" ||
      payload.nonce.trim() === ""
    ) {
      throw new Error("tauth.nonce_invalid");
    }
    return payload.nonce;
  }

  /**
   * @param {GoogleCredentialExchange} input
   * @returns {Promise<UserProfile>}
   */
  async function exchangeGoogleCredential(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizeGoogleCredentialInput(input);
    var response = await fetch(endpoints.googleUrl, {
      method: "POST",
      credentials: "include",
      headers: withTenantHeader({
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
      }),
      body: JSON.stringify({
        google_id_token: normalized.credential,
        nonce_token: normalized.nonceToken,
      }),
    });
    var payload;
    try {
      payload = await response.json();
    } catch (error) {
      throw new Error("tauth.exchange_failed");
    }
    if (!response.ok) {
      var errorCode =
        payload && typeof payload.error === "string"
          ? payload.error
          : "tauth.exchange_failed";
      throw new Error(errorCode);
    }
    if (!payload || typeof payload !== "object") {
      throw new Error("tauth.exchange_invalid");
    }
    applyAuthenticatedProfile(payload);
    return payload;
  }

  function ensureBroadcastChannel() {
    if (!runtime.broadcastChannel && typeof BroadcastChannel !== "undefined") {
      runtime.broadcastChannel = new BroadcastChannel(broadcastChannelName);
    }
  }

  function ensureBroadcastDispatch() {
    if (!runtime.broadcastChannel || runtime.broadcastListenerAttached) {
      return;
    }
    runtime.broadcastListenerAttached = true;
    runtime.broadcastChannel.onmessage = function handleBroadcastDispatch(event) {
      var listeners = runtime.broadcastListeners.slice();
      for (var listenerIndex = 0; listenerIndex < listeners.length; listenerIndex++) {
        listeners[listenerIndex](event);
      }
    };
  }

  function addBroadcastListener(listener) {
    ensureBroadcastChannel();
    ensureBroadcastDispatch();
    if (!runtime.broadcastChannel) {
      return function noop() {};
    }
    runtime.broadcastListeners.push(listener);
    return function removeListener() {
      var listeners = runtime.broadcastListeners;
      for (
        var listenerIndex = 0;
        listenerIndex < listeners.length;
        listenerIndex++
      ) {
        if (listeners[listenerIndex] === listener) {
          listeners.splice(listenerIndex, 1);
          break;
        }
      }
    };
  }

  function ensureBroadcastListener() {
    if (runtime.broadcastHandlerAttached) {
      return;
    }
    runtime.broadcastHandlerAttached = true;
    addBroadcastListener(handleBroadcastMessage);
  }

  function normalizeBroadcastMessage(message) {
    if (!message) {
      return "";
    }
    if (typeof message === "string") {
      return message;
    }
    if (typeof message === "object" && typeof message.type === "string") {
      return message.type;
    }
    return "";
  }

  function handleBroadcastMessage(event) {
    var messageType = normalizeBroadcastMessage(event && event.data);
    if (messageType === broadcastEventRefreshed) {
      handleExternalRefresh();
      return;
    }
    if (messageType === broadcastEventLoggedOut) {
      handleExternalLogout();
    }
  }

  function handleExternalRefresh() {
    if (!runtime.options) {
      return;
    }
    syncProfileFromServer();
  }

  function handleExternalLogout() {
    applyUnauthenticated();
  }

  function waitForBroadcast(messageType, timeoutMs) {
    ensureBroadcastChannel();
    if (!runtime.broadcastChannel) {
      return Promise.resolve(false);
    }
    return new Promise(function (resolve) {
      var isResolved = false;
      var removeListener = addBroadcastListener(function (event) {
        var message = normalizeBroadcastMessage(event && event.data);
        if (message !== messageType) {
          return;
        }
        if (isResolved) {
          return;
        }
        isResolved = true;
        removeListener();
        clearTimeout(timerId);
        resolve(true);
      });
      var timerId = setTimeout(function () {
        if (isResolved) {
          return;
        }
        isResolved = true;
        removeListener();
        resolve(false);
      }, timeoutMs);
    });
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
    var baseUrlCandidate =
      passed && typeof passed.baseUrl === "string" ? passed.baseUrl.trim() : "";
    if (!baseUrlCandidate) {
      throw new Error("tauth.missing_base_url");
    }
    options.baseUrl = baseUrlCandidate;
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

  function requireOptions() {
    if (runtime.options) {
      return runtime.options;
    }
    throw new Error("tauth.missing_base_url");
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

  async function fetchCurrentProfile() {
    var options = requireOptions();
    try {
      var response = await fetch(
        joinUrl(options.baseUrl, options.meEndpoint),
        {
          method: "GET",
          credentials: "include",
          headers: withTenantHeader({ "X-Client": "mprlab-ui" }),
        },
      );
      if (!response.ok) {
        return null;
      }
      return await response.json();
    } catch (error) {
      return null;
    }
  }

  function syncProfileFromServer() {
    if (runtime.profileSyncPromise) {
      return runtime.profileSyncPromise;
    }
    runtime.profileSyncPromise = (async function syncProfile() {
      var profile = await fetchCurrentProfile();
      if (profile) {
        applyAuthenticatedProfile(profile);
      }
      return profile;
    })();
    return runtime.profileSyncPromise.finally(function () {
      runtime.profileSyncPromise = null;
    });
  }

  async function attemptRefresh() {
    var options = requireOptions();
    try {
      var refreshResponse = await fetch(
        joinUrl(options.baseUrl, options.refreshEndpoint),
        {
          method: "POST",
          credentials: "include",
          headers: withTenantHeader({ "X-Requested-With": "XMLHttpRequest" }),
        },
      );
      if (refreshResponse.ok || refreshResponse.status === 204) {
        broadcast(broadcastEventRefreshed);
        return true;
      }
      return false;
    } catch (error) {
      return false;
    }
  }

  async function waitForPeerRefresh() {
    var received = await waitForBroadcast(
      broadcastEventRefreshed,
      broadcastWaitTimeoutMs,
    );
    if (!received) {
      return false;
    }
    await syncProfileFromServer();
    return true;
  }

  /**
   * @param {AuthClientInitOptions} passed
   * @returns {Promise<void>}
   */
  async function initAuthClient(passed) {
    runtime.options = normalizeOptions(passed);
    ensureBroadcastListener();
    try {
      var profile = await fetchCurrentProfile();
      if (profile) {
        applyAuthenticatedProfile(profile);
        return;
      }
      var refreshSucceeded = await attemptRefresh();
      if (refreshSucceeded) {
        var refreshedProfile = await fetchCurrentProfile();
        if (refreshedProfile) {
          applyAuthenticatedProfile(refreshedProfile);
          return;
        }
      }
      var peerRecovered = await waitForPeerRefresh();
      if (peerRecovered) {
        return;
      }
      if (runtime.userProfile) {
        return;
      }
      applyUnauthenticated();
    } catch (initializationError) {
      applyUnauthenticated();
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
    ensureBroadcastListener();
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
      var refreshSucceeded = await attemptRefresh();
      if (refreshSucceeded) {
        var retryResponse = await execute();
        flushPendingRequests(null);
        return retryResponse;
      }
      var peerRecovered = await waitForPeerRefresh();
      if (peerRecovered) {
        var recoveredResponse = await execute();
        flushPendingRequests(null);
        return recoveredResponse;
      }
      flushPendingRequests(new Error("refresh_failed"));
      return firstResponse;
    } finally {
      runtime.isRefreshing = false;
    }
  }

  /**
   * @returns {Promise<void>}
   */
  async function logout() {
    var options = requireOptions();
    try {
      await fetch(
        joinUrl(options.baseUrl, options.logoutEndpoint),
        {
          method: "POST",
          credentials: "include",
          headers: withTenantHeader({ "X-Requested-With": "XMLHttpRequest" }),
        },
      );
    } catch (ignore) {}
    applyUnauthenticated();
    broadcast(broadcastEventLoggedOut);
  }

  if (typeof window !== "undefined") {
    window["initAuthClient"] = initAuthClient;
    window["apiFetch"] = apiFetch;
    window["getCurrentUser"] = getCurrentUser;
    window["getAuthEndpoints"] = getAuthEndpoints;
    window["requestNonce"] = requestNonce;
    window["exchangeGoogleCredential"] = exchangeGoogleCredential;
    window["logout"] = logout;
    window["setAuthTenantId"] = setTenantId;
  }
})();
