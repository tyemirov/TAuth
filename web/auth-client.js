/* @mprlab/auth-client */
(function () {
  var defaultOptions = {
    baseUrl: "/",
    meEndpoint: "/me",
    refreshEndpoint: "/auth/refresh",
    logoutEndpoint: "/auth/logout",
    tenantId: "",
    onAuthenticated: function onAuthenticatedDefault(userProfile) {},
    onUnauthenticated: function onUnauthenticatedDefault() {},
  };

  var runtime = {
    options: null,
    userProfile: null,
    isRefreshing: false,
    pendingRequests: [],
    broadcastChannel: null,
    tenantId: "",
  };

  setTenantId(detectInitialTenantId());

  function detectInitialTenantId() {
    if (typeof window !== "undefined") {
      if (typeof window.__TAUTH_TENANT_ID__ === "string") {
        return window.__TAUTH_TENANT_ID__.trim();
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

  function setTenantId(value) {
    runtime.tenantId = typeof value === "string" ? value.trim() : "";
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

  function getCurrentUser() {
    return runtime.userProfile;
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

  function normalizeOptions(passed) {
    var options = Object.assign({}, defaultOptions, passed || {});
    options.baseUrl = options.baseUrl || "/";
    if (options.tenantId === undefined || options.tenantId === null) {
      options.tenantId = "";
    } else {
      options.tenantId = String(options.tenantId).trim();
    }
    return options;
  }

  function withTenantHeader(headers) {
    var combined = Object.assign({}, headers || {});
    if (runtime.options && runtime.options.tenantId) {
      combined[tenantHeaderName] = runtime.options.tenantId;
    }
    return combined;
  }

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

  async function apiFetch(inputUrl, initOptions) {
    var merged = Object.assign({}, initOptions || {});
    merged.credentials = "include";
    merged.headers = Object.assign(
      { "X-Client": "mprlab-ui" },
      merged.headers || {},
    );
    merged.headers = withTenantHeader(merged.headers);
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
    window.initAuthClient = initAuthClient;
    window.apiFetch = apiFetch;
    window.getCurrentUser = getCurrentUser;
    window.logout = logout;
    window.setAuthTenantId = setTenantId;
  }
})();
