// @ts-check
(function () {
  /**
   * @typedef {Record<string, unknown>} UserProfile
   */

  /**
   * @typedef {Error & { status?: number }} AuthClientError
   */

  /**
   * @typedef {Object} AuthClientOptions
   * @property {string} baseUrl
   * @property {string} meEndpoint
   * @property {string} sessionEndpoint
   * @property {string} nonceEndpoint
   * @property {string} googleEndpoint
   * @property {string} passwordEndpoint
   * @property {string} passwordSignupEndpoint
   * @property {string} passwordVerifyEmailEndpoint
   * @property {string} passwordResetStartEndpoint
   * @property {string} passwordResetCompleteEndpoint
   * @property {string} passwordChangeEndpoint
   * @property {string} passwordLinkStartEndpoint
   * @property {string} passwordLinkVerifyEndpoint
   * @property {string} googleLinkEndpoint
   * @property {string} accountUnlinkEndpoint
   * @property {string} accountDisableEndpoint
   * @property {string} refreshEndpoint
   * @property {string} logoutEndpoint
   * @property {string} tenantId
   * @property {string} bootstrapMode
   * @property {(profile: UserProfile) => void} onAuthenticated
   * @property {() => void} onUnauthenticated
   * @property {(error: AuthClientError) => void} onAuthError
   */

  /**
   * @typedef {Object} AuthClientInitOptions
   * @property {string} baseUrl
   * @property {string=} meEndpoint
   * @property {string=} sessionEndpoint
   * @property {string=} nonceEndpoint
   * @property {string=} googleEndpoint
   * @property {string=} passwordEndpoint
   * @property {string=} passwordSignupEndpoint
   * @property {string=} passwordVerifyEmailEndpoint
   * @property {string=} passwordResetStartEndpoint
   * @property {string=} passwordResetCompleteEndpoint
   * @property {string=} passwordChangeEndpoint
   * @property {string=} passwordLinkStartEndpoint
   * @property {string=} passwordLinkVerifyEndpoint
   * @property {string=} googleLinkEndpoint
   * @property {string=} accountUnlinkEndpoint
   * @property {string=} accountDisableEndpoint
   * @property {string=} refreshEndpoint
   * @property {string=} logoutEndpoint
   * @property {string=} tenantId
   * @property {string=} bootstrapMode
   * @property {(profile: UserProfile) => void=} onAuthenticated
   * @property {() => void=} onUnauthenticated
   * @property {(error: AuthClientError) => void=} onAuthError
   */

  /**
   * @typedef {Object} AuthEndpointMap
   * @property {string} baseUrl
   * @property {string} meUrl
   * @property {string} sessionUrl
   * @property {string} nonceUrl
   * @property {string} googleUrl
   * @property {string} passwordUrl
   * @property {string} passwordSignupUrl
   * @property {string} passwordVerifyEmailUrl
   * @property {string} passwordResetStartUrl
   * @property {string} passwordResetCompleteUrl
   * @property {string} passwordChangeUrl
   * @property {string} passwordLinkStartUrl
   * @property {string} passwordLinkVerifyUrl
   * @property {string} googleLinkUrl
   * @property {string} accountUnlinkUrl
   * @property {string} accountDisableUrl
   * @property {string} refreshUrl
   * @property {string} logoutUrl
   */

  /**
   * @typedef {Object} GoogleCredentialExchange
   * @property {string} credential
   * @property {string} nonceToken
   */

  /**
   * @typedef {Object} PasswordCredentialExchange
   * @property {string} email
   * @property {string} password
   */

  /**
   * @typedef {Object} PasswordSignupRequest
   * @property {string} email
   * @property {string} password
   * @property {string=} displayName
   * @property {string=} avatarUrl
   */

  /**
   * @typedef {Object} ChallengeTokenExchange
   * @property {string} token
   */

  /**
   * @typedef {Object} PasswordResetStartRequest
   * @property {string} email
   */

  /**
   * @typedef {Object} PasswordResetCompleteRequest
   * @property {string} token
   * @property {string} password
   */

  /**
   * @typedef {Object} PasswordChangeRequest
   * @property {string} currentPassword
   * @property {string} newPassword
   */

  /**
   * @typedef {Object} AccountIdentityUnlinkRequest
   * @property {string} provider
   * @property {string} providerId
   */

  /**
   * @typedef {Record<string, unknown>} AccountChallengePayload
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
    sessionEndpoint: "/auth/session",
    nonceEndpoint: "/auth/nonce",
    googleEndpoint: "/auth/google",
    passwordEndpoint: "/auth/password/login",
    passwordSignupEndpoint: "/auth/password/signup",
    passwordVerifyEmailEndpoint: "/auth/password/verify-email",
    passwordResetStartEndpoint: "/auth/password/reset/start",
    passwordResetCompleteEndpoint: "/auth/password/reset/complete",
    passwordChangeEndpoint: "/auth/account/password/change",
    passwordLinkStartEndpoint: "/auth/account/password/link/start",
    passwordLinkVerifyEndpoint: "/auth/account/password/link/verify",
    googleLinkEndpoint: "/auth/account/google/link",
    accountUnlinkEndpoint: "/auth/account/unlink",
    accountDisableEndpoint: "/auth/account/disable",
    refreshEndpoint: "/auth/refresh",
    logoutEndpoint: "/auth/logout",
    tenantId: "",
    bootstrapMode: "restore-if-hinted",
    onAuthenticated: function onAuthenticatedDefault(userProfile) {},
    onUnauthenticated: function onUnauthenticatedDefault() {},
    onAuthError: function onAuthErrorDefault(error) {},
  };

  /** @type {{ options: AuthClientOptions | null, userProfile: UserProfile | null, authState: string, isRefreshing: boolean, pendingRequests: PendingRequest[], broadcastChannel: BroadcastChannel | null, broadcastListeners: Array<(event: MessageEvent) => void>, broadcastListenerAttached: boolean, broadcastHandlerAttached: boolean, profileSyncPromise: Promise<UserProfile | null> | null, tenantId: string }} */
  var runtime = {
    options: null,
    userProfile: null,
    authState: "unknown",
    isRefreshing: false,
    pendingRequests: [],
    broadcastChannel: null,
    broadcastListeners: [],
    broadcastListenerAttached: false,
    broadcastHandlerAttached: false,
    profileSyncPromise: null,
    tenantId: "",
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

  /**
   * @param {PasswordCredentialExchange} input
   * @returns {{ email: string, password: string }}
   */
  function normalizePasswordCredentialInput(input) {
    if (!input || typeof input !== "object") {
      throw new Error("tauth.missing_password_credentials");
    }
    var email = requireNonEmptyString(input.email, "tauth.missing_email");
    if (typeof input.password !== "string" || input.password === "") {
      throw new Error("tauth.missing_password");
    }
    return { email: email, password: input.password };
  }

  /**
   * @param {PasswordSignupRequest} input
   * @returns {{ email: string, password: string, displayName: string, avatarUrl: string }}
   */
  function normalizePasswordSignupInput(input) {
    if (!input || typeof input !== "object") {
      throw new Error("tauth.missing_password_credentials");
    }
    var email = requireNonEmptyString(input.email, "tauth.missing_email");
    if (typeof input.password !== "string" || input.password === "") {
      throw new Error("tauth.missing_password");
    }
    return {
      email: email,
      password: input.password,
      displayName:
        typeof input.displayName === "string" ? input.displayName.trim() : "",
      avatarUrl:
        typeof input.avatarUrl === "string" ? input.avatarUrl.trim() : "",
    };
  }

  /**
   * @param {ChallengeTokenExchange} input
   * @returns {{ token: string }}
   */
  function normalizeChallengeTokenInput(input) {
    if (!input || typeof input !== "object") {
      throw new Error("tauth.missing_challenge_token");
    }
    return {
      token: requireNonEmptyString(input.token, "tauth.missing_challenge_token"),
    };
  }

  /**
   * @param {PasswordResetStartRequest} input
   * @returns {{ email: string }}
   */
  function normalizePasswordResetStartInput(input) {
    if (!input || typeof input !== "object") {
      throw new Error("tauth.missing_email");
    }
    return {
      email: requireNonEmptyString(input.email, "tauth.missing_email"),
    };
  }

  /**
   * @param {PasswordResetCompleteRequest} input
   * @returns {{ token: string, password: string }}
   */
  function normalizePasswordResetCompleteInput(input) {
    var challenge = normalizeChallengeTokenInput(input);
    if (typeof input.password !== "string" || input.password === "") {
      throw new Error("tauth.missing_password");
    }
    return { token: challenge.token, password: input.password };
  }

  /**
   * @param {PasswordChangeRequest} input
   * @returns {{ currentPassword: string, newPassword: string }}
   */
  function normalizePasswordChangeInput(input) {
    if (!input || typeof input !== "object") {
      throw new Error("tauth.missing_password_credentials");
    }
    if (
      typeof input.currentPassword !== "string" ||
      input.currentPassword === ""
    ) {
      throw new Error("tauth.missing_current_password");
    }
    if (typeof input.newPassword !== "string" || input.newPassword === "") {
      throw new Error("tauth.missing_new_password");
    }
    return {
      currentPassword: input.currentPassword,
      newPassword: input.newPassword,
    };
  }

  /**
   * @param {AccountIdentityUnlinkRequest} input
   * @returns {{ provider: string, providerId: string }}
   */
  function normalizeAccountUnlinkInput(input) {
    if (!input || typeof input !== "object") {
      throw new Error("tauth.missing_account_identity");
    }
    return {
      provider: requireNonEmptyString(input.provider, "tauth.missing_provider"),
      providerId: requireNonEmptyString(
        input.providerId,
        "tauth.missing_provider_id",
      ),
    };
  }

  var tenantHeaderName = "X-TAuth-Tenant";
  var broadcastChannelName = "auth";
  var broadcastEventRefreshed = "refreshed";
  var broadcastEventLoggedOut = "logged_out";
  var broadcastWaitTimeoutMs = 360;
  var bootstrapModeRestoreIfHinted = "restore-if-hinted";
  var bootstrapModeEager = "eager";
  var bootstrapModePassive = "passive";
  var restoreHintPrefix = "tauth.restore.v1:";

  function storageObject() {
    try {
      if (typeof window !== "undefined" && window.localStorage) {
        return window.localStorage;
      }
      if (typeof localStorage !== "undefined") {
        return localStorage;
      }
    } catch (error) {
      return null;
    }
    return null;
  }

  /**
   * @param {AuthClientOptions} options
   * @returns {string}
   */
  function restoreHintKey(options) {
    return (
      restoreHintPrefix +
      encodeURIComponent(options.baseUrl) +
      ":" +
      encodeURIComponent(options.tenantId || "")
    );
  }

  /**
   * @param {AuthClientOptions=} selectedOptions
   * @returns {boolean}
   */
  function hasRestoreHint(selectedOptions) {
    var options = selectedOptions || runtime.options;
    var storage = storageObject();
    if (!options || !storage) {
      return false;
    }
    try {
      return storage.getItem(restoreHintKey(options)) !== null;
    } catch (error) {
      return false;
    }
  }

  function rememberRestoreHint() {
    var storage = storageObject();
    if (!runtime.options || !storage) {
      return;
    }
    try {
      storage.setItem(restoreHintKey(runtime.options), "1");
    } catch (error) {
      void error;
    }
  }

  /**
   * @param {AuthClientOptions=} selectedOptions
   */
  function clearRestoreHint(selectedOptions) {
    var options = selectedOptions || runtime.options;
    var storage = storageObject();
    if (!options || !storage) {
      return;
    }
    try {
      storage.removeItem(restoreHintKey(options));
    } catch (error) {
      void error;
    }
  }

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

  function setAuthState(authState) {
    runtime.authState = authState;
  }

  function applyAuthenticatedProfile(profile) {
    setUserProfile(profile);
    setAuthState("authenticated");
    rememberRestoreHint();
    if (
      runtime.options &&
      typeof runtime.options.onAuthenticated === "function"
    ) {
      runtime.options.onAuthenticated(profile);
    }
  }

  function applyUnauthenticated() {
    setUserProfile(null);
    setAuthState("anonymous");
    clearRestoreHint();
    notifyUnauthenticated();
  }

  function applyPassiveUnauthenticated() {
    setUserProfile(null);
    setAuthState("anonymous");
    notifyUnauthenticated();
  }

  function notifyUnauthenticated() {
    if (
      runtime.options &&
      typeof runtime.options.onUnauthenticated === "function"
    ) {
      runtime.options.onUnauthenticated();
    }
  }

  /**
   * @param {AuthClientError} error
   */
  function applyAuthError(error) {
    setUserProfile(null);
    setAuthState("error");
    if (runtime.options && typeof runtime.options.onAuthError === "function") {
      runtime.options.onAuthError(error);
    }
  }

  /**
   * @returns {UserProfile | null}
   */
  function getCurrentUser() {
    return runtime.userProfile;
  }

  function getAuthState() {
    return runtime.authState;
  }

  /**
   * @returns {AuthEndpointMap}
   */
  function getAuthEndpoints() {
    var options = requireOptions();
    return {
      baseUrl: options.baseUrl,
      meUrl: joinUrl(options.baseUrl, options.meEndpoint),
      sessionUrl: joinUrl(options.baseUrl, options.sessionEndpoint),
      nonceUrl: joinUrl(options.baseUrl, options.nonceEndpoint),
      googleUrl: joinUrl(options.baseUrl, options.googleEndpoint),
      passwordUrl: joinUrl(options.baseUrl, options.passwordEndpoint),
      passwordSignupUrl: joinUrl(options.baseUrl, options.passwordSignupEndpoint),
      passwordVerifyEmailUrl: joinUrl(
        options.baseUrl,
        options.passwordVerifyEmailEndpoint,
      ),
      passwordResetStartUrl: joinUrl(
        options.baseUrl,
        options.passwordResetStartEndpoint,
      ),
      passwordResetCompleteUrl: joinUrl(
        options.baseUrl,
        options.passwordResetCompleteEndpoint,
      ),
      passwordChangeUrl: joinUrl(options.baseUrl, options.passwordChangeEndpoint),
      passwordLinkStartUrl: joinUrl(
        options.baseUrl,
        options.passwordLinkStartEndpoint,
      ),
      passwordLinkVerifyUrl: joinUrl(
        options.baseUrl,
        options.passwordLinkVerifyEndpoint,
      ),
      googleLinkUrl: joinUrl(options.baseUrl, options.googleLinkEndpoint),
      accountUnlinkUrl: joinUrl(options.baseUrl, options.accountUnlinkEndpoint),
      accountDisableUrl: joinUrl(options.baseUrl, options.accountDisableEndpoint),
      refreshUrl: joinUrl(options.baseUrl, options.refreshEndpoint),
      logoutUrl: joinUrl(options.baseUrl, options.logoutEndpoint),
    };
  }

  /**
   * @param {Response} response
   * @param {string} failureCode
   * @returns {Promise<unknown>}
   */
  async function readJsonOrThrow(response, failureCode) {
    try {
      return await response.json();
    } catch (error) {
      throw new Error(failureCode);
    }
  }

  /**
   * @param {string} requestUrl
   * @param {Record<string, unknown>} body
   * @param {string} failureCode
   * @param {string} invalidCode
   * @returns {Promise<Record<string, unknown>>}
   */
  async function postJson(requestUrl, body, failureCode, invalidCode) {
    var response = await fetch(requestUrl, {
      method: "POST",
      credentials: "include",
      headers: withTenantHeader({
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
      }),
      body: JSON.stringify(body),
    });
    var payload = await readJsonOrThrow(response, failureCode);
    if (!response.ok) {
      var errorPayload =
        payload && typeof payload === "object"
          ? /** @type {Record<string, unknown>} */ (payload)
          : null;
      var errorCode =
        errorPayload && typeof errorPayload["error"] === "string"
          ? errorPayload["error"]
          : failureCode;
      throw new Error(errorCode);
    }
    if (!payload || typeof payload !== "object") {
      throw new Error(invalidCode);
    }
    return /** @type {Record<string, unknown>} */ (payload);
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

  /**
   * @param {PasswordCredentialExchange} input
   * @returns {Promise<UserProfile>}
   */
  async function exchangePasswordCredential(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizePasswordCredentialInput(input);
    var response = await fetch(endpoints.passwordUrl, {
      method: "POST",
      credentials: "include",
      headers: withTenantHeader({
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
      }),
      body: JSON.stringify({
        email: normalized.email,
        password: normalized.password,
      }),
    });
    var payload;
    try {
      payload = await response.json();
    } catch (error) {
      throw new Error("tauth.password_exchange_failed");
    }
    if (!response.ok) {
      var errorCode =
        payload && typeof payload.error === "string"
          ? payload.error
          : "tauth.password_exchange_failed";
      throw new Error(errorCode);
    }
    if (!payload || typeof payload !== "object") {
      throw new Error("tauth.password_exchange_invalid");
    }
    applyAuthenticatedProfile(payload);
    return payload;
  }

  /**
   * @param {PasswordSignupRequest} input
   * @returns {Promise<AccountChallengePayload>}
   */
  async function signupPasswordCredential(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizePasswordSignupInput(input);
    return postJson(
      endpoints.passwordSignupUrl,
      {
        email: normalized.email,
        password: normalized.password,
        display_name: normalized.displayName,
        avatar_url: normalized.avatarUrl,
      },
      "tauth.password_signup_failed",
      "tauth.password_signup_invalid",
    );
  }

  /**
   * @param {ChallengeTokenExchange} input
   * @returns {Promise<UserProfile>}
   */
  async function verifyPasswordEmail(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizeChallengeTokenInput(input);
    var payload = await postJson(
      endpoints.passwordVerifyEmailUrl,
      { token: normalized.token },
      "tauth.password_verify_failed",
      "tauth.password_verify_invalid",
    );
    applyAuthenticatedProfile(payload);
    return payload;
  }

  /**
   * @param {PasswordResetStartRequest} input
   * @returns {Promise<AccountChallengePayload>}
   */
  async function startPasswordReset(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizePasswordResetStartInput(input);
    return postJson(
      endpoints.passwordResetStartUrl,
      { email: normalized.email },
      "tauth.password_reset_start_failed",
      "tauth.password_reset_start_invalid",
    );
  }

  /**
   * @param {PasswordResetCompleteRequest} input
   * @returns {Promise<UserProfile>}
   */
  async function completePasswordReset(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizePasswordResetCompleteInput(input);
    var payload = await postJson(
      endpoints.passwordResetCompleteUrl,
      { token: normalized.token, password: normalized.password },
      "tauth.password_reset_complete_failed",
      "tauth.password_reset_complete_invalid",
    );
    applyAuthenticatedProfile(payload);
    return payload;
  }

  /**
   * @param {PasswordChangeRequest} input
   * @returns {Promise<UserProfile>}
   */
  async function changePassword(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizePasswordChangeInput(input);
    var payload = await postJson(
      endpoints.passwordChangeUrl,
      {
        current_password: normalized.currentPassword,
        new_password: normalized.newPassword,
      },
      "tauth.password_change_failed",
      "tauth.password_change_invalid",
    );
    applyAuthenticatedProfile(payload);
    return payload;
  }

  /**
   * @param {PasswordSignupRequest} input
   * @returns {Promise<AccountChallengePayload>}
   */
  async function startPasswordLink(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizePasswordSignupInput(input);
    return postJson(
      endpoints.passwordLinkStartUrl,
      {
        email: normalized.email,
        password: normalized.password,
        display_name: normalized.displayName,
        avatar_url: normalized.avatarUrl,
      },
      "tauth.password_link_start_failed",
      "tauth.password_link_start_invalid",
    );
  }

  /**
   * @param {ChallengeTokenExchange} input
   * @returns {Promise<UserProfile>}
   */
  async function verifyPasswordLink(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizeChallengeTokenInput(input);
    var payload = await postJson(
      endpoints.passwordLinkVerifyUrl,
      { token: normalized.token },
      "tauth.password_link_verify_failed",
      "tauth.password_link_verify_invalid",
    );
    applyAuthenticatedProfile(payload);
    return payload;
  }

  /**
   * @param {GoogleCredentialExchange} input
   * @returns {Promise<UserProfile>}
   */
  async function linkGoogleCredential(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizeGoogleCredentialInput(input);
    var payload = await postJson(
      endpoints.googleLinkUrl,
      {
        google_id_token: normalized.credential,
        nonce_token: normalized.nonceToken,
      },
      "tauth.google_link_failed",
      "tauth.google_link_invalid",
    );
    applyAuthenticatedProfile(payload);
    return payload;
  }

  /**
   * @param {AccountIdentityUnlinkRequest} input
   * @returns {Promise<UserProfile>}
   */
  async function unlinkAccountIdentity(input) {
    var endpoints = getAuthEndpoints();
    var normalized = normalizeAccountUnlinkInput(input);
    var payload = await postJson(
      endpoints.accountUnlinkUrl,
      {
        provider: normalized.provider,
        provider_id: normalized.providerId,
      },
      "tauth.account_unlink_failed",
      "tauth.account_unlink_invalid",
    );
    applyAuthenticatedProfile(payload);
    return payload;
  }

  /**
   * @returns {Promise<void>}
   */
  async function disableAccount() {
    var endpoints = getAuthEndpoints();
    var response = await fetch(endpoints.accountDisableUrl, {
      method: "POST",
      credentials: "include",
      headers: withTenantHeader({ "X-Requested-With": "XMLHttpRequest" }),
    });
    if (!response.ok && response.status !== 204) {
      var payload = await readJsonOrThrow(
        response,
        "tauth.account_disable_failed",
      );
      var errorPayload =
        payload && typeof payload === "object"
          ? /** @type {Record<string, unknown>} */ (payload)
          : null;
      var errorCode =
        errorPayload && typeof errorPayload["error"] === "string"
          ? errorPayload["error"]
          : "tauth.account_disable_failed";
      throw new Error(errorCode);
    }
    applyUnauthenticated();
    broadcast(broadcastEventLoggedOut);
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
    options.bootstrapMode = normalizeBootstrapMode(options.bootstrapMode);
    return options;
  }

  /**
   * @param {string} rawMode
   * @returns {string}
   */
  function normalizeBootstrapMode(rawMode) {
    var mode = typeof rawMode === "string" ? rawMode.trim() : "";
    if (!mode) {
      return bootstrapModeRestoreIfHinted;
    }
    if (
      mode === bootstrapModeRestoreIfHinted ||
      mode === bootstrapModeEager ||
      mode === bootstrapModePassive
    ) {
      return mode;
    }
    throw new Error("tauth.invalid_bootstrap_mode");
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

  function withTenantHeader(headers) {
    var combined = Object.assign({}, headers || {});
    var tenantValue = currentTenantId();
    if (tenantValue) {
      combined[tenantHeaderName] = tenantValue;
    }
    return combined;
  }

  /**
   * @param {string} code
   * @param {number=} status
   * @returns {AuthClientError}
   */
  function createAuthClientError(code, status) {
    var error = /** @type {AuthClientError} */ (new Error(code));
    if (typeof status === "number") {
      error.status = status;
    }
    return error;
  }

  async function readCurrentProfile() {
    var options = requireOptions();
    try {
      var response = await fetch(
        joinUrl(options.baseUrl, options.sessionEndpoint),
        {
          method: "GET",
          credentials: "include",
          headers: withTenantHeader(),
        },
      );
      if (response.status === 204 || response.status === 401) {
        clearRestoreHint(options);
        return { outcome: "unauthenticated", profile: null };
      }
      if (response.ok) {
        return { outcome: "authenticated", profile: await response.json() };
      }
      return {
        outcome: "error",
        profile: null,
        error: createAuthClientError("tauth.profile_error", response.status),
      };
    } catch (error) {
      return {
        outcome: "error",
        profile: null,
        error: createAuthClientError("tauth.profile_network_error"),
      };
    }
  }

  function syncProfileFromServer() {
    if (runtime.profileSyncPromise) {
      return runtime.profileSyncPromise;
    }
    runtime.profileSyncPromise = (async function syncProfile() {
      var result = await readCurrentProfile();
      if (result.outcome === "authenticated") {
        applyAuthenticatedProfile(result.profile);
        return result.profile;
      }
      if (result.outcome === "error") {
        applyAuthError(result.error);
      }
      return null;
    })();
    return runtime.profileSyncPromise.finally(function () {
      runtime.profileSyncPromise = null;
    });
  }

  async function refreshSession() {
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
        rememberRestoreHint();
        broadcast(broadcastEventRefreshed);
        return { outcome: "refreshed", error: null };
      }
      if (refreshResponse.status === 401) {
        return { outcome: "unauthenticated", error: null };
      }
      return {
        outcome: "error",
        error: createAuthClientError("tauth.refresh_error", refreshResponse.status),
      };
    } catch (error) {
      return {
        outcome: "error",
        error: createAuthClientError("tauth.refresh_network_error"),
      };
    }
  }

  /**
   * @returns {Promise<{ received: boolean, profile: UserProfile | null }>}
   */
  async function waitForPeerRefresh() {
    var received = await waitForBroadcast(
      broadcastEventRefreshed,
      broadcastWaitTimeoutMs,
    );
    if (!received) {
      return { received: false, profile: null };
    }
    var profile = await syncProfileFromServer();
    return { received: true, profile: profile };
  }

  /**
   * @param {AuthClientInitOptions} passed
   * @returns {Promise<void>}
   */
  async function initAuthClient(passed) {
    runtime.options = normalizeOptions(passed);
    ensureBroadcastListener();
    try {
      if (runtime.options.bootstrapMode === bootstrapModePassive) {
        applyPassiveUnauthenticated();
        return;
      }
      if (
        runtime.options.bootstrapMode === bootstrapModeRestoreIfHinted &&
        !hasRestoreHint(runtime.options)
      ) {
        applyUnauthenticated();
        return;
      }
      setAuthState("restoring");
      var profileResult = await readCurrentProfile();
      if (profileResult.outcome === "authenticated") {
        applyAuthenticatedProfile(profileResult.profile);
        broadcast(broadcastEventRefreshed);
        return;
      }
      if (profileResult.outcome === "error") {
        applyAuthError(profileResult.error);
        return;
      }
      var peerResult = await waitForPeerRefresh();
      if (peerResult.profile) {
        return;
      }
      if (runtime.authState === "error") {
        return;
      }
      applyUnauthenticated();
    } catch (initializationError) {
      applyAuthError(createAuthClientError("tauth.bootstrap_failed"));
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
    merged.headers = Object.assign({}, merged.headers || {});
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
      var refreshResult = await refreshSession();
      if (refreshResult.outcome === "refreshed") {
        var retryResponse = await execute();
        flushPendingRequests(null);
        return retryResponse;
      }
      var peerResult = await waitForPeerRefresh();
      if (peerResult.received) {
        var recoveredResponse = await execute();
        flushPendingRequests(null);
        return recoveredResponse;
      }
      if (refreshResult.outcome === "error") {
        applyAuthError(refreshResult.error);
      } else {
        applyUnauthenticated();
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
    } catch (ignore) {
      void ignore;
    }
    applyUnauthenticated();
    broadcast(broadcastEventLoggedOut);
  }

  if (typeof window !== "undefined") {
    window["initAuthClient"] = initAuthClient;
    window["apiFetch"] = apiFetch;
    window["getCurrentUser"] = getCurrentUser;
    window["getAuthState"] = getAuthState;
    window["getAuthEndpoints"] = getAuthEndpoints;
    window["requestNonce"] = requestNonce;
    window["exchangeGoogleCredential"] = exchangeGoogleCredential;
    window["exchangePasswordCredential"] = exchangePasswordCredential;
    window["signupPasswordCredential"] = signupPasswordCredential;
    window["verifyPasswordEmail"] = verifyPasswordEmail;
    window["startPasswordReset"] = startPasswordReset;
    window["completePasswordReset"] = completePasswordReset;
    window["changePassword"] = changePassword;
    window["startPasswordLink"] = startPasswordLink;
    window["verifyPasswordLink"] = verifyPasswordLink;
    window["linkGoogleCredential"] = linkGoogleCredential;
    window["unlinkAccountIdentity"] = unlinkAccountIdentity;
    window["disableAccount"] = disableAccount;
    window["logout"] = logout;
    window["setAuthTenantId"] = setTenantId;
  }
})();
