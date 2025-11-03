/* @mprlab/mpr-ui */
(function (global) {
  "use strict";

  var DEFAULT_OPTIONS = {
    baseUrl: "",
    siteName: "",
    siteLink: "",
  };

  var ATTRIBUTE_MAP = {
    user_id: "data-user-id",
    user_email: "data-user-email",
    display: "data-user-display",
    avatar_url: "data-user-avatar-url",
  };

  function joinUrl(baseUrl, path) {
    if (!baseUrl) {
      return path;
    }
    if (baseUrl.endsWith("/") && path.startsWith("/")) {
      return baseUrl + path.slice(1);
    }
    if (!baseUrl.endsWith("/") && !path.startsWith("/")) {
      return baseUrl + "/" + path;
    }
    return baseUrl + path;
  }

  function toStringOrNull(value) {
    if (value === undefined || value === null) {
      return null;
    }
    return String(value);
  }

  function ensureMprUiRoot(globalObject) {
    if (!globalObject.MPRUI) {
      globalObject.MPRUI = {};
    }
    return globalObject.MPRUI;
  }

  function safeCustomEvent(globalObject, type, detail) {
    var EventCtor = globalObject.CustomEvent;
    if (typeof EventCtor === "function") {
      return new EventCtor(type, { detail: detail, bubbles: true });
    }
    var event = globalObject.document.createEvent("CustomEvent");
    event.initCustomEvent(type, true, false, detail);
    return event;
  }

  function createAuthHeader(rootElement, passedOptions) {
    if (!rootElement || typeof rootElement.dispatchEvent !== "function") {
      throw new Error("MPRUI.createAuthHeader requires a DOM element");
    }

    var options = Object.assign({}, DEFAULT_OPTIONS, passedOptions || {});
    var state = {
      status: "unauthenticated",
      profile: null,
    };
    var pendingProfile = null;
    var hasEmittedUnauthenticated = false;
    var lastAuthenticatedSignature = null;

    function dispatch(type, detail) {
      var event = safeCustomEvent(global, type, detail || {});
      rootElement.dispatchEvent(event);
    }

    function setAttribute(name, value) {
      if (value === null) {
        rootElement.removeAttribute(name);
      } else {
        rootElement.setAttribute(name, value);
      }
    }

    function updateDatasetFromProfile(profile) {
      Object.keys(ATTRIBUTE_MAP).forEach(function (key) {
        var attributeName = ATTRIBUTE_MAP[key];
        setAttribute(attributeName, toStringOrNull(profile ? profile[key] : null));
      });
    }

    function markAuthenticated(profile) {
      var signature = JSON.stringify(profile || {});
      if (state.status === "authenticated" && signature === lastAuthenticatedSignature) {
        state.profile = profile || null;
        return;
      }
      state.status = "authenticated";
      state.profile = profile || null;
      lastAuthenticatedSignature = signature;
      updateDatasetFromProfile(profile || {});
      dispatch("mpr-ui:auth:authenticated", { profile: state.profile });
    }

    function promptGoogleIfAvailable() {
      if (
        global.google &&
        global.google.accounts &&
        global.google.accounts.id &&
        typeof global.google.accounts.id.prompt === "function"
      ) {
        try {
          global.google.accounts.id.prompt();
        } catch (_ignore) {}
      }
    }

    function markUnauthenticated() {
      var shouldEmit =
        state.status !== "unauthenticated" ||
        state.profile !== null ||
        !hasEmittedUnauthenticated;
      state.status = "unauthenticated";
      state.profile = null;
      lastAuthenticatedSignature = null;
      updateDatasetFromProfile(null);
      if (shouldEmit) {
        dispatch("mpr-ui:auth:unauthenticated", {});
        hasEmittedUnauthenticated = true;
      }
      promptGoogleIfAvailable();
    }

    function emitError(code, extra) {
      var detail = Object.assign({ code: code }, extra || {});
      dispatch("mpr-ui:auth:error", detail);
    }

    function bootstrapSession() {
      if (typeof global.initAuthClient !== "function") {
        return Promise.resolve();
      }
      return Promise.resolve(
        global.initAuthClient({
          baseUrl: options.baseUrl,
          onAuthenticated: function (profile) {
            var resolvedProfile = pendingProfile || profile || null;
            pendingProfile = null;
            markAuthenticated(resolvedProfile);
          },
          onUnauthenticated: function () {
            pendingProfile = null;
            markUnauthenticated();
          },
        }),
      ).catch(function (error) {
        emitError("mpr-ui.auth.bootstrap_failed", {
          message: error && error.message ? error.message : String(error),
        });
      });
    }

    function exchangeCredential(credential) {
      var payload = { google_id_token: credential };
      return global
        .fetch(joinUrl(options.baseUrl, "/auth/google"), {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        })
        .then(function (response) {
          if (!response || !response.ok) {
            throw new Error("google_exchange_failed");
          }
          return response.json();
        });
    }

    function performLogout() {
      return global
        .fetch(joinUrl(options.baseUrl, "/auth/logout"), {
          method: "POST",
          credentials: "include",
          headers: { "X-Requested-With": "XMLHttpRequest" },
        })
        .catch(function () {
          return null;
        });
    }

    var controller = {
      state: state,
      handleCredential: function (credentialResponse) {
        if (!credentialResponse || !credentialResponse.credential) {
          emitError("mpr-ui.auth.missing_credential", {});
          return Promise.resolve();
        }
        return exchangeCredential(credentialResponse.credential)
          .then(function (profile) {
            if (typeof global.initAuthClient !== "function") {
              markAuthenticated(profile);
              return;
            }
            pendingProfile = profile || null;
            return bootstrapSession();
          })
          .catch(function (error) {
            emitError("mpr-ui.auth.exchange_failed", {
              message: error && error.message ? error.message : String(error),
            });
            markUnauthenticated();
            throw error;
          });
      },
      signOut: function () {
        return performLogout().then(function () {
          if (typeof global.initAuthClient !== "function") {
            markUnauthenticated();
            return;
          }
          pendingProfile = null;
          return bootstrapSession();
        });
      },
    };

    bootstrapSession();

    return controller;
  }

  var root = ensureMprUiRoot(global);
  root.createAuthHeader = createAuthHeader;
})(typeof window !== "undefined" ? window : globalThis);
