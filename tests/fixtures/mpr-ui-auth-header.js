(function (global) {
  "use strict";

  var namespace = ensureNamespace(global);
  var DEFAULT_OPTIONS = {
    baseUrl: "",
    loginPath: "/auth/google",
    logoutPath: "/auth/logout",
    siteName: "",
    siteLink: "",
  };

  function ensureNamespace(target) {
    if (!target.MPRUI) {
      target.MPRUI = {};
    }
    return target.MPRUI;
  }

  function joinUrl(base, path) {
    if (!base) {
      return path;
    }
    if (!path) {
      return base;
    }
    if (base.endsWith("/") && path.startsWith("/")) {
      return base + path.slice(1);
    }
    if (!base.endsWith("/") && !path.startsWith("/")) {
      return base + "/" + path;
    }
    return base + path;
  }

  function toStringOrNull(value) {
    return value == null ? null : String(value);
  }

  function setAttributeOrRemove(element, name, value) {
    var normalized = toStringOrNull(value);
    if (normalized === null) {
      element.removeAttribute(name);
      return;
    }
    element.setAttribute(name, normalized);
  }

  function dispatchEvent(element, type, detail) {
    if (!element || typeof element.dispatchEvent !== "function") {
      return;
    }
    var eventDetail = detail === undefined ? null : detail;
    try {
      var event = new global.CustomEvent(type, {
        detail: eventDetail,
        bubbles: true,
      });
      element.dispatchEvent(event);
    } catch (error) {
      // best-effort in non-DOM environments
    }
  }

  function promptGoogleSignIn(globalObject) {
    var google = globalObject.google;
    if (
      google &&
      google.accounts &&
      google.accounts.id &&
      typeof google.accounts.id.prompt === "function"
    ) {
      try {
        google.accounts.id.prompt();
      } catch (ignore) {
        // ignore prompt errors
      }
    }
  }

  function createAuthHeader(hostElement, rawOptions) {
    if (!hostElement) {
      throw new Error("hostElement is required for createAuthHeader");
    }

    var options = Object.assign({}, DEFAULT_OPTIONS, rawOptions || {});
    var state = {
      status: "initializing",
      profile: null,
      options: options,
    };

  function setAuthenticated(profile, options) {
    var emitEvent = !options || options.emit !== false;
    state.status = "authenticated";
    state.profile = profile || null;

    setAttributeOrRemove(hostElement, "data-user-id", profile && profile.user_id);
    setAttributeOrRemove(
      hostElement,
      "data-user-email",
      profile && profile.user_email,
    );
    setAttributeOrRemove(
      hostElement,
      "data-user-display",
      profile && (profile.display || profile.user_display),
    );
    setAttributeOrRemove(
      hostElement,
      "data-user-avatar-url",
      profile && (profile.avatar_url || profile.user_avatar_url),
    );

    if (emitEvent) {
      dispatchEvent(hostElement, "mpr-ui:auth:authenticated", {
        profile: profile || null,
      });
    }
  }

  function setUnauthenticated(options) {
    var emitEvent = !options || options.emit !== false;
    state.status = "unauthenticated";
    state.profile = null;

    hostElement.removeAttribute("data-user-id");
    hostElement.removeAttribute("data-user-email");
    hostElement.removeAttribute("data-user-display");
    hostElement.removeAttribute("data-user-avatar-url");

    if (emitEvent) {
      dispatchEvent(hostElement, "mpr-ui:auth:unauthenticated", {
        profile: null,
      });
    }
  }

    function dispatchError(code, extra) {
      dispatchEvent(hostElement, "mpr-ui:auth:error", {
        code: code,
        error: extra || null,
      });
    }

    function exchangeCredential(credential) {
      if (!global.fetch || typeof global.fetch !== "function") {
        throw new Error("fetch API is required to exchange credentials");
      }
      var requestBody = JSON.stringify({ google_id_token: credential });
      return global
        .fetch(joinUrl(options.baseUrl, options.loginPath), {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
          },
          body: requestBody,
        })
        .then(function (response) {
          if (!response || typeof response.json !== "function") {
            throw new Error("invalid response from credential exchange");
          }
          if (!response.ok) {
            var errorObject = new Error("credential exchange failed");
            errorObject.status = response.status;
            throw errorObject;
          }
          return response.json();
        });
    }

    function handleCredential(payload) {
      var hasSessionClient = typeof global.initAuthClient === "function";

      if (!payload || !payload.credential) {
        if (!hasSessionClient) {
          setUnauthenticated();
        }
        dispatchError("mpr-ui.auth.missing_credential", null);
        return Promise.resolve();
      }

      return exchangeCredential(payload.credential)
        .then(function (profile) {
          setAuthenticated(profile, { emit: !hasSessionClient });
          restartSessionWatcher();
        })
        .catch(function (error) {
          setUnauthenticated({ emit: !hasSessionClient });
          dispatchError("mpr-ui.auth.exchange_failed", {
            message: error && error.message ? error.message : String(error || ""),
            status: error && error.status ? error.status : null,
          });
        });
    }

    function signOut() {
      var logoutUrl = joinUrl(options.baseUrl, options.logoutPath);
      var performLogout = function () {
        if (!global.fetch || typeof global.fetch !== "function") {
          return Promise.reject(
            new Error("fetch API is required to perform logout"),
          );
        }
        return global.fetch(logoutUrl, {
          method: "POST",
          credentials: "include",
          headers: {
            "X-Requested-With": "XMLHttpRequest",
          },
        });
      };

      return performLogout()
        .catch(function () {
          // Ignore logout errors; still transition to unauthenticated state.
        })
        .then(function () {
          var hasSessionClient = typeof global.initAuthClient === "function";
          setUnauthenticated({ emit: hasSessionClient ? false : true });
          promptGoogleSignIn(global);
          restartSessionWatcher();
        });
    }

    function restartSessionWatcher() {
      var initAuth = global.initAuthClient;
      if (typeof initAuth !== "function") {
        setUnauthenticated();
        return;
      }
      try {
        var result = initAuth({
          onAuthenticated: function (profile) {
            setAuthenticated(profile);
          },
          onUnauthenticated: function () {
            setUnauthenticated();
            promptGoogleSignIn(global);
          },
        });
        if (result && typeof result.catch === "function") {
          result.catch(function (error) {
            dispatchError("mpr-ui.auth.session_init_failed", {
              message:
                error && error.message ? error.message : String(error || ""),
            });
          });
        }
      } catch (error) {
        dispatchError("mpr-ui.auth.session_init_failed", {
          message: error && error.message ? error.message : String(error || ""),
        });
      }
    }

    // Kick off initial session sync.
    restartSessionWatcher();

    return {
      host: hostElement,
      state: state,
      handleCredential: handleCredential,
      signOut: signOut,
      restartSessionWatcher: restartSessionWatcher,
    };
  }

  function renderAuthHeader(target, options) {
    var hostElement = target;
    if (typeof target === "string" && global.document) {
      hostElement = global.document.querySelector(target);
    }
    if (!hostElement) {
      throw new Error("renderAuthHeader requires a host element");
    }
    return createAuthHeader(hostElement, options || {});
  }

  namespace.createAuthHeader = createAuthHeader;
  namespace.renderAuthHeader = renderAuthHeader;
})(typeof window !== "undefined" ? window : global);
