/* @mprlab/mpr-ui */
(function (global) {
  "use strict";

  var DEFAULT_OPTIONS = {
    baseUrl: "",
    loginPath: "/auth/google",
    logoutPath: "/auth/logout",
    siteName: "",
    siteLink: "",
  };

  var ATTRIBUTE_MAP = {
    user_id: "data-user-id",
    user_email: "data-user-email",
    display: "data-user-display",
    avatar_url: "data-user-avatar-url",
  };

  function ensureNamespace(target) {
    if (!target.MPRUI) {
      target.MPRUI = {};
    }
    return target.MPRUI;
  }

  function joinUrl(baseUrl, path) {
    if (!baseUrl) {
      return path;
    }
    if (!path) {
      return baseUrl;
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
    return value === undefined || value === null ? null : String(value);
  }

  function setAttributeOrRemove(element, name, value) {
    var normalized = toStringOrNull(value);
    if (normalized === null) {
      element.removeAttribute(name);
      return;
    }
    element.setAttribute(name, normalized);
  }

  function createCustomEvent(globalObject, type, detail) {
    var EventCtor = globalObject.CustomEvent;
    if (typeof EventCtor === "function") {
      return new EventCtor(type, { detail: detail, bubbles: true });
    }
    if (
      globalObject.document &&
      typeof globalObject.document.createEvent === "function"
    ) {
      var legacyEvent = globalObject.document.createEvent("CustomEvent");
      legacyEvent.initCustomEvent(type, true, false, detail);
      return legacyEvent;
    }
    return { type: type, detail: detail, bubbles: true };
  }

  function dispatchEvent(element, type, detail) {
    if (!element || typeof element.dispatchEvent !== "function") {
      return;
    }
    var event = createCustomEvent(global, type, detail || {});
    try {
      element.dispatchEvent(event);
    } catch (_error) {}
  }

  function promptGoogleIfAvailable(globalObject) {
    var google = globalObject.google;
    if (
      google &&
      google.accounts &&
      google.accounts.id &&
      typeof google.accounts.id.prompt === "function"
    ) {
      try {
        google.accounts.id.prompt();
      } catch (_ignore) {}
    }
  }

  function createAuthHeader(rootElement, rawOptions) {
    if (!rootElement || typeof rootElement.dispatchEvent !== "function") {
      throw new Error("MPRUI.createAuthHeader requires a DOM element");
    }

    var options = Object.assign({}, DEFAULT_OPTIONS, rawOptions || {});
    var state = {
      status: "unauthenticated",
      profile: null,
      options: options,
    };
    var pendingProfile = null;
    var hasEmittedUnauthenticated = false;
    var lastAuthenticatedSignature = null;

    function updateDatasetFromProfile(profile) {
      Object.keys(ATTRIBUTE_MAP).forEach(function (key) {
        var attributeName = ATTRIBUTE_MAP[key];
        setAttributeOrRemove(
          rootElement,
          attributeName,
          profile ? profile[key] : null,
        );
      });
    }

    function markAuthenticated(profile) {
      var normalized = profile || null;
      var signature = JSON.stringify(normalized || {});
      var shouldEmit =
        state.status !== "authenticated" ||
        lastAuthenticatedSignature !== signature;
      state.status = "authenticated";
      state.profile = normalized;
      lastAuthenticatedSignature = signature;
      hasEmittedUnauthenticated = false;
      updateDatasetFromProfile(normalized);
      if (shouldEmit) {
        dispatchEvent(rootElement, "mpr-ui:auth:authenticated", {
          profile: normalized,
        });
      }
    }

    function markUnauthenticated(config) {
      var parameters = config || {};
      var emit = parameters.emit !== false;
      var prompt = parameters.prompt !== false;
      var shouldEmit =
        emit &&
        (state.status !== "unauthenticated" ||
          state.profile !== null ||
          !hasEmittedUnauthenticated);
      state.status = "unauthenticated";
      state.profile = null;
      lastAuthenticatedSignature = null;
      updateDatasetFromProfile(null);
      if (shouldEmit) {
        dispatchEvent(rootElement, "mpr-ui:auth:unauthenticated", {
          profile: null,
        });
        hasEmittedUnauthenticated = true;
      }
      if (prompt) {
        promptGoogleIfAvailable(global);
      }
    }

    function emitError(code, extra) {
      dispatchEvent(
        rootElement,
        "mpr-ui:auth:error",
        Object.assign({ code: code }, extra || {}),
      );
    }

    function bootstrapSession() {
      if (typeof global.initAuthClient !== "function") {
        markUnauthenticated({ emit: false, prompt: false });
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
            markUnauthenticated({ prompt: true });
          },
        }),
      ).catch(function (error) {
        emitError("mpr-ui.auth.bootstrap_failed", {
          message: error && error.message ? error.message : String(error),
        });
      });
    }

    function exchangeCredential(credential) {
      var payload = JSON.stringify({ google_id_token: credential });
      return global
        .fetch(joinUrl(options.baseUrl, options.loginPath), {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
          },
          body: payload,
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

    function performLogout() {
      return global
        .fetch(joinUrl(options.baseUrl, options.logoutPath), {
          method: "POST",
          credentials: "include",
          headers: { "X-Requested-With": "XMLHttpRequest" },
        })
        .catch(function () {
          return null;
        });
    }

    function handleCredential(credentialResponse) {
      if (!credentialResponse || !credentialResponse.credential) {
        emitError("mpr-ui.auth.missing_credential", {});
        markUnauthenticated({ prompt: true });
        return Promise.resolve();
      }
      return exchangeCredential(credentialResponse.credential)
        .then(function (profile) {
          if (typeof global.initAuthClient !== "function") {
            markAuthenticated(profile);
            return profile;
          }
          pendingProfile = profile || null;
          return bootstrapSession();
        })
        .catch(function (error) {
          emitError("mpr-ui.auth.exchange_failed", {
            message: error && error.message ? error.message : String(error),
            status: error && error.status ? error.status : null,
          });
          markUnauthenticated({ prompt: true });
          return Promise.resolve();
        });
    }

    function signOut() {
      return performLogout().then(function () {
        pendingProfile = null;
        if (typeof global.initAuthClient !== "function") {
          markUnauthenticated({ prompt: true });
          return null;
        }
        return bootstrapSession();
      });
    }

    markUnauthenticated({ emit: false, prompt: false });
    bootstrapSession();

    return {
      host: rootElement,
      state: state,
      handleCredential: handleCredential,
      signOut: signOut,
      restartSessionWatcher: bootstrapSession,
    };
  }

  function renderAuthHeader(target, options) {
    var host = target;
    if (typeof target === "string" && global.document) {
      host = global.document.querySelector(target);
    }
    if (!host) {
      throw new Error("renderAuthHeader requires a host element");
    }
    return createAuthHeader(host, options || {});
  }

  function escapeHtml(value) {
    if (value === null || value === undefined) {
      return "";
    }
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  var FOOTER_ROOT_CLASS = "mpr-footer";
  var FOOTER_STYLE_ID = "mpr-ui-footer-styles";
  var FOOTER_STYLE_MARKUP =
    "." +
    FOOTER_ROOT_CLASS +
    "{margin-top:48px;padding:32px 0;border-top:1px solid #e2e8f0;font-size:14px;line-height:1.6;color:#475569;background:#f8fafc}" +
    "." +
    FOOTER_ROOT_CLASS +
    "__container{max-width:960px;margin:0 auto;padding:0 20px;display:flex;flex-direction:column;gap:16px}" +
    "." +
    FOOTER_ROOT_CLASS +
    "__lines{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:6px}" +
    "." +
    FOOTER_ROOT_CLASS +
    "__links{display:flex;flex-wrap:wrap;gap:12px;align-items:center}" +
    "." +
    FOOTER_ROOT_CLASS +
    "__link{color:#1b6ef3;text-decoration:none;font-weight:500}" +
    "." +
    FOOTER_ROOT_CLASS +
    "__link:hover{text-decoration:underline}" +
    "." +
    FOOTER_ROOT_CLASS +
    "__copyright{margin:0;color:#64748b}";

  function normalizeFooterOptions(raw) {
    var source = raw || {};
    var lines = Array.isArray(source.lines)
      ? source.lines
          .map(function (line) {
            return typeof line === "string" ? line.trim() : "";
          })
          .filter(function (line) {
            return line.length > 0;
          })
      : [];
    var links = Array.isArray(source.links)
      ? source.links
          .map(function (link) {
            if (!link || typeof link !== "object") {
              return null;
            }
            var label =
              typeof link.label === "string" ? link.label.trim() : "";
            var href = typeof link.href === "string" ? link.href.trim() : "";
            if (!label || !href) {
              return null;
            }
            return { label: label, href: href };
          })
          .filter(function (entry) {
            return entry !== null;
          })
      : [];
    var copyrightName =
      typeof source.copyrightName === "string"
        ? source.copyrightName.trim()
        : "";
    var year =
      typeof source.year === "number" && isFinite(source.year)
        ? Math.floor(source.year)
        : new Date().getFullYear();
    return {
      lines: lines,
      links: links,
      copyrightName: copyrightName,
      year: year,
    };
  }

  function ensureFooterStyles(documentObject) {
    if (!documentObject || typeof documentObject.createElement !== "function") {
      return;
    }
    if (
      documentObject.getElementById &&
      documentObject.getElementById(FOOTER_STYLE_ID)
    ) {
      return;
    }
    if (!documentObject.head || typeof documentObject.head.appendChild !== "function") {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = FOOTER_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = FOOTER_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(FOOTER_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildFooterMarkup(options) {
    var html = '<div class="' + FOOTER_ROOT_CLASS + '__container">';
    if (options.lines.length > 0) {
      html += '<ul class="' + FOOTER_ROOT_CLASS + '__lines">';
      for (var index = 0; index < options.lines.length; index += 1) {
        html +=
          '<li class="' +
          FOOTER_ROOT_CLASS +
          '__line">' +
          escapeHtml(options.lines[index]) +
          "</li>";
      }
      html += "</ul>";
    }
    if (options.links.length > 0) {
      html +=
        '<nav class="' +
        FOOTER_ROOT_CLASS +
        '__links" aria-label="Footer links">';
      for (var linkIndex = 0; linkIndex < options.links.length; linkIndex += 1) {
        var link = options.links[linkIndex];
        html +=
          '<a class="' +
          FOOTER_ROOT_CLASS +
          '__link" href="' +
          escapeHtml(link.href) +
          '">' +
          escapeHtml(link.label) +
          "</a>";
      }
      html += "</nav>";
    }
    html +=
      '<p class="' +
      FOOTER_ROOT_CLASS +
      '__copyright">&copy; ' +
      options.year +
      " " +
      escapeHtml(options.copyrightName || "") +
      "</p>";
    html += "</div>";
    return html;
  }

  function applyFooterClass(host) {
    if (!host) {
      return;
    }
    if (host.classList && typeof host.classList.add === "function") {
      host.classList.add(FOOTER_ROOT_CLASS);
      return;
    }
    if (typeof host.className === "string") {
      if (host.className.indexOf(FOOTER_ROOT_CLASS) === -1) {
        host.className = (host.className + " " + FOOTER_ROOT_CLASS).trim();
      }
      return;
    }
    host.className = FOOTER_ROOT_CLASS;
  }

  function resolveHost(target) {
    if (typeof target !== "string") {
      return target;
    }
    if (!global.document || typeof global.document.querySelector !== "function") {
      return null;
    }
    return global.document.querySelector(target);
  }

  function renderFooter(target, options) {
    var host = resolveHost(target);
    if (!host || typeof host !== "object") {
      throw new Error("renderFooter requires a host element");
    }
    var normalized = normalizeFooterOptions(options);
    ensureFooterStyles(global.document || (global.window && global.window.document));
    applyFooterClass(host);
    host.innerHTML = buildFooterMarkup(normalized);
    return {
      update: function (nextOptions) {
        normalized = normalizeFooterOptions(nextOptions);
        host.innerHTML = buildFooterMarkup(normalized);
      },
      destroy: function () {
        host.innerHTML = "";
      },
    };
  }

  function mprFooter(options) {
    var normalized = normalizeFooterOptions(options);
    return {
      init: function () {
        var element =
          (this && this.$el) ||
          (this && this.el) ||
          (this && this.element) ||
          (this && this.host) ||
          null;
        if (!element) {
          throw new Error("mprFooter requires a root element");
        }
        this.__mprFooterController = renderFooter(element, normalized);
      },
      update: function (nextOptions) {
        normalized = normalizeFooterOptions(
          arguments.length > 0 ? nextOptions : normalized,
        );
        if (
          this.__mprFooterController &&
          typeof this.__mprFooterController.update === "function"
        ) {
          this.__mprFooterController.update(normalized);
        }
      },
      destroy: function () {
        if (
          this.__mprFooterController &&
          typeof this.__mprFooterController.destroy === "function"
        ) {
          this.__mprFooterController.destroy();
          this.__mprFooterController = null;
        }
      },
    };
  }

  var namespace = ensureNamespace(global);
  namespace.createAuthHeader = createAuthHeader;
  namespace.renderAuthHeader = renderAuthHeader;
  namespace.renderFooter = renderFooter;
  namespace.mprFooter = mprFooter;
})(typeof window !== "undefined" ? window : globalThis);
