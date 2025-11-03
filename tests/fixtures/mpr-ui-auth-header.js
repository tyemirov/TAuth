(() => {
  "use strict";

  const AUTH_EVENTS = Object.freeze({
    AUTHENTICATED: "mpr-ui:auth:authenticated",
    UNAUTHENTICATED: "mpr-ui:auth:unauthenticated",
    ERROR: "mpr-ui:auth:error",
  });

  const DATA_ATTRIBUTE_MAP = Object.freeze({
    user_id: "data-user-id",
    user_email: "data-user-email",
    display: "data-user-display",
    avatar_url: "data-user-avatar-url",
  });

  function setDataAttributes(rootElement, profile) {
    Object.entries(DATA_ATTRIBUTE_MAP).forEach(([key, attribute]) => {
      const value = profile && profile[key] !== undefined ? profile[key] : null;
      if (value === null || value === undefined || value === "") {
        rootElement.removeAttribute(attribute);
        return;
      }
      rootElement.setAttribute(attribute, String(value));
    });
  }

  function dispatch(rootElement, type, detail) {
    const event = new window.CustomEvent(type, {
      bubbles: true,
      detail,
    });
    rootElement.dispatchEvent(event);
  }

  function createController(rootElement, config) {
    const options = {
      baseUrl: "",
      ...config,
    };

    const state = {
      status: "unauthenticated",
      profile: null,
    };

    setDataAttributes(rootElement, null);

    const setUnauthenticated = ({ emitEvent = true } = {}) => {
      state.status = "unauthenticated";
      state.profile = null;
      setDataAttributes(rootElement, null);
      if (emitEvent) {
        dispatch(rootElement, AUTH_EVENTS.UNAUTHENTICATED, null);
      }
    };

    const setAuthenticated = (profile, { emitEvent = true } = {}) => {
      state.status = "authenticated";
      state.profile = profile || null;
      setDataAttributes(rootElement, profile || null);
      if (emitEvent) {
        dispatch(rootElement, AUTH_EVENTS.AUTHENTICATED, profile || null);
      }
    };

    const emitError = (detail) => {
      dispatch(rootElement, AUTH_EVENTS.ERROR, detail);
    };

    const invokeInitAuthClient = ({
      authenticatedEvent = true,
      unauthenticatedEvent = true,
    } = {}) => {
      if (typeof window.initAuthClient !== "function") {
        return;
      }
      try {
        const result = window.initAuthClient({
          onAuthenticated: (profile) => {
            setAuthenticated(profile, { emitEvent: authenticatedEvent });
          },
          onUnauthenticated: () => {
            setUnauthenticated({ emitEvent: unauthenticatedEvent });
          },
          onError: (error) => {
            emitError(error);
          },
        });
        if (result && typeof result.catch === "function") {
          result.catch((error) => {
            emitError({
              code: "mpr-ui.auth.init_failed",
              cause: error,
            });
          });
        }
      } catch (error) {
        emitError({
          code: "mpr-ui.auth.init_failed",
          cause: error,
        });
      }
    };

    setUnauthenticated({ emitEvent: false });
    invokeInitAuthClient();

    const ensureFetch = () => {
      if (typeof window.fetch !== "function") {
        throw new Error("fetch is required to use the mpr-ui auth header");
      }
      return window.fetch.bind(window);
    };

    const handleCredential = async (payload = {}) => {
      const credential = payload && payload.credential;
      if (!credential) {
        emitError({ code: "mpr-ui.auth.missing_credential" });
        return;
      }

      const fetchFn = ensureFetch();
      let response;
      try {
        response = await fetchFn(`${options.baseUrl}/auth/google`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            google_id_token: credential,
          }),
        });
      } catch (error) {
        emitError({
          code: "mpr-ui.auth.exchange_failed",
          cause: error,
        });
        return;
      }

      let body = {};
      try {
        body = await response.json();
      } catch (error) {
        body = {};
      }

      if (!response.ok) {
        emitError({
          code: "mpr-ui.auth.exchange_failed",
          detail: body,
        });
        return;
      }

      setAuthenticated(body);
      invokeInitAuthClient({ authenticatedEvent: false });
      return body;
    };

    const signOut = async () => {
      const fetchFn = ensureFetch();
      try {
        await fetchFn(`${options.baseUrl}/auth/logout`, {
          method: "POST",
        });
      } catch (error) {
        emitError({
          code: "mpr-ui.auth.logout_failed",
          cause: error,
        });
        return;
      }
      setUnauthenticated();
      invokeInitAuthClient({
        authenticatedEvent: false,
        unauthenticatedEvent: false,
      });
    };

    return {
      state,
      handleCredential,
      signOut,
    };
  }

  if (!window.MPRUI) {
    window.MPRUI = {};
  }

  window.MPRUI.createAuthHeader = function createAuthHeader(rootElement, config = {}) {
    if (!rootElement) {
      throw new Error("rootElement is required to create an auth header");
    }
    return createController(rootElement, config);
  };
})();
