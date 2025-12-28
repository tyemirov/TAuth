// @ts-check
'use strict';

const AUTHENTICATED_EVENT = 'tauth:auth:authenticated';
const UNAUTHENTICATED_EVENT = 'tauth:auth:unauthenticated';
const ERROR_EVENT = 'tauth:auth:error';
const AUTH_STATE_ATTRIBUTE = 'data-auth-state';
const AUTH_STATE_AUTHENTICATED = 'authenticated';
const AUTH_STATE_UNAUTHENTICATED = 'unauthenticated';
const AUTH_STATE_LOADING = 'loading';
const SIGNIN_CONTAINER_ID = 'google-signin-container';
const SIGNOUT_BUTTON_ID = 'signout-button';
const ERROR_MESSAGE_PREFIX = 'tauth-demo.auth_error';
const AUTH_CLIENT_READY_HANDLE = '__TAUTH_AUTH_CLIENT_READY__';

/**
 * @typedef {object} DemoConfig
 * @property {string} baseUrl
 * @property {string} googleClientId
 * @property {string} tenantId
 */

/**
 * @returns {DemoConfig}
 */
function getDemoConfig() {
  const candidate = window.TAUTH_DEMO_CONFIG;
  if (candidate && typeof candidate === 'object') {
    return /** @type {DemoConfig} */ (candidate);
  }
  return { baseUrl: '', googleClientId: '', tenantId: '' };
}

function setAuthState(state) {
  if (!document.body) {
    return;
  }
  document.body.setAttribute(AUTH_STATE_ATTRIBUTE, state);
}

function dispatchAuthEvent(eventName, detail) {
  document.dispatchEvent(new CustomEvent(eventName, { detail }));
}

function getGoogleIdentity() {
  if (
    window.google &&
    window.google.accounts &&
    window.google.accounts.id &&
    typeof window.google.accounts.id.initialize === 'function'
  ) {
    return window.google.accounts.id;
  }
  throw new Error(`${ERROR_MESSAGE_PREFIX}: google identity not available`);
}

function getSigninContainer() {
  return /** @type {HTMLElement | null} */ (
    document.getElementById(SIGNIN_CONTAINER_ID)
  );
}

function getSignoutButton() {
  return /** @type {HTMLButtonElement | null} */ (
    document.getElementById(SIGNOUT_BUTTON_ID)
  );
}

function getAuthClientReadyPromise() {
  if (typeof window === 'undefined') {
    return Promise.resolve();
  }
  const readyPromise = window[AUTH_CLIENT_READY_HANDLE];
  if (readyPromise && typeof readyPromise.then === 'function') {
    return readyPromise;
  }
  return Promise.resolve();
}

async function ensureAuthClientReady() {
  try {
    await getAuthClientReadyPromise();
  } catch (error) {
    throw new Error(`${ERROR_MESSAGE_PREFIX}: auth client load failed`);
  }
  if (typeof window.initAuthClient !== 'function') {
    throw new Error(`${ERROR_MESSAGE_PREFIX}: initAuthClient unavailable`);
  }
}

async function prepareGoogleSignIn(config) {
  const container = getSigninContainer();
  if (!container) {
    throw new Error(`${ERROR_MESSAGE_PREFIX}: missing sign-in container`);
  }
  if (!config.googleClientId) {
    throw new Error(`${ERROR_MESSAGE_PREFIX}: missing google client id`);
  }
  if (typeof window.requestNonce !== 'function') {
    throw new Error(`${ERROR_MESSAGE_PREFIX}: requestNonce unavailable`);
  }
  const nonceToken = await window.requestNonce();
  const googleIdentity = getGoogleIdentity();
  container.replaceChildren();
  googleIdentity.initialize({
    client_id: config.googleClientId,
    nonce: nonceToken,
    callback: (response) => {
      handleGoogleCredential(config, nonceToken, response);
    },
  });
  googleIdentity.renderButton(container, {
    theme: 'outline',
    size: 'large',
    shape: 'pill',
  });
  googleIdentity.prompt();
}

async function handleGoogleCredential(config, nonceToken, response) {
  if (!response || typeof response.credential !== 'string') {
    dispatchAuthEvent(ERROR_EVENT, {
      code: `${ERROR_MESSAGE_PREFIX}: missing credential`,
    });
    return;
  }
  if (typeof window.exchangeGoogleCredential !== 'function') {
    dispatchAuthEvent(ERROR_EVENT, {
      code: `${ERROR_MESSAGE_PREFIX}: exchangeGoogleCredential unavailable`,
    });
    return;
  }
  try {
    await window.exchangeGoogleCredential({
      credential: response.credential,
      nonceToken,
    });
  } catch (error) {
    dispatchAuthEvent(ERROR_EVENT, {
      code:
        error && error.message ? error.message : `${ERROR_MESSAGE_PREFIX}: exchange failed`,
    });
  }
}

async function initAuthClient(config) {
  await ensureAuthClientReady();
  await window.initAuthClient({
    baseUrl: config.baseUrl,
    tenantId: config.tenantId,
    onAuthenticated(profile) {
      setAuthState(AUTH_STATE_AUTHENTICATED);
      dispatchAuthEvent(AUTHENTICATED_EVENT, { profile });
    },
    onUnauthenticated() {
      setAuthState(AUTH_STATE_UNAUTHENTICATED);
      dispatchAuthEvent(UNAUTHENTICATED_EVENT, {});
      prepareGoogleSignIn(config).catch((error) => {
        dispatchAuthEvent(ERROR_EVENT, {
          code: error && error.message ? error.message : `${ERROR_MESSAGE_PREFIX}: nonce failed`,
        });
      });
    },
  });
}

function wireSignout() {
  const button = getSignoutButton();
  if (!button) {
    return;
  }
  button.addEventListener('click', () => {
    if (typeof window.logout !== 'function') {
      dispatchAuthEvent(ERROR_EVENT, {
        code: `${ERROR_MESSAGE_PREFIX}: logout unavailable`,
      });
      return;
    }
    window.logout();
  });
}

async function initAuthUi() {
  const config = getDemoConfig();
  setAuthState(AUTH_STATE_LOADING);
  wireSignout();
  try {
    await initAuthClient(config);
  } catch (error) {
    setAuthState(AUTH_STATE_UNAUTHENTICATED);
    dispatchAuthEvent(ERROR_EVENT, {
      code: error && error.message ? error.message : `${ERROR_MESSAGE_PREFIX}: init failed`,
    });
  }
}

window.addEventListener('load', initAuthUi);
