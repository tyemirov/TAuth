// @ts-check
'use strict';

const STATUS_HOST_SELECTOR = '[data-demo-auth-status]';
const HEADER_SELECTOR = 'header#demo-header';
const GOOGLE_SIGNIN_SELECTOR = '[data-demo-google-signin]';
const SIGN_OUT_SELECTOR = '[data-demo-sign-out]';
const AUTHENTICATED_CLASS = 'demo-header--authenticated';

/**
 * @typedef {object} AuthProfile
 * @property {string} [display]
 * @property {string} [user_email]
 * @property {string} [avatar_url]
 * @property {string} [expires]
 * @property {string[]} [roles]
 */

/**
 * @returns {{ baseUrl: string, googleClientId: string, tenantId: string }}
 */
function readDemoConfig() {
  const header = document.querySelector(HEADER_SELECTOR);
  if (!(header instanceof HTMLElement)) {
    throw new Error('tauth.demo.header_missing');
  }
  const baseUrl = String(header.dataset.baseUrl || '').trim();
  const googleClientId = String(header.dataset.googleClientId || '').trim();
  const tenantId = String(header.dataset.tenantId || '').trim();
  if (!baseUrl || !googleClientId || !tenantId) {
    throw new Error('tauth.demo.config_missing');
  }
  return { baseUrl, googleClientId, tenantId };
}

/**
 * @param {boolean} authenticated
 * @returns {void}
 */
function updateHeaderState(authenticated) {
  const header = document.querySelector(HEADER_SELECTOR);
  if (!header) {
    return;
  }
  header.classList.toggle(AUTHENTICATED_CLASS, authenticated);
}

/**
 * @param {AuthProfile | null | undefined} profile
 * @returns {void}
 */
function renderSession(profile) {
  const host = document.querySelector(STATUS_HOST_SELECTOR);
  if (!host) {
    return;
  }
  updateHeaderState(Boolean(profile));
  const roles = Array.isArray(profile?.roles) ? profile.roles : [];
  const roleLabel = roles.length ? roles.join(', ') : 'user';
  host.replaceChildren();
  if (!profile) {
    const title = document.createElement('h3');
    title.textContent = 'Signed out';
    const details = document.createElement('p');
    details.textContent = 'Use the Google Sign-In button in the header to begin.';
    host.append(title, details);
    return;
  }
  const title = document.createElement('h3');
  title.textContent = 'Signed in';
  const summary = document.createElement('p');
  summary.textContent = `Session active for ${profile.display || 'Unknown user'}.`;
  const details = document.createElement('dl');
  const nameLabel = document.createElement('dt');
  nameLabel.textContent = 'Name';
  const nameValue = document.createElement('dd');
  nameValue.textContent = profile.display || 'Unknown';
  const emailLabel = document.createElement('dt');
  emailLabel.textContent = 'Email';
  const emailValue = document.createElement('dd');
  emailValue.textContent = profile.user_email || 'Hidden';
  const roleLabelElement = document.createElement('dt');
  roleLabelElement.textContent = 'Roles';
  const roleValue = document.createElement('dd');
  roleValue.textContent = roleLabel;
  details.append(nameLabel, nameValue, emailLabel, emailValue, roleLabelElement, roleValue);
  if (profile.avatar_url) {
    const avatar = document.createElement('img');
    avatar.src = profile.avatar_url;
    avatar.alt = profile.display || 'Avatar';
    avatar.loading = 'lazy';
    host.append(avatar);
  }
  const expiryParagraph = document.createElement('p');
  if (profile.expires) {
    const timeElement = document.createElement('time');
    timeElement.dateTime = profile.expires;
    timeElement.textContent = new Date(profile.expires).toLocaleString();
    expiryParagraph.append(
      document.createTextNode('Current session cookie expires at '),
      timeElement,
      document.createTextNode('.'),
    );
  } else {
    expiryParagraph.textContent =
      'Session cookie expiry unavailable (auto-refresh will keep you signed in until you sign out).';
  }
  const refreshParagraph = document.createElement('p');
  refreshParagraph.textContent =
    'The refresh token keeps renewing this session in the background until you click Sign out or stop the stack.';
  host.append(title, summary, details, expiryParagraph, refreshParagraph);
}

/**
 * @param {unknown} error
 * @returns {void}
 */
function renderError(error) {
  const host = document.querySelector(STATUS_HOST_SELECTOR);
  if (!host) {
    return;
  }
  host.replaceChildren();
  const title = document.createElement('h3');
  title.textContent = 'Sign-in error';
  const details = document.createElement('p');
  details.textContent = error instanceof Error ? error.message : 'Unable to complete authentication.';
  host.append(title, details);
}

/**
 * @returns {Promise<any>}
 */
async function waitForGoogleIdentity() {
  const readIdentity = () => /** @type {any} */ (window).google?.accounts?.id;
  const availableIdentity = readIdentity();
  if (availableIdentity) {
    return availableIdentity;
  }
  const script = document.querySelector('script[src="https://accounts.google.com/gsi/client"]');
  if (!(script instanceof HTMLScriptElement)) {
    throw new Error('tauth.demo.google_script_missing');
  }
  await new Promise((resolve, reject) => {
    script.addEventListener('load', resolve, { once: true });
    script.addEventListener('error', () => reject(new Error('tauth.demo.google_script_failed')), {
      once: true,
    });
  });
  const loadedIdentity = readIdentity();
  if (!loadedIdentity) {
    throw new Error('tauth.demo.google_unavailable');
  }
  return loadedIdentity;
}

/**
 * @param {{ googleClientId: string }} config
 * @returns {Promise<void>}
 */
async function renderGoogleButton(config) {
  const buttonHost = document.querySelector(GOOGLE_SIGNIN_SELECTOR);
  if (!(buttonHost instanceof HTMLElement)) {
    throw new Error('tauth.demo.google_button_host_missing');
  }
  if (typeof window.requestNonce !== 'function' || typeof window.exchangeGoogleCredential !== 'function') {
    throw new Error('tauth.demo.auth_client_missing');
  }
  const googleIdentity = await waitForGoogleIdentity();
  const nonceToken = await window.requestNonce();
  googleIdentity.initialize({
    client_id: config.googleClientId,
    nonce: nonceToken,
    callback: async (response) => {
      try {
        await window.exchangeGoogleCredential({
          credential: String(response?.credential || ''),
          nonceToken,
        });
      } catch (error) {
        renderError(error);
      }
    },
  });
  googleIdentity.renderButton(buttonHost, { theme: 'outline', size: 'large' });
}

function attachSignOut() {
  const signOutButton = document.querySelector(SIGN_OUT_SELECTOR);
  if (!(signOutButton instanceof HTMLButtonElement)) {
    throw new Error('tauth.demo.sign_out_missing');
  }
  signOutButton.addEventListener('click', async () => {
    if (typeof window.logout !== 'function') {
      renderError(new Error('tauth.demo.auth_client_missing'));
      return;
    }
    await window.logout();
  });
}

async function initializeDemo() {
  try {
    const config = readDemoConfig();
    if (typeof window.initAuthClient !== 'function') {
      throw new Error('tauth.demo.auth_client_missing');
    }
    await window.initAuthClient({
      baseUrl: config.baseUrl,
      tenantId: config.tenantId,
      onAuthenticated: renderSession,
      onUnauthenticated: () => renderSession(null),
      onAuthError: renderError,
    });
    renderSession(typeof window.getCurrentUser === 'function' ? window.getCurrentUser() : null);
    attachSignOut();
    await renderGoogleButton(config);
  } catch (error) {
    renderError(error);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => void initializeDemo());
} else {
  void initializeDemo();
}
