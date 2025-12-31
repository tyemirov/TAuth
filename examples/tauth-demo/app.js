// @ts-check
'use strict';

const STATUS_HOST_SELECTOR = '[data-demo-auth-status]';
const HEADER_HOST_SELECTOR = 'mpr-header#demo-header';
const HEADER_ERROR_MESSAGES = Object.freeze({
  'missing-site-id': 'Missing Google client ID (site-id).',
  'missing-tauth-tenant-id': 'Missing TAuth tenant id (tauth-tenant-id).',
});

/**
 * @typedef {object} AuthProfile
 * @property {string} [display]
 * @property {string} [user_email]
 * @property {string} [avatar_url]
 * @property {string} [expires]
 * @property {string[]} [roles]
 */

/**
 * Renders the session snapshot with the provided profile.
 * @param {AuthProfile | null | undefined} profile
 * @returns {void}
 */
function renderSession(profile) {
  const host = document.querySelector(STATUS_HOST_SELECTOR);
  if (!host) {
    return;
  }
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
  details.append(
    nameLabel,
    nameValue,
    emailLabel,
    emailValue,
    roleLabelElement,
    roleValue
  );
  if (profile.avatar_url) {
    const avatar = document.createElement('img');
    avatar.src = profile.avatar_url;
    avatar.alt = profile.display || 'Avatar';
    avatar.loading = 'lazy';
    host.append(avatar);
  }
  const expiryParagraph = document.createElement('p');
  if (profile.expires) {
    const readableExpires = new Date(profile.expires).toLocaleString();
    const timeElement = document.createElement('time');
    timeElement.dateTime = profile.expires;
    timeElement.textContent = readableExpires;
    expiryParagraph.append(
      document.createTextNode('Current session cookie expires at '),
      timeElement,
      document.createTextNode('.')
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

function renderError(message) {
  const host = document.querySelector(STATUS_HOST_SELECTOR);
  if (!host) {
    return;
  }
  host.replaceChildren();
  const title = document.createElement('h3');
  title.textContent = 'Sign-in error';
  const details = document.createElement('p');
  details.textContent = message;
  host.append(title, details);
}

/**
 * @param {unknown} code
 * @param {unknown} message
 * @returns {string}
 */
function formatErrorMessage(code, message) {
  const normalizedCode = typeof code === 'string' ? code.trim() : '';
  const normalizedMessage = typeof message === 'string' ? message.trim() : '';
  if (normalizedMessage) {
    return normalizedMessage;
  }
  if (normalizedCode && HEADER_ERROR_MESSAGES[normalizedCode]) {
    return HEADER_ERROR_MESSAGES[normalizedCode];
  }
  if (normalizedCode) {
    return `Sign-in error: ${normalizedCode}`;
  }
  return 'Unable to complete authentication.';
}

/**
 * @returns {string}
 */
function readHeaderErrorMessage() {
  const headerElement = document.querySelector(HEADER_HOST_SELECTOR);
  if (!headerElement) {
    return '';
  }
  const headerError = headerElement.getAttribute('data-mpr-google-error');
  return headerError ? formatErrorMessage(headerError, '') : '';
}

function initSessionPanel() {
  const currentProfile =
    typeof window.getCurrentUser === 'function' ? window.getCurrentUser() : null;
  if (currentProfile) {
    renderSession(currentProfile);
  } else {
    const headerError = readHeaderErrorMessage();
    if (headerError) {
      renderError(headerError);
    } else {
      renderSession(null);
    }
  }
  document.addEventListener('mpr-ui:auth:authenticated', (event) => {
    renderSession(event?.detail?.profile ?? null);
  });
  document.addEventListener('mpr-ui:auth:unauthenticated', () => {
    const headerError = readHeaderErrorMessage();
    if (headerError) {
      renderError(headerError);
      return;
    }
    renderSession(null);
  });
  const handleErrorEvent = (event) => {
    const detail = event?.detail;
    renderError(formatErrorMessage(detail?.code, detail?.message));
  };
  document.addEventListener('mpr-ui:auth:error', handleErrorEvent);
  document.addEventListener('mpr-ui:header:error', handleErrorEvent);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initSessionPanel);
} else {
  initSessionPanel();
}
