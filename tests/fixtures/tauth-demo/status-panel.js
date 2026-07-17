// @ts-check
'use strict';

const STATUS_HOST_SELECTOR = '[data-demo-auth-status]';

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

function initSessionPanel() {
  renderSession(typeof window.getCurrentUser === 'function' ? window.getCurrentUser() : null);
  document.addEventListener('tauth-demo:authenticated', (event) => {
    renderSession(event?.detail?.profile ?? null);
  });
  document.addEventListener('tauth-demo:unauthenticated', () => {
    renderSession(null);
  });
  document.addEventListener('tauth-demo:error', (event) => {
    const code = event?.detail?.code;
    renderError(code ? String(code) : 'Unable to complete authentication.');
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initSessionPanel);
} else {
  initSessionPanel();
}
