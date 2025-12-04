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
  const profileContainer = document.createElement('div');
  profileContainer.classList.add('session-card__profile');
  if (profile.avatar_url) {
    const avatar = document.createElement('img');
    avatar.classList.add('session-card__avatar');
    avatar.src = profile.avatar_url;
    avatar.alt = profile.display || 'Avatar';
    profileContainer.append(avatar);
  }
  const list = document.createElement('ul');
  const nameItem = document.createElement('li');
  const nameLabel = document.createElement('strong');
  nameLabel.textContent = 'Name:';
  nameItem.append(nameLabel, document.createTextNode(` ${profile.display || 'Unknown'}`));
  const emailItem = document.createElement('li');
  const emailLabel = document.createElement('strong');
  emailLabel.textContent = 'Email:';
  emailItem.append(emailLabel, document.createTextNode(` ${profile.user_email || 'Hidden'}`));
  const roleItem = document.createElement('li');
  const roleLabelElement = document.createElement('strong');
  roleLabelElement.textContent = 'Roles:';
  roleItem.append(roleLabelElement, document.createTextNode(` ${roleLabel}`));
  list.append(nameItem, emailItem, roleItem);
  profileContainer.append(list);
  const expiryParagraph = document.createElement('p');
  expiryParagraph.classList.add('session-card__expires');
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
  refreshParagraph.classList.add('session-card__expires');
  refreshParagraph.textContent =
    'The refresh token keeps renewing this session in the background until you click Sign out or stop the stack.';
  host.append(profileContainer, expiryParagraph, refreshParagraph);
}

function initSessionPanel() {
  renderSession(typeof window.getCurrentUser === 'function' ? window.getCurrentUser() : null);
  document.addEventListener('mpr-ui:auth:authenticated', (event) => {
    renderSession(event?.detail?.profile ?? null);
  });
  document.addEventListener('mpr-ui:auth:unauthenticated', () => {
    renderSession(null);
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initSessionPanel);
} else {
  initSessionPanel();
}
