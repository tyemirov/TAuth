// @ts-check
'use strict';

/**
 * Applies the TAUTH_DEMO_CONFIG to the demo header element so the client ID
 * and base URL stay aligned with the backend configuration.
 */
(function applyTauthConfig() {
  var config = globalThis.TAUTH_DEMO_CONFIG || {};
  var header = /** @type {HTMLElement|null} */ (document.getElementById('demo-header'));
  if (!header) {
    return;
  }
  if (config.googleClientId) {
    header.setAttribute('site-id', String(config.googleClientId));
  }
  if (config.baseUrl) {
    header.setAttribute('base-url', String(config.baseUrl));
  }
  if (!config.googleClientId) {
    // eslint-disable-next-line no-console
    console.warn(
      'mpr-ui demo: set googleClientId in demo/tauth-config.js to your Google OAuth Web client ID; GIS will reject sign-in without it.'
    );
  }
})();
