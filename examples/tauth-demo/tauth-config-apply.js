// @ts-check
'use strict';

const DEMO_CONFIG_EVENT_NAME = 'tauth-demo:config';

/**
 * Applies the TAUTH_DEMO_CONFIG to the demo header element so the client ID
 * and base URL stay aligned with the backend configuration.
 */
function resolveDemoConfig(candidate) {
  return candidate && typeof candidate === 'object' ? candidate : {};
}

function applyTauthConfig(config) {
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
      'mpr-ui demo: set a valid Google OAuth Web client ID via the TAuth demo config endpoint or update demo/tauth-config.js.'
    );
  }
}

function handleDemoConfigEvent(eventObject) {
  var detailConfig =
    eventObject && typeof eventObject.detail === 'object'
      ? eventObject.detail
      : null;
  applyTauthConfig(resolveDemoConfig(detailConfig));
}

(function initTauthConfig() {
  applyTauthConfig(resolveDemoConfig(globalThis.TAUTH_DEMO_CONFIG));
  document.addEventListener(DEMO_CONFIG_EVENT_NAME, handleDemoConfigEvent);
})();
