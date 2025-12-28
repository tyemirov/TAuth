// @ts-check
/* eslint-disable no-undef */
'use strict';

const PRODUCTION_TAUTH_BASE_URL = 'https://tauth.mprlab.com';
const LOCAL_TAUTH_BASE_URL = 'http://localhost:8082';
const DEMO_TENANT_ID = 'mpr-sites';
const AUTH_CLIENT_SCRIPT_ATTRIBUTE = 'data-tauth-auth-client';
const MPR_UI_SCRIPT_ATTRIBUTE = 'data-mpr-ui-bundle';
const DEMO_CONFIG_EVENT_NAME = 'tauth-demo:config';
const DEMO_CONFIG_ENDPOINT = '/demo/config.json';
const MPR_UI_BUNDLE_URL =
  'https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@latest/mpr-ui.js';
const DEMO_HEADER_ID = 'demo-header';
const FALLBACK_GOOGLE_CLIENT_ID = '';
const currentHostname = window.location.hostname || '';
const resolvedBaseUrl = currentHostname.endsWith('.mprlab.com')
  ? PRODUCTION_TAUTH_BASE_URL
  : LOCAL_TAUTH_BASE_URL;
const normalizedBaseUrl = resolvedBaseUrl.replace(/\/+$/, '');
const authClientUrl = `${normalizedBaseUrl}/tauth.js`;
const demoConfigUrl = `${normalizedBaseUrl}${DEMO_CONFIG_ENDPOINT}`;

function normalizeGoogleClientId(candidateId) {
  if (typeof candidateId !== 'string') {
    return FALLBACK_GOOGLE_CLIENT_ID;
  }
  const trimmed = candidateId.trim();
  return trimmed ? trimmed : FALLBACK_GOOGLE_CLIENT_ID;
}

function resolveDemoConfig(candidateConfig) {
  const incoming =
    candidateConfig && typeof candidateConfig === 'object' ? candidateConfig : {};
  return Object.freeze({
    baseUrl: normalizedBaseUrl,
    googleClientId: normalizeGoogleClientId(incoming.googleClientId),
  });
}

function applyDemoConfig(config, warnOnMissingClientId) {
  const headerElement = document.getElementById(DEMO_HEADER_ID);
  if (!headerElement) {
    return;
  }
  if (config.baseUrl) {
    headerElement.setAttribute('base-url', String(config.baseUrl));
  }
  if (config.googleClientId) {
    headerElement.setAttribute('site-id', String(config.googleClientId));
    return;
  }
  if (warnOnMissingClientId) {
    // eslint-disable-next-line no-console
    console.warn(
      'mpr-ui demo: set a valid Google OAuth Web client ID in the TAuth demo config.'
    );
  }
}

function updateDemoConfig(nextConfig, options) {
  const resolvedConfig = resolveDemoConfig(nextConfig);
  window.TAUTH_DEMO_CONFIG = resolvedConfig;
  document.dispatchEvent(
    new CustomEvent(DEMO_CONFIG_EVENT_NAME, { detail: resolvedConfig })
  );
  const shouldWarnOnMissing =
    options && typeof options.warnOnMissingClientId === 'boolean'
      ? options.warnOnMissingClientId
      : false;
  applyDemoConfig(resolvedConfig, shouldWarnOnMissing);
  return resolvedConfig;
}

function createScriptLoadError(scriptUrl) {
  return new Error(`tauth-demo.script_load_failed: ${scriptUrl}`);
}

function loadScriptOnce(scriptUrl, attributeName, attributeValues) {
  const existingScript = document.querySelector(`script[${attributeName}]`);
  if (existingScript) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    const scriptElement = document.createElement('script');
    scriptElement.defer = true;
    scriptElement.src = scriptUrl;
    scriptElement.crossOrigin = 'anonymous';
    scriptElement.setAttribute(attributeName, 'true');
    if (attributeValues && typeof attributeValues === 'object') {
      Object.entries(attributeValues).forEach(([attributeKey, attributeValue]) => {
        scriptElement.setAttribute(attributeKey, String(attributeValue));
      });
    }
    scriptElement.addEventListener('load', () => resolve());
    scriptElement.addEventListener('error', () =>
      reject(createScriptLoadError(scriptUrl))
    );
    const head = document.head || document.documentElement;
    head.appendChild(scriptElement);
  });
}

function fetchDemoConfig() {
  return fetch(demoConfigUrl, {
    method: 'GET',
    credentials: 'include',
    headers: {
      'X-Requested-With': 'XMLHttpRequest',
    },
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`tauth-demo.config_fetch_failed: ${response.status}`);
      }
      return response.json();
    })
    .then((payload) => {
      if (!payload || typeof payload !== 'object') {
        throw new Error('tauth-demo.config_invalid: expected object payload');
      }
      return payload;
    });
}

function initDemoConfig() {
  updateDemoConfig(window.__TAUTH_DEMO_CONFIG, {
    warnOnMissingClientId: false,
  });
  const authClientPromise = loadScriptOnce(
    authClientUrl,
    AUTH_CLIENT_SCRIPT_ATTRIBUTE,
    { 'data-tenant-id': DEMO_TENANT_ID }
  );
  const demoConfigPromise = fetchDemoConfig().then((payload) =>
    updateDemoConfig(payload, { warnOnMissingClientId: true })
  );
  Promise.all([authClientPromise, demoConfigPromise])
    .then(() => loadScriptOnce(MPR_UI_BUNDLE_URL, MPR_UI_SCRIPT_ATTRIBUTE))
    .catch((error) => {
      // eslint-disable-next-line no-console
      console.warn('tauth demo: unable to initialize scripts.', error);
    });
}

initDemoConfig();
