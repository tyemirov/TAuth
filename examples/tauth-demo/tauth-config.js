// @ts-check
/* eslint-disable no-undef */
'use strict';

const PRODUCTION_TAUTH_BASE_URL = 'https://tauth.mprlab.com';
const LOCAL_TAUTH_BASE_URL = 'http://localhost:8082';
const DEMO_TENANT_ID = 'mpr-sites';
const AUTH_CLIENT_SCRIPT_ATTRIBUTE = 'data-tauth-auth-client';
const MPR_UI_SCRIPT_ATTRIBUTE = 'data-mpr-ui-bundle';
const MPR_UI_BUNDLE_URL =
  'https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@latest/mpr-ui.js';
const DEMO_HEADER_ID = 'demo-header';
const FALLBACK_GOOGLE_CLIENT_ID = '';
const DEMO_CONFIG_WARNING =
  'mpr-ui demo: set a valid Google OAuth Web client ID in examples/tauth-demo/demo-config.js.';
const INIT_FAILURE_WARNING =
  'tauth demo: unable to initialize the authentication scripts.';

function normalizeGoogleClientId(candidateId) {
  if (typeof candidateId !== 'string') {
    return FALLBACK_GOOGLE_CLIENT_ID;
  }
  const trimmed = candidateId.trim();
  return trimmed ? trimmed : FALLBACK_GOOGLE_CLIENT_ID;
}

function resolveBaseUrl(candidateConfig) {
  const incoming =
    candidateConfig && typeof candidateConfig === 'object' ? candidateConfig : {};
  if (typeof incoming.baseUrl === 'string') {
    const trimmed = incoming.baseUrl.trim();
    if (trimmed) {
      return trimmed.replace(/\/+$/, '');
    }
  }
  const currentHostname = window.location.hostname || '';
  const resolvedBaseUrl = currentHostname.endsWith('.mprlab.com')
    ? PRODUCTION_TAUTH_BASE_URL
    : LOCAL_TAUTH_BASE_URL;
  return resolvedBaseUrl.replace(/\/+$/, '');
}

function resolveDemoConfig(candidateConfig) {
  const incoming =
    candidateConfig && typeof candidateConfig === 'object' ? candidateConfig : {};
  return Object.freeze({
    baseUrl: resolveBaseUrl(incoming),
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
    console.warn(DEMO_CONFIG_WARNING);
  }
}

function updateDemoConfig(nextConfig, options) {
  const resolvedConfig = resolveDemoConfig(nextConfig);
  window.TAUTH_DEMO_CONFIG = resolvedConfig;
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

function initDemoConfig() {
  const resolvedConfig = updateDemoConfig(window.__TAUTH_DEMO_CONFIG, {
    warnOnMissingClientId: true,
  });
  const authClientUrl = `${resolvedConfig.baseUrl}/tauth.js`;
  loadScriptOnce(authClientUrl, AUTH_CLIENT_SCRIPT_ATTRIBUTE, {
    'data-tenant-id': DEMO_TENANT_ID,
  })
    .then(() => loadScriptOnce(MPR_UI_BUNDLE_URL, MPR_UI_SCRIPT_ATTRIBUTE))
    .catch((error) => {
      // eslint-disable-next-line no-console
      console.warn(INIT_FAILURE_WARNING, error);
    });
}

initDemoConfig();
