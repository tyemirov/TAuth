// @ts-check
/* eslint-disable no-undef */
'use strict';

const PRODUCTION_TAUTH_BASE_URL = 'https://tauth.mprlab.com';
const LOCAL_TAUTH_BASE_URL = 'http://localhost:8082';
const AUTH_CLIENT_SCRIPT_ATTRIBUTE = 'data-tauth-auth-client';
const AUTH_CLIENT_READY_HANDLE = '__TAUTH_AUTH_CLIENT_READY__';
const DEFAULT_TENANT_ID = 'mpr-sites';
const FALLBACK_GOOGLE_CLIENT_ID = '';
const DEMO_CONFIG_WARNING =
  'tauth demo: set a valid Google OAuth Web client ID in examples/tauth-demo/demo-config.js.';
const INIT_FAILURE_WARNING = 'tauth demo: unable to initialize tauth.js.';

function normalizeGoogleClientId(candidateId) {
  if (typeof candidateId !== 'string') {
    return FALLBACK_GOOGLE_CLIENT_ID;
  }
  const trimmed = candidateId.trim();
  return trimmed ? trimmed : FALLBACK_GOOGLE_CLIENT_ID;
}

function normalizeTenantId(candidateId) {
  if (typeof candidateId !== 'string') {
    return DEFAULT_TENANT_ID;
  }
  const trimmed = candidateId.trim();
  return trimmed ? trimmed : DEFAULT_TENANT_ID;
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
    tenantId: normalizeTenantId(incoming.tenantId),
  });
}

function updateDemoConfig(nextConfig, options) {
  const resolvedConfig = resolveDemoConfig(nextConfig);
  window.TAUTH_DEMO_CONFIG = resolvedConfig;
  const shouldWarnOnMissing =
    options && typeof options.warnOnMissingClientId === 'boolean'
      ? options.warnOnMissingClientId
      : false;
  if (shouldWarnOnMissing && !resolvedConfig.googleClientId) {
    // eslint-disable-next-line no-console
    console.warn(DEMO_CONFIG_WARNING);
  }
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
  if (!resolvedConfig.googleClientId) {
    // eslint-disable-next-line no-console
    console.warn(DEMO_CONFIG_WARNING);
  }
  const authClientUrl = `${resolvedConfig.baseUrl}/tauth.js`;
  const authClientPromise = loadScriptOnce(authClientUrl, AUTH_CLIENT_SCRIPT_ATTRIBUTE, {
    'data-tenant-id': resolvedConfig.tenantId,
  });
  window[AUTH_CLIENT_READY_HANDLE] = authClientPromise;
  authClientPromise
    .catch((error) => {
      // eslint-disable-next-line no-console
      console.warn(INIT_FAILURE_WARNING, error);
    });
}

initDemoConfig();
