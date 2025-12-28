// @ts-check
/* eslint-disable no-undef */
'use strict';

const PRODUCTION_TAUTH_BASE_URL = 'https://tauth.mprlab.com';
const LOCAL_TAUTH_BASE_URL = 'http://localhost:8082';
const DEMO_TENANT_ID = 'mpr-sites';
const AUTH_CLIENT_SCRIPT_ATTRIBUTE = 'data-tauth-auth-client';
const DEMO_CONFIG_SCRIPT_ATTRIBUTE = 'data-tauth-demo-config';
const DEMO_CONFIG_EVENT_NAME = 'tauth-demo:config';
const FALLBACK_GOOGLE_CLIENT_ID = '';
const currentHostname = window.location.hostname || '';
const resolvedBaseUrl = currentHostname.endsWith('.mprlab.com')
  ? PRODUCTION_TAUTH_BASE_URL
  : LOCAL_TAUTH_BASE_URL;
const authClientUrl = `${resolvedBaseUrl.replace(/\/+$/, '')}/tauth.js`;

function normalizeGoogleClientId(candidateId) {
  if (typeof candidateId !== 'string') {
    return FALLBACK_GOOGLE_CLIENT_ID;
  }
  const trimmed = candidateId.trim();
  return trimmed ? trimmed : FALLBACK_GOOGLE_CLIENT_ID;
}

function updateDemoConfig(nextConfig) {
  const incoming =
    nextConfig && typeof nextConfig === 'object' ? nextConfig : {};
  const resolvedConfig = Object.freeze({
    baseUrl: resolvedBaseUrl,
    googleClientId: normalizeGoogleClientId(incoming.googleClientId),
  });
  window.TAUTH_DEMO_CONFIG = resolvedConfig;
  document.dispatchEvent(
    new CustomEvent(DEMO_CONFIG_EVENT_NAME, { detail: resolvedConfig })
  );
}

// Merge backend demo config into the local base URL so the UI stays aligned with TAuth.
updateDemoConfig(window.__TAUTH_DEMO_CONFIG);

const demoConfigUrl = `${resolvedBaseUrl.replace(/\/+$/, '')}/demo/config.js`;
if (!document.querySelector(`script[${DEMO_CONFIG_SCRIPT_ATTRIBUTE}]`)) {
  const demoConfigScript = document.createElement('script');
  demoConfigScript.defer = true;
  demoConfigScript.src = demoConfigUrl;
  demoConfigScript.crossOrigin = 'anonymous';
  demoConfigScript.setAttribute(DEMO_CONFIG_SCRIPT_ATTRIBUTE, 'true');
  demoConfigScript.addEventListener('load', () => {
    updateDemoConfig(window.__TAUTH_DEMO_CONFIG);
  });
  document.head.appendChild(demoConfigScript);
}

if (!document.querySelector(`script[${AUTH_CLIENT_SCRIPT_ATTRIBUTE}]`)) {
  const authClientScript = document.createElement('script');
  authClientScript.defer = true;
  authClientScript.src = authClientUrl;
  authClientScript.crossOrigin = 'anonymous';
  authClientScript.setAttribute(AUTH_CLIENT_SCRIPT_ATTRIBUTE, 'true');
  authClientScript.setAttribute('data-tenant-id', DEMO_TENANT_ID);
  document.head.appendChild(authClientScript);
}
