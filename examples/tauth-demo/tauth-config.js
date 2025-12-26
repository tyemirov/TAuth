// @ts-check
/* eslint-disable no-undef */
'use strict';

const PRODUCTION_TAUTH_BASE_URL = 'https://tauth.mprlab.com';
const LOCAL_TAUTH_BASE_URL = 'http://localhost:8082';
const DEMO_TENANT_ID = 'mpr-sites';
const AUTH_CLIENT_SCRIPT_ATTRIBUTE = 'data-tauth-auth-client';
const currentHostname = window.location.hostname || '';
const resolvedBaseUrl = currentHostname.endsWith('.mprlab.com')
  ? PRODUCTION_TAUTH_BASE_URL
  : LOCAL_TAUTH_BASE_URL;
const authClientUrl = `${resolvedBaseUrl.replace(/\/+$/, '')}/tauth.js`;

/**
 * Update `googleClientId` to your Google OAuth Web client ID.
 * Keep it in sync with `APP_GOOGLE_WEB_CLIENT_ID` in `.env.tauth`
 * so the frontend and TAuth share the same configuration.
 * The default `baseUrl` targets tauth.mprlab.com on hosted deployments and falls back to the
 * docker-compose container URL for local demos.
 */
window.TAUTH_DEMO_CONFIG = Object.freeze({
  googleClientId: '991677581607-r0dj8q6irjagipali0jpca7nfp8sfj9r.apps.googleusercontent.com',
  baseUrl: resolvedBaseUrl,
});

if (!document.querySelector(`script[${AUTH_CLIENT_SCRIPT_ATTRIBUTE}]`)) {
  const authClientScript = document.createElement('script');
  authClientScript.defer = true;
  authClientScript.src = authClientUrl;
  authClientScript.crossOrigin = 'anonymous';
  authClientScript.setAttribute(AUTH_CLIENT_SCRIPT_ATTRIBUTE, 'true');
  authClientScript.setAttribute('data-tenant-id', DEMO_TENANT_ID);
  document.head.appendChild(authClientScript);
}
