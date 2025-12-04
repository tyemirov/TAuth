// @ts-check
/* eslint-disable no-undef */
'use strict';

/**
 * Update `googleClientId` to your Google OAuth Web client ID.
 * Keep it in sync with `APP_GOOGLE_WEB_CLIENT_ID` in `.env.tauth`
 * so the frontend and TAuth share the same configuration.
 * The default `baseUrl` points at the TAuth container from `docker-compose.tauth.yml`.
 */
window.TAUTH_DEMO_CONFIG = Object.freeze({
  googleClientId: '991677581607-r0dj8q6irjagipali0jpca7nfp8sfj9r.apps.googleusercontent.com',
  baseUrl: 'http://localhost:8082',
});
