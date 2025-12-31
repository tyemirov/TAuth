// @ts-check
"use strict";

const AUTH_CLIENT_CACHE_BUSTER_PARAM = "tauth_cache_buster";
const GIS_SCRIPT_URL = "https://accounts.google.com/gsi/client";
const MPR_UI_SCRIPT_URL =
  "https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@3.3.0/mpr-ui.js";
const DEFAULT_DEMO_CONFIG = Object.freeze({
  baseUrl: "http://localhost:8082",
  googleClientId:
    "212947889486-vr99ionvvoie1ke2ee8qelv34oglseoj.apps.googleusercontent.com",
  tenantId: "demo",
});

/**
 * @param {unknown} value
 * @returns {string}
 */
function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

/**
 * @param {string} value
 * @returns {string}
 */
function normalizeBaseUrl(value) {
  const trimmedValue = normalizeString(value);
  if (trimmedValue.endsWith("/")) {
    return trimmedValue.slice(0, -1);
  }
  return trimmedValue;
}

/**
 * @returns {{ baseUrl: string, googleClientId: string, tenantId: string }}
 */
function resolveDemoConfig() {
  const rawConfig =
    typeof window.__TAUTH_DEMO_CONFIG === "object" && window.__TAUTH_DEMO_CONFIG
      ? window.__TAUTH_DEMO_CONFIG
      : {};
  const baseUrlCandidate = normalizeBaseUrl(rawConfig.baseUrl);
  const googleClientCandidate = normalizeString(rawConfig.googleClientId);
  const tenantCandidate = normalizeString(rawConfig.tenantId);
  return Object.freeze({
    baseUrl: baseUrlCandidate || DEFAULT_DEMO_CONFIG.baseUrl,
    googleClientId: googleClientCandidate || DEFAULT_DEMO_CONFIG.googleClientId,
    tenantId: tenantCandidate || DEFAULT_DEMO_CONFIG.tenantId,
  });
}

/**
 * @param {{ baseUrl: string, googleClientId: string, tenantId: string }} config
 * @returns {void}
 */
function applyHeaderConfig(config) {
  const headerElement = document.querySelector("mpr-header#demo-header");
  if (!headerElement) {
    return;
  }
  headerElement.setAttribute("tauth-url", config.baseUrl);
  headerElement.setAttribute("google-site-id", config.googleClientId);
  headerElement.setAttribute("tauth-tenant-id", config.tenantId);
  ensureHeaderRoot(headerElement);
}

/**
 * @param {boolean} isAuthenticated
 * @returns {void}
 */
function updateHeaderAuthState(isAuthenticated) {
  const headerElement = document.querySelector("mpr-header#demo-header");
  const headerRoot = headerElement ? ensureHeaderRoot(headerElement) : null;
  if (!headerRoot) {
    return;
  }
  if (isAuthenticated) {
    headerRoot.classList.add("mpr-header--authenticated");
    return;
  }
  headerRoot.classList.remove("mpr-header--authenticated");
}

/**
 * @param {string} eventName
 * @param {unknown} detail
 * @returns {void}
 */
function dispatchAuthEvent(eventName, detail) {
  const detailPayload = detail ? { detail: detail } : {};
  document.dispatchEvent(new CustomEvent(eventName, detailPayload));
}

/**
 * @param {unknown} profile
 * @returns {void}
 */
function handleAuthenticated(profile) {
  updateHeaderAuthState(true);
  dispatchAuthEvent("mpr-ui:auth:authenticated", { profile: profile });
}

/**
 * @returns {void}
 */
function handleUnauthenticated() {
  updateHeaderAuthState(false);
  dispatchAuthEvent("mpr-ui:auth:unauthenticated", null);
}

/**
 * @param {Element} headerHost
 * @returns {HTMLElement | null}
 */
function ensureHeaderRoot(headerHost) {
  const existingHeader = headerHost.querySelector("header.mpr-header");
  if (existingHeader instanceof HTMLElement) {
    return existingHeader;
  }
  const headerElement = document.createElement("header");
  headerElement.classList.add("mpr-header");
  const signOutButton = document.createElement("button");
  signOutButton.type = "button";
  signOutButton.setAttribute("data-mpr-header", "sign-out-button");
  signOutButton.textContent = "Sign out";
  headerElement.appendChild(signOutButton);
  headerHost.appendChild(headerElement);
  return headerElement;
}

/**
 * @param {string} sourceUrl
 * @param {Record<string, string>} attributes
 * @returns {Promise<HTMLScriptElement>}
 */
function loadScript(sourceUrl, attributes) {
  return new Promise((resolve, reject) => {
    const scriptElement = document.createElement("script");
    scriptElement.src = sourceUrl;
    scriptElement.defer = true;
    const attributeEntries = Object.entries(attributes || {});
    for (const [attributeName, attributeValue] of attributeEntries) {
      scriptElement.setAttribute(attributeName, attributeValue);
    }
    scriptElement.addEventListener("load", () => {
      resolve(scriptElement);
    });
    scriptElement.addEventListener("error", () => {
      reject(new Error("tauth.demo.script_load_failed"));
    });
    document.head.appendChild(scriptElement);
  });
}

/**
 * @returns {void}
 */
function attachLogoutListener() {
  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }
    const signOutButton = target.closest(
      '[data-mpr-header="sign-out-button"]',
    );
    if (!signOutButton || typeof window.logout !== "function") {
      return;
    }
    window.logout();
  });
}

const resolvedConfig = resolveDemoConfig();
const authClientCacheBuster = Date.now();
const authClientPromise = (async () => {
  applyHeaderConfig(resolvedConfig);
  void loadScript(GIS_SCRIPT_URL, {}).catch(() => {
    dispatchAuthEvent("mpr-ui:auth:error", { code: "tauth.demo.gis_load_failed" });
  });
  void loadScript(MPR_UI_SCRIPT_URL, {}).catch(() => {
    dispatchAuthEvent("mpr-ui:auth:error", { code: "tauth.demo.mpr_ui_load_failed" });
  });
  await loadScript(
    `${resolvedConfig.baseUrl}/tauth.js?${AUTH_CLIENT_CACHE_BUSTER_PARAM}=${authClientCacheBuster}`,
    { "data-tenant-id": resolvedConfig.tenantId },
  );
  if (typeof window.initAuthClient !== "function") {
    throw new Error("tauth.demo.auth_client_missing");
  }
  await window.initAuthClient({
    baseUrl: resolvedConfig.baseUrl,
    tenantId: resolvedConfig.tenantId,
    onAuthenticated: handleAuthenticated,
    onUnauthenticated: handleUnauthenticated,
  });
  attachLogoutListener();
})();

window.__TAUTH_AUTH_CLIENT_READY__ = authClientPromise;
