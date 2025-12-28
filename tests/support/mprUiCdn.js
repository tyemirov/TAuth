// @ts-check
"use strict";

const scriptCache = new Map();

/**
 * @param {string} scriptUrl
 * @returns {Promise<string>}
 */
function loadMprUiScript(scriptUrl) {
  if (scriptCache.has(scriptUrl)) {
    return scriptCache.get(scriptUrl);
  }
  const loadPromise = (async () => {
    const fetchImpl = globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new Error("fetch API required to load mpr-ui script from CDN");
    }
    const response = await fetchImpl(scriptUrl);
    if (!response || typeof response.text !== "function") {
      throw new Error("invalid response when loading mpr-ui script from CDN");
    }
    if (response.ok === false) {
      throw new Error(
        `failed to load mpr-ui script from CDN (status ${response.status})`,
      );
    }
    return response.text();
  })();
  scriptCache.set(scriptUrl, loadPromise);
  return loadPromise;
}

module.exports = {
  loadMprUiScript,
};
