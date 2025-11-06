"use strict";

const MPR_UI_CDN_PREFIX =
  "https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@0.0.5/mpr-ui.js";

async function interceptMprUiRequest(page, scriptBody) {
  if (!page || typeof page.setRequestInterception !== "function") {
    throw new Error("interceptMprUiRequest requires a Puppeteer page instance");
  }
  await page.setRequestInterception(true);
  async function handleRequest(request) {
    try {
      const url = request.url();
      if (url === MPR_UI_CDN_PREFIX || url.startsWith(MPR_UI_CDN_PREFIX + "?")) {
        await request.respond({
          status: 200,
          contentType: "application/javascript; charset=utf-8",
          body: scriptBody,
        });
        return;
      }
      await request.continue();
    } catch (error) {
      try {
        await request.abort();
      } catch (_abortError) {
        // ignore secondary failure
      }
      throw error;
    }
  }
  page.on("request", handleRequest);
  let cleaned = false;
  return async function cleanup() {
    if (cleaned) {
      return;
    }
    cleaned = true;
    page.off("request", handleRequest);
    try {
      await page.setRequestInterception(false);
    } catch (_error) {
      // ignore teardown errors
    }
  };
}

module.exports = {
  interceptMprUiRequest,
};
