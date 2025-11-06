// @ts-check

(function exportMprSites(globalObject) {
  "use strict";

  const sites = Object.freeze([
    { label: "Marco Polo Research Lab", url: "https://mprlab.com" },
    { label: "Gravity Notes", url: "https://gravity.mprlab.com" },
    { label: "LoopAware", url: "https://loopaware.mprlab.com" },
    { label: "Allergy Wheel", url: "https://allergy.mprlab.com" },
    { label: "Social Threader", url: "https://threader.mprlab.com" },
    { label: "RSVP", url: "https://rsvp.mprlab.com" },
    { label: "Countdown Calendar", url: "https://countdown.mprlab.com" },
    { label: "LLM Crossword", url: "https://llm-crossword.mprlab.com" },
    { label: "Prompt Bubbles", url: "https://prompts.mprlab.com" },
    { label: "Wallpapers", url: "https://wallpapers.mprlab.com" },
  ]);

  if (globalObject && typeof globalObject === "object") {
    globalObject.MPR_SITES = sites;
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { MPR_SITES: sites };
  }
})(typeof window !== "undefined" ? window : globalThis);
