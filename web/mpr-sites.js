// @ts-check

(function exportMprSites(globalObject) {
  "use strict";

  const sites = Object.freeze([
    { label: "Marco Polo Research Lab", href: "https://mprlab.com" },
    { label: "Gravity Notes", href: "https://gravity.mprlab.com" },
    { label: "LoopAware", href: "https://loopaware.mprlab.com" },
    { label: "Allergy Wheel", href: "https://allergy.mprlab.com" },
    { label: "Social Threader", href: "https://threader.mprlab.com" },
    { label: "RSVP", href: "https://rsvp.mprlab.com" },
    { label: "Countdown Calendar", href: "https://countdown.mprlab.com" },
    { label: "LLM Crossword", href: "https://llm-crossword.mprlab.com" },
    { label: "Prompt Bubbles", href: "https://prompts.mprlab.com" },
    { label: "Wallpapers", href: "https://wallpapers.mprlab.com" },
  ]);

  if (globalObject && typeof globalObject === "object") {
    globalObject.MPR_SITES = sites;
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { MPR_SITES: sites };
  }
})(typeof window !== "undefined" ? window : globalThis);
