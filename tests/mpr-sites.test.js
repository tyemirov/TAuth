const test = require("node:test");
const assert = require("node:assert/strict");

const { MPR_SITES } = require("../web/mpr-sites.js");

const EXPECTED_SITE_CATALOG = Object.freeze([
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

test("site catalog exports expected URLs and labels", () => {
  assert.equal(Object.isFrozen(MPR_SITES), true, "Expected site catalog to be frozen");
  assert.deepEqual(
    MPR_SITES,
    EXPECTED_SITE_CATALOG,
    "Expected site catalog to match the curated Marco Polo property list",
  );
});
