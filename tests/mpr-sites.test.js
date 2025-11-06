const test = require("node:test");
const assert = require("node:assert/strict");

const { MPR_SITES } = require("../web/mpr-sites.js");

const EXPECTED_SITE_CATALOG = Object.freeze([
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

test("site catalog exports expected URLs and labels", () => {
  assert.equal(Object.isFrozen(MPR_SITES), true, "Expected site catalog to be frozen");
  assert.deepEqual(
    MPR_SITES,
    EXPECTED_SITE_CATALOG,
    "Expected site catalog to match the curated Marco Polo property list",
  );
});
