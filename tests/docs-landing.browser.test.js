// @ts-check
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

let puppeteer = null;
try {
  puppeteer = require("puppeteer");
} catch (primaryError) {
  try {
    puppeteer = require("puppeteer-core");
  } catch (_secondaryError) {
    puppeteer = null;
  }
}

const chromiumExecutable = process.env.CHROMIUM_PATH || "";
const DOCS_INDEX_PATH = path.join(__dirname, "..", "docs", "index.html");

if (!puppeteer) {
  test.skip("docs landing renders key sections", () => {});
} else {
  test("docs landing renders key sections", async (testingHandle) => {
    const launchOptions = {
      headless: "new",
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    };
    if (chromiumExecutable) {
      launchOptions.executablePath = chromiumExecutable;
    }
    const browser = await puppeteer.launch(launchOptions);
    testingHandle.after(() => browser.close());

    const page = await browser.newPage();
    const docsUrl = pathToFileURL(DOCS_INDEX_PATH).href;
    await page.goto(docsUrl, { waitUntil: "domcontentloaded" });

    const sectionSelectors = ["#features", "#blueprint", "#deep-dive", "#palette", "#docs"];
    for (const selector of sectionSelectors) {
      await page.waitForSelector(selector, { timeout: 3000 });
    }

    const heroText = await page.$eval("h1", (node) => node.textContent || "");
    assert.match(heroText, /own the session/i);

    const featureCount = await page.$$eval(".feature-card", (nodes) => nodes.length);
    assert.ok(featureCount >= 3, "Expected at least three feature cards");

    const footerLinksValue = await page.$eval(
      "mpr-footer",
      (node) => node.getAttribute("links-collection") || "",
    );
    const footerLinks = JSON.parse(footerLinksValue);
    const footerLabels = footerLinks.links.map((link) => link.label);
    assert.deepEqual(footerLabels, ["GitHub", "Docs", "Community"]);
  });
}
