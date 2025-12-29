// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const { startDemoServer } = require("./support/demoServer");

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

if (!puppeteer) {
  test.skip("demo footer renders in browser", () => {});
} else {
  test("demo footer renders in browser", async (t) => {
    const server = await startDemoServer();
    t.after(() => server.close());

    const launchOptions = {
      headless: "new",
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    };
    if (chromiumExecutable) {
      launchOptions.executablePath = chromiumExecutable;
    }
    const browser = await puppeteer.launch(launchOptions);
    t.after(() => browser.close());

    const page = await browser.newPage();
    await page.goto(`${server.baseUrl}/demo`, { waitUntil: "networkidle0" });

    await page.waitForSelector("mpr-footer", {
      visible: true,
      timeout: 5000,
    });

    const footerState = await page.evaluate(() => {
      const footerRoot = document.querySelector("mpr-footer");
      if (!footerRoot) {
        return null;
      }
      return {
        prefixText: footerRoot.getAttribute("prefix-text"),
        links: footerRoot.getAttribute("links"),
        sticky: footerRoot.getAttribute("sticky"),
      };
    });
    assert.ok(footerState, "Expected footer root element to exist");
    assert.match(footerState.prefixText || "", /Built by/i);
    assert.match(footerState.prefixText || "", /Marco Polo Research Lab/);
    assert.ok(footerState.links, "Expected footer links to be configured");
    assert.equal(footerState.sticky, "true", "Expected footer to opt into sticky layout");

  });
}
