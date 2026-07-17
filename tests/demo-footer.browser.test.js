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

    await page.waitForSelector("footer#page-footer", {
      visible: true,
      timeout: 5000,
    });

    const footerState = await page.evaluate(() => {
      const footerRoot = document.querySelector("footer#page-footer");
      if (!footerRoot) {
        return null;
      }
      return {
        text: footerRoot.textContent,
        links: footerRoot.querySelectorAll("a").length,
      };
    });
    assert.ok(footerState, "Expected footer root element to exist");
    assert.match(footerState.text || "", /TAuth demonstration/);
    assert.ok(footerState.links > 0, "Expected footer links to be configured");

  });
}
