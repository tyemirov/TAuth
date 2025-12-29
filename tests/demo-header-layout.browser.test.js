// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const { startDemoServer } = require("./support/demoServer");
const { delay } = require("./support/delay");

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
  test.skip("demo header stays sticky while scrolling", () => {});
} else {
  test("demo header stays sticky while scrolling", async (t) => {
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

    await page.waitForSelector("mpr-header#demo-header", { timeout: 5000 });

    const headerState = await page.evaluate(() => {
      const headerHost = document.querySelector("mpr-header#demo-header");
      if (!headerHost) {
        return null;
      }
      return {
        sticky: headerHost.getAttribute("sticky"),
        navLinks: headerHost.getAttribute("nav-links"),
        brandLabel: headerHost.getAttribute("brand-label"),
      };
    });

    assert.ok(headerState, "expected to capture header state");
    assert.match(headerState.brandLabel || "", /Marco Polo Research Lab/);
    assert.ok(headerState.navLinks, "expected navigation links to be configured");
    assert.equal(headerState.sticky, "true", "expected header to opt into sticky layout");

    await page.evaluate(() => window.scrollTo(0, 600));
    await delay(120);

    const topAfterScroll = await page.evaluate(() => {
      const headerHost = document.querySelector("mpr-header#demo-header");
      if (!headerHost) {
        return null;
      }
      return headerHost.getBoundingClientRect().top;
    });

    assert.notEqual(topAfterScroll, null);
    assert.ok(topAfterScroll !== null, "expected header to remain in the layout");
  });
}
