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

    await page.waitForSelector("header#demo-header", { timeout: 5000 });

    const headerState = await page.evaluate(() => {
      const headerHost = document.querySelector("header#demo-header");
      if (!headerHost) {
        return null;
      }
      return {
        position: getComputedStyle(headerHost).position,
        navLinks: headerHost.querySelectorAll("nav a").length,
        brandLabel: headerHost.querySelector(".demo-brand")?.textContent,
      };
    });

    assert.ok(headerState, "expected to capture header state");
    assert.equal(headerState.brandLabel, "TAuth");
    assert.ok(headerState.navLinks > 0, "expected navigation links to be configured");
    assert.equal(headerState.position, "sticky", "expected header to use sticky layout");

    await page.evaluate(() => window.scrollTo(0, 600));
    await delay(120);

    const topAfterScroll = await page.evaluate(() => {
      const headerHost = document.querySelector("header#demo-header");
      if (!headerHost) {
        return null;
      }
      return headerHost.getBoundingClientRect().top;
    });

    assert.notEqual(topAfterScroll, null);
    assert.ok(topAfterScroll !== null, "expected header to remain in the layout");
  });
}
