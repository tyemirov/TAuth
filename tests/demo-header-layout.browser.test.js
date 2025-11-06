const test = require("node:test");
const assert = require("node:assert/strict");
const { startDemoServer } = require("./support/demoServer");
const { interceptMprUiRequest } = require("./support/interceptMprUi");
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
    const removeIntercept = await interceptMprUiRequest(
      page,
      server.mprUiSource,
    );
    t.after(() => removeIntercept());

    await page.goto(`${server.baseUrl}/demo`, { waitUntil: "networkidle0" });

    await page.waitForSelector("header.mpr-header", {
      visible: true,
      timeout: 5000,
    });

    const headerState = await page.evaluate(() => {
      const header = document.querySelector("header.mpr-header");
      if (!header) {
        return null;
      }
      const rect = header.getBoundingClientRect();
      const style = window.getComputedStyle(header);
      return {
        position: style.position,
        topStyle: style.top,
        topBefore: rect.top,
        width: rect.width,
        viewportWidth: window.innerWidth,
      };
    });

    assert.ok(headerState, "expected to capture header state");
    assert.equal(headerState.position, "sticky");
    assert.equal(headerState.topStyle, "0px");
    assert.ok(
      Math.abs(headerState.width - headerState.viewportWidth) <= 2,
      "expected header to span the viewport width",
    );

    const navLinkStates = await page.$$eval("header.mpr-header nav a", (nodes) =>
      nodes.map((node) => ({
        target: node.getAttribute("target"),
        rel: node.getAttribute("rel") || "",
      })),
    );
    assert.ok(navLinkStates.length > 0, "expected navigation links to be present");
    navLinkStates.forEach((linkState) => {
      assert.equal(linkState.target, "_blank", "expected nav link to open in a new tab");
      assert.ok(
        /\bnoopener\b/.test(linkState.rel),
        "expected nav link to include noopener in rel attribute",
      );
    });

    await page.evaluate(() => window.scrollTo(0, 600));
    await delay(120);

    const topAfterScroll = await page.evaluate(() => {
      const header = document.querySelector("header.mpr-header");
      if (!header) {
        return null;
      }
      return header.getBoundingClientRect().top;
    });

    assert.notEqual(topAfterScroll, null);
    assert.ok(
      topAfterScroll !== null && Math.abs(topAfterScroll) <= 1,
      `expected header to remain pinned after scrolling (top=${topAfterScroll})`,
    );
  });
}
