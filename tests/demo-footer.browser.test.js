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

    await page.waitForSelector("#landing-footer", {
      visible: true,
      timeout: 5000,
    });

    const footerText = await page.$eval(
      "#landing-footer",
      (node) => node.textContent || "",
    );
    assert.match(footerText, /Built by/i);
    assert.match(footerText, /Marco Polo Research Lab/);

    const footerState = await page.evaluate(() => {
      const footerRoot = document.querySelector("#landing-footer");
      if (!footerRoot) {
        return null;
      }
      const rect = footerRoot.getBoundingClientRect();
      const style = window.getComputedStyle(footerRoot);
      return {
        position: style.position,
        width: rect.width,
        viewportWidth: window.innerWidth,
        left: rect.left,
      };
    });
    assert.ok(footerState, "Expected footer root element to exist");
    assert.equal(footerState.position, "fixed");
    assert.ok(
      Math.abs(footerState.width - footerState.viewportWidth) <= 2,
      "Expected footer to span the viewport width",
    );
    assert.ok(
      footerState.left >= -1 && footerState.left <= 1,
      "Expected footer to align with the viewport edge",
    );

    const linkStates = await page.$$eval(
      "#landing-footer a",
      (nodes) =>
        nodes.map((node) => ({
          target: node.getAttribute("target"),
          rel: node.getAttribute("rel") || "",
        })),
    );
    assert.ok(linkStates.length > 0, "Expected footer links to be present");
    linkStates.forEach((state) => {
      assert.equal(state.target, "_blank", "Expected footer link to open in a new tab");
      assert.ok(/\bnoopener\b/.test(state.rel), "Expected footer link to include noopener");
    });
  });
}
