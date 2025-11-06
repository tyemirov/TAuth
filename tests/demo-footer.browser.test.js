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
    const removeIntercept = await interceptMprUiRequest(
      page,
      server.mprUiSource,
    );
    t.after(() => removeIntercept());

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
    assert.match(footerText, /Privacy • Terms/);

    const displayValue = await page.$eval("#landing-footer", (node) => {
      const style = window.getComputedStyle(node);
      return style ? style.display : "";
    });
    assert.notEqual(displayValue, "none");

    const toggleSelector = "#landing-footer [data-mpr-footer='toggle-button']";
    await page.click(toggleSelector);
    await page.waitForSelector("#landing-footer .dropdown-menu.show", {
      visible: true,
      timeout: 5000,
    });
    const ariaExpanded = await page.$eval(
      toggleSelector,
      (node) => node.getAttribute("aria-expanded"),
    );
    assert.equal(ariaExpanded, "true");
    await page.click(toggleSelector);
    await delay(100);
    const ariaCollapsed = await page.$eval(
      toggleSelector,
      (node) => node.getAttribute("aria-expanded"),
    );
    assert.equal(ariaCollapsed, "false");
    const menuVisible = await page.$eval(
      "#landing-footer .dropdown-menu",
      (node) => node.classList.contains("show"),
    );
    assert.equal(menuVisible, false, "Expected dropdown menu to close");

    const themeToggleSelector = "#public-theme-toggle";
    const initialTheme = await page.evaluate(() =>
      window.MPRUI ? window.MPRUI.getThemeMode() : null,
    );
    await page.click(themeToggleSelector);
    await delay(150);
    const toggledTheme = await page.evaluate(() =>
      window.MPRUI ? window.MPRUI.getThemeMode() : null,
    );
    assert.notEqual(
      toggledTheme,
      initialTheme,
      "Expected theme toggle to switch the active mode",
    );
    const docThemeAttribute = await page.evaluate(() =>
      document.documentElement.getAttribute("data-mpr-theme"),
    );
    assert.equal(
      docThemeAttribute,
      toggledTheme,
      "Expected document theme attribute to match active mode",
    );
    await page.click(themeToggleSelector);
    await delay(150);
    const finalTheme = await page.evaluate(() =>
      window.MPRUI ? window.MPRUI.getThemeMode() : null,
    );
    assert.equal(
      finalTheme,
      initialTheme,
      "Expected second toggle to restore the original theme mode",
    );
  });
}
