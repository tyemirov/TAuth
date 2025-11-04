const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");

let puppeteer = null;
try {
  puppeteer = require("puppeteer-core");
} catch (error) {
  puppeteer = null;
}

const chromiumExecutable = process.env.CHROMIUM_PATH || "";

async function startDemoServer() {
  const demoHtml = await fs.readFile(
    path.join(__dirname, "..", "web", "demo.html"),
    "utf8",
  );
  const authClientSource = await fs.readFile(
    path.join(__dirname, "..", "web", "auth-client.js"),
    "utf8",
  );
  const footerSource = await fs.readFile(
    path.join(__dirname, "..", "tools", "mpr-ui", "footer.js"),
    "utf8",
  );

  const server = http.createServer((request, response) => {
    const { url, method } = request;
    if (method === "GET" && (url === "/" || url === "/demo" || url === "/demo.html")) {
      response.statusCode = 200;
      response.setHeader("Content-Type", "text/html; charset=utf-8");
      response.end(demoHtml);
      return;
    }
    if (method === "GET" && url === "/static/auth-client.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.end(authClientSource);
      return;
    }
    if (method === "GET" && url === "/me") {
      response.statusCode = 401;
      response.setHeader("Content-Type", "application/json; charset=utf-8");
      response.end(JSON.stringify({ error: "unauthenticated" }));
      return;
    }
    if (method === "POST" && url === "/auth/refresh") {
      response.statusCode = 401;
      response.setHeader("Content-Type", "application/json; charset=utf-8");
      response.end(JSON.stringify({ error: "refresh_denied" }));
      return;
    }
    if (method === "POST" && url === "/auth/nonce") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/json; charset=utf-8");
      response.end(JSON.stringify({ nonce: "demo-nonce" }));
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    baseUrl,
    footerSource,
    close() {
      return new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    },
  };
}

if (!puppeteer || !chromiumExecutable) {
  test.skip("demo footer renders in browser", () => {});
} else {
  test("demo footer renders in browser", async (t) => {
    const server = await startDemoServer();
    t.after(() => server.close());

    const browser = await puppeteer.launch({
      executablePath: chromiumExecutable,
      headless: "new",
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });
    t.after(() => browser.close());

    const page = await browser.newPage();
    await page.route(
      "https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@main/footer.js*",
      (route) => {
        route.fulfill({
          status: 200,
          contentType: "application/javascript; charset=utf-8",
          body: server.footerSource,
        });
      },
    );

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
      timeout: 2000,
    });
    const ariaExpanded = await page.$eval(
      toggleSelector,
      (node) => node.getAttribute("aria-expanded"),
    );
    assert.equal(ariaExpanded, "true");
    await page.click(toggleSelector);
    await page.waitForTimeout(100);
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
    const initialTheme = await page.evaluate(
      () => document.body.getAttribute("data-bs-theme"),
    );
    await page.click(themeToggleSelector);
    await page.waitForTimeout(50);
    const darkTheme = await page.evaluate(
      () => document.body.getAttribute("data-bs-theme"),
    );
    assert.equal(darkTheme, "dark", "Expected theme toggle to enable dark theme");
    await page.click(themeToggleSelector);
    await page.waitForTimeout(50);
    const finalTheme = await page.evaluate(
      () => document.body.getAttribute("data-bs-theme"),
    );
    assert.equal(finalTheme, initialTheme, "Expected second toggle to restore initial theme");
  });
}
