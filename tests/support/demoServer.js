"use strict";

const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");

async function startDemoServer() {
  const [demoHtml, authClientSource, sitesSource, mprUiSource] = await Promise.all([
    fs.readFile(path.join(__dirname, "..", "..", "web", "demo.html"), "utf8"),
    fs.readFile(path.join(__dirname, "..", "..", "web", "auth-client.js"), "utf8"),
    fs.readFile(path.join(__dirname, "..", "..", "web", "mpr-sites.js"), "utf8"),
    fs.readFile(path.join(__dirname, "..", "..", "tools", "mpr-ui", "mpr-ui.js"), "utf8"),
  ]);

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
    if (method === "GET" && url === "/static/mpr-sites.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.end(sitesSource);
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
    if (method === "POST" && url === "/auth/google") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/json; charset=utf-8");
      response.end(
        JSON.stringify({
          user_id: "demo-user",
          user_email: "demo@example.com",
          display: "Demo User",
          avatar_url: "https://example.com/avatar.png",
        }),
      );
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    baseUrl,
    mprUiSource,
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

module.exports = {
  startDemoServer,
};
