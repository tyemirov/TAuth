// @ts-check
"use strict";

const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");
async function startDemoServer() {
  const demoRoot = path.join(__dirname, "..", "..", "examples", "tauth-demo");
  const [
    demoHtml,
    authClientSource,
    demoConfigSource,
    authConfigSource,
    statusPanelSource,
  ] = await Promise.all([
    fs.readFile(path.join(demoRoot, "index.html"), "utf8"),
    fs.readFile(path.join(__dirname, "..", "..", "web", "tauth.js"), "utf8"),
    fs.readFile(path.join(demoRoot, "demo-config.js"), "utf8"),
    fs.readFile(path.join(demoRoot, "tauth-config.js"), "utf8"),
    fs.readFile(path.join(demoRoot, "status-panel.js"), "utf8"),
  ]);

  const server = http.createServer((request, response) => {
    const { url, method } = request;
    if (method === "GET" && (url === "/" || url === "/demo" || url === "/demo.html")) {
      response.statusCode = 200;
      response.setHeader("Content-Type", "text/html; charset=utf-8");
      response.end(demoHtml);
      return;
    }
    if (method === "GET" && url === "/tauth.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.end(authClientSource);
      return;
    }
    if (method === "GET" && url === "/demo-config.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.end(demoConfigSource);
      return;
    }
    if (method === "GET" && url === "/tauth-config.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.end(authConfigSource);
      return;
    }
    if (method === "GET" && url === "/status-panel.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.end(statusPanelSource);
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
