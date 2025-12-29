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

  const demoProfile = Object.freeze({
    user_id: "demo-user",
    user_email: "demo@example.com",
    display: "Demo User",
    avatar_url: "https://example.com/avatar.png",
    roles: ["user"],
  });
  let activeProfile = null;

  const server = http.createServer((request, response) => {
    const { url, method } = request;
    const requestPath = url ? url.split("?")[0] : "";
    if (
      method === "GET" &&
      (requestPath === "/" ||
        requestPath === "/demo" ||
        requestPath === "/demo.html")
    ) {
      response.statusCode = 200;
      response.setHeader("Content-Type", "text/html; charset=utf-8");
      response.end(demoHtml);
      return;
    }
    if (method === "GET" && requestPath === "/tauth.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.end(authClientSource);
      return;
    }
    if (method === "GET" && requestPath === "/demo-config.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.end(demoConfigSource);
      return;
    }
    if (method === "GET" && requestPath === "/tauth-config.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.end(authConfigSource);
      return;
    }
    if (method === "GET" && requestPath === "/status-panel.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.end(statusPanelSource);
      return;
    }
    if (method === "GET" && requestPath === "/me") {
      if (activeProfile) {
        response.statusCode = 200;
        response.setHeader("Content-Type", "application/json; charset=utf-8");
        response.end(JSON.stringify(activeProfile));
        return;
      }
      response.statusCode = 401;
      response.setHeader("Content-Type", "application/json; charset=utf-8");
      response.end(JSON.stringify({ error: "unauthenticated" }));
      return;
    }
    if (method === "POST" && requestPath === "/auth/refresh") {
      if (activeProfile) {
        response.statusCode = 204;
        response.end();
        return;
      }
      response.statusCode = 401;
      response.setHeader("Content-Type", "application/json; charset=utf-8");
      response.end(JSON.stringify({ error: "refresh_denied" }));
      return;
    }
    if (method === "POST" && requestPath === "/auth/nonce") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/json; charset=utf-8");
      response.end(JSON.stringify({ nonce: "demo-nonce" }));
      return;
    }
    if (method === "POST" && requestPath === "/auth/google") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/json; charset=utf-8");
      activeProfile = demoProfile;
      response.end(JSON.stringify(demoProfile));
      return;
    }
    if (method === "POST" && requestPath === "/auth/logout") {
      activeProfile = null;
      response.statusCode = 204;
      response.end();
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
