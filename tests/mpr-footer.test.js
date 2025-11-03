const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const path = require("node:path");
const fs = require("node:fs/promises");

const SCRIPT_PATH = path.join(__dirname, "..", "web", "mpr-ui.js");

function createVmContext() {
  const hostElement = { innerHTML: "", className: "", classList: { add() {} } };
  const document = {
    querySelector() {
      return hostElement;
    },
    head: {
      appendChild() {},
    },
  };
  const CustomEvent = class CustomEvent {
    constructor(type, options = {}) {
      this.type = type;
      this.detail = options.detail;
      this.bubbles = Boolean(options.bubbles);
    }
  };
  const windowObject = {
    document,
    CustomEvent,
  };
  const context = {
    window: windowObject,
    document,
    CustomEvent,
    console,
  };
  context.globalThis = windowObject;
  return { context, hostElement };
}

test("mpr-ui exposes renderFooter helper", async () => {
  const script = await fs.readFile(SCRIPT_PATH, "utf8");
  const { context, hostElement } = createVmContext();
  vm.runInNewContext(script, context);

  assert.ok(
    context.window.MPRUI,
    "Expected MPRUI namespace after script evaluation",
  );
  assert.equal(
    typeof context.window.MPRUI.renderFooter,
    "function",
    "renderFooter helper should be defined",
  );

  context.window.MPRUI.renderFooter(hostElement, {
    lines: ["Support: support@mprlab.com"],
    copyrightName: "Marco Polo Research Lab",
  });

  assert.ok(
    hostElement.innerHTML.includes("Support: support@mprlab.com"),
    "Footer markup should include provided support line",
  );
  assert.ok(
    hostElement.innerHTML.includes("Marco Polo Research Lab"),
    "Footer markup should include copyright name",
  );
});
