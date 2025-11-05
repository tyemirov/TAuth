const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const path = require("node:path");
const fs = require("node:fs/promises");

const SCRIPT_PATH = path.join(
  __dirname,
  "..",
  "tools",
  "mpr-ui",
  "mpr-ui.js",
);

function createVmContext() {
  const hostElement = {
    innerHTML: "",
    className: "",
    classList: { add() {}, remove() {} },
    setAttribute() {},
    querySelector() {
      return null;
    },
  };
  const document = {
    querySelector() {
      return hostElement;
    },
    createElement() {
      return {
        setAttribute() {},
        appendChild() {},
        textContent: "",
        styleSheet: null,
      };
    },
    createTextNode() {
      return {};
    },
    head: {
      appendChild() {},
      querySelector() {
        return null;
      },
    },
    getElementById() {
      return null;
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
    prefixText: "Built by",
    links: [{ label: "Support", href: "mailto:support@mprlab.com" }],
  });

  assert.ok(
    hostElement.innerHTML && hostElement.innerHTML.length > 0,
    "Footer markup should be rendered into the host element",
  );
});
