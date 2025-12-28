// @ts-check
const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const { loadMprUiScript } = require("./support/mprUiCdn");

const MPR_UI_CDN_URL =
  "https://cdn.jsdelivr.net/gh/MarcoPoloResearchLab/mpr-ui@3.1.0/mpr-ui.js";

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

function createFooterHost() {
  let innerHTMLValue = "";
  const hostAttributes = {};
  const footerAttributes = {};
  const stickySpacer = {
    style: {},
    setAttribute() {},
    removeAttribute() {},
  };
  const footerRoot = {
    className: "",
    classList: { add() {}, remove() {} },
    setAttribute(name, value) {
      footerAttributes[name] = String(value);
    },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(footerAttributes, name)
        ? footerAttributes[name]
        : null;
    },
    removeAttribute(name) {
      delete footerAttributes[name];
    },
    getBoundingClientRect() {
      return { height: 0 };
    },
    querySelector() {
      return null;
    },
    querySelectorAll() {
      return [];
    },
  };
  return {
    hostElement: {
      get innerHTML() {
        return innerHTMLValue;
      },
      set innerHTML(value) {
        innerHTMLValue = value;
      },
      setAttribute(name, value) {
        hostAttributes[name] = String(value);
      },
      removeAttribute(name) {
        delete hostAttributes[name];
      },
      querySelector(selector) {
        if (
          selector === 'footer[role="contentinfo"]' ||
          selector === '[data-mpr-footer="root"]' ||
          selector === "footer.mpr-footer"
        ) {
          return footerRoot;
        }
        if (selector === '[data-mpr-footer="sticky-spacer"]') {
          return stickySpacer;
        }
        return null;
      },
    },
    footerRoot,
  };
}

test("mpr-ui exposes mountFooterDom helper", async () => {
  const script = await loadMprUiScript(MPR_UI_CDN_URL);
  const { context } = createVmContext();
  vm.runInNewContext(script, context);

  assert.ok(
    context.window.MPRUI,
    "Expected MPRUI namespace after script evaluation",
  );
  const mountFooterDom =
    context.window.MPRUI &&
    context.window.MPRUI.__dom &&
    context.window.MPRUI.__dom.mountFooterDom;
  assert.equal(
    typeof mountFooterDom,
    "function",
    "mountFooterDom helper should be defined",
  );

  const { hostElement, footerRoot } = createFooterHost();
  const footerElement = mountFooterDom(hostElement, {
    linksMenuEnabled: false,
    themeToggle: { enabled: false },
    privacyLinkHref: "#",
    privacyLinkLabel: "Privacy • Terms",
  });

  assert.ok(
    hostElement.innerHTML && hostElement.innerHTML.length > 0,
    "Footer markup should be rendered into the host element",
  );
  assert.equal(
    footerRoot.getAttribute("data-mpr-footer-root"),
    "true",
    "Footer root should be marked for styling",
  );
  assert.equal(
    footerElement,
    footerRoot,
    "mountFooterDom should return the footer root element",
  );
});
