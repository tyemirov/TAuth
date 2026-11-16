// @ts-check

const STORAGE_KEY = "tauth.console.palette";
const CHANGE_EVENT = "mpr-ui:theme-change";
const STORAGE_ERROR_EVENT = "mpr-ui:theme-storage-error";
const STORAGE_EVENT = "storage";
const PAGE_SHOW_EVENT = "pageshow";
const FOCUS_EVENT = "focus";
const VISIBILITY_EVENT = "visibilitychange";
const DEFAULT_MODE = "default-dark";
const MODES = [
  {
    value: "default-light",
    attributeValue: "light",
    dataset: { "data-tauth-palette": "default" },
  },
  {
    value: "sunrise-light",
    attributeValue: "light",
    dataset: { "data-tauth-palette": "sunrise" },
  },
  {
    value: DEFAULT_MODE,
    attributeValue: "dark",
    dataset: { "data-tauth-palette": "default" },
  },
  {
    value: "forest-dark",
    attributeValue: "dark",
    dataset: { "data-tauth-palette": "forest" },
  },
];

function readPalette() {
  const storedMode = localStorage.getItem(STORAGE_KEY);
  if (storedMode !== null && !MODES.some((mode) => mode.value === storedMode)) {
    throw new Error("Stored color palette is invalid.");
  }
  return storedMode ?? DEFAULT_MODE;
}

/**
 * @param {HTMLElement} footer
 * @param {(error: Error) => void} reportError
 * @returns {() => void}
 */
export function initializePalette(footer, reportError) {
  let currentMode = readPalette();
  let disposed = false;
  function applyPalette(mode = currentMode) {
    footer.setAttribute(
      "theme-config",
      JSON.stringify({
        attribute: "data-mpr-theme",
        targets: ["document", "body"],
        initialMode: mode,
        storageKey: STORAGE_KEY,
        modes: MODES,
      }),
    );
  }
  applyPalette();

  async function synchronizePalette() {
    try {
      await customElements.whenDefined("mpr-footer");
      if (disposed) return;
      const mode = readPalette();
      if (mode !== currentMode) {
        applyPalette(mode);
        const themeUI = /** @type {Window & {MPRUI: {configureTheme: (config: {initialMode: string}) => void}}} */ (/** @type {unknown} */ (window)).MPRUI;
        themeUI.configureTheme({ initialMode: mode });
        currentMode = mode;
      }
    } catch (error) {
      reportError(
        new Error(`Color palette could not be synchronized: ${error.message}`),
      );
    }
  }

  /** @param {StorageEvent} event */
  function storageChanged(event) {
    if (
      event.storageArea === localStorage &&
      (event.key === STORAGE_KEY || event.key === null)
    ) {
      synchronizePalette();
    }
  }

  function visibilityChanged() {
    if (document.visibilityState === "visible") synchronizePalette();
  }

  /** @param {Event} event */
  function paletteChanged(event) {
    const { mode } = /** @type {CustomEvent<{mode: string}>} */ (event).detail;
    currentMode = mode;
  }
  /** @param {Event} event */
  function storageFailed(event) {
    const { message } = /** @type {CustomEvent<{message: string}>} */ (event).detail;
    reportError(new Error(`Color palette could not be stored: ${message}`));
  }
  document.addEventListener(CHANGE_EVENT, paletteChanged);
  footer.addEventListener(STORAGE_ERROR_EVENT, storageFailed);
  window.addEventListener(STORAGE_EVENT, storageChanged);
  window.addEventListener(PAGE_SHOW_EVENT, synchronizePalette);
  window.addEventListener(FOCUS_EVENT, synchronizePalette);
  document.addEventListener(VISIBILITY_EVENT, visibilityChanged);
  return () => {
    disposed = true;
    document.removeEventListener(CHANGE_EVENT, paletteChanged);
    footer.removeEventListener(STORAGE_ERROR_EVENT, storageFailed);
    window.removeEventListener(STORAGE_EVENT, storageChanged);
    window.removeEventListener(PAGE_SHOW_EVENT, synchronizePalette);
    window.removeEventListener(FOCUS_EVENT, synchronizePalette);
    document.removeEventListener(VISIBILITY_EVENT, visibilityChanged);
  };
}
