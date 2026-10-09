// @ts-check

const STORAGE_KEY = "tauth.console.palette";
const CHANGE_EVENT = "mpr-ui:theme-change";
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

/**
 * @param {HTMLElement} footer
 * @param {(error: Error) => void} reportError
 * @returns {() => void}
 */
export function initializePalette(footer, reportError) {
  const storedMode = localStorage.getItem(STORAGE_KEY);
  if (storedMode !== null && !MODES.some((mode) => mode.value === storedMode)) {
    throw new Error("Stored color palette is invalid.");
  }
  footer.setAttribute(
    "theme-config",
    JSON.stringify({
      attribute: "data-mpr-theme",
      targets: ["document", "body"],
      initialMode: storedMode ?? DEFAULT_MODE,
      modes: MODES,
    }),
  );

  /** @param {Event} event */
  function persistPalette(event) {
    const { mode } = /** @type {CustomEvent<{mode: string}>} */ (event).detail;
    if (!MODES.some((candidate) => candidate.value === mode)) {
      throw new Error("Selected color palette is invalid.");
    }
    try {
      localStorage.setItem(STORAGE_KEY, mode);
    } catch (error) {
      reportError(
        new Error(`Color palette could not be stored: ${error.message}`),
      );
    }
  }
  document.addEventListener(CHANGE_EVENT, persistPalette);
  return () => document.removeEventListener(CHANGE_EVENT, persistPalette);
}
