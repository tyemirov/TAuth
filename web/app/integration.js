// @ts-check
import {
  Client,
  RequestError,
  integrationView,
  reauthentication,
  exportedKey,
  setupCheck,
  tenantPath,
} from "./client.js";
/** @typedef {{accounts:{id:{initialize:(options:{client_id:string,nonce:string,auto_select:boolean,callback:(response:{credential:string})=>void})=>void,renderButton:(element:HTMLElement,options:{type:string,size:string})=>void}}}} GoogleIdentity */
/** @typedef {{tenant:import('./client.js').Tenant,config:import('./client.js').Configuration,apiOrigin:string,signal:AbortSignal}} Selection */
/** @param {string} id */
const element = (id) => {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing integration element ${id}`);
  return value;
};
const dialog = /** @type {HTMLDialogElement} */ (element("export-dialog"));
let selection = /** @type {Selection|null} */ (null),
  view = /** @type {import('./client.js').IntegrationView|null} */ (null),
  client = /** @type {Client|null} */ (null);
let etag = "",
  generation = 0,
  exportController = /** @type {AbortController|null} */ (null),
  expiryTimer = 0;
function clearSecret() {
  exportController?.abort();
  exportController = null;
  clearTimeout(expiryTimer);
  element("export-key").textContent = "";
  element("reauth-google").replaceChildren();
  element("export-message").textContent = "";
  element("export-key-panel").hidden = true;
}
function clearSelection() {
  generation++;
  selection = null;
  view = null;
  etag = "";
  clearSecret();
  dialog.close();
  element("browser-example").textContent = "";
  element("backend-example").textContent = "";
  element("proxy-routes").textContent = "";
  element("integration-ready").hidden = true;
  element("setup-result").textContent = "";
  button("run-setup-check").disabled = false;
  element("integration-status").textContent =
    "Select an active tenant to prepare its integration.";
}
dialog.addEventListener("close", clearSecret);
element("dismiss-export").onclick = () => {
  dialog.close();
  element("export-session-key").focus();
};
document.addEventListener("tauth-console:clear-secrets", clearSelection);
window.addEventListener("pagehide", clearSelection);
document.addEventListener("tauth-console:selected", (event) => {
  clearSelection();
  selection = /** @type {CustomEvent<Selection>} */ (event).detail;
  client = new Client(selection.apiOrigin);
  const version = generation;
  const selected = selection;
  if (selected.tenant.state !== "active") {
    element("integration-status").textContent =
      "Activate a saved configuration to prepare its integration.";
    return;
  }
  void client
    .request(
      "GET",
      tenantPath(selected.tenant.id) + "/integration",
      selected.signal,
    )
    .then((result) => {
      if (version !== generation || selected.signal.aborted) return;
      view = integrationView(result.value);
      if (!result.etag) throw new Error("Active revision is unavailable");
      etag = result.etag;
      element("integration-status").textContent =
        `Settings from active revision ${view.revision}. Session lifetime: ${view.session_ttl}.`;
      element("browser-example").textContent = view.browser_html;
      element("backend-example").textContent = JSON.stringify(
        view.backend_configuration,
        null,
        2,
      );
      element("proxy-routes").textContent = view.auth_routes.join("\n");
      element("integration-ready").hidden = false;
      return /** @type {Client} */ (client)
        .collection(
          tenantPath(selected.tenant.id) + "/setup-checks",
          setupCheck,
          selected.signal,
        )
        .then((checks) => {
          if (version !== generation || selected.signal.aborted) return;
          checks.sort(
            (a, b) => Date.parse(b.created_at) - Date.parse(a.created_at),
          );
          const current = checks.find(
            (check) => check.revision === view?.revision,
          );
          renderCheck(current || null);
        });
    })
    .catch((error) => {
      if (version !== generation || selected.signal.aborted) return;
      element("integration-status").textContent =
        error instanceof RequestError &&
        error.code === "management.customer_api_configuration_required"
          ? "Save a customer API origin and Google client ID, then activate that revision."
          : error.message;
    });
});
element("export-session-key").onclick = async () => {
  clearSecret();
  const selected = selection,
    active = view,
    api = client;
  if (!selected || !active || !api) return;
  exportController = new AbortController();
  const controller = exportController;
  const version = generation;
  selected.signal.addEventListener("abort", () => controller.abort(), {
    once: true,
  });
  dialog.showModal();
  element("export-message").textContent =
    "Preparing fresh Google authentication…";
  const failed = (error) => {
    if (!controller.signal.aborted)
      element("export-message").textContent =
        error instanceof Error ? error.message : "Export failed.";
  };
  try {
    const result = await api.request(
      "POST",
      tenantPath(selected.tenant.id) + "/reauthentications",
      controller.signal,
      { revision: active.revision, operation: "session-key-export" },
      etag,
      crypto.randomUUID(),
    );
    const challenge = reauthentication(result.value);
    if (controller.signal.aborted || version !== generation) return;
    expiryTimer = window.setTimeout(
      () => {
        clearSecret();
        element("export-message").textContent =
          "Authentication expired. Close this dialog and start again.";
      },
      Math.max(0, Date.parse(challenge.expires_at) - Date.now()),
    );
    const identity =
      /** @type {Window & typeof globalThis & {google:GoogleIdentity}} */ (
        window
      ).google;
    const bootstrap = await api.bootstrap(controller.signal);
    if (controller.signal.aborted) return;
    identity.accounts.id.initialize({
      client_id: bootstrap.clientId,
      nonce: challenge.nonce,
      auto_select: false,
      callback: (response) => {
        if (controller.signal.aborted || version !== generation) return;
        element("export-message").textContent =
          "Verifying your Google account…";
        void api
          .request(
            "POST",
            tenantPath(selected.tenant.id) + "/key-exports",
            controller.signal,
            {
              reauthentication_id: challenge.id,
              google_id_token: response.credential,
            },
            etag,
            crypto.randomUUID(),
          )
          .then((exported) => {
            if (controller.signal.aborted || version !== generation) return;
            element("export-key").textContent = exportedKey(exported.value);
            element("export-key-panel").hidden = false;
            element("reauth-google").replaceChildren();
            element("export-message").textContent =
              "Install this base64 key only in your backend secret store. Close this dialog when finished.";
          })
          .catch(failed);
      },
    });
    element("export-message").textContent =
      "Use the Google account that owns this tenant. This transaction expires in five minutes.";
    identity.accounts.id.renderButton(element("reauth-google"), {
      type: "standard",
      size: "large",
    });
  } catch (error) {
    failed(error);
  }
};

/** @param {string} id */
function button(id) {
  return /** @type {HTMLButtonElement} */ (element(id));
}
/** @param {import('./client.js').SetupCheck|null} check */
function renderCheck(check) {
  element("setup-result").textContent = check
    ? `Revision ${check.revision}: ${check.state} at ${new Date(check.created_at).toLocaleString()}\n${check.evidence.map((e) => `${e.path || "Destination"}: ${e.code} (${e.status})`).join("\n")}${selection?.config.revision !== check.revision ? "\nSaved changes require activation and a new check." : ""}`
    : "No setup check for this active revision.";
}
button("run-setup-check").onclick = async () => {
  const selected = selection,
    active = view,
    api = client,
    version = generation;
  if (!selected || !active || !api) return;
  button("run-setup-check").disabled = true;
  element("setup-result").textContent = "Checking the active revision…";
  try {
    const result = await api.request(
      "POST",
      tenantPath(selected.tenant.id) + "/setup-checks",
      selected.signal,
      { revision: active.revision },
      etag,
      crypto.randomUUID(),
    );
    if (version === generation && !selected.signal.aborted)
      renderCheck(setupCheck(result.value));
  } catch (error) {
    if (version === generation && !selected.signal.aborted)
      element("setup-result").textContent =
        error instanceof Error ? error.message : "Setup check failed.";
  } finally {
    if (version === generation) button("run-setup-check").disabled = false;
  }
};
