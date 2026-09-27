// @ts-check
import "./integration.js";
import {
  Client,
  PATHS,
  RequestError,
  configuration,
  loadClient,
  ownerAccount,
  tenant,
  tenantPath,
} from "./client.js";
/** @typedef {import('./client.js').Tenant} Tenant */
/** @typedef {Awaited<ReturnType<Client['selected']>>} Selected */
/** @param {string} id */
const el = (id) => {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing workspace element ${id}`);
  return node;
};
/** @param {string} id */ const input = (id) =>
  /** @type {HTMLInputElement} */ (el(id));
const form = /** @type {HTMLFormElement} */ (el("configuration"));
const dialog = /** @type {HTMLDialogElement} */ (el("tenant-dialog"));
const suspendDialog = /** @type {HTMLDialogElement} */ (el("suspend-dialog"));
const sections = ["overview", "domains", "signin", "integration", "settings"];
let client = /** @type {Client|null} */ (null),
  selected = /** @type {Selected|null} */ (null);
let tenants = /** @type {Tenant[]} */ ([]),
  controller = new AbortController(),
  epoch = 0,
  authenticated = false,
  busy = false;
let section = "overview",
  dialogIntent = "create",
  dialogKey = "",
  returnFocus = /** @type {HTMLElement|null} */ (null);
/** @param {string} message */ const notice = (message) => {
  el("notice").textContent = message;
};
function clearProtected() {
  controller.abort();
  controller = new AbortController();
  epoch++;
  selected = null;
  tenants = [];
  busy = false;
  form.reset();
  /** @type {HTMLFormElement} */ (el("tenant-form")).reset();
  el("workspace").hidden = true;
  el("tenant-detail").hidden = true;
  el("tenant-list").replaceChildren();
  el("tenant-select").replaceChildren();
  el("admin-accounts").hidden = true;
  el("account-list").replaceChildren();
  el("accounts-status").textContent = "";
  for (const id of [
    "tenant-name",
    "tenant-id",
    "providers",
    "proofs",
    "proof-actions",
    "field-error",
    "google-origins",
    "provider-summary",
    "active-revision",
    "draft-revision",
    "tenant-state",
    "next-step",
    "dialog-error",
  ])
    el(id).replaceChildren();
  dialog.close();
  suspendDialog.close();
  document.dispatchEvent(new Event("tauth-console:clear-secrets"));
}
function signOut() {
  authenticated = false;
  clearProtected();
  el("signed-out").hidden = false;
  notice("Sign in to manage your tenants.");
}
/** @param {unknown} error */
function showError(error) {
  if (error instanceof DOMException && error.name === "AbortError") return;
  if (error instanceof RequestError && error.status === 401) {
    signOut();
    return;
  }
  const message =
    error instanceof RequestError && error.status === 412
      ? "This configuration changed in another session. Reload it before saving."
      : error instanceof Error
        ? error.message
        : "The request failed.";
  notice(message);
  el("field-error").textContent = message;
  el("dialog-error").textContent = message;
  if (error instanceof RequestError) {
    const fields = {
      "management.session_ttl_invalid": ["session-ttl", "settings"],
      "management.refresh_ttl_invalid": ["refresh-ttl", "settings"],
      "management.origin_invalid": ["frontend-origins", "domains"],
      "management.name_invalid": ["new-name", ""],
    };
    const field = fields[error.code];
    if (field) {
      if (field[1]) showSection(field[1]);
      input(field[0]).setAttribute("aria-invalid", "true");
      input(field[0]).setAttribute(
        "aria-describedby",
        field[0] === "new-name" ? "dialog-error" : "field-error",
      );
      input(field[0]).focus();
    }
  }
  el("reload").hidden = !(
    error instanceof RequestError && error.status === 412
  );
}
function canActivate() {
  if (!selected) return false;
  const { tenant, config, proofs } = selected;
  if (tenant.state === "active" && tenant.active_revision === config.revision)
    return false;
  if (
    !config.google_web_client_id ||
    !config.frontend_origins.length ||
    !config.api_base_url
  )
    return false;
  if (config.local_development) return true;
  return [...config.frontend_origins, config.api_base_url].every((address) =>
    proofs.some(
      (proof) =>
        proof.hostname === new URL(address).hostname &&
        proof.revision === config.revision &&
        proof.state === "verified" &&
        Date.parse(proof.expires_at) > Date.now(),
    ),
  );
}
/** @param {boolean} pending */
function pending(pending) {
  busy = pending;
  document
    .querySelectorAll("#configuration button,#confirm-tenant,#confirm-suspend")
    .forEach((node) => {
      /** @type {HTMLButtonElement} */ (node).disabled =
        pending ||
        (node.id === "activate" && !canActivate()) ||
        node.getAttribute("data-expired") === "true";
    });
}
/** @param {(api:Client,signal:AbortSignal)=>Promise<void>} operation */
async function action(operation) {
  if (!client || busy) return;
  const version = epoch;
  const signal = controller.signal;
  pending(true);
  el("field-error").textContent = "";
  document
    .querySelectorAll("[aria-invalid]")
    .forEach((node) => node.removeAttribute("aria-invalid"));
  el("dialog-error").textContent = "";
  notice("Saving…");
  try {
    await operation(client, signal);
  } catch (error) {
    if (version === epoch) showError(error);
  } finally {
    if (version === epoch) pending(false);
  }
}
function drawCollection() {
  const list = el("tenant-list"),
    select = el("tenant-select");
  list.replaceChildren();
  select.replaceChildren();
  for (const item of tenants) {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.tenant = item.id;
    const title = document.createElement("strong");
    title.textContent = item.name;
    const code = document.createElement("code");
    code.textContent = item.id;
    button.append(title, code);
    button.setAttribute(
      "aria-current",
      selected?.tenant.id === item.id ? "page" : "false",
    );
    button.onclick = () => void selectTenant(item.id, true);
    list.append(button);
    const option = document.createElement("option");
    option.value = item.id;
    option.textContent = item.name;
    select.append(option);
  }
  if (selected)
    /** @type {HTMLSelectElement} */ (select).value = selected.tenant.id;
  el("empty").hidden = tenants.length > 0;
}
/** @param {string} next */
function showSection(next) {
  section = sections.includes(next) ? next : "overview";
  document.querySelectorAll("[data-panel]").forEach((node) => {
    /** @type {HTMLElement} */ (node).hidden =
      node.getAttribute("data-panel") !== section;
  });
  document
    .querySelectorAll("[data-section]")
    .forEach((node) =>
      node.setAttribute(
        "aria-current",
        node.getAttribute("data-section") === section ? "page" : "false",
      ),
    );
  el("save-actions").hidden = !["domains", "signin", "settings"].includes(
    section,
  );
  if (selected)
    history.replaceState(
      null,
      "",
      `#${new URLSearchParams({ tenant: selected.tenant.id, section })}`,
    );
}
function render() {
  if (!selected) return;
  const { tenant: current, config, proofs } = selected;
  el("tenant-detail").hidden = false;
  el("tenant-name").textContent = current.name;
  el("tenant-id").textContent = current.id;
  el("tenant-state").textContent = current.state;
  el("active-revision").textContent =
    current.active_revision === null
      ? "Not active"
      : String(current.active_revision);
  el("draft-revision").textContent = String(config.revision);
  el("providers").textContent =
    config.providers.join(", ") || "None configured";
  el("next-step").textContent =
    current.active_revision === config.revision
      ? "The saved configuration is active. Continue with integration setup."
      : "Configure Google and your addresses, verify your domains, then activate this saved draft.";
  input("google-client").value = config.google_web_client_id;
  input("frontend-origins").value = config.frontend_origins.join("\n");
  input("api-base").value = config.api_base_url;
  input("local-development").checked = config.local_development;
  input("session-ttl").value = config.session_ttl;
  input("refresh-ttl").value = config.refresh_ttl;
  el("google-origins").textContent = config.frontend_origins.join("\n");
  el("provider-summary").textContent =
    `Current providers: ${config.providers.join(", ") || "none"}. This form preserves other provider settings.`;
  el("reload").hidden = true;
  const proofList = el("proofs");
  proofList.replaceChildren();
  for (const p of proofs.filter((p) => p.revision === config.revision)) {
    const li = document.createElement("li");
    const label = document.createElement("strong");
    label.textContent = `${p.hostname} · ${p.state}`;
    const data = document.createElement("pre");
    data.textContent = `TXT ${p.name}\n${p.value}\nExpires ${new Date(p.expires_at).toLocaleString()}`;
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Verify TXT record";
    button.setAttribute(
      "data-expired",
      String(Date.parse(p.expires_at) < Date.now()),
    );
    button.onclick = () =>
      void action(async (api, signal) => {
        await api.request(
          "POST",
          tenantPath(current.id) +
            `/origin-proofs/${encodeURIComponent(p.id)}/verifications`,
          signal,
          {},
          undefined,
          crypto.randomUUID(),
        );
        await refreshSelected(current.id, signal);
        notice("Domain verified.");
      });
    li.append(label, data, button);
    proofList.append(li);
  }
  const proofActions = el("proof-actions");
  proofActions.replaceChildren();
  const addresses = [
    ...config.frontend_origins,
    ...(config.api_base_url ? [config.api_base_url] : []),
  ];
  for (const hostname of new Set(
    addresses.map((value) => new URL(value).hostname),
  )) {
    if (["localhost", "127.0.0.1", "[::1]"].includes(hostname)) continue;
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `Create proof for ${hostname}`;
    button.onclick = () =>
      void action(async (api, signal) => {
        await api.request(
          "POST",
          tenantPath(current.id) + "/origin-proofs",
          signal,
          { revision: config.revision, hostname },
          undefined,
          crypto.randomUUID(),
        );
        await refreshSelected(current.id, signal);
        notice("Publish the TXT record, then verify it.");
      });
    proofActions.append(button);
  }
  drawCollection();
  showSection(section);
  pending(busy);
  document.dispatchEvent(
    new CustomEvent("tauth-console:selected", {
      detail: {
        tenant: current,
        config,
        apiOrigin: client.origin,
        signal: controller.signal,
      },
    }),
  );
}
/** @param {string} id @param {AbortSignal} signal */
async function refreshSelected(id, signal) {
  const result = await client.selected(id, signal);
  if (signal.aborted || selected?.tenant.id !== id) return;
  selected = result;
  tenants = tenants.map((item) => (item.id === id ? result.tenant : item));
  render();
}
/** @param {string} id @param {boolean} focus */
async function selectTenant(id, focus) {
  controller.abort();
  controller = new AbortController();
  epoch++;
  const version = epoch;
  selected = null;
  busy = false;
  pending(false);
  document.dispatchEvent(new Event("tauth-console:clear-secrets"));
  dialog.close();
  suspendDialog.close();
  el("tenant-detail").hidden = true;
  form.reset();
  el("field-error").textContent = "";
  notice("Loading tenant…");
  try {
    const result = await client.selected(id, controller.signal);
    if (version !== epoch) return;
    selected = result;
    render();
    notice("Tenant loaded.");
    if (focus) el("tenant-name").focus();
  } catch (error) {
    if (version === epoch) showError(error);
  }
}
async function openWorkspace() {
  if (authenticated) return;
  authenticated = true;
  clearProtected();
  el("signed-out").hidden = true;
  notice("Loading your tenants…");
  const version = epoch;
  try {
    const owner = await client.enroll(controller.signal);
    const items = await client.collection(
      PATHS.tenants,
      tenant,
      controller.signal,
    );
    if (version !== epoch) return;
    el("admin-accounts").hidden = !owner.administrator;
    tenants = items;
    el("workspace").hidden = false;
    drawCollection();
    const state = new URLSearchParams(location.hash.slice(1));
    section = state.get("section") || "overview";
    const requested = state.get("tenant");
    if (requested) await selectTenant(requested, false);
    else if (items.length) await selectTenant(items[0].id, false);
    else notice("Create your first tenant.");
  } catch (error) {
    if (version === epoch) {
      authenticated = false;
      showError(error);
      el("retry-workspace").hidden = false;
    }
  }
}
el("refresh-accounts").addEventListener("click", async () => {
  const version = epoch;
  el("accounts-status").textContent = "Loading accounts…";
  try {
    const accounts = await client.collection(
      PATHS.accounts,
      ownerAccount,
      controller.signal,
    );
    if (version !== epoch) return;
    el("account-list").replaceChildren(
      ...accounts.map((account) => {
        const item = document.createElement("li");
        item.textContent = `${account.displayName} · ${account.email}${account.administrator ? " · Administrator" : ""}`;
        return item;
      }),
    );
    el("accounts-status").textContent = `${accounts.length} accounts`;
  } catch (error) {
    if (version !== epoch) return;
    el("account-list").replaceChildren();
    el("accounts-status").textContent =
      error instanceof Error ? error.message : "Accounts could not load.";
    if (error instanceof RequestError && error.status === 401) signOut();
  }
});
/** @param {string} intent */
function openTenantDialog(intent) {
  dialogIntent = intent;
  dialogKey = crypto.randomUUID();
  returnFocus = /** @type {HTMLElement} */ (document.activeElement);
  input("new-name").value = intent === "rename" ? selected.tenant.name : "";
  input("new-environment").value =
    intent === "rename" ? selected.tenant.environment : "";
  el("dialog-title").textContent =
    intent === "rename" ? "Rename tenant" : "Create tenant";
  el("confirm-tenant").textContent =
    intent === "rename" ? "Save name" : "Create tenant";
  el("dialog-error").textContent = "";
  dialog.showModal();
  input("new-name").focus();
}
document
  .querySelectorAll("[data-create]")
  .forEach((node) =>
    node.addEventListener("click", () => openTenantDialog("create")),
  );
document.querySelectorAll("[data-close]").forEach((node) =>
  node.addEventListener("click", () => {
    node.closest("dialog").close();
    returnFocus?.focus();
  }),
);
document
  .querySelectorAll("[data-section]")
  .forEach((node) =>
    node.addEventListener("click", () =>
      showSection(node.getAttribute("data-section")),
    ),
  );
el("tenant-select").addEventListener(
  "change",
  () => void selectTenant(input("tenant-select").value, true),
);
el("rename").onclick = () => openTenantDialog("rename");
el("tenant-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void action(async (api, signal) => {
    const body = {
      name: input("new-name").value,
      environment: input("new-environment").value,
    };
    const result =
      dialogIntent === "create"
        ? await api.request(
            "POST",
            PATHS.tenants,
            signal,
            body,
            undefined,
            dialogKey,
          )
        : await api.request(
            "PATCH",
            tenantPath(selected.tenant.id),
            signal,
            body,
            selected.tenantETag,
          );
    if (signal.aborted) return;
    const item = tenant(result.value);
    tenants = tenants.filter((t) => t.id !== item.id).concat(item);
    dialog.close();
    await selectTenant(item.id, true);
    notice(dialogIntent === "create" ? "Tenant created." : "Tenant renamed.");
  });
});
form.addEventListener("submit", (event) => {
  event.preventDefault();
  void action(async (api, signal) => {
    const id = selected.tenant.id;
    const body = {
      google_web_client_id: input("google-client").value.trim(),
      frontend_origins: input("frontend-origins")
        .value.split("\n")
        .map((v) => v.trim())
        .filter(Boolean),
      api_base_url: input("api-base").value.trim(),
      local_development: input("local-development").checked,
      session_ttl: input("session-ttl").value.trim(),
      refresh_ttl: input("refresh-ttl").value.trim(),
    };
    const result = await api.request(
      "PUT",
      tenantPath(id) + "/configuration",
      signal,
      body,
      selected.configETag,
    );
    configuration(result.value);
    await refreshSelected(id, signal);
    notice("Draft saved. Activate it when setup is complete.");
  });
});
el("activate").onclick = () =>
  void action(async (api, signal) => {
    const id = selected.tenant.id;
    await api.request(
      "POST",
      tenantPath(id) + "/activations",
      signal,
      { revision: selected.config.revision },
      selected.configETag,
      crypto.randomUUID(),
    );
    await refreshSelected(id, signal);
    notice("Configuration activated.");
  });
el("reload").onclick = () => void selectTenant(selected.tenant.id, true);
el("suspend").onclick = () => {
  returnFocus = /** @type {HTMLElement} */ (document.activeElement);
  suspendDialog.showModal();
};
el("confirm-suspend").onclick = () =>
  void action(async (api, signal) => {
    const id = selected.tenant.id;
    await api.request(
      "PATCH",
      tenantPath(id),
      signal,
      { state: "suspended" },
      selected.tenantETag,
    );
    suspendDialog.close();
    await refreshSelected(id, signal);
    returnFocus?.focus();
    notice("Tenant suspended.");
  });
el("retry-workspace").onclick = () => {
  el("retry-workspace").hidden = true;
  void openWorkspace();
};
document.addEventListener(
  "mpr-ui:auth:authenticated",
  () => void openWorkspace(),
);
document.addEventListener("mpr-ui:auth:unauthenticated", signOut);
document.addEventListener("mpr-ui:auth:status-change", (event) => {
  if (/** @type {CustomEvent} */ (event).detail?.status === "unauthenticated")
    signOut();
});
window.addEventListener("hashchange", () => {
  if (authenticated) {
    const state = new URLSearchParams(location.hash.slice(1));
    const id = state.get("tenant");
    section = state.get("section") || "overview";
    if (id && id !== selected?.tenant.id) void selectTenant(id, true);
    else showSection(section);
  }
});
window.addEventListener("pagehide", clearProtected);
async function start() {
  try {
    client = await loadClient();
    const publicConfig = await client.bootstrap(controller.signal);
    const config = {
      tauthUrl: client.origin,
      tenantId: publicConfig.tenantId,
      logoutPath: "/auth/logout",
      sessionPath: "/auth/session",
      providers: {
        google: {
          enabled: true,
          clientId: publicConfig.clientId,
          loginPath: "/auth/google",
          noncePath: "/auth/nonce",
        },
        apple: { enabled: false },
        password: { enabled: false },
      },
    };
    el("console-header").setAttribute("auth-config", JSON.stringify(config));
    await new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = "./vendor/mpr-ui.js";
      script.onload = resolve;
      script.onerror = () =>
        reject(new Error("Account controls could not load"));
      document.head.append(script);
    });
  } catch (error) {
    showError(error);
  }
}
void start();
