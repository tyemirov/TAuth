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
const adminDialog = /** @type {HTMLDialogElement} */ (el("admin-dialog"));
const userMenu = el("console-user");
const ADMIN_MENU_ACTION = "admin";
const AUTO_SAVE_DELAY = 500;
const AUTO_REFRESH_DELAY = 15000;
const RETRY_DELAY = 5000;
let saveTimer = 0,
  renameTimer = 0,
  editVersion = 0;
let editBase = /** @type {import('./client.js').ConfigurationInput|null} */ (
  null
);
const configurationFields = /** @type {Map<string,number>} */ (new Map());
let configurationSnapshot =
  /** @type {import('./client.js').ConfigurationInput|null} */ (null);
let nameSnapshot = /** @type {{name:string,environment:string}|null} */ (null);
let nameVersion = 0;
let saveOperation = /** @type {Promise<boolean>|null} */ (null);
let nameDraft =
  /** @type {{id:string,name:string,environment:string,fields:Map<string,number>}|null} */ (
    null
  );
let nameOperation = /** @type {Promise<boolean>|null} */ (null);
let nameBlocked = false;
let saveBlocked = false,
  synchronizing = false;
const sections = ["overview", "domains", "signin", "integration", "settings"];
let client = /** @type {Client|null} */ (null),
  selected = /** @type {Selected|null} */ (null);
let tenants = /** @type {Tenant[]} */ ([]),
  controller = new AbortController(),
  epoch = 0,
  hasSession = false,
  authenticated = false,
  administrator = false,
  busy = false;
let section = "overview",
  dialogIntent = "create",
  dialogKey = "",
  returnFocus = /** @type {HTMLElement|null} */ (null);
/** @param {string} message */ const notice = (message) => {
  el("notice").textContent = message;
  el("notice").hidden = message === "";
};
function clearProtected() {
  clearTimeout(saveTimer);
  clearTimeout(renameTimer);
  nameDraft = null;
  nameSnapshot = null;
  nameVersion++;
  configurationFields.clear();
  configurationSnapshot = null;
  nameOperation = null;
  nameBlocked = false;
  editBase = null;
  saveBlocked = false;
  saveOperation = null;
  editVersion++;
  adminDialog.close();
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
  administrator = false;
  userMenu.setAttribute("menu-items", "[]");
  el("account-list").replaceChildren();
  el("accounts-status").textContent = "";
  for (const id of [
    "tenant-name",
    "tenant-id",
    "providers",
    "field-error",
    "google-origins",
    "provider-summary",
    "active-revision",
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
  hasSession = false;
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
      ? "This configuration changed in another session. Checking current values…"
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
}
function canResume() {
  return selected && selected.tenant.state === "suspended" && !editBase;
}
function validCreation() {
  const name = input("new-name").value.trim();
  const origin = input("new-origin");
  const google = input("new-google-client");
  if (!name || !origin.validity.valid || !google.validity.valid) return false;
  const address = new URL(origin.value);
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(address.hostname);
  const canonical =
    address.origin === origin.value && !address.username && !address.password;
  return (
    canonical &&
    (local
      ? ["http:", "https:"].includes(address.protocol)
      : address.protocol === "https:" &&
        address.hostname.includes(".") &&
        !address.hostname.endsWith(".") &&
        !/^[0-9.]+$/.test(address.hostname))
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
        (node.id === "resume" && !canResume()) ||
        (node.id === "confirm-tenant" &&
          dialogIntent === "create" &&
          !validCreation()) ||
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
/** @param {Tenant} item */
function tenantLabel(item) {
  return item.name === "" ? item.id : item.name;
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
    title.textContent = tenantLabel(item);
    button.append(title);
    button.setAttribute(
      "aria-current",
      selected?.tenant.id === item.id ? "page" : "false",
    );
    button.onclick = () => void selectTenant(item.id, true);
    list.append(button);
    const option = document.createElement("option");
    option.value = item.id;
    option.textContent = tenantLabel(item);
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
  const { tenant: current, config } = selected;
  el("tenant-detail").hidden = false;
  el("tenant-name").textContent = tenantLabel(current);
  el("tenant-id").textContent = current.id;
  const authentication = {
    active: {
      label: "Authentication active",
      explanation:
        "TAuth accepts sign-ins using this configuration. Continue with integration setup.",
    },
    suspended: {
      label: "Authentication suspended",
      explanation:
        "TAuth is not accepting sign-ins for this tenant. Resume tenant to use the saved configuration.",
    },
    draft: {
      label: "Authentication unavailable",
      explanation:
        "This tenant has no active configuration. Its saved settings are not currently used for sign-in. Valid configuration changes apply automatically.",
    },
  }[current.state];
  el("tenant-state").textContent = authentication.label;
  el("active-revision").textContent =
    current.active_revision === null ? "None" : String(current.active_revision);
  el("resume").hidden = current.state !== "suspended";
  el("providers").textContent =
    config.providers.join(", ") || "None configured";
  el("next-step").textContent = authentication.explanation;
  if (!editBase) writeConfiguration(config);
  el("google-origins").textContent = config.frontend_origins.join("\n");
  el("provider-summary").textContent =
    `Current providers: ${config.providers.join(", ") || "none"}. This form preserves other provider settings.`;
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
  if (editBase) return;
  const changed = !same(selected, result);
  selected = result;
  tenants = tenants.map((item) => (item.id === id ? result.tenant : item));
  if (changed) render();
  else drawCollection();
}
/** @param {string} id @param {boolean} focus */
async function selectTenant(id, focus) {
  if (selected && editBase && !(await persistConfiguration())) return;
  if (nameDraft && !(await persistName())) return;
  clearTimeout(renameTimer);
  clearTimeout(saveTimer);
  editBase = null;
  configurationFields.clear();
  configurationSnapshot = null;
  saveBlocked = false;
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
    notice("");
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
    administrator = owner.administrator;
    userMenu.setAttribute(
      "menu-items",
      JSON.stringify(
        administrator ? [{ label: "Admin", action: ADMIN_MENU_ACTION }] : [],
      ),
    );
    tenants = items;
    el("workspace").hidden = false;
    drawCollection();
    const state = new URLSearchParams(location.hash.slice(1));
    section = state.get("section") || "overview";
    const requested = state.get("tenant");
    if (requested) await selectTenant(requested, false);
    else if (items.length) await selectTenant(items[0].id, false);
    else notice("");
  } catch (error) {
    if (version === epoch) {
      authenticated = false;
      showError(error);
    }
  }
}
async function loadAccounts() {
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
    el("accounts-status").textContent =
      `${accounts.length} ${accounts.length === 1 ? "account" : "accounts"}`;
  } catch (error) {
    if (version !== epoch) return;
    el("account-list").replaceChildren();
    el("accounts-status").textContent =
      error instanceof Error ? error.message : "Accounts could not load.";
    if (error instanceof RequestError && error.status === 401) signOut();
  }
}
el("console-header").addEventListener("mpr-user:menu-item", (event) => {
  if (
    /** @type {CustomEvent} */ (event).detail.action !== ADMIN_MENU_ACTION ||
    !administrator
  )
    return;
  adminDialog.showModal();
  void loadAccounts();
});
adminDialog.addEventListener("close", () => {
  el("account-list").replaceChildren();
  if (authenticated)
    /** @type {HTMLElement} */ (
      userMenu.querySelector('[data-mpr-user="trigger"]')
    ).focus();
});
/** @param {string} intent */
function openTenantDialog(intent) {
  dialogIntent = intent;
  dialogKey = crypto.randomUUID();
  returnFocus = /** @type {HTMLElement} */ (document.activeElement);
  input("new-name").value =
    intent === "rename"
      ? nameDraft?.fields.has("name")
        ? nameDraft.name
        : selected.tenant.name
      : "";
  input("new-environment").value =
    intent === "rename"
      ? nameDraft?.fields.has("environment")
        ? nameDraft.environment
        : selected.tenant.environment
      : "";
  nameSnapshot = {
    name: input("new-name").value.trim(),
    environment: input("new-environment").value.trim(),
  };
  el("dialog-title").textContent =
    intent === "rename" ? "Rename tenant" : "Create tenant";
  el("confirm-tenant").textContent = "Create tenant";
  el("confirm-tenant").hidden = intent === "rename";
  const authentication = /** @type {HTMLFieldSetElement} */ (
    el("new-authentication")
  );
  authentication.hidden = intent === "rename";
  authentication.disabled = intent === "rename";
  el("rename-environment").hidden = intent !== "rename";
  input("new-origin").value = "";
  input("new-google-client").value = "";
  pending(busy);
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
  if (dialogIntent === "rename") {
    void persistName();
    return;
  }
  if (!validCreation()) return;
  void action(async (api, signal) => {
    const body = {
      name: input("new-name").value.trim(),
      application_origin: input("new-origin").value,
      google_web_client_id: input("new-google-client").value,
    };
    const result = await api.request(
      "POST",
      PATHS.tenants,
      signal,
      body,
      undefined,
      dialogKey,
    );
    if (signal.aborted) return;
    const item = tenant(result.value);
    tenants = tenants.filter((t) => t.id !== item.id).concat(item);
    dialog.close();
    await selectTenant(item.id, true);
    notice("Tenant created.");
  });
});
/** @param {import('./client.js').ConfigurationInput} value */
function writeConfiguration(value) {
  input("google-client").value = value.google_web_client_id;
  input("frontend-origins").value = value.frontend_origins.join("\n");
  input("api-base").value = value.api_base_url;
  input("local-development").checked = value.local_development;
  input("session-ttl").value = value.session_ttl;
  input("refresh-ttl").value = value.refresh_ttl;
  configurationSnapshot = readConfiguration();
}
function readConfiguration() {
  return {
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
}
/** @param {unknown} a @param {unknown} b */
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
async function persistConfiguration() {
  if (saveOperation) return saveOperation;
  if (!selected || !editBase) return true;
  if (busy || saveBlocked) return false;
  clearTimeout(saveTimer);
  const version = epoch,
    id = selected.tenant.id,
    signal = controller.signal;
  const local = readConfiguration(),
    fields = new Map(configurationFields),
    edits = editVersion;
  saveOperation = (async () => {
    pending(true);
    el("save-status").textContent = "Saving…";
    el("field-error").textContent = "";
    try {
      const current = await client.selected(id, signal);
      if (version !== epoch) return false;
      const merged = { ...local };
      for (const key of Object.keys(local))
        if (!fields.has(key)) merged[key] = current.config[key];
      const changed = Object.keys(merged).some(
        (key) => !same(merged[key], current.config[key]),
      );
      if (changed) {
        const result = await client.request(
          "PUT",
          tenantPath(id) + "/configuration",
          signal,
          merged,
          current.configETag,
        );
        configuration(result.value);
      }
      const latest = changed ? await client.selected(id, signal) : current;
      if (version !== epoch) return false;
      selected = latest;
      for (const [key, revision] of fields)
        if (configurationFields.get(key) === revision)
          configurationFields.delete(key);
      const next = readConfiguration();
      for (const key of Object.keys(next))
        if (!configurationFields.has(key)) next[key] = latest.config[key];
      writeConfiguration(next);
      editBase = configurationFields.size ? latest.config : null;
      render();
      el("save-status").textContent = editBase
        ? "Changes pending…"
        : "Saved automatically.";
      notice("Configuration saved.");
      return !editBase;
    } catch (error) {
      if (version !== epoch) return false;
      if (error instanceof RequestError && error.status === 401) {
        showError(error);
      } else if (edits !== editVersion) {
        el("save-status").textContent = "Changes pending…";
      } else if (error instanceof RequestError && error.status === 412) {
        el("save-status").textContent = "Checking concurrent changes…";
      } else {
        showError(error);
        saveBlocked = permanentFailure(error);
        el("save-status").textContent =
          "Changes not saved. Your edits are preserved.";
      }
      return false;
    } finally {
      if (version === epoch) {
        saveOperation = null;
        pending(false);
        if (editBase && !saveBlocked)
          saveTimer = window.setTimeout(
            () => void persistConfiguration(),
            edits !== editVersion ? AUTO_SAVE_DELAY : RETRY_DELAY,
          );
      }
    }
  })();
  return saveOperation;
}
form.addEventListener("submit", (event) => event.preventDefault());
form.addEventListener("input", () => {
  if (!selected) return;
  const values = readConfiguration();
  const changed = Object.keys(values).filter(
    (key) => !same(values[key], configurationSnapshot[key]),
  );
  if (!changed.length) return;
  if (!editBase) editBase = selected.config;
  editVersion++;
  for (const key of changed) configurationFields.set(key, editVersion);
  configurationSnapshot = values;
  el("field-error").textContent = "";
  form
    .querySelectorAll("[aria-invalid]")
    .forEach((node) => node.removeAttribute("aria-invalid"));
  saveBlocked = false;
  clearTimeout(saveTimer);
  el("save-status").textContent = "Changes pending…";
  notice("Changes pending…");
  pending(busy);
  saveTimer = window.setTimeout(
    () => void persistConfiguration(),
    AUTO_SAVE_DELAY,
  );
});
/** @param {unknown} error */
function permanentFailure(error) {
  return (
    error instanceof RequestError &&
    error.status < 500 &&
    ![408, 412, 429].includes(error.status)
  );
}
async function persistName() {
  if (nameOperation) return nameOperation;
  if (!nameDraft || nameBlocked) return !nameDraft;
  if (busy) {
    renameTimer = window.setTimeout(() => void persistName(), AUTO_SAVE_DELAY);
    return false;
  }
  clearTimeout(renameTimer);
  const draft = nameDraft,
    version = epoch,
    edits = nameVersion,
    signal = controller.signal,
    fields = new Map(draft.fields);
  const body = Object.fromEntries(
    [...fields.keys()].map((key) => [key, draft[key]]),
  );
  nameOperation = (async () => {
    pending(true);
    try {
      const current = await client.selected(draft.id, signal);
      if (version !== epoch) return false;
      const result = await client.request(
        "PATCH",
        tenantPath(draft.id),
        signal,
        body,
        current.tenantETag,
      );
      if (version !== epoch) return false;
      const item = tenant(result.value);
      tenants = tenants.map((value) => (value.id === item.id ? item : value));
      if (selected?.tenant.id === item.id) {
        selected.tenant = item;
        selected.tenantETag = result.etag;
      }
      for (const [key, revision] of fields)
        if (nameDraft.fields.get(key) === revision)
          nameDraft.fields.delete(key);
      if (!nameDraft.fields.size) nameDraft = null;
      if (dialog.open && dialogIntent === "rename") {
        for (const [key, id] of [
          ["name", "new-name"],
          ["environment", "new-environment"],
        ])
          if (!nameDraft?.fields.has(key)) input(id).value = item[key];
        nameSnapshot = {
          name: input("new-name").value.trim(),
          environment: input("new-environment").value.trim(),
        };
      }
      render();
      el("dialog-error").textContent = nameDraft
        ? "Changes pending…"
        : "Saved automatically.";
      notice(nameDraft ? "Changes pending…" : "Tenant renamed.");
      return !nameDraft;
    } catch (error) {
      if (version === epoch) {
        if (error instanceof RequestError && error.status === 401)
          showError(error);
        else if (edits === nameVersion) {
          nameBlocked = permanentFailure(error);
          showError(error);
        } else el("dialog-error").textContent = "Changes pending…";
      }
      return false;
    } finally {
      if (version === epoch) {
        nameOperation = null;
        pending(false);
        if (nameDraft && !nameBlocked)
          renameTimer = window.setTimeout(
            () => void persistName(),
            edits !== nameVersion ? AUTO_SAVE_DELAY : RETRY_DELAY,
          );
      }
    }
  })();
  return nameOperation;
}
dialog.addEventListener("close", () => {
  clearTimeout(renameTimer);
  if (dialogIntent === "rename") void persistName();
});
el("tenant-form").addEventListener("input", () => {
  if (dialogIntent === "create") {
    pending(busy);
    return;
  }
  if (!selected) return;
  const values = {
    name: input("new-name").value.trim(),
    environment: input("new-environment").value.trim(),
  };
  const changed = Object.keys(values).filter(
    (key) => values[key] !== nameSnapshot[key],
  );
  if (!changed.length) return;
  clearTimeout(renameTimer);
  nameVersion++;
  const fields = new Map(nameDraft?.fields);
  for (const key of changed) fields.set(key, nameVersion);
  nameDraft = { id: selected.tenant.id, ...values, fields };
  nameSnapshot = values;
  input("new-name").removeAttribute("aria-invalid");
  nameBlocked = false;
  el("dialog-error").textContent = "Changes pending…";
  renameTimer = window.setTimeout(() => void persistName(), AUTO_SAVE_DELAY);
});
async function synchronize() {
  if (document.hidden || synchronizing || busy || saveOperation || !client)
    return;
  synchronizing = true;
  const version = epoch;
  try {
    if (!authenticated) {
      if (hasSession) await openWorkspace();
      return;
    }
    if (adminDialog.open) await loadAccounts();
    if (editBase) {
      await persistConfiguration();
      return;
    }
    const items = await client.collection(
      PATHS.tenants,
      tenant,
      controller.signal,
    );
    if (version !== epoch || editBase) return;
    tenants = items;
    if (selected) await refreshSelected(selected.tenant.id, controller.signal);
    else if (items.length) await selectTenant(items[0].id, false);
    else drawCollection();
  } catch (error) {
    if (version === epoch) showError(error);
  } finally {
    synchronizing = false;
  }
}
window.addEventListener("focus", () => void synchronize());
window.addEventListener("online", () => void synchronize());
document.addEventListener("visibilitychange", () => void synchronize());
const refreshTimer = window.setInterval(
  () => void synchronize(),
  AUTO_REFRESH_DELAY,
);
el("resume").onclick = () =>
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
    notice("Tenant resumed.");
  });
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
document.addEventListener("mpr-ui:auth:authenticated", () => {
  hasSession = true;
  void openWorkspace();
});
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
window.addEventListener("pagehide", () => {
  clearInterval(refreshTimer);
  clearProtected();
});
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
