// @ts-check
import "./integration.js";
import {
  Client,
  app,
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
const appDialog = /** @type {HTMLDialogElement} */ (el("app-dialog"));
let apps = /** @type {import('./client.js').App[]} */ ([]);
let expandedAppID = "";
let appID = "",
  appKey = "";
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
let nameSnapshot = "";
let editingName =
  /** @type {{kind:"tenant"|"app",id:string,labelID:string,buttonID:string}|null} */ (
    null
  );
let finishNameRequested = false;
let restoreNameFocus = false;
let nameVersion = 0;
let saveOperation = /** @type {Promise<boolean>|null} */ (null);
let nameDraft =
  /** @type {{kind:"tenant"|"app",id:string,name:string}|null} */ (null);
let nameOperation = /** @type {Promise<boolean>|null} */ (null);
let nameBlocked = false;
let saveBlocked = false,
  synchronizing = false;
const sections = ["configuration", "integration"];
let client = /** @type {Client|null} */ (null),
  selected = /** @type {Selected|null} */ (null);
let tenants = /** @type {Tenant[]} */ ([]),
  controller = new AbortController(),
  epoch = 0,
  hasSession = false,
  authenticated = false,
  administrator = false,
  busy = false;
let section = "configuration",
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
  nameSnapshot = "";
  closeNameEditor(false);
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
  apps = [];
  appID = "";
  appDialog.close();
  input("app-name").value = "";
  expandedAppID = "";
  el("app-list").replaceChildren();
  busy = false;
  form.reset();
  form.setAttribute("aria-busy", "false");
  /** @type {HTMLFormElement} */ (el("tenant-form")).reset();
  el("workspace").hidden = true;
  el("tenant-detail").hidden = true;
  el("inventory-summary").textContent = "";
  el("selected-app-name").textContent = "";
  el("empty-app-name").textContent = "";
  administrator = false;
  userMenu.setAttribute("menu-items", "[]");
  el("account-list").replaceChildren();
  el("accounts-status").textContent = "";
  for (const id of [
    "tenant-name",
    "tenant-id",
    "field-error",
    "google-origins",
    "provider-summary",
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
  history.replaceState(null, "", location.pathname + location.search);
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
      "management.session_ttl_invalid": ["session-ttl", "configuration"],
      "management.refresh_ttl_invalid": ["refresh-ttl", "configuration"],
      "management.origin_invalid": ["frontend-origins", "configuration"],
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
      const disclosure = input(field[0]).closest("details");
      if (disclosure) disclosure.open = true;
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
    .querySelectorAll(
      "#configuration button,#confirm-tenant,#confirm-suspend,#authentication-toggle",
    )
    .forEach((node) => {
      /** @type {HTMLButtonElement} */ (node).disabled =
        pending ||
        (node.id === "authentication-toggle" &&
          (!selected ||
            selected.tenant.state === "draft" ||
            (selected.tenant.state === "suspended" && !canResume()))) ||
        (node.id === "confirm-tenant" && !validCreation()) ||
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
  const active = /** @type {HTMLElement|null} */ (document.activeElement);
  const focusSelector = active?.dataset.app
    ? `[data-app="${CSS.escape(active.dataset.app)}"]`
    : active?.dataset.tenant
      ? `[data-tenant="${CSS.escape(active.dataset.tenant)}"]`
      : "";
  const list = el("app-list");
  list.replaceChildren();
  el("inventory-summary").textContent =
    `${apps.length} Apps · ${tenants.length} tenants`;
  for (const item of [...apps].sort((a, b) => a.name.localeCompare(b.name))) {
    const row = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.app = item.id;
    const members = tenants.filter((value) => value.app_id === item.id);
    const expanded = expandedAppID === item.id;
    button.setAttribute("aria-expanded", String(expanded));
    button.setAttribute("aria-controls", `app-tenants-${item.id}`);
    const title = document.createElement("span");
    title.className = "app-name";
    title.textContent = item.name;
    const count = document.createElement("span");
    count.className = "tenant-count";
    count.textContent = String(members.length);
    count.setAttribute("aria-label", `${members.length} tenants`);
    button.append(title, count);
    button.onclick = () => {
      if (appID === item.id) {
        expandedAppID = expanded ? "" : item.id;
        drawCollection();
      } else void selectApp(item.id);
    };
    row.append(button);
    const children = document.createElement("ul");
    children.id = `app-tenants-${item.id}`;
    children.className = "app-tenants";
    children.hidden = !expanded;
    // Render children only for the expanded App. Counts expose the complete inventory.
    if (expanded) {
      for (const member of members) {
        const child = document.createElement("li");
        const tenantButton = document.createElement("button");
        tenantButton.type = "button";
        tenantButton.dataset.tenant = member.id;
        tenantButton.textContent = tenantLabel(member);
        tenantButton.setAttribute(
          "aria-current",
          selected?.tenant.id === member.id ? "page" : "false",
        );
        tenantButton.onclick = () => void selectTenant(member.id, true);
        child.append(tenantButton);
        children.append(child);
      }
      const child = document.createElement("li");
      const create = document.createElement("button");
      create.type = "button";
      create.dataset.create = "";
      create.className = "create-tenant";
      create.textContent = "+ Create tenant";
      create.onclick = () => openTenantDialog();
      child.append(create);
      children.append(child);
    }
    row.append(children);
    list.append(row);
  }
  const visibleTenants = tenants.filter((item) => item.app_id === appID);
  el("empty").hidden = visibleTenants.length > 0;
  el("empty-title").textContent = appID
    ? "Create your first tenant"
    : "Create your first App";
  const appName = apps.find((item) => item.id === appID)?.name || "";
  el("selected-app-name").textContent = appName;
  el("empty-app-name").textContent = appName;
  el("empty-app-heading").hidden = !appID;
  if (focusSelector)
    /** @type {HTMLElement|null} */ (list.querySelector(focusSelector))?.focus({
      preventScroll: true,
    });
}
/** @param {string} next */
function showSection(next) {
  section = sections.includes(next) ? next : "configuration";
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
  el("save-actions").hidden = section !== "configuration";
  if (selected)
    history.replaceState(
      null,
      "",
      `#${new URLSearchParams({ app: appID, tenant: selected.tenant.id, section })}`,
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
  el("tenant-state").dataset.state = current.state;
  el("authentication-toggle").dataset.state = current.state;
  const authenticationAction =
    current.state === "active"
      ? "Pause authentication"
      : "Resume authentication";
  el("authentication-toggle").setAttribute(
    "aria-label",
    current.state === "draft" ? authentication.label : authenticationAction,
  );
  el("authentication-toggle").title =
    current.state === "draft" ? authentication.label : authenticationAction;
  el("authentication-icon").setAttribute(
    "d",
    current.state === "active" ? "M8 5v14 M16 5v14" : "m8 5 11 7-11 7Z",
  );
  el("next-step").textContent = authentication.explanation;
  el("next-step").hidden = current.state === "active";
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
  closeNameEditor(false);
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
  form.setAttribute("aria-busy", "false");
  el("field-error").textContent = "";
  notice("Loading tenant…");
  try {
    const result = await client.selected(id, controller.signal);
    if (version !== epoch) return;
    selected = result;
    appID = result.tenant.app_id;
    expandedAppID = appID;
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
    const appItems = await client.collection(
      PATHS.apps,
      app,
      controller.signal,
    );
    if (version !== epoch) return;
    apps = appItems;
    const requestedApp = new URLSearchParams(location.hash.slice(1)).get("app");
    appID =
      apps.find((item) => item.id === requestedApp)?.id || apps[0]?.id || "";
    expandedAppID = appID;
    tenants = items;
    el("workspace").hidden = false;
    drawCollection();
    const state = new URLSearchParams(location.hash.slice(1));
    section = state.get("section") || "configuration";
    const requested = state.get("tenant");
    if (requested) await selectTenant(requested, false);
    else if (items.some((item) => item.app_id === appID))
      await selectTenant(items.find((item) => item.app_id === appID).id, false);
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
async function openTenantDialog() {
  if (nameDraft && !(await persistName())) return;
  closeNameEditor(false);
  dialogKey = crypto.randomUUID();
  returnFocus = /** @type {HTMLElement} */ (document.activeElement);
  input("new-name").value = "";
  input("new-origin").value = "";
  input("new-google-client").value = "";
  pending(busy);
  el("dialog-error").textContent = "";
  dialog.showModal();
  input("new-name").focus();
}
document
  .querySelectorAll("[data-create]")
  .forEach((node) => node.addEventListener("click", () => openTenantDialog()));
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
el("rename").onclick = () =>
  void startNameEditing("tenant", "tenant-name", "rename");
el("rename-app").onclick = () =>
  void startNameEditing("app", "selected-app-name", "rename-app");
el("rename-empty-app").onclick = () =>
  void startNameEditing("app", "empty-app-name", "rename-empty-app");
el("tenant-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!validCreation()) return;
  void action(async (api, signal) => {
    const body = {
      app_id: appID,
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
    form.setAttribute("aria-busy", "true");
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
      form.setAttribute("aria-busy", String(Boolean(editBase)));
      notice("");
      return !editBase;
    } catch (error) {
      if (version !== epoch) return false;
      if (error instanceof RequestError && error.status === 401) {
        showError(error);
      } else if (
        edits === editVersion &&
        !(error instanceof RequestError && error.status === 412)
      ) {
        showError(error);
        saveBlocked = permanentFailure(error);
        form.setAttribute("aria-busy", String(!saveBlocked));
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
  form.setAttribute("aria-busy", "true");
  notice("");
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
    signal = controller.signal;
  const body = { name: draft.name };
  nameOperation = (async () => {
    pending(true);
    try {
      const path =
        draft.kind === "app"
          ? `${PATHS.apps}/${encodeURIComponent(draft.id)}`
          : tenantPath(draft.id);
      const current = await client.request("GET", path, signal);
      if (!current.etag)
        throw new Error("Revision precondition is unavailable");
      if (version !== epoch) return false;
      const result = await client.request(
        "PATCH",
        path,
        signal,
        body,
        current.etag,
      );
      if (version !== epoch) return false;
      const item =
        draft.kind === "app" ? app(result.value) : tenant(result.value);
      if (draft.kind === "app") {
        apps = apps.map((value) =>
          value.id === item.id
            ? /** @type {import('./client.js').App} */ (item)
            : value,
        );
      } else {
        const updated = /** @type {Tenant} */ (item);
        tenants = tenants.map((value) =>
          value.id === item.id ? updated : value,
        );
        if (selected?.tenant.id === item.id) {
          selected.tenant = updated;
          selected.tenantETag = result.etag;
        }
      }
      if (edits === nameVersion) {
        nameDraft = null;
        nameSnapshot = item.name;
        el("name-error").textContent = "";
        input("edited-name").removeAttribute("aria-invalid");
        el("name-editor").setAttribute("aria-busy", "false");
      }
      if (selected) render();
      else drawCollection();

      return !nameDraft;
    } catch (error) {
      if (version === epoch) {
        if (error instanceof RequestError && error.status === 401)
          showError(error);
        else if (edits === nameVersion) {
          nameBlocked = permanentFailure(error);
          el("name-error").textContent =
            error instanceof Error ? error.message : "Name update failed.";
          input("edited-name").setAttribute(
            "aria-invalid",
            String(nameBlocked),
          );
          el("name-editor").setAttribute("aria-busy", String(!nameBlocked));
        }
      }
      return false;
    } finally {
      if (version === epoch) {
        nameOperation = null;
        pending(false);
        if (!nameDraft && finishNameRequested)
          closeNameEditor(restoreNameFocus);
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
/** @param {boolean} restoreFocus */
function closeNameEditor(restoreFocus) {
  if (!editingName) return;
  const previous = editingName;
  editingName = null;
  finishNameRequested = false;
  el(previous.labelID).hidden = false;
  el(previous.buttonID).hidden = false;
  el("name-editor").hidden = true;
  input("edited-name").value = "";
  el("name-error").textContent = "";
  if (restoreFocus) el(previous.buttonID).focus();
}
/** @param {"tenant"|"app"} kind @param {string} labelID @param {string} buttonID */
async function startNameEditing(kind, labelID, buttonID) {
  const version = epoch;
  const id = kind === "app" ? appID : selected.tenant.id;
  if (editingName?.kind === kind && editingName.id === id) {
    input("edited-name").focus();
    return;
  }
  if (nameDraft && !(await persistName())) return;
  if (version !== epoch) return;
  closeNameEditor(false);
  const item =
    kind === "app" ? apps.find((item) => item.id === id) : selected.tenant;
  editingName = { kind, id, labelID, buttonID };
  nameSnapshot = item.name;
  input("edited-name").value = item.name;
  input("edited-name").setAttribute(
    "aria-label",
    kind === "app" ? "App name" : "Tenant name",
  );
  input("edited-name").removeAttribute("aria-invalid");
  el("name-editor").setAttribute("aria-busy", "false");
  el(labelID).after(el("name-editor"));
  el(labelID).hidden = true;
  el(buttonID).hidden = true;
  el("name-editor").hidden = false;
  input("edited-name").focus();
  input("edited-name").select();
}
/** @param {boolean} restoreFocus */
function finishNameEditing(restoreFocus) {
  if (!editingName) return;
  finishNameRequested = true;
  restoreNameFocus = restoreFocus;
  if (nameDraft) void persistName();
  else closeNameEditor(restoreFocus);
}
input("edited-name").addEventListener("blur", () => finishNameEditing(false));
input("edited-name").addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === "Escape") {
    event.preventDefault();
    finishNameEditing(true);
  }
});
input("edited-name").addEventListener("input", () => {
  const name = input("edited-name").value.trim();
  if (name === nameSnapshot) return;
  clearTimeout(renameTimer);
  nameVersion++;
  nameDraft = { kind: editingName.kind, id: editingName.id, name };
  nameSnapshot = name;
  finishNameRequested = false;
  nameBlocked = false;
  input("edited-name").removeAttribute("aria-invalid");
  el("name-error").textContent = "";
  el("name-editor").setAttribute("aria-busy", "true");
  renameTimer = window.setTimeout(() => void persistName(), AUTO_SAVE_DELAY);
});
el("tenant-form").addEventListener("input", () => pending(busy));
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
    const appItems = await client.collection(
      PATHS.apps,
      app,
      controller.signal,
    );
    if (version !== epoch || editBase) return;
    apps = appItems;
    if (!appID) appID = apps[0]?.id || "";
    tenants = items;
    if (selected) await refreshSelected(selected.tenant.id, controller.signal);
    else if (items.some((item) => item.app_id === appID))
      await selectTenant(items.find((item) => item.app_id === appID).id, false);
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
function resumeAuthentication() {
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
}
el("authentication-toggle").onclick = () => {
  if (selected.tenant.state === "suspended") {
    resumeAuthentication();
    return;
  }
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
    section = state.get("section") || "configuration";
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

/** @param {string} id */
async function selectApp(id) {
  if (selected && editBase && !(await persistConfiguration())) {
    drawCollection();
    return;
  }
  if (nameDraft && !(await persistName())) {
    drawCollection();
    return;
  }
  closeNameEditor(false);
  appID = id;
  expandedAppID = id;
  const first = tenants.find((item) => item.app_id === id);
  if (first) {
    await selectTenant(first.id, false);
    return;
  }
  controller.abort();
  controller = new AbortController();
  epoch++;
  selected = null;
  busy = false;
  pending(false);
  document.dispatchEvent(new Event("tauth-console:clear-secrets"));
  dialog.close();
  suspendDialog.close();
  form.reset();
  form.setAttribute("aria-busy", "false");
  el("tenant-detail").hidden = true;
  el("tenant-id").textContent = "";
  history.replaceState(null, "", `#${new URLSearchParams({ app: id })}`);
  drawCollection();
  notice("");
}
document.querySelectorAll("#create-app,[data-create-app]").forEach((node) =>
  node.addEventListener("click", () => {
    returnFocus = /** @type {HTMLElement} */ (document.activeElement);
    input("app-name").value = "";
    el("app-error").textContent = "";
    appKey = crypto.randomUUID();
    appDialog.showModal();
    input("app-name").focus();
  }),
);
el("app-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!input("app-name").value.trim()) return;
  void action(async (api, signal) => {
    try {
      const result = await api.request(
        "POST",
        PATHS.apps,
        signal,
        { name: input("app-name").value.trim() },
        undefined,
        appKey,
      );
      if (signal.aborted) return;
      const item = app(result.value);
      apps = apps.filter((value) => value.id !== item.id).concat(item);
      appDialog.close();
      await selectApp(item.id);
    } catch (error) {
      if (!signal.aborted)
        el("app-error").textContent =
          error instanceof Error ? error.message : "App creation failed";
      throw error;
    }
  });
});

document.querySelectorAll("dialog").forEach((modal) => {
  modal.addEventListener("click", (event) => {
    if (event.target !== modal) return;
    const box = modal.getBoundingClientRect();
    if (
      event.clientX < box.left ||
      event.clientX > box.right ||
      event.clientY < box.top ||
      event.clientY > box.bottom
    )
      modal.close();
  });
});
