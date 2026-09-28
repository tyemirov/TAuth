// @ts-check
/** @typedef {{id:string,name:string,environment:string,version:number,state:"draft"|"active"|"suspended",active_revision:number|null}} Tenant */
/** @typedef {{google_web_client_id:string,frontend_origins:string[],api_base_url:string,local_development:boolean,session_ttl:string,refresh_ttl:string}} ConfigurationInput */
/** @typedef {ConfigurationInput & {revision:number,providers:string[],session_cookie_name:string,refresh_cookie_name:string}} Configuration */
export const PATHS = Object.freeze({
  owner: "/api/management/owner-account",
  accounts: "/api/management/accounts",
  tenants: "/api/management/tenants",
  bootstrap: "/.well-known/tauth-console",
});
export class RequestError extends Error {
  /** @param {number} status @param {string} code @param {string} message */
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
/** @param {unknown} value @returns {Record<string,unknown>} */
function object(value) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Invalid service response");
  return /** @type {Record<string,unknown>} */ (value);
}
/** @param {unknown} value @returns {string} */
function text(value) {
  if (typeof value !== "string") throw new Error("Invalid service text");
  return value;
}
/** @param {unknown} value @returns {number} */
function integer(value) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1)
    throw new Error("Invalid service revision");
  return value;
}
/** @param {unknown} value @returns {string[]} */
function texts(value) {
  if (!Array.isArray(value)) throw new Error("Invalid service list");
  return value.map(text);
}
/** @param {unknown} value */
export function ownerAccount(value) {
  const account = object(value);
  if (typeof account.administrator !== "boolean")
    throw new Error("Invalid administrator setting");
  if (account.state !== "active") throw new Error("Owner account is inactive");
  return {
    id: text(account.id),
    displayName: text(account.display_name),
    email: text(account.contact_email),
    administrator: account.administrator,
  };
}
/** @param {unknown} value @returns {Tenant} */
export function tenant(value) {
  const v = object(value);
  const state = text(v.state);
  if (!["draft", "active", "suspended"].includes(state))
    throw new Error("Invalid tenant state");
  return {
    id: text(v.id),
    name: text(v.name),
    environment: text(v.environment),
    version: integer(v.version),
    state: /** @type {Tenant["state"]} */ (state),
    active_revision:
      v.active_revision === null ? null : integer(v.active_revision),
  };
}
/** @param {unknown} value @returns {Configuration} */
export function configuration(value) {
  const v = object(value);
  if (typeof v.local_development !== "boolean")
    throw new Error("Invalid local development setting");
  return {
    google_web_client_id: text(v.google_web_client_id),
    frontend_origins: texts(v.frontend_origins),
    api_base_url: text(v.api_base_url),
    local_development: v.local_development,
    session_ttl: text(v.session_ttl),
    refresh_ttl: text(v.refresh_ttl),
    revision: integer(v.revision),
    providers: texts(v.providers),
    session_cookie_name: text(v.session_cookie_name),
    refresh_cookie_name: text(v.refresh_cookie_name),
  };
}
/** @param {Configuration} value @returns {ConfigurationInput} */
export function editable(value) {
  return {
    google_web_client_id: value.google_web_client_id,
    frontend_origins: value.frontend_origins,
    api_base_url: value.api_base_url,
    local_development: value.local_development,
    session_ttl: value.session_ttl,
    refresh_ttl: value.refresh_ttl,
  };
}
/** @param {string} id */
export function tenantPath(id) {
  return `${PATHS.tenants}/${encodeURIComponent(id)}`;
}
export class Client {
  /** @param {string} origin */
  constructor(origin) {
    const u = new URL(origin);
    const loopbackHTTP =
      u.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
    if (u.origin !== origin || (u.protocol !== "https:" && !loopbackHTTP))
      throw new Error(
        "The console requires HTTPS or a loopback HTTP API origin",
      );
    this.origin = origin;
  }
  /** @param {string} method @param {string} path @param {AbortSignal} signal @param {unknown} [body] @param {string} [etag] @param {string} [key] */
  async request(method, path, signal, body, etag, key) {
    /** @type {Record<string,string>} */ const headers = {};
    if (method !== "GET") {
      headers["X-TAuth-CSRF"] = "1";
      headers["Content-Type"] = "application/json";
    }
    if (etag) headers["If-Match"] = etag;
    if (key) headers["Idempotency-Key"] = key;
    const response = await fetch(this.origin + path, {
      method,
      headers,
      credentials: "include",
      cache: "no-store",
      signal,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const value = object(await response.json());
    if (!response.ok)
      throw new RequestError(
        response.status,
        text(value.code),
        text(value.message),
      );
    return { value, etag: response.headers.get("ETag") || "" };
  }
  /** @template T @param {string} path @param {(v:unknown)=>T} parse @param {AbortSignal} signal @returns {Promise<T[]>} */
  async collection(path, parse, signal) {
    let cursor = "";
    const seen = new Set();
    /** @type {T[]} */ const items = [];
    do {
      const { value } = await this.request(
        "GET",
        `${path}?limit=100&cursor=${encodeURIComponent(cursor)}`,
        signal,
      );
      if (!Array.isArray(value.items)) throw new Error("Invalid collection");
      items.push(...value.items.map(parse));
      cursor = text(value.next_cursor);
      if (cursor && seen.has(cursor))
        throw new Error("Invalid collection cursor");
      seen.add(cursor);
    } while (cursor);
    return items;
  }
  /** @param {AbortSignal} signal */
  async bootstrap(signal) {
    const { value } = await this.request("GET", PATHS.bootstrap, signal);
    if (
      value.tenant_id !== "tauth-console" ||
      value.console_origin !== location.origin
    )
      throw new Error("Console origin does not match bootstrap");
    return {
      tenantId: "tauth-console",
      clientId: text(value.google_web_client_id),
    };
  }
  /** @param {AbortSignal} signal */
  async enroll(signal) {
    const { value } = await this.request("PUT", PATHS.owner, signal);
    return ownerAccount(value);
  }
  /** @param {string} id @param {AbortSignal} signal */
  async selected(id, signal) {
    const [resource, config] = await Promise.all([
      this.request("GET", tenantPath(id), signal),
      this.request("GET", tenantPath(id) + "/configuration", signal),
    ]);
    if (!resource.etag || !config.etag)
      throw new Error("Revision precondition is unavailable");
    return {
      tenant: tenant(resource.value),
      config: configuration(config.value),
      tenantETag: resource.etag,
      configETag: config.etag,
    };
  }
}
/** @returns {Promise<Client>} */
export async function loadClient() {
  const response = await fetch("./runtime.json", { cache: "no-store" });
  if (!response.ok) throw new Error("Runtime configuration is unavailable");
  const v = object(await response.json());
  return new Client(text(v.api_origin));
}

/** @typedef {{tenant_id:string,revision:number,api_base_url:string,frontend_origins:string[],google_web_client_id:string,script_url:string,session_cookie_name:string,session_ttl:string,browser_html:string,backend_configuration:Record<string,string>,auth_routes:string[]}} IntegrationView */
/** @param {unknown} value @returns {IntegrationView} */
export function integrationView(value) {
  const v = object(value);
  const backend = object(v.backend_configuration);
  return {
    tenant_id: text(v.tenant_id),
    revision: integer(v.revision),
    api_base_url: text(v.api_base_url),
    frontend_origins: texts(v.frontend_origins),
    google_web_client_id: text(v.google_web_client_id),
    script_url: text(v.script_url),
    session_cookie_name: text(v.session_cookie_name),
    session_ttl: text(v.session_ttl),
    browser_html: text(v.browser_html),
    backend_configuration: Object.fromEntries(
      Object.entries(backend).map(([key, value]) => [key, text(value)]),
    ),
    auth_routes: texts(v.auth_routes),
  };
}
/** @param {unknown} value */
export function reauthentication(value) {
  const v = object(value);
  const expires = text(v.expires_at);
  if (
    !Number.isFinite(Date.parse(expires)) ||
    v.operation !== "session-key-export"
  )
    throw new Error("Invalid authentication transaction");
  return {
    id: text(v.id),
    nonce: text(v.nonce),
    expires_at: expires,
    revision: integer(v.revision),
  };
}
/** @param {unknown} value */
export function exportedKey(value) {
  const v = object(value);
  text(v.id);
  integer(v.revision);
  const key = text(v.session_key_base64);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(key))
    throw new Error("Invalid exported key");
  return key;
}
/** @typedef {{id:string,revision:number,state:string,created_at:string,evidence:{path:string,status:number,code:string}[]}} SetupCheck */
/** @param {unknown} value @returns {SetupCheck} */
export function setupCheck(value) {
  const v = object(value);
  const state = text(v.state),
    created = text(v.created_at);
  if (
    !["succeeded", "failed"].includes(state) ||
    !Number.isFinite(Date.parse(created)) ||
    !Array.isArray(v.evidence)
  )
    throw new Error("Invalid setup result");
  return {
    id: text(v.id),
    revision: integer(v.revision),
    state,
    created_at: created,
    evidence: v.evidence.map((item) => {
      const e = object(item);
      if (
        typeof e.status !== "number" ||
        !Number.isSafeInteger(e.status) ||
        e.status < 0 ||
        e.status > 599
      )
        throw new Error("Invalid probe status");
      return { path: text(e.path), status: e.status, code: text(e.code) };
    }),
  };
}
