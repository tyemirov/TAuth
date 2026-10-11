// @ts-check

/* @mprlab/mpr-ui */
(function (global) {
  "use strict";

  var DEFAULT_OPTIONS = {
    siteName: "",
    siteLink: "",
  };
  var AUTH_CONFIG_ATTRIBUTE = "auth-config";
  var AUTH_PATH_VALIDATION_ORIGIN = "https://mpr-ui.invalid";
  var AUTH_CONFIG_ERROR_CODES = Object.freeze({
    REQUIRED: "mpr-ui.auth.config_required",
    INVALID_JSON: "mpr-ui.auth.config_invalid_json",
    UNKNOWN_KEY: "mpr-ui.auth.config_unknown_key",
    VALUE_REQUIRED: "mpr-ui.auth.config_value_required",
    VALUE_INVALID: "mpr-ui.auth.config_value_invalid",
    PROVIDER_REQUIRED: "mpr-ui.auth.provider_required",
    PROVIDER_SETTINGS_DISABLED: "mpr-ui.auth.provider_settings_disabled",
    ENABLED_PROVIDER_REQUIRED: "mpr-ui.auth.enabled_provider_required",
    PROVIDER_DISABLED: "mpr-ui.auth.provider_disabled",
    REDIRECT_NAVIGATION_UNAVAILABLE: "mpr-ui.auth.redirect_navigation_unavailable",
    REDIRECT_LIFECYCLE_CHANGED: "mpr-ui.auth.redirect_lifecycle_changed",
  });
  var AUTH_CONFIG_KEYS = Object.freeze([
    "tauthUrl",
    "tenantId",
    "logoutPath",
    "sessionPath",
    "providers",
    "password",
    "account",
  ]);
  var AUTH_CONFIG_PROVIDER_KEYS = Object.freeze(["google", "apple", "password"]);
  var AUTH_CONFIG_GOOGLE_KEYS = Object.freeze([
    "enabled",
    "clientId",
    "loginPath",
    "noncePath",
  ]);
  var AUTH_CONFIG_APPLE_KEYS = Object.freeze([
    "enabled",
    "startPath",
    "returnTo",
    "label",
  ]);
  var AUTH_CONFIG_PASSWORD_PROVIDER_KEYS = Object.freeze(["enabled"]);
  var AUTH_CONFIG_PASSWORD_KEYS = Object.freeze([
    "loginPath",
    "signupPath",
    "verifyEmailPath",
    "resetStartPath",
    "resetCompletePath",
  ]);
  var AUTH_CONFIG_ACCOUNT_KEYS = Object.freeze([
    "passwordChangePath",
    "passwordLinkStartPath",
    "passwordLinkVerifyPath",
    "googleLinkPath",
    "unlinkPath",
    "disablePath",
  ]);
  var APPLE_PROVIDER_LABELS = Object.freeze([
    "Sign in with Apple",
    "Sign up with Apple",
    "Continue with Apple",
  ]);
  var APPLE_RETURN_TARGET_POLICY = Object.freeze({
    CURRENT_URL: "current-url",
    CURRENT_ORIGIN: "current-origin",
  });
  var APPLE_RETURN_QUERY_KEYS = Object.freeze([
    "code",
    "state",
    "id_token",
    "access_token",
    "refresh_token",
    "client_secret",
    "user",
    "error",
    "error_description",
    "session_state",
    "tenant_id",
    "return_to",
  ]);
  var AUTH_REDIRECT_QUERY_KEYS = Object.freeze({
    TENANT_ID: "tenant_id",
    RETURN_TO: "return_to",
  });
  var AUTH_ACTION_LABELS = Object.freeze({
    google: "Sign in with Google",
    googlePreparing: "Starting Google sign-in…",
    googleFailure: "Unable to start Google sign-in. Try again.",
    applePreparing: "Opening Apple sign-in…",
    appleFailure: "Unable to open Apple sign-in. Try again.",
    passwordPreparing: "Email sign-in is ready.",
    passwordFailure: "Unable to open email sign-in. Try again.",
  });
  var AUTH_DIAGNOSTICS_LABELS = Object.freeze({
    heading: "Authentication diagnostics",
    status: "Status",
    user: "User",
    noUser: "No authenticated user",
    bootstrapping: "Bootstrapping",
    authenticating: "Authenticating",
    authenticated: "Authenticated",
    unauthenticated: "Unauthenticated",
    error: "Error",
  });
  var AUTH_DIAGNOSTICS_TARGET_ATTRIBUTE = "auth-target";
  var AUTH_DIAGNOSTICS_TARGET_REQUIRED_ERROR_CODE =
    "mpr-ui.auth_diagnostics.target_required";
  var AUTH_DIAGNOSTICS_TARGET_MISSING_ERROR_CODE =
    "mpr-ui.auth_diagnostics.target_missing";
  var AUTH_DIAGNOSTICS_TARGET_INVALID_ERROR_CODE =
    "mpr-ui.auth_diagnostics.target_invalid";
  var AUTH_COMPONENT_TARGET_ATTRIBUTE = "auth-target";
  var PASSWORD_AUTH_MODE_ATTRIBUTE = "mode";
  var PASSWORD_AUTH_MODE_EVENT = "mpr-ui:password-auth:mode-change";
  var ACCOUNT_PANEL_ACTION_ATTRIBUTE = "action";
  var ACCOUNT_PANEL_IDENTITIES_ATTRIBUTE = "identities";
  var CHALLENGE_TOKEN_FRAGMENT_PARAMETER_ATTRIBUTE =
    "token-fragment-parameter";
  var AUTH_FORM_STYLE_ID = "mpr-ui-auth-form-styles";
  var PASSWORD_AUTH_MODES = Object.freeze([
    "login",
    "signup",
    "verify-email",
    "reset-start",
    "reset-complete",
  ]);
  var ACCOUNT_PANEL_ACTIONS = Object.freeze([
    "password-change",
    "password-link-start",
    "password-link-verify",
    "google-link",
    "unlink",
    "disable",
  ]);
  var ACCOUNT_IDENTITY_PROVIDERS = Object.freeze([
    "apple",
    "google",
    "password",
  ]);
  var AUTH_FORM_LABELS = Object.freeze({
    email: "Email",
    password: "Password",
    token: "Challenge token",
    currentPassword: "Current password",
    newPassword: "New password",
    identity: "Sign-in method",
    emailAuthModes: "Email authentication",
    loginTitle: "Sign in with email",
    loginSubmit: "Sign in",
    signupTitle: "Create an account",
    signupSubmit: "Create account",
    verifyEmailTitle: "Verify your email",
    verifyEmailSubmit: "Verify email",
    resetStartTitle: "Reset your password",
    resetStartSubmit: "Send reset instructions",
    forgotPassword: "Forgot password?",
    backToSignIn: "Back to sign in",
    newResetLink: "Send a new reset link",
    resetStartSuccess: "Check your email. If this account supports email sign-in, you will receive a password reset link.",
    resetCompleteSuccess: "Your password has been reset.",
    resetCompleteTitle: "Choose a new password",
    resetCompleteSubmit: "Reset password",
    passwordChangeTitle: "Change password",
    passwordChangeSubmit: "Change password",
    passwordLinkStartTitle: "Add email sign-in",
    passwordLinkStartSubmit: "Send verification",
    passwordLinkVerifyTitle: "Verify email sign-in",
    passwordLinkVerifySubmit: "Link password",
    googleLinkTitle: "Add Google sign-in",
    unlinkTitle: "Remove a sign-in method",
    unlinkSubmit: "Remove identity",
    disableTitle: "Disable account",
    disableSubmit: "Disable account",
    unauthenticated: "Sign in to manage this account.",
    ready: "",
    loading: "Working…",
    success: "Completed.",
    failure: "Unable to complete the request.",
  });
  var normalizedAuthOptions = new WeakSet();
  var REQUESTED_WITH_HEADER = "XMLHttpRequest";
  var TAUTH_RUNTIME_SESSION_PATH = "/auth/session";
  var AUTH_RESTORE_HINT_PREFIX = "tauth.restore.v1:";
  var AUTH_RECOVERY_RECORD_PREFIX = "mpr-ui.auth.recovery.v2:";
  var AUTH_RECOVERY_LOCK_PREFIX = "mpr-ui:auth:recovery:v2:";
  var AUTH_RECOVERY_LIFECYCLE_CHANGED_ERROR_CODE =
    "mpr-ui.auth.recovery_lifecycle_changed";
  var AUTH_MUTATION_REPLAY_POLICY = "authorization-before-domain-work";
  var AUTH_SESSION_RETRY_POLICY = Object.freeze({
    initialDelayMs: 250,
    maximumDelayMs: 5000,
    multiplier: 2,
  });
  var AUTH_BOOTSTRAP_RESTORE_IF_HINTED = "restore-if-hinted";
  var authSessionRecoveryPromises = Object.create(null);
  var AUTH_CONTROLLER_STATUS = Object.freeze({
    BOOTSTRAPPING: "bootstrapping",
    AUTHENTICATING: "authenticating",
    AUTHENTICATED: "authenticated",
    UNAUTHENTICATED: "unauthenticated",
  });
  var GOOGLE_SIGNIN_TEST_ID = "google-signin";
  var GOOGLE_NONCE_REFRESH_INTERVAL_MS = 4 * 60 * 1000;
  var GOOGLE_NONCE_RETRY_INTERVAL_MS = 30 * 1000;
  var GOOGLE_SIGNIN_TEXT_OPTION = Object.freeze({
    SIGN_IN_WITH: "signin_with",
    SIGN_UP_WITH: "signup_with",
    CONTINUE_WITH: "continue_with",
    SIGN_IN: "signin",
  });
  var GOOGLE_SIGNIN_TEXT_LABELS = Object.freeze(
    (function createGoogleSignInTextLabels() {
      var labels = {};
      labels[GOOGLE_SIGNIN_TEXT_OPTION.SIGN_IN_WITH] = "Sign in with Google";
      labels[GOOGLE_SIGNIN_TEXT_OPTION.SIGN_UP_WITH] = "Sign up with Google";
      labels[GOOGLE_SIGNIN_TEXT_OPTION.CONTINUE_WITH] = "Continue with Google";
      labels[GOOGLE_SIGNIN_TEXT_OPTION.SIGN_IN] = "Sign in";
      return labels;
    })()
  );
  var LOGIN_BUTTON_ROOT_CLASS = "mpr-login-button";
  var LOGIN_BUTTON_STYLE_ID = "mpr-ui-login-button-styles";
  var LOGIN_BUTTON_CONTAINER_SELECTOR = '[data-mpr-login="auth-actions"]';
  var LOGIN_BUTTON_MOUNTED_ATTRIBUTE = "data-mpr-login-mounted";
  var LOGIN_BUTTON_THEME_ATTRIBUTE = "data-mpr-login-theme";
  var LOGIN_BUTTON_SIZE_ATTRIBUTE = "data-mpr-login-size";
  var LOGIN_BUTTON_SHAPE_ATTRIBUTE = "data-mpr-login-shape";
  var LOGIN_BUTTON_THEME = Object.freeze({
    OUTLINE: "outline",
    FILLED_BLUE: "filled_blue",
    FILLED_BLACK: "filled_black",
  });
  var LOGIN_BUTTON_SIZE = Object.freeze({
    SMALL: "small",
    MEDIUM: "medium",
    LARGE: "large",
  });
  var LOGIN_BUTTON_SHAPE = Object.freeze({
    RECTANGULAR: "rectangular",
    PILL: "pill",
    SQUARE: "square",
    CIRCLE: "circle",
  });
  var LOGIN_BUTTON_PRESENTATION_VALUES = Object.freeze({
    theme: Object.freeze([
      LOGIN_BUTTON_THEME.OUTLINE,
      LOGIN_BUTTON_THEME.FILLED_BLUE,
      LOGIN_BUTTON_THEME.FILLED_BLACK,
    ]),
    size: Object.freeze([
      LOGIN_BUTTON_SIZE.SMALL,
      LOGIN_BUTTON_SIZE.MEDIUM,
      LOGIN_BUTTON_SIZE.LARGE,
    ]),
    shape: Object.freeze([
      LOGIN_BUTTON_SHAPE.RECTANGULAR,
      LOGIN_BUTTON_SHAPE.PILL,
      LOGIN_BUTTON_SHAPE.SQUARE,
      LOGIN_BUTTON_SHAPE.CIRCLE,
    ]),
  });
  var LOGIN_BUTTON_PRESENTATION_ERROR_CODES = Object.freeze({
    theme: "mpr-ui.login_button.invalid_theme",
    size: "mpr-ui.login_button.invalid_size",
    shape: "mpr-ui.login_button.invalid_shape",
  });
  var LOGIN_BUTTON_PRESENTATION_DEFAULTS = Object.freeze({
    theme: LOGIN_BUTTON_THEME.OUTLINE,
    size: LOGIN_BUTTON_SIZE.MEDIUM,
    shape: LOGIN_BUTTON_SHAPE.RECTANGULAR,
  });
  var AUTH_PROVIDER_CHOOSER_ROOT_CLASS = "mpr-auth-provider-chooser";
  var AUTH_PROVIDER_CHOOSER_STYLE_ID = "mpr-ui-auth-provider-chooser-styles";
  var AUTH_PROVIDER_CHOOSER_PROVIDERS_ATTRIBUTE = "providers";
  var AUTH_PROVIDER_CHOOSER_VARIANT_ATTRIBUTE = "variant";
  var AUTH_PROVIDER_CHOOSER_ERROR_ATTRIBUTE = "data-mpr-auth-provider-error";
  var AUTH_PROVIDER_CHOOSER_SELECTED_ATTRIBUTE =
    "data-mpr-auth-provider-selected";
  var AUTH_PROVIDER_CHOOSER_EMAIL_EXPANDED_ATTRIBUTE =
    "data-mpr-auth-provider-email-expanded";
  var AUTH_PROVIDER_SELECT_EVENT = "mpr-auth-provider:select";
  var AUTH_PROVIDER_EMAIL_SUBMIT_EVENT = "mpr-auth-provider:email-submit";
  var AUTH_PROVIDER_EMAIL_MODE_EVENT = "mpr-auth-provider:email-mode";
  var AUTH_PROVIDER_ERROR_EVENT = "mpr-auth-provider:error";
  var AUTH_PROVIDER_CHOOSER_PROVIDERS_REQUIRED_ERROR_CODE =
    "mpr-ui.auth_provider_chooser.providers_required";
  var AUTH_PROVIDER_CHOOSER_PROVIDERS_INVALID_ERROR_CODE =
    "mpr-ui.auth_provider_chooser.providers_invalid";
  var AUTH_PROVIDER_CHOOSER_UNSUPPORTED_PROVIDER_ERROR_CODE =
    "mpr-ui.auth_provider_chooser.unsupported_provider";
  var AUTH_PROVIDER_CHOOSER_DUPLICATE_PROVIDER_ERROR_CODE =
    "mpr-ui.auth_provider_chooser.duplicate_provider";
  var AUTH_PROVIDER_CHOOSER_UNSUPPORTED_VARIANT_ERROR_CODE =
    "mpr-ui.auth_provider_chooser.unsupported_variant";
  var AUTH_PROVIDER_CHOOSER_LABELS = Object.freeze({
    group: "Authentication providers",
    apple: "Continue with Apple",
    google: "Continue with Google",
    email: "Continue with email",
    emailField: "Email",
    passwordField: "Password",
    submit: "Sign in",
    forgotPassword: "Forgot password",
    createAccount: "Create account",
  });
  var AUTH_PROVIDER_CHOOSER_MARKUP = Object.freeze({
    apple:
      '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path fill="currentColor" d="M11.182.008C11.148-.03 9.923.023 8.857 1.18 7.791 2.336 7.955 3.662 7.979 3.696c.024.034 1.52.087 2.475-1.258C11.409 1.093 11.216.046 11.182.008Zm3.314 11.733c-.048-.096-2.325-1.234-2.113-3.422.212-2.189 1.675-2.789 1.698-2.854.023-.065-.597-.79-1.254-1.157a3.692 3.692 0 0 0-1.563-.434c-.108-.003-.483-.095-1.254.116-.508.139-1.653.589-1.968.607-.316.018-1.256-.522-2.267-.665-.647-.125-1.333.131-1.824.328-.49.196-1.422.754-2.074 2.237-.652 1.482-.311 3.83-.067 4.56.244.729.625 1.924 1.273 2.796.576.984 1.34 1.667 1.659 1.899.319.232 1.219.386 1.843.067.502-.308 1.408-.485 1.766-.472.357.013 1.061.154 1.782.539.571.197 1.111.115 1.652-.105.541-.221 1.324-1.059 2.238-2.758.347-.79.505-1.217.473-1.282Z"/></svg>',
    google:
      '<svg viewBox="0 0 18 18" aria-hidden="true" focusable="false"><path fill="#4285f4" d="M17.64 9.204c0-.638-.057-1.252-.164-1.841H9v3.482h4.844a4.14 4.14 0 0 1-1.793 2.716v2.258h2.909c1.699-1.563 2.68-3.874 2.68-6.615Z"/><path fill="#34a853" d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.909-2.259c-.806.54-1.837.859-3.047.859-2.344 0-4.328-1.583-5.036-3.71H.957v2.332C2.438 15.983 5.482 18 9 18Z"/><path fill="#fbbc05" d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.594.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332Z"/><path fill="#ea4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.346l2.582-2.582C13.463.892 11.426 0 9 0 5.482 0 2.438 2.017.957 4.958L3.964 7.29C4.672 5.162 6.656 3.58 9 3.58Z"/></svg>',
    email:
      '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M4 6h16v12H4z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="m4 7 8 6 8-6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  });
  var AUTH_PROVIDER_IDS = Object.freeze({
    APPLE: "apple",
    GOOGLE: "google",
    EMAIL: "email",
  });
  var AUTH_PROVIDER_ID_VALUES = Object.freeze([
    AUTH_PROVIDER_IDS.APPLE,
    AUTH_PROVIDER_IDS.GOOGLE,
    AUTH_PROVIDER_IDS.EMAIL,
  ]);
  var AUTH_PROVIDER_EMAIL_MODE = Object.freeze({
    RESET_START: "reset-start",
    SIGNUP: "signup",
  });
  var AUTH_PROVIDER_CHOOSER_VARIANTS = Object.freeze({
    STACK: "stack",
    ICON_ROW: "icon-row",
  });
  var AUTH_PROVIDER_CHOOSER_VARIANT_VALUES = Object.freeze([
    AUTH_PROVIDER_CHOOSER_VARIANTS.STACK,
    AUTH_PROVIDER_CHOOSER_VARIANTS.ICON_ROW,
  ]);

  /**
   * @typedef {{ code?: string, status?: number }} MprUiErrorMetadata
   * @typedef {Error & MprUiErrorMetadata} MprUiError
   * @typedef {"apple"|"google"|"email"} AuthProviderId
   * @typedef {"current-url"|"current-origin"|string} AppleReturnTargetPolicy
   * @typedef {{ enabled: false } | { enabled: true, clientId: string, loginPath: string, noncePath: string }} GoogleAuthProviderConfig
   * @typedef {{ enabled: false } | { enabled: true, startPath: string, returnTo: AppleReturnTargetPolicy, label: string }} AppleAuthProviderConfig
   * @typedef {{ enabled: boolean }} PasswordAuthProviderConfig
   * @typedef {GoogleAuthProviderConfig|AppleAuthProviderConfig|PasswordAuthProviderConfig} AuthProviderConfig
   * @typedef {{ google: GoogleAuthProviderConfig, apple: AppleAuthProviderConfig, password: PasswordAuthProviderConfig }} AuthProviderMap
   * @typedef {{ loginPath: string, signupPath: string, verifyEmailPath: string, resetStartPath: string, resetCompletePath: string }} PasswordAuthPathConfig
   * @typedef {{ passwordChangePath: string, passwordLinkStartPath: string, passwordLinkVerifyPath: string, googleLinkPath: string, unlinkPath: string, disablePath: string }} AccountAuthPathConfig
   * @typedef {"login"|"signup"|"verify-email"|"reset-start"|"reset-complete"} PasswordAuthAction
   * @typedef {"password-change"|"password-link-start"|"password-link-verify"|"google-link"|"unlink"|"disable"} AccountAuthAction
   * @typedef {{ email?: string, password?: string, token?: string }} PasswordActionRequest
   * @typedef {{ currentPassword?: string, newPassword?: string, email?: string, password?: string, token?: string, credential?: string, nonceToken?: string, provider?: string, providerId?: string }} AccountActionRequest
   * @typedef {{ provider: "apple"|"google"|"password", providerId: string, label: string }} AccountIdentityOption
   * @typedef {{ action: PasswordAuthAction|AccountAuthAction, status: "authenticated"|"accepted"|"updated"|"disabled", expiresUnix?: number|null }} NormalizedAuthActionResult
   * @typedef {{ mode: PasswordAuthAction, status: "loading"|"success"|"error", code?: string }} PasswordAuthStatusEventDetail
   * @typedef {{ action: AccountAuthAction, status: "loading"|"success"|"error", code?: string }} AccountPanelStatusEventDetail
   * @typedef {{
   *   tauthUrl: string,
   *   tenantId: string,
   *   logoutPath: string,
   *   sessionPath: string,
   *   providers: AuthProviderMap,
   *   password?: PasswordAuthPathConfig,
   *   account?: AccountAuthPathConfig,
   * }} AuthOptions
   * @typedef {{
   *   provider: "apple",
   *   url: string,
   *   pendingRestore: true,
   * }} NormalizedProviderActionOptions
   * @typedef {"stack"|"icon-row"} AuthProviderChooserVariant
   * @typedef {{ providers: readonly AuthProviderId[], variant: AuthProviderChooserVariant }} AuthProviderChooserOptions
   * @typedef {"top"|"bottom"} DropdownPlacement
   * @typedef {"static"|"expanded"|"collapsed"} DropdownSectionMode
   * @typedef {{ label: string, href: string, target: string, rel: string }} DropdownLink
   * @typedef {{ id: string, label: string, mode: DropdownSectionMode, links: readonly DropdownLink[] }} DropdownSection
   * @typedef {{ label: string, placement: DropdownPlacement, sections: readonly DropdownSection[] }} DropdownMenu
   * @typedef {{
   *   mutationReplay?: "authorization-before-domain-work",
   * }} AuthenticatedFetchPolicy
   * @typedef {{
   *   generation: number,
   *   status: "authenticated"|"unauthenticated",
   *   code?: string,
   *   responseStatus?: number,
   * }} AuthRecoveryRecord
   * @typedef {{
   *   status: "authenticated"|"unauthenticated"|"error",
   *   profile: object|null,
   *   code?: string,
   *   responseStatus?: number,
   * }} AuthRecoveryResult
   * @typedef {{ script: string, title: string, copy: string, height?: number }} SubscribeConfig
   * @typedef {{
   *   id: string,
   *   name: string,
   *   description: string,
   *   status: string,
   *   category: string,
   *   url: string,
   *   icon: string,
   *   subscribe?: SubscribeConfig,
   * }} BandCatalogEntry
   * @typedef {{
   *   companyName: string,
   *   companyShortName: string,
   *   companyForm: string,
   *   websiteUrl: string,
   *   supportEmail: string,
   *   legalNoticesEmail: string,
   *   phoneDisplay: string,
   *   phoneHref: string,
   * }} LegalProfile
   * @typedef {{
   *   id: string,
   *   heading: string,
   *   paragraphs: string[],
   *   list: string[],
   * }} LegalDocumentSection
   * @typedef {{
   *   type: string,
   *   title: string,
   *   productName: string,
   *   effectiveDate: string,
   *   effectiveDateText: string,
   *   lastUpdatedDate: string,
   *   profile: LegalProfile,
   *   introduction: string[],
   *   sections: LegalDocumentSection[],
   * }} LegalDocument
   * @typedef {{
   *   render?: () => void,
   *   destroy?: () => void,
   *   update?: (name: string, oldValue: string|null, newValue: string|null) => void,
   *   __mprConnected?: boolean,
   * }} MprElementLifecycle
   */

  var ATTRIBUTE_MAP = {
    user_id: "data-user-id",
    user_email: "data-user-email",
    display: "data-user-display",
    avatar_url: "data-user-avatar-url",
  };
  var SAFE_AUTH_PROFILE_FIELDS = Object.freeze([
    "user_id",
    "user_email",
    "display",
    "avatar_url",
    "given_name",
    "first_name",
    "full_name",
    "name",
  ]);

  var GOOGLE_IDENTITY_SCRIPT_URL = "https://accounts.google.com/gsi/client";
  var GOOGLE_SITE_ID_ERROR_CODE = "mpr-ui.google_site_id_required";
  var TENANT_ID_ERROR_CODE = "mpr-ui.tenant_id_required";
  var AUTH_TENANT_ID_CHANGE_ERROR_CODE =
    "mpr-ui.auth.tenant_id_change_unsupported";
  var googleIdentityPromise = null;

  function normalizeGoogleSiteId(value) {
    if (typeof value !== "string") {
      return null;
    }
    var trimmed = value.trim();
    return trimmed ? trimmed : null;
  }

  /**
   * @param {string=} message
   * @returns {MprUiError}
   */
  function createGoogleSiteIdError(message) {
    /** @type {MprUiError} */
    var error = new Error(message || "Google client ID is required");
    error.code = GOOGLE_SITE_ID_ERROR_CODE;
    return error;
  }

  function normalizeTenantId(value) {
    if (typeof value !== "string") {
      return null;
    }
    var trimmed = value.trim();
    return trimmed ? trimmed : null;
  }

  /**
   * @param {string=} message
   * @returns {MprUiError}
   */
  function createTenantIdError(message) {
    /** @type {MprUiError} */
    var error = new Error(message || "Tenant ID is required");
    error.code = TENANT_ID_ERROR_CODE;
    return error;
  }

  function requireTenantId(value) {
    var normalized = normalizeTenantId(value);
    if (!normalized) {
      throw createTenantIdError();
    }
    return normalized;
  }

  /**
   * @param {string} code
   * @param {string} message
   * @returns {MprUiError}
   */
  function createAuthConfigError(code, message) {
    /** @type {MprUiError} */
    var error = new Error(message);
    error.code = code;
    return error;
  }

  function requireAuthConfigObject(value, scope) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.VALUE_REQUIRED,
        scope + " must be an object",
      );
    }
    return value;
  }

  function rejectUnknownAuthConfigKeys(value, allowedKeys, scope) {
    Object.keys(value).forEach(function rejectUnknownAuthConfigKey(key) {
      if (allowedKeys.indexOf(key) === -1) {
        throw createAuthConfigError(
          AUTH_CONFIG_ERROR_CODES.UNKNOWN_KEY,
          "Unknown " + scope + "." + key,
        );
      }
    });
  }

  function requireAuthConfigString(value, key, scope, allowEmpty) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.VALUE_REQUIRED,
        scope + "." + key + " is required",
      );
    }
    var rawValue = value[key];
    if (typeof rawValue !== "string") {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.VALUE_REQUIRED,
        scope + "." + key + " is required",
      );
    }
    var normalizedValue = rawValue.trim();
    if (!allowEmpty && !normalizedValue) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.VALUE_REQUIRED,
        scope + "." + key + " is required",
      );
    }
    return normalizedValue;
  }

  function requireAuthConfigBoolean(value, key, scope) {
    if (typeof value[key] !== "boolean") {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.VALUE_REQUIRED,
        scope + "." + key + " is required",
      );
    }
    return value[key];
  }

  function normalizeAuthOrigin(value, key, scope) {
    var normalizedValue = requireAuthConfigString(value, key, scope, true);
    if (!normalizedValue) {
      return "";
    }
    var parsedUrl;
    try {
      parsedUrl = new URL(normalizedValue);
    } catch (_error) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.VALUE_INVALID,
        scope + "." + key + " must be an HTTP origin",
      );
    }
    if (
      (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") ||
      parsedUrl.username ||
      parsedUrl.password ||
      parsedUrl.pathname !== "/" ||
      parsedUrl.search ||
      parsedUrl.hash
    ) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.VALUE_INVALID,
        scope + "." + key + " must be an HTTP origin",
      );
    }
    return parsedUrl.origin;
  }

  function normalizeAuthNavigationPath(value, key, scope) {
    var normalizedValue = requireAuthConfigString(value, key, scope, false);
    if (!isSameOriginAuthNavigationPath(normalizedValue)) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.VALUE_INVALID,
        scope + "." + key + " must be a same-origin path",
      );
    }
    return normalizedValue;
  }

  function isSameOriginAuthNavigationPath(value) {
    if (
      value.charAt(0) !== "/" ||
      value.indexOf("//") === 0 ||
      value.indexOf("\\") !== -1 ||
      value.indexOf("?") !== -1 ||
      value.indexOf("#") !== -1
    ) {
      return false;
    }
    return new URL(value, AUTH_PATH_VALIDATION_ORIGIN).origin ===
      AUTH_PATH_VALIDATION_ORIGIN;
  }

  function normalizeAppleReturnTargetPolicy(value, key, scope) {
    var normalizedValue = requireAuthConfigString(value, key, scope, false);
    if (
      normalizedValue === APPLE_RETURN_TARGET_POLICY.CURRENT_URL ||
      normalizedValue === APPLE_RETURN_TARGET_POLICY.CURRENT_ORIGIN
    ) {
      return normalizedValue;
    }
    if (isSameOriginAuthNavigationPath(normalizedValue)) {
      return normalizedValue;
    }
    throw createAuthConfigError(
      AUTH_CONFIG_ERROR_CODES.VALUE_INVALID,
      scope + "." + key + " must be current-url, current-origin, or a same-origin path",
    );
  }

  function requireDisabledProviderShape(providerConfig, scope) {
    if (Object.keys(providerConfig).length !== 1) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.PROVIDER_SETTINGS_DISABLED,
        scope + " cannot include settings when disabled",
      );
    }
  }

  function normalizeGoogleAuthProviderConfig(providersConfig) {
    var scope = "auth.providers.google";
    var providerConfig = requireAuthConfigObject(providersConfig.google, scope);
    rejectUnknownAuthConfigKeys(providerConfig, AUTH_CONFIG_GOOGLE_KEYS, scope);
    var enabled = requireAuthConfigBoolean(providerConfig, "enabled", scope);
    if (!enabled) {
      requireDisabledProviderShape(providerConfig, scope);
      return Object.freeze({ enabled: false });
    }
    return Object.freeze({
      enabled: true,
      clientId: requireAuthConfigString(providerConfig, "clientId", scope, false),
      loginPath: normalizeAuthNavigationPath(providerConfig, "loginPath", scope),
      noncePath: normalizeAuthNavigationPath(providerConfig, "noncePath", scope),
    });
  }

  function normalizeAppleAuthProviderConfig(providersConfig) {
    var scope = "auth.providers.apple";
    var providerConfig = requireAuthConfigObject(providersConfig.apple, scope);
    rejectUnknownAuthConfigKeys(providerConfig, AUTH_CONFIG_APPLE_KEYS, scope);
    var enabled = requireAuthConfigBoolean(providerConfig, "enabled", scope);
    if (!enabled) {
      requireDisabledProviderShape(providerConfig, scope);
      return Object.freeze({ enabled: false });
    }
    var label = requireAuthConfigString(providerConfig, "label", scope, false);
    if (APPLE_PROVIDER_LABELS.indexOf(label) === -1) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.VALUE_INVALID,
        scope + ".label must use an Apple-approved title",
      );
    }
    return Object.freeze({
      enabled: true,
      startPath: normalizeAuthNavigationPath(providerConfig, "startPath", scope),
      returnTo: normalizeAppleReturnTargetPolicy(providerConfig, "returnTo", scope),
      label: label,
    });
  }

  function normalizePasswordAuthProviderConfig(providersConfig) {
    var scope = "auth.providers.password";
    var providerConfig = requireAuthConfigObject(providersConfig.password, scope);
    rejectUnknownAuthConfigKeys(
      providerConfig,
      AUTH_CONFIG_PASSWORD_PROVIDER_KEYS,
      scope,
    );
    return Object.freeze({
      enabled: requireAuthConfigBoolean(providerConfig, "enabled", scope),
    });
  }

  function normalizeAuthPathConfig(authConfig, key, allowedKeys, scope) {
    if (!Object.prototype.hasOwnProperty.call(authConfig, key)) {
      return null;
    }
    var pathConfig = requireAuthConfigObject(authConfig[key], scope);
    rejectUnknownAuthConfigKeys(pathConfig, allowedKeys, scope);
    var normalizedPaths = {};
    allowedKeys.forEach(function normalizeConfiguredPath(pathKey) {
      normalizedPaths[pathKey] = normalizeAuthNavigationPath(
        pathConfig,
        pathKey,
        scope,
      );
    });
    return Object.freeze(normalizedPaths);
  }

  /**
   * Create the normalized provider-aware authentication options.
   *
   * @param {unknown} rawValue
   * @returns {AuthOptions}
   */
  function createAuthOptions(rawValue) {
    if (
      rawValue &&
      typeof rawValue === "object" &&
      normalizedAuthOptions.has(/** @type {object} */ (rawValue))
    ) {
      return /** @type {AuthOptions} */ (rawValue);
    }
    var authConfig = requireAuthConfigObject(rawValue, "auth");
    rejectUnknownAuthConfigKeys(authConfig, AUTH_CONFIG_KEYS, "auth");
    var providersConfig = requireAuthConfigObject(
      authConfig.providers,
      "auth.providers",
    );
    rejectUnknownAuthConfigKeys(
      providersConfig,
      AUTH_CONFIG_PROVIDER_KEYS,
      "auth.providers",
    );
    var googleProvider = normalizeGoogleAuthProviderConfig(providersConfig);
    var appleProvider = normalizeAppleAuthProviderConfig(providersConfig);
    var passwordProvider = normalizePasswordAuthProviderConfig(providersConfig);
    if (!googleProvider.enabled && !appleProvider.enabled && !passwordProvider.enabled) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.ENABLED_PROVIDER_REQUIRED,
        "Authentication requires an enabled provider",
      );
    }
    var passwordConfig = normalizeAuthPathConfig(
      authConfig,
      "password",
      AUTH_CONFIG_PASSWORD_KEYS,
      "auth.password",
    );
    var accountConfig = normalizeAuthPathConfig(
      authConfig,
      "account",
      AUTH_CONFIG_ACCOUNT_KEYS,
      "auth.account",
    );
    if (passwordProvider.enabled && !passwordConfig) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.VALUE_REQUIRED,
        "auth.password is required when password authentication is enabled",
      );
    }
    var normalizedOptionsPayload = {
      tauthUrl: normalizeAuthOrigin(authConfig, "tauthUrl", "auth"),
      tenantId: requireAuthConfigString(authConfig, "tenantId", "auth", false),
      logoutPath: normalizeAuthNavigationPath(authConfig, "logoutPath", "auth"),
      sessionPath: normalizeAuthNavigationPath(authConfig, "sessionPath", "auth"),
      providers: Object.freeze({
        google: googleProvider,
        apple: appleProvider,
        password: passwordProvider,
      }),
    };
    if (passwordConfig) {
      normalizedOptionsPayload.password = passwordConfig;
    }
    if (accountConfig) {
      normalizedOptionsPayload.account = accountConfig;
    }
    /** @type {AuthOptions} */
    var normalizedOptions = Object.freeze(normalizedOptionsPayload);
    normalizedAuthOptions.add(normalizedOptions);
    return normalizedOptions;
  }

  function parseAuthConfigAttribute(hostElement) {
    var rawValue = hostElement.getAttribute(AUTH_CONFIG_ATTRIBUTE);
    if (typeof rawValue !== "string" || !rawValue.trim()) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.REQUIRED,
        "auth-config is required",
      );
    }
    var parsedValue;
    try {
      parsedValue = JSON.parse(rawValue);
    } catch (_error) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.INVALID_JSON,
        "auth-config must be valid JSON",
      );
    }
    return createAuthOptions(parsedValue);
  }

  /**
   * @param {string} currentTenantId
   * @param {string|null} nextTenantId
   * @returns {MprUiError}
   */
  function createAuthTenantIdChangeError(currentTenantId, nextTenantId) {
    var nextTenantLabel =
      typeof nextTenantId === "string" && nextTenantId.trim()
        ? nextTenantId
        : "<missing>";
    /** @type {MprUiError} */
    var error = new Error(
      "Tenant ID cannot change after auth controller initialization (" +
        currentTenantId +
        " -> " +
        nextTenantLabel +
        ")",
    );
    error.code = AUTH_TENANT_ID_CHANGE_ERROR_CODE;
    return error;
  }

  function ensureNamespace(target) {
    if (!target.MPRUI) {
      target.MPRUI = {};
    }
    return target.MPRUI;
  }

  function joinUrl(tauthUrl, path) {
    if (!tauthUrl) {
      return path;
    }
    if (!path) {
      return tauthUrl;
    }
    if (tauthUrl.endsWith("/") && path.startsWith("/")) {
      return tauthUrl + path.slice(1);
    }
    if (!tauthUrl.endsWith("/") && !path.startsWith("/")) {
      return tauthUrl + "/" + path;
    }
    return tauthUrl + path;
  }

  function shouldFallbackToFetch(error) {
    if (!error || typeof error.message !== "string") {
      return false;
    }
    return error.message.indexOf("tauth.missing_base_url") !== -1;
  }

  function withTenantHeaderValue(tenantId, headers) {
    var combined = Object.assign({}, headers || {});
    var normalizedTenantId = normalizeTenantId(tenantId);
    if (normalizedTenantId) {
      combined["X-TAuth-Tenant"] = normalizedTenantId;
    }
    return combined;
  }

  function getCurrentLocationOrigin() {
    var locationObject = null;
    if (global.location) {
      locationObject = global.location;
    } else if (global.document && global.document.location) {
      locationObject = global.document.location;
    } else if (global.window && global.window.location) {
      locationObject = global.window.location;
    }
    if (
      locationObject &&
      typeof locationObject.origin === "string" &&
      locationObject.origin.trim()
    ) {
      return locationObject.origin.trim();
    }
    return "";
  }

  function resolveAuthRestoreBaseUrl(authOptions) {
    var configuredBaseUrl =
      authOptions && typeof authOptions.tauthUrl === "string"
        ? authOptions.tauthUrl.trim()
        : "";
    return configuredBaseUrl || getCurrentLocationOrigin();
  }

  function authRestoreStorage() {
    try {
      var localStorageDescriptor = Object.getOwnPropertyDescriptor(
        global,
        "localStorage",
      );
      if (
        localStorageDescriptor &&
        Object.prototype.hasOwnProperty.call(localStorageDescriptor, "value")
      ) {
        return localStorageDescriptor.value || null;
      }
      if (
        global.process &&
        global.process.versions &&
        global.process.versions.node
      ) {
        return null;
      }
      if (global.localStorage) {
        return global.localStorage;
      }
      if (global.window && global.window.localStorage) {
        return global.window.localStorage;
      }
    } catch (error) {
      return null;
    }
    return null;
  }

  function authRestoreHintKey(authOptions) {
    var baseUrl = resolveAuthRestoreBaseUrl(authOptions);
    if (!baseUrl) {
      return null;
    }
    return (
      AUTH_RESTORE_HINT_PREFIX +
      encodeURIComponent(baseUrl) +
      ":" +
      encodeURIComponent(normalizeTenantId(authOptions && authOptions.tenantId) || "")
    );
  }

  function hasConfiguredAuthSessionPath(authOptions) {
    return Boolean(
      authOptions &&
        typeof authOptions.sessionPath === "string" &&
        authOptions.sessionPath.trim(),
    );
  }

  function usesDefaultAuthSessionPath(authOptions) {
    return (
      authOptions &&
      authOptions.sessionPath === TAUTH_RUNTIME_SESSION_PATH
    );
  }

  function authSessionRetryDelay(attempt) {
    return Math.min(
      AUTH_SESSION_RETRY_POLICY.maximumDelayMs,
      AUTH_SESSION_RETRY_POLICY.initialDelayMs *
        Math.pow(AUTH_SESSION_RETRY_POLICY.multiplier, attempt),
    );
  }

  function waitForAuthSessionRetry(attempt) {
    return new Promise(function waitForRetry(resolve) {
      global.setTimeout(resolve, authSessionRetryDelay(attempt));
    });
  }

  function isRetryableAuthSessionStatus(status) {
    return (
      typeof status !== "number" ||
      status === 408 ||
      status === 425 ||
      status === 429 ||
      status >= 500
    );
  }

  function isRetryableAuthSessionResult(result) {
    return Boolean(
      result &&
        result.status === "error" &&
        isRetryableAuthSessionStatus(result.responseStatus),
    );
  }

  function isRetryableAuthSessionError(error) {
    return isRetryableAuthSessionStatus(
      error && typeof error.status === "number" ? error.status : undefined,
    );
  }

  function hasAuthRestoreHint(authOptions) {
    if (!hasConfiguredAuthSessionPath(authOptions)) {
      return false;
    }
    var storage = authRestoreStorage();
    var key = authRestoreHintKey(authOptions);
    if (!storage || !key) {
      return false;
    }
    try {
      return storage.getItem(key) !== null;
    } catch (error) {
      return false;
    }
  }

  function rememberAuthRestoreHint(authOptions) {
    if (!hasConfiguredAuthSessionPath(authOptions)) {
      return;
    }
    var storage = authRestoreStorage();
    var key = authRestoreHintKey(authOptions);
    if (!storage || !key) {
      return;
    }
    try {
      storage.setItem(key, "1");
    } catch (error) {
      return;
    }
  }

  function clearAuthRestoreHint(authOptions) {
    var storage = authRestoreStorage();
    var key = authRestoreHintKey(authOptions);
    if (!storage || !key) {
      return;
    }
    try {
      storage.removeItem(key);
    } catch (error) {
      return;
    }
  }

  function requireLocationForRedirect() {
    var locationObject = global.location ||
      (global.window && global.window.location) ||
      (global.document && global.document.location) ||
      null;
    if (
      !locationObject ||
      typeof locationObject.origin !== "string" ||
      !locationObject.origin.trim()
    ) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.REDIRECT_NAVIGATION_UNAVAILABLE,
        "Apple sign-in requires a browser location",
      );
    }
    return locationObject;
  }

  function buildSafeCurrentReturnUrl(locationObject) {
    var currentUrl = new URL(
      typeof locationObject.href === "string" && locationObject.href
        ? locationObject.href
        : locationObject.origin + "/",
    );
    APPLE_RETURN_QUERY_KEYS.forEach(function removeSensitiveReturnValue(key) {
      currentUrl.searchParams.delete(key);
    });
    currentUrl.hash = "";
    return currentUrl.toString();
  }

  function resolveAppleReturnTarget(returnTargetPolicy, locationObject) {
    if (returnTargetPolicy === APPLE_RETURN_TARGET_POLICY.CURRENT_ORIGIN) {
      return locationObject.origin;
    }
    if (returnTargetPolicy === APPLE_RETURN_TARGET_POLICY.CURRENT_URL) {
      return buildSafeCurrentReturnUrl(locationObject);
    }
    return new URL(returnTargetPolicy, locationObject.origin).toString();
  }

  /**
   * Build a redirect-provider action from normalized authentication options.
   *
   * @param {AuthOptions} authOptions
   * @returns {NormalizedProviderActionOptions}
   */
  function buildAppleProviderAction(authOptions) {
    var appleProvider = authOptions.providers.apple;
    if (!appleProvider.enabled) {
      throw createAuthConfigError(
        AUTH_CONFIG_ERROR_CODES.PROVIDER_DISABLED,
        "Apple authentication is disabled",
      );
    }
    var locationObject = requireLocationForRedirect();
    var authBaseUrl = authOptions.tauthUrl || locationObject.origin;
    var startUrl = new URL(appleProvider.startPath, authBaseUrl);
    startUrl.searchParams.set(
      AUTH_REDIRECT_QUERY_KEYS.TENANT_ID,
      authOptions.tenantId,
    );
    startUrl.searchParams.set(
      AUTH_REDIRECT_QUERY_KEYS.RETURN_TO,
      resolveAppleReturnTarget(appleProvider.returnTo, locationObject),
    );
    return Object.freeze({
      provider: "apple",
      url: startUrl.toString(),
      pendingRestore: true,
    });
  }

  /**
   * @param {string} message
   * @param {{ status?: number } | null | undefined} response
   * @returns {MprUiError}
   */
  function createStatusError(message, response) {
    /** @type {MprUiError} */
    var error = new Error(message);
    if (response && typeof response.status === "number") {
      error.status = response.status;
    }
    return error;
  }

  /**
   * @param {string} code
   * @param {string} message
   * @param {number=} status
   * @returns {MprUiError}
   */
  function createAuthRecoveryError(code, message, status) {
    /** @type {MprUiError} */
    var error = new Error(message);
    error.code = code;
    if (typeof status === "number") {
      error.status = status;
    }
    return error;
  }

  function authRecoveryScope(authOptions) {
    var baseUrl = resolveAuthRestoreBaseUrl(authOptions);
    var tenantId = normalizeTenantId(authOptions && authOptions.tenantId) || "";
    var sessionPath =
      authOptions && typeof authOptions.sessionPath === "string"
        ? authOptions.sessionPath.trim()
        : "";
    if (!baseUrl || !tenantId || !sessionPath) {
      throw createAuthRecoveryError(
        "mpr-ui.auth.recovery_config_required",
        "Authenticated fetch requires a TAuth URL, tenant ID, and session path",
      );
    }
    return [baseUrl, tenantId, sessionPath].map(encodeURIComponent).join(":");
  }

  function requireAuthRecoveryStorage() {
    var storage = authRestoreStorage();
    if (!storage) {
      throw createAuthRecoveryError(
        "mpr-ui.auth.recovery_storage_unavailable",
        "Authenticated fetch requires local storage for browser-tab recovery coordination",
      );
    }
    return storage;
  }

  function requireAuthRecoveryLocks() {
    var lockManager =
      global.navigator && global.navigator.locks ? global.navigator.locks : null;
    if (!lockManager || typeof lockManager.request !== "function") {
      throw createAuthRecoveryError(
        "mpr-ui.auth.recovery_lock_unavailable",
        "Authenticated fetch requires Web Locks for browser-tab recovery coordination",
      );
    }
    return lockManager;
  }

  /**
   * @param {Storage} storage
   * @param {string} recordKey
   * @returns {AuthRecoveryRecord|null}
   */
  function readAuthRecoveryRecord(storage, recordKey) {
    var serializedRecord;
    try {
      serializedRecord = storage.getItem(recordKey);
    } catch (error) {
      throw createAuthRecoveryError(
        "mpr-ui.auth.recovery_storage_failed",
        "Authenticated fetch could not read the recovery generation record",
      );
    }
    if (serializedRecord === null) {
      return null;
    }
    var parsedRecord;
    try {
      parsedRecord = JSON.parse(serializedRecord);
    } catch (error) {
      throw createAuthRecoveryError(
        "mpr-ui.auth.recovery_record_invalid",
        "Authenticated fetch found an invalid recovery generation record",
      );
    }
    if (
      !parsedRecord ||
      typeof parsedRecord !== "object" ||
      !Number.isSafeInteger(parsedRecord.generation) ||
      parsedRecord.generation < 1 ||
      ["authenticated", "unauthenticated"].indexOf(parsedRecord.status) === -1
    ) {
      throw createAuthRecoveryError(
        "mpr-ui.auth.recovery_record_invalid",
        "Authenticated fetch found an invalid recovery generation record",
      );
    }
    return parsedRecord;
  }

  /**
   * @param {Storage} storage
   * @param {string} recordKey
   * @param {AuthRecoveryRecord} record
   */
  function writeAuthRecoveryRecord(storage, recordKey, record) {
    try {
      storage.setItem(recordKey, JSON.stringify(record));
    } catch (error) {
      throw createAuthRecoveryError(
        "mpr-ui.auth.recovery_storage_failed",
        "Authenticated fetch could not write the recovery generation record",
      );
    }
  }

  /**
   * @param {AuthOptions} authOptions
   * @returns {{ scope: string, generation: number }}
   */
  function captureAuthRecoveryGeneration(authOptions) {
    var scope = authRecoveryScope(authOptions);
    var storage = requireAuthRecoveryStorage();
    requireAuthRecoveryLocks();
    var record = readAuthRecoveryRecord(
      storage,
      AUTH_RECOVERY_RECORD_PREFIX + scope,
    );
    return {
      scope: scope,
      generation: record ? record.generation : 0,
    };
  }

  /**
   * @param {AuthOptions} authOptions
   * @returns {Promise<AuthRecoveryResult>}
   */
  function requestAuthSessionRecovery(authOptions) {
    if (!global.fetch) {
      return Promise.resolve({
        status: "error",
        profile: null,
        code: "mpr-ui.auth.session_recovery_failed",
      });
    }
    return global
      .fetch(joinUrl(authOptions.tauthUrl, authOptions.sessionPath), {
        method: "GET",
        credentials: "include",
        headers: withTenantHeaderValue(authOptions.tenantId, {
          "X-Requested-With": REQUESTED_WITH_HEADER,
        }),
      })
      .then(
        /**
         * @param {Response} response
         * @returns {AuthRecoveryResult|Promise<AuthRecoveryResult>}
         */
        function classifyAuthSessionRecoveryResponse(response) {
          if (!response) {
            return {
              status: "error",
              profile: null,
              code: "mpr-ui.auth.session_recovery_failed",
            };
          }
          if (response.status === 204) {
            return {
              status: "unauthenticated",
              profile: null,
              responseStatus: response.status,
            };
          }
          if (!response.ok || typeof response.json !== "function") {
            return {
              status: "error",
              profile: null,
              code: "mpr-ui.auth.session_recovery_failed",
              responseStatus: response.status,
            };
          }
          return response
            .json()
            .then(function validateAuthSessionRecoveryProfile(profile) {
              if (
                !profile ||
                typeof profile !== "object" ||
                Array.isArray(profile)
              ) {
                return {
                  status: "error",
                  profile: null,
                  code: "mpr-ui.auth.session_recovery_invalid_profile",
                  responseStatus: response.status,
                };
              }
              return {
                status: "authenticated",
                profile: profile,
                responseStatus: response.status,
              };
            });
        },
      )
      .catch(
        /** @returns {AuthRecoveryResult} */
        function classifyAuthSessionRecoveryNetworkFailure() {
          return {
            status: "error",
            profile: null,
            code: "mpr-ui.auth.session_recovery_failed",
          };
        },
      );
  }

  function requestAuthSessionRecoveryUntilSettled(authOptions, attempt) {
    return requestAuthSessionRecovery(authOptions).then(function (result) {
      if (result.status !== "error") {
        return result;
      }
      if (!isRetryableAuthSessionResult(result)) {
        throw createAuthRecoveryError(
          result.code || "mpr-ui.auth.session_recovery_failed",
          "TAuth session recovery returned a permanent failure",
          result.responseStatus,
        );
      }
      return waitForAuthSessionRetry(attempt).then(function retryRecovery() {
        return requestAuthSessionRecoveryUntilSettled(authOptions, attempt + 1);
      });
    });
  }

  /**
   * @param {AuthRecoveryRecord} record
   * @returns {AuthRecoveryResult}
   */
  function authRecoveryResultFromRecord(record) {
    return {
      status: record.status,
      profile: null,
      code: record.code,
      responseStatus: record.responseStatus,
    };
  }

  /**
   * @param {AuthOptions} authOptions
   * @param {{ scope: string, generation: number }} observedRecovery
   * @returns {Promise<AuthRecoveryResult>}
   */
  function coordinateAuthSessionRecovery(authOptions, observedRecovery) {
    var scope = authRecoveryScope(authOptions);
    if (!observedRecovery || observedRecovery.scope !== scope) {
      return Promise.reject(
        createAuthRecoveryError(
          "mpr-ui.auth.recovery_scope_mismatch",
          "Authenticated fetch recovery scope changed during the protected request",
        ),
      );
    }
    if (authSessionRecoveryPromises[scope]) {
      return authSessionRecoveryPromises[scope];
    }
    var recoveryPromise = Promise.resolve().then(function coordinateRecovery() {
      var storage = requireAuthRecoveryStorage();
      var lockManager = requireAuthRecoveryLocks();
      var recordKey = AUTH_RECOVERY_RECORD_PREFIX + scope;
      return lockManager.request(
        AUTH_RECOVERY_LOCK_PREFIX + scope,
        function runRecoveryInsideWebLock() {
          var currentRecord = readAuthRecoveryRecord(storage, recordKey);
          if (
            currentRecord &&
            currentRecord.generation > observedRecovery.generation
          ) {
            return authRecoveryResultFromRecord(currentRecord);
          }
          var nextGeneration = currentRecord
            ? currentRecord.generation + 1
            : 1;
          return requestAuthSessionRecoveryUntilSettled(authOptions, 0).then(
            function publishAuthSessionRecovery(result) {
              /** @type {AuthRecoveryRecord} */
              var nextRecord = {
                generation: nextGeneration,
                status: result.status,
              };
              if (result.code) {
                nextRecord.code = result.code;
              }
              if (typeof result.responseStatus === "number") {
                nextRecord.responseStatus = result.responseStatus;
              }
              writeAuthRecoveryRecord(storage, recordKey, nextRecord);
              return result;
            },
          );
        },
      );
    });
    authSessionRecoveryPromises[scope] = recoveryPromise.finally(
      function releaseAuthSessionRecoveryPromise() {
        delete authSessionRecoveryPromises[scope];
      },
    );
    return authSessionRecoveryPromises[scope];
  }

  function requestCurrentProfileWithFetch(authOptions) {
    if (
      !hasAuthRestoreHint(authOptions)
    ) {
      return Promise.resolve(null);
    }
    if (!global.fetch) {
      return Promise.reject(new Error("fetch is required to load auth profile"));
    }
    return global
      .fetch(joinUrl(authOptions.tauthUrl, authOptions.sessionPath), {
        method: "GET",
        credentials: "include",
        headers: withTenantHeaderValue(authOptions.tenantId, {
          "X-Requested-With": REQUESTED_WITH_HEADER,
        }),
      })
      .then(function (response) {
        if (!response) {
          throw new Error("invalid response from session endpoint");
        }
        if (response.status === 204) {
          clearAuthRestoreHint(authOptions);
          return null;
        }
        if (!response.ok) {
          throw createStatusError("auth session request failed", response);
        }
        if (typeof response.json !== "function") {
          throw createStatusError("invalid response from session endpoint", response);
        }
        return response.json().then(function (payload) {
          if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
            throw createStatusError("invalid profile from session endpoint", response);
          }
          rememberAuthRestoreHint(authOptions);
          return payload;
        });
      });
  }

  function requestCurrentProfileFromRuntime(authOptions) {
    if (!usesDefaultAuthSessionPath(authOptions)) {
      return requestCurrentProfileWithFetch(authOptions);
    }
    if (typeof global.getCurrentUser === "function") {
      var helperResult = global.getCurrentUser();
      if (helperResult && typeof helperResult.then === "function") {
        return helperResult.then(function (profile) {
          if (profile) {
            return profile;
          }
          return null;
        }).catch(function (error) {
          if (!shouldFallbackToFetch(error)) {
            throw error;
          }
          return requestCurrentProfileWithFetch(authOptions);
        });
      }
      return helperResult;
    }
    return requestCurrentProfileWithFetch(authOptions);
  }

  function performLogoutRequestWithFetch(authOptions) {
    if (!global.fetch) {
      return Promise.reject(new Error("fetch is required to log out"));
    }
    return global
      .fetch(joinUrl(authOptions.tauthUrl, authOptions.logoutPath), {
        method: "POST",
        credentials: "include",
        headers: withTenantHeaderValue(authOptions.tenantId, {
          "X-Requested-With": REQUESTED_WITH_HEADER,
        }),
      })
      .then(function (response) {
        if (!response) {
          throw new Error("invalid response from logout endpoint");
        }
        if (!response.ok) {
          throw createStatusError("logout failed", response);
        }
        clearAuthRestoreHint(authOptions);
        return null;
      });
  }

  function performLogoutFromRuntime(authOptions) {
    if (typeof global.logout === "function") {
      var helperResult = global.logout();
      if (helperResult && typeof helperResult.then === "function") {
        return helperResult.catch(function (error) {
          if (shouldFallbackToFetch(error)) {
            return performLogoutRequestWithFetch(authOptions);
          }
          throw error;
        });
      }
      return helperResult;
    }
    return performLogoutRequestWithFetch(authOptions);
  }

  function matchesTagName(node, tagNames) {
    if (!node || !tagNames || !tagNames.length) {
      return false;
    }
    var nodeTagName = node.tagName || node.nodeName;
    if (typeof nodeTagName !== "string") {
      return false;
    }
    return tagNames.indexOf(nodeTagName.toLowerCase()) !== -1;
  }

  function findClosestHostByTagName(node, tagNames) {
    if (!node || !tagNames || !tagNames.length) {
      return null;
    }
    if (typeof node.closest === "function") {
      var selector = tagNames.join(", ");
      var matchedNode = node.closest(selector);
      if (matchedNode) {
        return matchedNode;
      }
    }
    var currentNode = node.parentElement || node.parentNode || null;
    while (currentNode) {
      if (matchesTagName(currentNode, tagNames)) {
        return currentNode;
      }
      currentNode = currentNode.parentElement || currentNode.parentNode || null;
    }
    return null;
  }

  function toStringOrNull(value) {
    return value === undefined || value === null ? null : String(value);
  }

  function setAttributeOrRemove(element, name, value) {
    var normalized = toStringOrNull(value);
    if (normalized === null) {
      element.removeAttribute(name);
      return;
    }
    element.setAttribute(name, normalized);
  }

  function createCustomEvent(globalObject, type, detail) {
    var EventCtor = globalObject.CustomEvent;
    if (typeof EventCtor === "function") {
      return new EventCtor(type, { detail: detail, bubbles: true });
    }
    if (
      globalObject.document &&
      typeof globalObject.document.createEvent === "function"
    ) {
      var legacyEvent = globalObject.document.createEvent("CustomEvent");
      legacyEvent.initCustomEvent(type, true, false, detail);
      return legacyEvent;
    }
    return { type: type, detail: detail, bubbles: true };
  }

  function dispatchEvent(element, type, detail) {
    if (!element || typeof element.dispatchEvent !== "function") {
      return;
    }
    var event = createCustomEvent(global, type, detail || {});
    try {
      element.dispatchEvent(event);
    } catch (_error) {}
  }

  var LOGGER_PREFIX = "[mpr-ui]";

  function logError(code, message) {
    if (
      !global.console ||
      typeof global.console.error !== "function"
    ) {
      return;
    }
    var parts = [LOGGER_PREFIX];
    if (code) {
      parts.push(code);
    }
    if (message) {
      parts.push(message);
    }
    global.console.error(parts.join(" "));
  }

  var LEGACY_DSL_ATTRIBUTE_ERROR_CODE = "mpr-ui.dsl.legacy_attribute";
  var LEGACY_DSL_CONFIG_ERROR_CODE = "mpr-ui.dsl.legacy_config";
  var LEGACY_DSL_THEME_MODE_REPLACEMENT = '"theme-config" with "initialMode"';
  var LEGACY_DSL_SETTINGS_REPLACEMENT = '"settings"';
  var LEGACY_DSL_LINKS_REPLACEMENT = '"menu"';
  var LEGACY_DSL_THEME_VARIANT_REPLACEMENT =
    '"themeToggle.variant" or "theme-switcher"';
  var HORIZONTAL_LINKS_ALIGNMENT_ERROR_CODE =
    "mpr-ui.horizontal-links.invalid_alignment";
  var HORIZONTAL_LINKS_CONFIG_ERROR_CODE = "mpr-ui.horizontal-links.invalid_config";
  var HORIZONTAL_LINKS_ALIGNMENT_VALUES = Object.freeze(["left", "right", "center"]);
  var HORIZONTAL_LINKS_DEFAULTS = Object.freeze({
    alignment: "center",
    links: Object.freeze([]),
  });
  var USER_MENU_DISPLAY_MODE_ERROR_CODE = "mpr-ui.user.invalid_display_mode";
  var USER_MENU_LOGOUT_URL_ERROR_CODE = "mpr-ui.user.missing_logout_url";
  var USER_MENU_LOGOUT_LABEL_ERROR_CODE = "mpr-ui.user.missing_logout_label";
  var USER_MENU_CUSTOM_AVATAR_ERROR_CODE = "mpr-ui.user.missing_custom_avatar";
  var USER_MENU_AUTH_TARGET_ERROR_CODE = "mpr-ui.user.invalid_auth_target";
  var USER_MENU_ITEMS_ERROR_CODE = "mpr-ui.user.invalid_menu_items";
  var USER_MENU_TAUTH_MISSING_ERROR_CODE = "mpr-ui.user.tauth_missing";
  var USER_MENU_PROFILE_ERROR_CODE = "mpr-ui.user.invalid_profile";
  var USER_MENU_LOGOUT_FAILED_ERROR_CODE = "mpr-ui.user.logout_failed";
  var USER_MENU_GENERIC_ERROR_CODE = "mpr-ui.user.error";
  var USER_MENU_ITEM_EVENT = "mpr-user:menu-item";
  var USER_MENU_ITEM_SELECTOR = '[data-mpr-user="menu-item"]';
  var USER_MENU_ITEM_ACTION_ATTRIBUTE = "data-mpr-user-action";
  var USER_MENU_ITEM_INDEX_ATTRIBUTE = "data-mpr-user-index";

  var USER_MENU_DISPLAY_MODES = Object.freeze({
    AVATAR: "avatar",
    AVATAR_NAME: "avatar-name",
    AVATAR_FULL_NAME: "avatar-full-name",
    CUSTOM_AVATAR: "custom-avatar",
  });
  /** @type {readonly string[]} */
  var USER_MENU_DISPLAY_MODE_VALUES = Object.freeze([
    USER_MENU_DISPLAY_MODES.AVATAR,
    USER_MENU_DISPLAY_MODES.AVATAR_NAME,
    USER_MENU_DISPLAY_MODES.AVATAR_FULL_NAME,
    USER_MENU_DISPLAY_MODES.CUSTOM_AVATAR,
  ]);
  var USER_MENU_PROFILE_SHORT_NAME_FIELDS = Object.freeze([
    "given_name",
    "first_name",
  ]);
  var USER_MENU_PROFILE_FULL_NAME_FIELDS = Object.freeze([
    "full_name",
    "name",
    "display",
  ]);
  var USER_MENU_PROFILE_AVATAR_FIELDS = Object.freeze([
    "avatar_url",
    "avatarUrl",
  ]);
  var USER_MENU_DEFAULT_AVATAR_URL =
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='16' fill='%231f2126'/%3E%3Ccircle cx='16' cy='11.5' r='5' fill='%23e3e5ec'/%3E%3Cpath d='M7 28c1-6 4-9 9-9s8 3 9 9' fill='%23e3e5ec'/%3E%3C/svg%3E";

  function logLegacyAttribute(componentLabel, attributeName, replacement) {
    if (!attributeName) {
      return;
    }
    var message =
      'Unsupported legacy attribute "' +
      attributeName +
      '" on ' +
      componentLabel;
    if (replacement) {
      message += ". Use " + replacement + ".";
    }
    logError(LEGACY_DSL_ATTRIBUTE_ERROR_CODE, message);
  }

  function logLegacyConfig(componentLabel, configKey, replacement) {
    if (!configKey) {
      return;
    }
    var message =
      'Unsupported legacy config key "' + configKey + '" on ' + componentLabel;
    if (replacement) {
      message += ". Use " + replacement + ".";
    }
    logError(LEGACY_DSL_CONFIG_ERROR_CODE, message);
  }

  function hasAttributeValue(hostElement, attributeName) {
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return false;
    }
    return hostElement.getAttribute(attributeName) !== null;
  }

  function resolveHost(target) {
    if (!target) {
      throw new Error("resolveHost requires a selector or element reference");
    }
    if (typeof target === "string") {
      var documentObject = global.document || (global.window && global.window.document);
      if (!documentObject || typeof documentObject.querySelector !== "function") {
        throw new Error("resolveHost cannot query selectors without a document");
      }
      var element = documentObject.querySelector(target);
      if (!element) {
        throw new Error('resolveHost could not find element for selector "' + target + '"');
      }
      return element;
    }
    if (typeof target === "object") {
      return target;
    }
    throw new Error("resolveHost expected a selector string or an element reference");
  }

  var PROHIBITED_MERGE_KEYS = Object.freeze(["__proto__", "constructor", "prototype"]);

  function deepMergeOptions(target) {
    var baseObject = !target || typeof target !== "object" ? {} : target;
    for (var index = 1; index < arguments.length; index += 1) {
      var sourceObject = arguments[index];
      if (!sourceObject || typeof sourceObject !== "object") {
        continue;
      }
      Object.keys(sourceObject).forEach(function handleKey(key) {
        if (PROHIBITED_MERGE_KEYS.indexOf(key) !== -1) {
          return;
        }
        var value = sourceObject[key];
        if (Array.isArray(value)) {
          baseObject[key] = value.slice();
          return;
        }
        if (value && typeof value === "object") {
          if (!baseObject[key] || typeof baseObject[key] !== "object") {
            baseObject[key] = {};
          }
          deepMergeOptions(baseObject[key], value);
          return;
        }
        if (value !== undefined) {
          baseObject[key] = value;
        }
      });
    }
    return baseObject;
  }

  function parseJsonValue(textValue, fallbackValue) {
    try {
      return JSON.parse(String(textValue));
    } catch (_error) {
      return fallbackValue;
    }
  }

  function parseHeaderAuthTransitionValue(rawValue) {
    if (rawValue === null || rawValue === undefined) {
      return null;
    }
    if (typeof rawValue === "boolean") {
      return { enabled: rawValue };
    }
    if (rawValue && typeof rawValue === "object" && !Array.isArray(rawValue)) {
      return rawValue;
    }
    if (typeof rawValue !== "string") {
      return null;
    }
    var trimmed = rawValue.trim();
    if (!trimmed || trimmed.toLowerCase() === "true") {
      return { enabled: true };
    }
    if (trimmed.toLowerCase() === "false") {
      return { enabled: false };
    }
    var parsed = parseJsonValue(trimmed, null);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed;
    }
    return null;
  }

  var HEADER_ATTRIBUTE_DATASET_MAP = Object.freeze({
    "brand-label": "brandLabel",
    "brand-href": "brandHref",
    "nav-links": "navLinks",
    "horizontal-links": "horizontalLinks",
    "auth-transition": "authTransition",
    "settings-label": "settingsLabel",
    "settings": "settingsEnabled",
    "theme-config": "themeToggle",
    "sign-out-label": "signOutLabel",
    "sign-in-redirect-url": "signInRedirectUrl",
    "logout-url": "logoutUrl",
    "user-menu-display-mode": "userMenuDisplayMode",
    "user-menu-avatar-url": "userMenuAvatarUrl",
    "user-menu-avatar-label": "userMenuAvatarLabel",
    sticky: "sticky",
    size: "size",
  });

  var HEADER_ATTRIBUTE_OBSERVERS = Object.freeze(
    Object.keys(HEADER_ATTRIBUTE_DATASET_MAP).concat([AUTH_CONFIG_ATTRIBUTE]),
  );

  var FOOTER_ATTRIBUTE_DATASET_MAP = Object.freeze({
    "element-id": "elementId",
    "base-class": "baseClass",
    "inner-element-id": "innerElementId",
    "inner-class": "innerClass",
    "wrapper-class": "wrapperClass",
    "brand-wrapper-class": "brandWrapperClass",
    "prefix-class": "prefixClass",
    "prefix-text": "prefixText",
    "horizontal-links": "horizontalLinks",
    "privacy-link-class": "privacyLinkClass",
    "privacy-link-href": "privacyLinkHref",
    "privacy-link-label": "privacyLinkLabel",
    "privacy-link-hidden": "privacyLinkHidden",
    "privacy-modal-content": "privacyModalContent",
    "theme-config": "themeToggle",
    "theme-switcher": "themeSwitcher",
    menu: "menu",
    sticky: "sticky",
    size: "size",
  });

  var FOOTER_ATTRIBUTE_OBSERVERS = Object.freeze(
    Object.keys(FOOTER_ATTRIBUTE_DATASET_MAP),
  );

  var HEADER_SLOT_NAMES = Object.freeze(["brand", "nav-left", "nav-right", "aux"]);
  var FOOTER_SLOT_NAMES = Object.freeze(["menu-prefix", "legal"]);
  var DROPDOWN_ATTRIBUTE_NAMES = Object.freeze(["menu"]);
  var THEME_TOGGLE_ATTRIBUTE_NAMES = Object.freeze([
    "variant",
    "label",
    "aria-label",
    "show-label",
    "wrapper-class",
    "control-class",
    "icon-class",
    "theme-config",
  ]);
  var LOGIN_BUTTON_ATTRIBUTE_NAMES = Object.freeze([
    AUTH_CONFIG_ATTRIBUTE,
    "button-text",
    "button-theme",
    "button-size",
    "button-shape",
  ]);
  var AUTH_PROVIDER_CHOOSER_ATTRIBUTE_NAMES = Object.freeze([
    AUTH_PROVIDER_CHOOSER_PROVIDERS_ATTRIBUTE,
    AUTH_PROVIDER_CHOOSER_VARIANT_ATTRIBUTE,
  ]);
  var USER_MENU_ATTRIBUTE_NAMES = Object.freeze([
    AUTH_COMPONENT_TARGET_ATTRIBUTE,
    "display-mode",
    "logout-url",
    "logout-label",
    AUTH_CONFIG_ATTRIBUTE,
    "avatar-url",
    "avatar-label",
    "menu-items",
  ]);

  var SETTINGS_ATTRIBUTE_NAMES = Object.freeze([
    "label",
    "icon",
    "panel-id",
    "button-class",
    "panel-class",
    "open",
  ]);
  var SETTINGS_SLOT_NAMES = Object.freeze(["trigger", "panel"]);
  var SITES_ATTRIBUTE_NAMES = Object.freeze(["variant", "columns", "links", "heading"]);
  var DETAIL_DRAWER_ATTRIBUTE_NAMES = Object.freeze([
    "open",
    "heading",
    "subheading",
    "placement",
    "busy",
  ]);
  var DETAIL_DRAWER_SLOT_NAMES = Object.freeze([
    "header-actions",
    "body",
    "footer",
  ]);
  var WORKSPACE_LAYOUT_ATTRIBUTE_NAMES = Object.freeze([
    "sidebar-width",
    "collapsed",
    "stacked-breakpoint",
  ]);
  var WORKSPACE_LAYOUT_SLOT_NAMES = Object.freeze([
    "header",
    "sidebar",
    "content",
  ]);
  var SIDEBAR_NAV_ATTRIBUTE_NAMES = Object.freeze([
    "label",
    "dense",
    "variant",
  ]);
  var SIDEBAR_NAV_SLOT_NAMES = Object.freeze(["header", "footer"]);
  var ENTITY_RAIL_ATTRIBUTE_NAMES = Object.freeze([
    "label",
    "empty-label",
    "show-nav",
    "nav-step",
  ]);
  var ENTITY_RAIL_SLOT_NAMES = Object.freeze(["leading", "trailing"]);
  var ENTITY_TILE_ATTRIBUTE_NAMES = Object.freeze([
    "selected",
    "interactive",
    "disabled",
    "variant",
  ]);
  var ENTITY_TILE_SLOT_NAMES = Object.freeze([
    "title",
    "meta",
    "badge",
    "actions",
    "empty",
  ]);
  var ENTITY_WORKSPACE_ATTRIBUTE_NAMES = Object.freeze([
    "busy",
    "empty",
    "selection-count",
    "can-load-more",
  ]);
  var ENTITY_WORKSPACE_SLOT_NAMES = Object.freeze([
    "heading",
    "toolbar",
    "filters",
    "bulk-actions",
    "list",
    "empty",
    "load-more",
  ]);
  var ENTITY_CARD_ATTRIBUTE_NAMES = Object.freeze([
    "selected",
    "interactive",
    "disabled",
    "busy",
    "density",
  ]);
  var ENTITY_CARD_SLOT_NAMES = Object.freeze([
    "select",
    "media",
    "title",
    "meta",
    "summary",
    "metric",
    "actions",
    "footer",
  ]);
  var BAND_ATTRIBUTE_NAMES = Object.freeze(["category", "theme", "layout"]);
  var CARD_ATTRIBUTE_NAMES = Object.freeze(["card", "theme"]);

  function normalizeAttributeReflectionValue(attributeName, value) {
    if (value === null || value === undefined) {
      return null;
    }
    if (attributeName === "settings") {
      if (value === "") {
        return "true";
      }
      return String(value);
    }
    return String(value);
  }

  function reflectAttributeToDataset(element, attributeName, rawValue, map) {
    if (
      !element ||
      !map ||
      !Object.prototype.hasOwnProperty.call(map, attributeName)
    ) {
      return;
    }
    if (!element.dataset) {
      element.dataset = {};
    }
    var datasetKey = map[attributeName];
    if (rawValue === null || rawValue === undefined) {
      delete element.dataset[datasetKey];
      return;
    }
    element.dataset[datasetKey] = String(rawValue);
  }

  function syncDatasetFromAttributes(hostElement, attributeMap) {
    if (!hostElement || !hostElement.getAttribute || !attributeMap) {
      return;
    }
    Object.keys(attributeMap).forEach(function reflect(attrName) {
      var attrValue = hostElement.getAttribute(attrName);
      reflectAttributeToDataset(
        hostElement,
        attrName,
        normalizeAttributeReflectionValue(attrName, attrValue),
        attributeMap,
      );
    });
  }

  function normalizeBooleanAttribute(value, fallback) {
    if (value === null || value === undefined) {
      return fallback;
    }
    if (typeof value === "boolean") {
      return value;
    }
    if (typeof value === "string") {
      var normalized = value.trim().toLowerCase();
      if (normalized === "" || normalized === "true") {
        return true;
      }
      if (normalized === "false") {
        return false;
      }
    }
    return Boolean(value);
  }

  function buildThemeToggleOptionsFromAttributes(hostElement) {
    if (hasAttributeValue(hostElement, "theme-mode")) {
      logLegacyAttribute(
        "<mpr-theme-toggle>",
        "theme-mode",
        LEGACY_DSL_THEME_MODE_REPLACEMENT,
      );
    }
    var options = {};
    var variant = hostElement.getAttribute("variant");
    if (variant) {
      options.variant = variant;
    }
    var label = hostElement.getAttribute("label");
    if (label) {
      options.label = label;
    }
    var ariaLabel = hostElement.getAttribute("aria-label");
    if (ariaLabel) {
      options.ariaLabel = ariaLabel;
    }
    var showLabelAttr = hostElement.getAttribute("show-label");
    if (showLabelAttr !== null) {
      options.showLabel = normalizeBooleanAttribute(showLabelAttr, true);
    }
    var wrapperClass = hostElement.getAttribute("wrapper-class");
    if (wrapperClass) {
      options.wrapperClass = wrapperClass;
    }
    var controlClass = hostElement.getAttribute("control-class");
    if (controlClass) {
      options.controlClass = controlClass;
    }
    var iconClass = hostElement.getAttribute("icon-class");
    if (iconClass) {
      options.iconClass = iconClass;
    }
    var themeConfig = {};
    var themeAttr = hostElement.getAttribute("theme-config");
    if (themeAttr) {
      themeConfig = parseJsonValue(themeAttr, {});
    }
    if (Object.keys(themeConfig).length) {
      options.theme = themeConfig;
    }
    return options;
  }

  function buildLoginAuthOptionsFromAttributes(hostElement) {
    return parseAuthConfigAttribute(hostElement);
  }

  function buildLoginButtonDisplayOptions(hostElement) {
    var options = {};
    var buttonText = hostElement.getAttribute("button-text");
    if (buttonText) {
      options.text = buttonText;
    }
    var buttonTheme = hostElement.getAttribute("button-theme");
    if (buttonTheme) {
      options.theme = buttonTheme;
    }
    var buttonSize = hostElement.getAttribute("button-size");
    if (buttonSize) {
      options.size = buttonSize;
    }
    var buttonShape = hostElement.getAttribute("button-shape");
    if (buttonShape) {
      options.shape = buttonShape;
    }
    return options;
  }

  function normalizeGoogleSignInButtonLabel(value, fallbackLabel) {
    var normalizedValue = typeof value === "string" ? value.trim() : "";
    if (!normalizedValue) {
      return fallbackLabel;
    }
    return GOOGLE_SIGNIN_TEXT_LABELS[normalizedValue] || normalizedValue;
  }

  function ensureLoginButtonContainer(hostElement) {
    if (
      hostElement.querySelector &&
      typeof hostElement.querySelector === "function"
    ) {
      var existing = hostElement.querySelector(LOGIN_BUTTON_CONTAINER_SELECTOR);
      if (existing) {
        return existing;
      }
    }
    if (!hostElement || typeof hostElement.appendChild !== "function") {
      return null;
    }
    var documentObject =
      hostElement.ownerDocument ||
      (global.document || (global.window && global.window.document));
    var container = documentObject && typeof documentObject.createElement === "function"
      ? documentObject.createElement("div")
      : null;
    if (!container) {
      return null;
    }
    container.setAttribute("data-mpr-login", "auth-actions");
    container.setAttribute("class", LOGIN_BUTTON_ROOT_CLASS);
    hostElement.innerHTML = "";
    hostElement.appendChild(container);
    return container;
  }

  function prepareLoginButtonHost(hostElement) {
    if (!hostElement || typeof hostElement.setAttribute !== "function") {
      return;
    }
    hostElement.setAttribute(LOGIN_BUTTON_MOUNTED_ATTRIBUTE, "true");
    if (typeof hostElement.removeAttribute !== "function") {
      return;
    }
    hostElement.removeAttribute("role");
    hostElement.removeAttribute("tabindex");
    hostElement.removeAttribute("aria-label");
  }

  function getLoginButtonPresentationValue(
    value,
    fallbackValue,
    allowedValues,
    errorCode,
  ) {
    var normalizedValue = typeof value === "string" ? value.trim() : "";
    if (!normalizedValue) {
      return fallbackValue;
    }
    if (allowedValues.indexOf(normalizedValue) === -1) {
      throw new Error(errorCode + ": " + normalizedValue);
    }
    return normalizedValue;
  }

  function applyLoginButtonPresentation(containerElement, buttonOptions) {
    if (!containerElement || typeof containerElement.setAttribute !== "function") {
      return;
    }
    var options = buttonOptions && typeof buttonOptions === "object"
      ? buttonOptions
      : {};
    containerElement.setAttribute(
      LOGIN_BUTTON_THEME_ATTRIBUTE,
      getLoginButtonPresentationValue(
        options.theme,
        LOGIN_BUTTON_PRESENTATION_DEFAULTS.theme,
        LOGIN_BUTTON_PRESENTATION_VALUES.theme,
        LOGIN_BUTTON_PRESENTATION_ERROR_CODES.theme,
      ),
    );
    containerElement.setAttribute(
      LOGIN_BUTTON_SIZE_ATTRIBUTE,
      getLoginButtonPresentationValue(
        options.size,
        LOGIN_BUTTON_PRESENTATION_DEFAULTS.size,
        LOGIN_BUTTON_PRESENTATION_VALUES.size,
        LOGIN_BUTTON_PRESENTATION_ERROR_CODES.size,
      ),
    );
    containerElement.setAttribute(
      LOGIN_BUTTON_SHAPE_ATTRIBUTE,
      getLoginButtonPresentationValue(
        options.shape,
        LOGIN_BUTTON_PRESENTATION_DEFAULTS.shape,
        LOGIN_BUTTON_PRESENTATION_VALUES.shape,
        LOGIN_BUTTON_PRESENTATION_ERROR_CODES.shape,
      ),
    );
  }

  function buildHeaderOptionsFromAttributes(hostElement) {
    if (hasAttributeValue(hostElement, "settings-enabled")) {
      logLegacyAttribute(
        "<mpr-header>",
        "settings-enabled",
        LEGACY_DSL_SETTINGS_REPLACEMENT,
      );
    }
    if (hasAttributeValue(hostElement, "theme-mode")) {
      logLegacyAttribute(
        "<mpr-header>",
        "theme-mode",
        LEGACY_DSL_THEME_MODE_REPLACEMENT,
      );
    }
    var datasetOptions = readHeaderOptionsFromDataset(hostElement);
    var externalOptions = {};
    if (hasAttributeValue(hostElement, AUTH_CONFIG_ATTRIBUTE)) {
      externalOptions.auth = parseAuthConfigAttribute(hostElement);
    }
    return deepMergeOptions({}, datasetOptions, externalOptions);
  }

  function buildFooterOptionsFromAttributes(hostElement) {
    [
      "links",
      "links-collection",
      "menu-wrapper-class",
      "toggle-button-id",
      "toggle-button-class",
      "toggle-label",
      "menu-class",
      "menu-item-class",
    ].forEach(function reportObsoleteFooterMenuAttribute(attributeName) {
      if (hasAttributeValue(hostElement, attributeName)) {
        logLegacyAttribute(
          "<mpr-footer>",
          attributeName,
          LEGACY_DSL_LINKS_REPLACEMENT,
        );
      }
    });
    if (hasAttributeValue(hostElement, "theme-mode")) {
      logLegacyAttribute(
        "<mpr-footer>",
        "theme-mode",
        LEGACY_DSL_THEME_MODE_REPLACEMENT,
      );
    }
    var datasetOptions = readFooterOptionsFromDataset(hostElement);
    return deepMergeOptions({}, datasetOptions);
  }

  function captureSlotNodes(hostElement, slotNames) {
    var slots = {};
    if (!slotNames || !slotNames.length) {
      return slots;
    }
    slotNames.forEach(function initSlot(name) {
      slots[name] = [];
    });
    if (!hostElement || typeof hostElement.querySelectorAll !== "function") {
      return slots;
    }
    var nodes = hostElement.querySelectorAll('[slot]');
    if (!nodes || typeof nodes.length !== "number") {
      return slots;
    }
    for (var index = 0; index < nodes.length; index += 1) {
      var node = nodes[index];
      if (!node) {
        continue;
      }
      var slotName = null;
      if (typeof node.getAttribute === "function") {
        slotName = node.getAttribute("slot");
      }
      if (!slotName && typeof node.slot === "string") {
        slotName = node.slot;
      }
      if (slotName && Object.prototype.hasOwnProperty.call(slots, slotName)) {
        slots[slotName].push(node);
      }
    }
    return slots;
  }

  function clearNodeContents(targetNode) {
    if (!targetNode) {
      return;
    }
    if (typeof targetNode.innerHTML === "string") {
      targetNode.innerHTML = "";
    }
    if (typeof targetNode.textContent === "string") {
      targetNode.textContent = "";
    }
    if (Array.isArray(targetNode.children)) {
      targetNode.children.length = 0;
    }
    if (Array.isArray(targetNode.childNodes)) {
      targetNode.childNodes.length = 0;
    }
    if (typeof targetNode.clear === "function") {
      targetNode.clear();
    }
  }

  function createElementNear(referenceElement, tagName) {
    var ownerDocument =
      (referenceElement && referenceElement.ownerDocument) ||
      global.document ||
      (global.window && global.window.document) ||
      null;
    if (!ownerDocument || typeof ownerDocument.createElement !== "function") {
      return null;
    }
    return ownerDocument.createElement(tagName);
  }

  function isSignInTriggerActivationKey(eventObject) {
    var keyValue =
      eventObject && typeof eventObject.key === "string"
        ? eventObject.key
        : "";
    return keyValue === "Enter" || keyValue === " " || keyValue === "Spacebar";
  }

  function createSignInTriggerControl(containerElement, config) {
    if (!containerElement || typeof config !== "object") {
      return null;
    }
    var buttonLabel =
      typeof config.label === "string" && config.label.trim()
        ? config.label.trim()
        : "Sign in";
    var clickHandler = config.clickHandler;
    if (typeof clickHandler !== "function") {
      return null;
    }
    clearNodeContents(containerElement);
    var buttonElement = createElementNear(containerElement, "button");
    if (
      buttonElement &&
      typeof buttonElement.addEventListener === "function" &&
      typeof buttonElement.removeEventListener === "function" &&
      typeof containerElement.appendChild === "function"
    ) {
      buttonElement.type = "button";
      if (typeof buttonElement.setAttribute === "function") {
        buttonElement.setAttribute("type", "button");
        buttonElement.setAttribute("data-test", GOOGLE_SIGNIN_TEST_ID);
        if (config.dataRoleName) {
          buttonElement.setAttribute(config.dataRoleName, config.dataRoleValue || "");
        }
        if (config.className) {
          buttonElement.setAttribute("class", config.className);
        }
      }
      buttonElement.textContent = buttonLabel;
      if (typeof config.contentBuilder === "function") {
        config.contentBuilder(buttonElement, buttonLabel);
      }
      buttonElement.addEventListener("click", clickHandler);
      containerElement.appendChild(buttonElement);
      return {
        target: buttonElement,
        cleanup: function cleanupSignInButton() {
          buttonElement.removeEventListener("click", clickHandler);
          clearNodeContents(containerElement);
        },
      };
    }
    if (config.requireNativeButton) {
      throw new Error(
        config.nativeControlErrorCode || "mpr-ui.signin.native_control_unavailable",
      );
    }
    containerElement.textContent = buttonLabel;
    if (typeof containerElement.setAttribute === "function") {
      containerElement.setAttribute("role", "button");
      containerElement.setAttribute("tabindex", "0");
      containerElement.setAttribute("data-test", GOOGLE_SIGNIN_TEST_ID);
    }
    function handleFallbackTriggerKey(eventObject) {
      if (!isSignInTriggerActivationKey(eventObject)) {
        return;
      }
      if (typeof eventObject.preventDefault === "function") {
        eventObject.preventDefault();
      }
      clickHandler(eventObject);
    }
    if (typeof containerElement.addEventListener === "function") {
      containerElement.addEventListener("click", clickHandler);
      containerElement.addEventListener("keydown", handleFallbackTriggerKey);
    }
    return {
      target: containerElement,
      cleanup: function cleanupSignInFallbackControl() {
        if (typeof containerElement.removeEventListener === "function") {
          containerElement.removeEventListener("click", clickHandler);
          containerElement.removeEventListener("keydown", handleFallbackTriggerKey);
        }
        if (typeof containerElement.removeAttribute === "function") {
          containerElement.removeAttribute("role");
          containerElement.removeAttribute("tabindex");
          containerElement.removeAttribute("data-test");
        }
        clearNodeContents(containerElement);
      },
    };
  }

  var authProviderEmailPanelCounter = 0;

  function createAuthProviderEmailPanelId() {
    authProviderEmailPanelCounter += 1;
    return "mpr-auth-provider-email-" + authProviderEmailPanelCounter;
  }

  /**
   * @param {string} code
   * @param {string} message
   * @returns {MprUiError}
   */
  function createAuthProviderChooserError(code, message) {
    /** @type {MprUiError} */
    var error = new Error(message);
    error.code = code;
    return error;
  }

  /**
   * @param {unknown} value
   * @param {number} index
   * @returns {AuthProviderId}
   */
  function normalizeAuthProviderId(value, index) {
    if (typeof value !== "string" || !value.trim()) {
      throw createAuthProviderChooserError(
        AUTH_PROVIDER_CHOOSER_PROVIDERS_INVALID_ERROR_CODE,
        "Auth provider at index " + index + " must be a non-empty string",
      );
    }
    var normalized = /** @type {AuthProviderId} */ (value.trim().toLowerCase());
    if (AUTH_PROVIDER_ID_VALUES.indexOf(normalized) === -1) {
      throw createAuthProviderChooserError(
        AUTH_PROVIDER_CHOOSER_UNSUPPORTED_PROVIDER_ERROR_CODE,
        'Unsupported auth provider "' + normalized + '"',
      );
    }
    return /** @type {AuthProviderId} */ (normalized);
  }

  /**
   * @param {string|null} rawValue
   * @returns {readonly AuthProviderId[]}
   */
  function parseAuthProviderListAttribute(rawValue) {
    if (typeof rawValue !== "string" || !rawValue.trim()) {
      throw createAuthProviderChooserError(
        AUTH_PROVIDER_CHOOSER_PROVIDERS_REQUIRED_ERROR_CODE,
        "Auth provider chooser requires an explicit providers attribute",
      );
    }
    var parsedValue = null;
    try {
      parsedValue = JSON.parse(rawValue);
    } catch (_error) {
      throw createAuthProviderChooserError(
        AUTH_PROVIDER_CHOOSER_PROVIDERS_INVALID_ERROR_CODE,
        "Auth provider chooser providers must be a JSON array",
      );
    }
    if (!Array.isArray(parsedValue) || parsedValue.length === 0) {
      throw createAuthProviderChooserError(
        AUTH_PROVIDER_CHOOSER_PROVIDERS_INVALID_ERROR_CODE,
        "Auth provider chooser providers must be a non-empty JSON array",
      );
    }
    var seenProviders = {};
    var providers = parsedValue.map(function normalizeProvider(provider, index) {
      var providerId = normalizeAuthProviderId(provider, index);
      if (seenProviders[providerId]) {
        throw createAuthProviderChooserError(
          AUTH_PROVIDER_CHOOSER_DUPLICATE_PROVIDER_ERROR_CODE,
          'Duplicate auth provider "' + providerId + '"',
        );
      }
      seenProviders[providerId] = true;
      return providerId;
    });
    return Object.freeze(providers);
  }

  /**
   * @param {string|null} rawValue
   * @returns {AuthProviderChooserVariant}
   */
  function normalizeAuthProviderChooserVariant(rawValue) {
    if (typeof rawValue !== "string" || !rawValue.trim()) {
      return AUTH_PROVIDER_CHOOSER_VARIANTS.STACK;
    }
    var normalized = /** @type {AuthProviderChooserVariant} */ (
      rawValue.trim().toLowerCase()
    );
    if (AUTH_PROVIDER_CHOOSER_VARIANT_VALUES.indexOf(normalized) === -1) {
      throw createAuthProviderChooserError(
        AUTH_PROVIDER_CHOOSER_UNSUPPORTED_VARIANT_ERROR_CODE,
        'Unsupported auth provider chooser variant "' + normalized + '"',
      );
    }
    return normalized;
  }

  /**
   * @param {{ getAttribute: (attributeName: string) => (string|null) }} hostElement
   * @returns {AuthProviderChooserOptions}
   */
  function buildAuthProviderChooserOptionsFromAttributes(hostElement) {
    return Object.freeze({
      providers: parseAuthProviderListAttribute(
        hostElement.getAttribute(AUTH_PROVIDER_CHOOSER_PROVIDERS_ATTRIBUTE),
      ),
      variant: normalizeAuthProviderChooserVariant(
        hostElement.getAttribute(AUTH_PROVIDER_CHOOSER_VARIANT_ATTRIBUTE),
      ),
    });
  }

  function getAuthProviderLabel(providerId, labelOverride) {
    if (typeof labelOverride === "string" && labelOverride.trim()) {
      return labelOverride.trim();
    }
    return AUTH_PROVIDER_CHOOSER_LABELS[providerId];
  }

  function setAuthProviderChooserError(hostElement, error) {
    if (!hostElement || typeof hostElement.setAttribute !== "function") {
      return;
    }
    var errorCode = error && error.code ? error.code : "mpr-ui.auth_provider_chooser.error";
    hostElement.setAttribute(AUTH_PROVIDER_CHOOSER_ERROR_ATTRIBUTE, errorCode);
    logError(errorCode, error && error.message ? error.message : String(error));
    dispatchEvent(hostElement, AUTH_PROVIDER_ERROR_EVENT, {
      code: errorCode,
      message: error && error.message ? error.message : String(error),
    });
  }

  function clearAuthProviderChooserError(hostElement) {
    if (!hostElement || typeof hostElement.removeAttribute !== "function") {
      return;
    }
    hostElement.removeAttribute(AUTH_PROVIDER_CHOOSER_ERROR_ATTRIBUTE);
  }

  function createAuthProviderElement(hostElement, tagName) {
    var element = createElementNear(hostElement, tagName);
    if (!element) {
      throw createAuthProviderChooserError(
        AUTH_PROVIDER_CHOOSER_PROVIDERS_INVALID_ERROR_CODE,
        "Auth provider chooser requires document.createElement",
      );
    }
    return element;
  }

  function appendAuthProviderElement(parentElement, childElement) {
    if (!parentElement || typeof parentElement.appendChild !== "function") {
      throw createAuthProviderChooserError(
        AUTH_PROVIDER_CHOOSER_PROVIDERS_INVALID_ERROR_CODE,
        "Auth provider chooser requires appendChild support",
      );
    }
    parentElement.appendChild(childElement);
  }

  function setAuthProviderElementClass(element, className) {
    if (element && typeof element.setAttribute === "function") {
      element.setAttribute("class", className);
    }
  }

  function setAuthProviderElementText(element, text) {
    element.textContent = text;
  }

  function createAuthProviderMark(hostElement, providerId) {
    var markElement = createAuthProviderElement(hostElement, "span");
    setAuthProviderElementClass(
      markElement,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
        "__mark " +
        AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
        "__mark--" +
        providerId,
    );
    markElement.innerHTML = AUTH_PROVIDER_CHOOSER_MARKUP[providerId];
    if (typeof markElement.setAttribute === "function") {
      markElement.setAttribute("aria-hidden", "true");
      markElement.setAttribute("data-mpr-auth-provider-mark", providerId);
    }
    return markElement;
  }

  function createAuthProviderLabel(hostElement, providerId, labelOverride) {
    var labelElement = createAuthProviderElement(hostElement, "span");
    setAuthProviderElementClass(
      labelElement,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__label",
    );
    setAuthProviderElementText(
      labelElement,
      getAuthProviderLabel(providerId, labelOverride),
    );
    if (typeof labelElement.setAttribute === "function") {
      labelElement.setAttribute("data-mpr-auth-provider-label", providerId);
    }
    return labelElement;
  }

  function createAuthProviderActionButton(
    hostElement,
    providerId,
    emailPanelId,
    emailExpanded,
    handleClick,
    labelOverride,
  ) {
    var buttonElement = createAuthProviderElement(hostElement, "button");
    buttonElement.type = "button";
    setAuthProviderElementClass(
      buttonElement,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
        "__action " +
        AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
        "__action--" +
        providerId,
    );
    if (typeof buttonElement.setAttribute === "function") {
      buttonElement.setAttribute("type", "button");
      buttonElement.setAttribute("data-mpr-auth-provider", providerId);
      buttonElement.setAttribute("data-test", "auth-provider-" + providerId);
      buttonElement.setAttribute(
        "aria-label",
        getAuthProviderLabel(providerId, labelOverride),
      );
      if (providerId === AUTH_PROVIDER_IDS.EMAIL) {
        buttonElement.setAttribute("aria-expanded", emailExpanded ? "true" : "false");
        buttonElement.setAttribute("aria-controls", emailPanelId);
      }
    }
    appendAuthProviderElement(
      buttonElement,
      createAuthProviderMark(hostElement, providerId),
    );
    appendAuthProviderElement(
      buttonElement,
      createAuthProviderLabel(hostElement, providerId, labelOverride),
    );
    buttonElement.addEventListener("click", handleClick);
    return buttonElement;
  }

  function enabledAuthProviderIds(authOptions) {
    var providerIds = [];
    if (authOptions.providers.google.enabled) {
      providerIds.push(AUTH_PROVIDER_IDS.GOOGLE);
    }
    if (authOptions.providers.apple.enabled) {
      providerIds.push(AUTH_PROVIDER_IDS.APPLE);
    }
    if (authOptions.providers.password.enabled) {
      providerIds.push(AUTH_PROVIDER_IDS.EMAIL);
    }
    return providerIds;
  }

  function authProviderActionLabel(authOptions, providerId, displayOptions) {
    if (providerId === AUTH_PROVIDER_IDS.APPLE) {
      return authOptions.providers.apple.label;
    }
    if (providerId === AUTH_PROVIDER_IDS.EMAIL) {
      return AUTH_PROVIDER_CHOOSER_LABELS.email;
    }
    var configuredGoogleLabel =
      displayOptions && typeof displayOptions.googleLabel === "string"
        ? displayOptions.googleLabel.trim()
        : "";
    return configuredGoogleLabel || AUTH_ACTION_LABELS.google;
  }

  function authProviderActionStatus(providerId, status) {
    if (providerId === AUTH_PROVIDER_IDS.APPLE) {
      return status === "error"
        ? AUTH_ACTION_LABELS.appleFailure
        : AUTH_ACTION_LABELS.applePreparing;
    }
    if (providerId === AUTH_PROVIDER_IDS.EMAIL) {
      return status === "error"
        ? AUTH_ACTION_LABELS.passwordFailure
        : AUTH_ACTION_LABELS.passwordPreparing;
    }
    return status === "error"
      ? AUTH_ACTION_LABELS.googleFailure
      : AUTH_ACTION_LABELS.googlePreparing;
  }

  // Google renders its personalized control inside a cross-origin iframe,
  // so page styles cannot size it. Forward the allocated slot width as the
  // provider minimum width (documented maximum 400px) to keep the visible
  // control aligned with its neighboring controls.
  var GOOGLE_BUTTON_MAXIMUM_WIDTH_PX = 400;

  function measureGoogleButtonSlotWidth(slotElement) {
    if (!slotElement || typeof slotElement.clientWidth !== "number") {
      return null;
    }
    var slotWidth = Math.floor(slotElement.clientWidth);
    if (slotWidth <= 0) {
      return null;
    }
    return String(Math.min(slotWidth, GOOGLE_BUTTON_MAXIMUM_WIDTH_PX));
  }

  function buildGoogleButtonRenderOptions(displayOptions, handleClick) {
    var source =
      displayOptions &&
      displayOptions.googleButtonOptions &&
      typeof displayOptions.googleButtonOptions === "object"
        ? displayOptions.googleButtonOptions
        : {};
    var shape = source.shape || LOGIN_BUTTON_SHAPE.RECTANGULAR;
    return {
      type:
        shape === LOGIN_BUTTON_SHAPE.SQUARE ||
        shape === LOGIN_BUTTON_SHAPE.CIRCLE
          ? "icon"
          : "standard",
      theme: source.theme || LOGIN_BUTTON_THEME.OUTLINE,
      size: source.size || LOGIN_BUTTON_SIZE.MEDIUM,
      text: source.text || GOOGLE_SIGNIN_TEXT_OPTION.SIGN_IN_WITH,
      shape: shape,
      logo_alignment: "left",
      click_listener: handleClick,
    };
  }

  var googleProviderActions = new Map();
  var googleProviderActionSequence = 0;
  var currentGoogleNonceToken = null;

  function dispatchGoogleProviderCredential(payload) {
    var action = payload && googleProviderActions.get(payload.state);
    if (!action || !action.nonce) {
      return;
    }
    var nonceToken = action.nonce;
    action.nonce = null;
    return action.handleCredential(payload, nonceToken);
  }

  function mountGoogleProviderAction(
    hostElement,
    actionsElement,
    authController,
    displayOptions,
    setActionStatus,
  ) {
    var googleButtonHost = createAuthProviderElement(hostElement, "div");
    var isActive = true;
    var renderSequence = 0;
    var refreshTimerId = null;
    var resizeObserver = null;
    var resizeFrameId = null;
    var resizeGoogleButton = null;
    var actionState = "mpr-google-" + (++googleProviderActionSequence);
    var googleAction = { nonce: null, handleCredential: handleGoogleCredential };
    googleProviderActions.set(actionState, googleAction);
    setAuthProviderElementClass(
      googleButtonHost,
      "mpr-auth-google-button",
    );
    googleButtonHost.setAttribute("data-mpr-auth-action", AUTH_PROVIDER_IDS.GOOGLE);
    googleButtonHost.setAttribute(
      "data-mpr-auth-provider",
      AUTH_PROVIDER_IDS.GOOGLE,
    );
    googleButtonHost.setAttribute("data-test", "auth-provider-google");
    googleButtonHost.setAttribute("aria-busy", "true");
    appendAuthProviderElement(actionsElement, googleButtonHost);

    function clearRefreshTimer() {
      if (refreshTimerId === null || typeof global.clearTimeout !== "function") {
        return;
      }
      global.clearTimeout(refreshTimerId);
      refreshTimerId = null;
    }

    function scheduleRender(delayMilliseconds) {
      clearRefreshTimer();
      if (!isActive || typeof global.setTimeout !== "function") {
        return;
      }
      refreshTimerId = global.setTimeout(function refreshGoogleButtonNonce() {
        refreshTimerId = null;
        renderNonceBoundButton();
      }, delayMilliseconds);
      if (
        refreshTimerId &&
        typeof refreshTimerId.unref === "function"
      ) {
        refreshTimerId.unref();
      }
    }

    function handleGoogleButtonClick() {
      googleAction.nonce = currentGoogleNonceToken;
      if (displayOptions && typeof displayOptions.handleStart === "function") {
        displayOptions.handleStart(AUTH_PROVIDER_IDS.GOOGLE);
      }
    }

    function handleGoogleCredential(payload, nonceToken) {
      setActionStatus(
        AUTH_CONTROLLER_STATUS.AUTHENTICATING,
        AUTH_PROVIDER_IDS.GOOGLE,
      );
      return Promise.resolve(
        authController.handleCredential(payload, nonceToken),
      ).then(
        function handleGoogleCredentialComplete(result) {
          if (isActive) {
            setActionStatus("ready", AUTH_PROVIDER_IDS.GOOGLE);
            if (
              displayOptions &&
              typeof displayOptions.handleSuccess === "function"
            ) {
              displayOptions.handleSuccess(AUTH_PROVIDER_IDS.GOOGLE, result);
            }
          }
          return result;
        },
        function handleGoogleCredentialFailure(error) {
          if (isActive) {
            setActionStatus("error", AUTH_PROVIDER_IDS.GOOGLE);
            if (
              displayOptions &&
              typeof displayOptions.handleError === "function"
            ) {
              displayOptions.handleError(AUTH_PROVIDER_IDS.GOOGLE, error);
            }
          }
          throw error;
        },
      );
    }

    function renderNonceBoundButton() {
      renderSequence += 1;
      var currentRenderSequence = renderSequence;
      resizeGoogleButton = null;
      clearNodeContents(googleButtonHost);
      googleButtonHost.removeAttribute("data-mpr-google-ready");
      googleButtonHost.removeAttribute("data-mpr-google-error");
      googleButtonHost.setAttribute("aria-busy", "true");
      Promise.resolve(
        authController.prepareGoogleNonce(dispatchGoogleProviderCredential),
      ).then(
        function renderPreparedGoogleButton() {
          if (!isActive || currentRenderSequence !== renderSequence) {
            return;
          }
          var googleId =
            global.google &&
            global.google.accounts &&
            global.google.accounts.id
              ? global.google.accounts.id
              : null;
          if (!googleId || typeof googleId.renderButton !== "function") {
            throw new Error("google identity button unavailable");
          }
          var renderOptions = buildGoogleButtonRenderOptions(
            displayOptions,
            handleGoogleButtonClick,
          );
          renderOptions.state = actionState;
          if (renderOptions.type === "standard") {
            var slotWidth = measureGoogleButtonSlotWidth(actionsElement);
            if (slotWidth !== null) {
              renderOptions.width = slotWidth;
            }
          }
          googleId.renderButton(googleButtonHost, renderOptions);
          if (renderOptions.type === "standard") {
            resizeGoogleButton = function renderResizedGoogleButton() {
              var slotWidth = measureGoogleButtonSlotWidth(actionsElement);
              if (slotWidth === null || slotWidth === renderOptions.width) {
                return;
              }
              renderOptions = Object.assign({}, renderOptions, { width: slotWidth });
              clearNodeContents(googleButtonHost);
              googleId.renderButton(googleButtonHost, renderOptions);
            };
            if (resizeObserver === null) {
              resizeObserver = new global.ResizeObserver(function handleGoogleSlotResize() {
                if (resizeFrameId !== null) {
                  return;
                }
                resizeFrameId = global.requestAnimationFrame(function updateGoogleButtonWidth() {
                  resizeFrameId = null;
                  if (isActive && resizeGoogleButton !== null) {
                    resizeGoogleButton();
                  }
                });
              });
              resizeObserver.observe(actionsElement);
            }
          }
          googleButtonHost.setAttribute("data-mpr-google-ready", "true");
          googleButtonHost.setAttribute("aria-busy", "false");
          setActionStatus("ready", AUTH_PROVIDER_IDS.GOOGLE);
          scheduleRender(GOOGLE_NONCE_REFRESH_INTERVAL_MS);
        },
        function handleGoogleButtonPreparationFailure(error) {
          if (!isActive || currentRenderSequence !== renderSequence) {
            return;
          }
          googleButtonHost.setAttribute("aria-busy", "false");
          googleButtonHost.setAttribute("data-mpr-google-error", "nonce-failed");
          setActionStatus("error", AUTH_PROVIDER_IDS.GOOGLE);
          if (
            displayOptions &&
            typeof displayOptions.handleError === "function"
          ) {
            displayOptions.handleError(AUTH_PROVIDER_IDS.GOOGLE, error);
          }
          scheduleRender(GOOGLE_NONCE_RETRY_INTERVAL_MS);
        },
      );
    }

    renderNonceBoundButton();
    return {
      target: googleButtonHost,
      cleanup: function cleanupGoogleProviderAction() {
        googleProviderActions.delete(actionState);
        isActive = false;
        renderSequence += 1;
        clearRefreshTimer();
        if (resizeObserver !== null) {
          resizeObserver.disconnect();
        }
        if (resizeFrameId !== null) {
          global.cancelAnimationFrame(resizeFrameId);
        }
        resizeGoogleButton = null;
        clearNodeContents(googleButtonHost);
      },
    };
  }

  function mountAuthProviderActions(
    hostElement,
    containerElement,
    authOptions,
    authController,
    displayOptions,
  ) {
    clearNodeContents(containerElement);
    var documentObject =
      hostElement.ownerDocument ||
      global.document ||
      (global.window && global.window.document) ||
      null;
    ensureAuthProviderChooserStyles(documentObject);
    var rootElement = createAuthProviderElement(hostElement, "div");
    var actionsElement = createAuthProviderElement(hostElement, "div");
    var statusElement = createAuthProviderElement(hostElement, "p");
    var providerButtons = [];
    var cleanupHandlers = [];
    var currentAttempt = 0;
    var passwordPanelElement = null;
    var passwordAuthElement = null;
    var passwordModeButtons = [];
    var passwordModeListElement = null;
    var passwordModeCleanupHandlers = [];
    var passwordPanelId = createAuthProviderEmailPanelId();
    var passwordAuthId = passwordPanelId + "-form";
    setAuthProviderElementClass(rootElement, "mpr-auth-actions");
    setAuthProviderElementClass(actionsElement, "mpr-auth-actions__controls");
    setAuthProviderElementClass(statusElement, "mpr-auth-actions__status");
    rootElement.setAttribute("data-mpr-auth-actions", "root");
    actionsElement.setAttribute("data-mpr-auth-actions", "controls");
    actionsElement.setAttribute("role", "group");
    actionsElement.setAttribute("aria-label", AUTH_PROVIDER_CHOOSER_LABELS.group);
    statusElement.setAttribute("data-mpr-auth-actions", "status");
    statusElement.setAttribute("role", "status");
    statusElement.setAttribute("aria-live", "polite");
    statusElement.textContent = "";

    function setActionStatus(status, providerId) {
      rootElement.setAttribute("data-mpr-auth-action-status", status);
      rootElement.setAttribute("data-mpr-auth-action-provider", providerId);
      var isPending = status === AUTH_CONTROLLER_STATUS.AUTHENTICATING;
      providerButtons.forEach(function updateProviderButton(buttonElement) {
        buttonElement.disabled = isPending;
        buttonElement.setAttribute("aria-busy", isPending ? "true" : "false");
      });
      statusElement.textContent =
        status === "ready" ? "" : authProviderActionStatus(providerId, status);
    }

    function setPasswordMode(mode) {
      if (passwordAuthElement.getAttribute(PASSWORD_AUTH_MODE_ATTRIBUTE) !== mode) {
        passwordAuthElement.setAttribute(PASSWORD_AUTH_MODE_ATTRIBUTE, mode);
      }
      passwordModeListElement.style.display = mode === "reset-start" ? "none" : "";
      passwordPanelElement.setAttribute("data-mpr-auth-email-mode", mode);
      passwordModeButtons.forEach(function updatePasswordModeButton(buttonElement) {
        buttonElement.setAttribute(
          "aria-selected",
          buttonElement.getAttribute("data-mpr-auth-email-mode") === mode
            ? "true"
            : "false",
        );
        buttonElement.setAttribute(
          "tabindex",
          buttonElement.getAttribute("data-mpr-auth-email-mode") === mode
            ? "0"
            : "-1",
        );
      });
    }

    function createPasswordModeButton(mode, label) {
      var buttonElement = createAuthProviderElement(hostElement, "button");
      function handlePasswordModeClick(event) {
        if (event && typeof event.preventDefault === "function") {
          event.preventDefault();
        }
        setPasswordMode(mode);
      }
      function handlePasswordModeKeydown(event) {
        if (!event || (event.key !== "ArrowLeft" && event.key !== "ArrowRight")) {
          return;
        }
        event.preventDefault();
        var currentIndex = passwordModeButtons.indexOf(buttonElement);
        var offset = event.key === "ArrowRight" ? 1 : -1;
        var nextIndex =
          (currentIndex + offset + passwordModeButtons.length) %
          passwordModeButtons.length;
        var nextButton = passwordModeButtons[nextIndex];
        setPasswordMode(nextButton.getAttribute("data-mpr-auth-email-mode"));
        nextButton.focus();
      }
      setAuthProviderElementClass(
        buttonElement,
        "mpr-auth-actions__email-mode",
      );
      buttonElement.type = "button";
      buttonElement.setAttribute("role", "tab");
      buttonElement.setAttribute("aria-controls", passwordAuthId);
      buttonElement.setAttribute("data-mpr-auth-email-mode", mode);
      setAuthProviderElementText(buttonElement, label);
      buttonElement.addEventListener("click", handlePasswordModeClick);
      buttonElement.addEventListener("keydown", handlePasswordModeKeydown);
      passwordModeButtons.push(buttonElement);
      passwordModeCleanupHandlers.push(function cleanupPasswordModeButton() {
        buttonElement.removeEventListener("click", handlePasswordModeClick);
        buttonElement.removeEventListener("keydown", handlePasswordModeKeydown);
      });
      return buttonElement;
    }

    function createPasswordPanel() {
      var panelElement = createAuthProviderElement(hostElement, "div");
      var modeListElement = createAuthProviderElement(hostElement, "div");
      passwordModeListElement = modeListElement;
      passwordAuthElement = createAuthProviderElement(
        hostElement,
        "mpr-password-auth",
      );
      passwordModeButtons = [];
      passwordModeCleanupHandlers = [];
      function handlePasswordModeChange(event) {
        setPasswordMode(event.detail.mode);
      }
      passwordAuthElement.addEventListener(PASSWORD_AUTH_MODE_EVENT, handlePasswordModeChange);
      var ownedPasswordAuth = passwordAuthElement;
      passwordModeCleanupHandlers.push(function cleanupPasswordModeChange() {
        ownedPasswordAuth.removeEventListener(PASSWORD_AUTH_MODE_EVENT, handlePasswordModeChange);
      });
      panelElement.id = passwordPanelId;
      panelElement.setAttribute("data-mpr-auth-email-panel", "");
      setAuthProviderElementClass(panelElement, "mpr-auth-actions__email-panel");
      modeListElement.setAttribute("role", "tablist");
      modeListElement.setAttribute("aria-label", AUTH_FORM_LABELS.emailAuthModes);
      setAuthProviderElementClass(
        modeListElement,
        "mpr-auth-actions__email-modes",
      );
      appendAuthProviderElement(
        modeListElement,
        createPasswordModeButton("login", AUTH_FORM_LABELS.loginSubmit),
      );
      appendAuthProviderElement(
        modeListElement,
        createPasswordModeButton("signup", AUTH_FORM_LABELS.signupSubmit),
      );
      passwordAuthElement.id = passwordAuthId;
      passwordAuthElement.setAttribute(
        AUTH_CONFIG_ATTRIBUTE,
        JSON.stringify(authOptions),
      );
      passwordAuthElement.__authControllerOverride = authController;
      appendAuthProviderElement(panelElement, modeListElement);
      appendAuthProviderElement(panelElement, passwordAuthElement);
      passwordPanelElement = panelElement;
      setPasswordMode("login");
      return panelElement;
    }

    function clearPasswordPanel() {
      if (passwordPanelElement && passwordPanelElement.parentNode) {
        passwordPanelElement.parentNode.removeChild(passwordPanelElement);
      }
      passwordModeCleanupHandlers.forEach(function cleanupPasswordMode(cleanup) {
        cleanup();
      });
      passwordPanelElement = null;
      passwordAuthElement = null;
      passwordModeButtons = [];
      passwordModeCleanupHandlers = [];
    }

    var providerIds = enabledAuthProviderIds(authOptions);
    setActionStatus("ready", providerIds[0]);
    providerIds.forEach(function mountProviderAction(providerId) {
      var providerLabel = authProviderActionLabel(
        authOptions,
        providerId,
        displayOptions,
      );
      function handleProviderAction(event) {
        if (event && typeof event.preventDefault === "function") {
          event.preventDefault();
        }
        if (providerId === AUTH_PROVIDER_IDS.EMAIL) {
          if (passwordPanelElement && passwordPanelElement.parentNode) {
            clearPasswordPanel();
            actionButton.setAttribute("aria-expanded", "false");
            setActionStatus("ready", providerId);
            return;
          }
          appendAuthProviderElement(rootElement, createPasswordPanel());
          actionButton.setAttribute("aria-expanded", "true");
          setActionStatus("ready", providerId);
          if (displayOptions && typeof displayOptions.handleStart === "function") {
            displayOptions.handleStart(providerId);
          }
          return;
        }
        currentAttempt += 1;
        var attempt = currentAttempt;
        setActionStatus(AUTH_CONTROLLER_STATUS.AUTHENTICATING, providerId);
        if (displayOptions && typeof displayOptions.handleStart === "function") {
          displayOptions.handleStart(providerId);
        }
        Promise.resolve(authController.startAppleSignIn()).then(
          function handleProviderActionReady() {
            if (attempt !== currentAttempt || providerId === AUTH_PROVIDER_IDS.APPLE) {
              return;
            }
            setActionStatus("ready", providerId);
          },
          function handleProviderActionFailure(error) {
            if (attempt !== currentAttempt) {
              return;
            }
            setActionStatus("error", providerId);
            if (displayOptions && typeof displayOptions.handleError === "function") {
              displayOptions.handleError(providerId, error);
            }
          },
        );
      }
      if (providerId === AUTH_PROVIDER_IDS.GOOGLE) {
        var googleProviderAction = mountGoogleProviderAction(
          hostElement,
          actionsElement,
          authController,
          displayOptions,
          setActionStatus,
        );
        providerButtons.push(googleProviderAction.target);
        cleanupHandlers.push(googleProviderAction.cleanup);
        return;
      }
      var actionButton = createAuthProviderActionButton(
        hostElement,
        providerId,
        "",
        false,
        handleProviderAction,
        providerLabel,
      );
      if (providerId === AUTH_PROVIDER_IDS.EMAIL) {
        actionButton.setAttribute("aria-controls", passwordPanelId);
      }
      actionButton.setAttribute("data-mpr-auth-action", providerId);
      actionButton.setAttribute("data-mpr-auth-provider", providerId);
      providerButtons.push(actionButton);
      cleanupHandlers.push(function cleanupProviderAction() {
        actionButton.removeEventListener("click", handleProviderAction);
      });
      appendAuthProviderElement(actionsElement, actionButton);
    });
    appendAuthProviderElement(rootElement, actionsElement);
    appendAuthProviderElement(rootElement, statusElement);
    appendAuthProviderElement(containerElement, rootElement);
    return {
      root: rootElement,
      buttons: providerButtons,
      cleanup: function cleanupAuthProviderActions() {
        currentAttempt += 1;
        clearPasswordPanel();
        cleanupHandlers.forEach(function runCleanup(cleanup) {
          cleanup();
        });
        clearNodeContents(containerElement);
      },
    };
  }

  function createAuthProviderField(
    hostElement,
    fieldId,
    fieldName,
    fieldType,
    label,
    autocompleteValue,
  ) {
    var fieldWrapper = createAuthProviderElement(hostElement, "label");
    var labelText = createAuthProviderElement(hostElement, "span");
    var inputElement = createAuthProviderElement(hostElement, "input");
    setAuthProviderElementClass(
      fieldWrapper,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__field",
    );
    setAuthProviderElementClass(
      labelText,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__field-label",
    );
    setAuthProviderElementClass(
      inputElement,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__input",
    );
    setAuthProviderElementText(labelText, label);
    if (typeof inputElement.setAttribute === "function") {
      inputElement.setAttribute("id", fieldId);
      inputElement.setAttribute("name", fieldName);
      inputElement.setAttribute("type", fieldType);
      inputElement.setAttribute("autocomplete", autocompleteValue);
      inputElement.setAttribute("required", "");
      inputElement.setAttribute("data-mpr-auth-provider-field", fieldName);
    }
    if (typeof fieldWrapper.setAttribute === "function") {
      fieldWrapper.setAttribute("for", fieldId);
    }
    appendAuthProviderElement(fieldWrapper, labelText);
    appendAuthProviderElement(fieldWrapper, inputElement);
    return fieldWrapper;
  }

  function createAuthProviderEmailPanel(
    hostElement,
    emailPanelId,
    handleSubmit,
    handleForgotPasswordClick,
    handleCreateAccountClick,
  ) {
    var panelElement = createAuthProviderElement(hostElement, "div");
    var formElement = createAuthProviderElement(hostElement, "form");
    var submitButton = createAuthProviderElement(hostElement, "button");
    var secondaryActions = createAuthProviderElement(hostElement, "div");
    var forgotPasswordButton = createAuthProviderElement(hostElement, "button");
    var createAccountButton = createAuthProviderElement(hostElement, "button");
    setAuthProviderElementClass(
      panelElement,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__email-panel",
    );
    setAuthProviderElementClass(
      formElement,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__email-form",
    );
    setAuthProviderElementClass(
      submitButton,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__submit",
    );
    setAuthProviderElementClass(
      secondaryActions,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__secondary-actions",
    );
    setAuthProviderElementClass(
      forgotPasswordButton,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__link-button",
    );
    setAuthProviderElementClass(
      createAccountButton,
      AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__link-button",
    );
    if (typeof panelElement.setAttribute === "function") {
      panelElement.setAttribute("id", emailPanelId);
      panelElement.setAttribute("data-mpr-auth-provider-chooser", "email-panel");
    }
    if (typeof formElement.setAttribute === "function") {
      formElement.setAttribute("data-mpr-auth-provider-email", "form");
    }
    if (typeof submitButton.setAttribute === "function") {
      submitButton.setAttribute("type", "submit");
      submitButton.setAttribute("data-mpr-auth-provider-email", "submit");
    }
    if (typeof secondaryActions.setAttribute === "function") {
      secondaryActions.setAttribute(
        "data-mpr-auth-provider-email",
        "secondary-actions",
      );
    }
    if (typeof forgotPasswordButton.setAttribute === "function") {
      forgotPasswordButton.setAttribute("type", "button");
      forgotPasswordButton.setAttribute(
        "data-mpr-auth-provider-email",
        AUTH_PROVIDER_EMAIL_MODE.RESET_START,
      );
    }
    if (typeof createAccountButton.setAttribute === "function") {
      createAccountButton.setAttribute("type", "button");
      createAccountButton.setAttribute(
        "data-mpr-auth-provider-email",
        AUTH_PROVIDER_EMAIL_MODE.SIGNUP,
      );
    }
    setAuthProviderElementText(submitButton, AUTH_PROVIDER_CHOOSER_LABELS.submit);
    setAuthProviderElementText(
      forgotPasswordButton,
      AUTH_PROVIDER_CHOOSER_LABELS.forgotPassword,
    );
    setAuthProviderElementText(
      createAccountButton,
      AUTH_PROVIDER_CHOOSER_LABELS.createAccount,
    );
    appendAuthProviderElement(
      formElement,
      createAuthProviderField(
        hostElement,
        emailPanelId + "-email",
        "email",
        "email",
        AUTH_PROVIDER_CHOOSER_LABELS.emailField,
        "username",
      ),
    );
    appendAuthProviderElement(
      formElement,
      createAuthProviderField(
        hostElement,
        emailPanelId + "-password",
        "password",
        "password",
        AUTH_PROVIDER_CHOOSER_LABELS.passwordField,
        "current-password",
      ),
    );
    appendAuthProviderElement(formElement, submitButton);
    appendAuthProviderElement(secondaryActions, forgotPasswordButton);
    appendAuthProviderElement(secondaryActions, createAccountButton);
    appendAuthProviderElement(panelElement, formElement);
    appendAuthProviderElement(panelElement, secondaryActions);
    formElement.addEventListener("submit", handleSubmit);
    forgotPasswordButton.addEventListener("click", handleForgotPasswordClick);
    createAccountButton.addEventListener("click", handleCreateAccountClick);
    return {
      panel: panelElement,
      cleanup: function cleanupAuthProviderEmailPanel() {
        formElement.removeEventListener("submit", handleSubmit);
        forgotPasswordButton.removeEventListener("click", handleForgotPasswordClick);
        createAccountButton.removeEventListener("click", handleCreateAccountClick);
      },
    };
  }

  function dispatchAuthProviderModeEvent(hostElement, mode) {
    dispatchEvent(hostElement, AUTH_PROVIDER_EMAIL_MODE_EVENT, {
      provider: AUTH_PROVIDER_IDS.EMAIL,
      mode: mode,
    });
  }

  function normalizeSelectionStateId(value) {
    if (value === null || value === undefined) {
      return "";
    }
    return String(value).trim();
  }

  function toSelectionStateList(values) {
    if (Array.isArray(values)) {
      return values.slice();
    }
    if (values && typeof values.forEach === "function") {
      var list = [];
      values.forEach(function appendValue(value) {
        list.push(value);
      });
      return list;
    }
    return [];
  }

  function createNormalizedSelectionStateSet(values) {
    var selectionSet = new Set();
    toSelectionStateList(values).forEach(function appendSelection(value) {
      var normalizedId = normalizeSelectionStateId(value);
      if (normalizedId) {
        selectionSet.add(normalizedId);
      }
    });
    return selectionSet;
  }

  function areEqualSelectionStateSets(left, right) {
    if (!(left instanceof Set) || !(right instanceof Set)) {
      return false;
    }
    if (left.size !== right.size) {
      return false;
    }
    return Array.from(left.values()).every(function compareEntry(value) {
      return right.has(value);
    });
  }

  function createSelectionState(initialIds) {
    var selectedIds = createNormalizedSelectionStateSet(initialIds);
    return {
      isSelected: function isSelected(id) {
        var normalizedId = normalizeSelectionStateId(id);
        return normalizedId.length > 0 && selectedIds.has(normalizedId);
      },
      setSelected: function setSelected(id, selected) {
        var normalizedId = normalizeSelectionStateId(id);
        if (!normalizedId) {
          return false;
        }
        var shouldSelect = Boolean(selected);
        var alreadySelected = selectedIds.has(normalizedId);
        if (alreadySelected === shouldSelect) {
          return false;
        }
        if (shouldSelect) {
          selectedIds.add(normalizedId);
        } else {
          selectedIds.delete(normalizedId);
        }
        return true;
      },
      toggle: function toggle(id) {
        var normalizedId = normalizeSelectionStateId(id);
        if (!normalizedId) {
          return false;
        }
        if (selectedIds.has(normalizedId)) {
          selectedIds.delete(normalizedId);
        } else {
          selectedIds.add(normalizedId);
        }
        return true;
      },
      replace: function replace(ids) {
        var nextSelectedIds = createNormalizedSelectionStateSet(ids);
        if (areEqualSelectionStateSets(selectedIds, nextSelectedIds)) {
          return false;
        }
        selectedIds = nextSelectedIds;
        return true;
      },
      clear: function clear() {
        if (selectedIds.size === 0) {
          return false;
        }
        selectedIds.clear();
        return true;
      },
      reconcile: function reconcile(validIds) {
        if (selectedIds.size === 0) {
          return false;
        }
        var authoritativeIds = createNormalizedSelectionStateSet(validIds);
        var nextSelectedIds = createNormalizedSelectionStateSet(
          Array.from(selectedIds.values()).filter(function keepSelection(id) {
            return authoritativeIds.has(id);
          }),
        );
        if (areEqualSelectionStateSets(selectedIds, nextSelectedIds)) {
          return false;
        }
        selectedIds = nextSelectedIds;
        return true;
      },
      getSelectedIds: function getSelectedIds() {
        return Array.from(selectedIds.values());
      },
      count: function count() {
        return selectedIds.size;
      },
    };
  }

  var DEFAULT_THEME_ATTRIBUTE = "data-mpr-theme";
  var DEFAULT_THEME_TARGETS = Object.freeze(["document", "body"]);
  var DEFAULT_THEME_MODES = Object.freeze([
    Object.freeze({
      value: "dark",
      attributeValue: "dark",
      classList: Object.freeze([]),
      dataset: Object.freeze({}),
    }),
    Object.freeze({
      value: "light",
      attributeValue: "light",
      classList: Object.freeze([]),
      dataset: Object.freeze({}),
    }),
  ]);

  var THEME_STYLE_ID = "mpr-ui-theme-tokens";
  var THEME_STYLE_MARKUP =
    ":root{" +
    "--mpr-color-surface-primary:#0f1114;" +
    "--mpr-color-surface-elevated:#1f2126;" +
    "--mpr-color-surface-backdrop:rgba(15,17,20,0.72);" +
    "--mpr-color-text-primary:#e3e5ec;" +
    "--mpr-color-text-muted:#c4c7d1;" +
    "--mpr-color-border:#2c2f36;" +
    "--mpr-color-divider:#3b3f48;" +
    "--mpr-chip-bg:rgba(114,120,135,0.16);" +
    "--mpr-chip-hover-bg:rgba(114,120,135,0.25);" +
    "--mpr-menu-hover-bg:rgba(93,147,255,0.12);" +
    "--mpr-color-accent:#5d93ff;" +
    "--mpr-color-accent-alt:#95c23d;" +
    "--mpr-color-accent-contrast:#0f1114;" +
    "--mpr-theme-toggle-knob-bg:#e3e5ec;" +
    "--mpr-theme-toggle-knob-active:#0f1114;" +
    "--mpr-theme-toggle-bg:rgba(114,120,135,0.15);" +
    "--mpr-shadow-elevated:none;" +
    "--mpr-shadow-flyout:0 8px 24px rgba(0,0,0,0.3);" +
    "--mpr-content-width:960px;" +
    "--mpr-content-width-expanded:1180px;" +
    "--mpr-radius-control:6px;" +
    "}" +
    "[data-mpr-theme=\"dark\"]{" +
    "--mpr-color-surface-primary:#0f1114;" +
    "--mpr-color-surface-elevated:#1f2126;" +
    "--mpr-color-surface-backdrop:rgba(15,17,20,0.72);" +
    "--mpr-color-text-primary:#e3e5ec;" +
    "--mpr-color-text-muted:#c4c7d1;" +
    "--mpr-color-border:#2c2f36;" +
    "--mpr-color-divider:#3b3f48;" +
    "--mpr-chip-bg:rgba(114,120,135,0.16);" +
    "--mpr-chip-hover-bg:rgba(114,120,135,0.25);" +
    "--mpr-menu-hover-bg:rgba(93,147,255,0.12);" +
    "--mpr-color-accent:#5d93ff;" +
    "--mpr-color-accent-alt:#95c23d;" +
    "--mpr-color-accent-contrast:#0f1114;" +
    "--mpr-theme-toggle-knob-bg:#e3e5ec;" +
    "--mpr-theme-toggle-knob-active:#0f1114;" +
    "--mpr-theme-toggle-bg:rgba(114,120,135,0.15);" +
    "--mpr-shadow-elevated:none;" +
    "--mpr-shadow-flyout:0 8px 24px rgba(0,0,0,0.3);" +
    "}" +
    "[data-mpr-theme=\"light\"]{" +
    "--mpr-color-surface-primary:rgba(248,250,252,0.94);" +
    "--mpr-color-surface-elevated:#ffffff;" +
    "--mpr-color-surface-backdrop:rgba(226,232,240,0.8);" +
    "--mpr-color-text-primary:#0f172a;" +
    "--mpr-color-text-muted:#334155;" +
    "--mpr-color-border:rgba(148,163,184,0.35);" +
    "--mpr-color-divider:rgba(148,163,184,0.4);" +
    "--mpr-chip-bg:rgba(148,163,184,0.18);" +
    "--mpr-chip-hover-bg:rgba(148,163,184,0.28);" +
    "--mpr-menu-hover-bg:rgba(14,165,233,0.12);" +
    "--mpr-color-accent:#0284c7;" +
    "--mpr-color-accent-alt:#0ea5e9;" +
    "--mpr-color-accent-contrast:#f8fafc;" +
    "--mpr-theme-toggle-knob-bg:#0f172a;" +
    "--mpr-theme-toggle-knob-active:#e2e8f0;" +
    "--mpr-theme-toggle-bg:rgba(14,165,233,0.12);" +
    "--mpr-shadow-elevated:0 8px 16px rgba(15,23,42,0.18);" +
    "--mpr-shadow-flyout:0 16px 32px rgba(15,23,42,0.18);" +
    "}";

  function ensureThemeTokenStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    if (documentObject.getElementById(THEME_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = THEME_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = THEME_STYLE_MARKUP;
    } else {
      styleElement.appendChild(documentObject.createTextNode(THEME_STYLE_MARKUP));
    }
    documentObject.head.appendChild(styleElement);
  }

  function normalizeThemeTargets(targets) {
    if (targets === undefined || targets === null) {
      return DEFAULT_THEME_TARGETS.slice();
    }
    var list = Array.isArray(targets) ? targets : [targets];
    var normalized = list
      .map(function normalizeSingleTarget(entry) {
        if (entry === null || entry === undefined) {
          return null;
        }
        if (typeof entry === "string") {
          var trimmed = entry.trim();
          return trimmed ? trimmed : null;
        }
        if (entry && typeof entry.selector === "string") {
          var selectorValue = entry.selector.trim();
          return selectorValue ? selectorValue : null;
        }
        return null;
      })
      .filter(Boolean);
    if (!normalized.length) {
      return DEFAULT_THEME_TARGETS.slice();
    }
    var deduped = [];
    var seen = Object.create(null);
    normalized.forEach(function dedupeTarget(target) {
      if (!seen[target]) {
        seen[target] = true;
        deduped.push(target);
      }
    });
    return deduped;
  }

  function normalizeThemeModes(candidateModes) {
    var list = Array.isArray(candidateModes) && candidateModes.length
      ? candidateModes
      : DEFAULT_THEME_MODES;
    var normalized = [];
    var seen = Object.create(null);
    for (var index = 0; index < list.length; index += 1) {
      var entry = list[index];
      var modeValue;
      if (entry && typeof entry.value === "string") {
        modeValue = entry.value.trim();
      } else if (typeof entry === "string") {
        modeValue = entry.trim();
      } else {
        modeValue = "";
      }
      if (!modeValue || seen[modeValue]) {
        continue;
      }
      seen[modeValue] = true;
      var attributeValue =
        entry && typeof entry.attributeValue === "string"
          ? entry.attributeValue.trim()
          : modeValue;
      var classList =
        entry && Array.isArray(entry.classList)
          ? entry.classList
              .map(function normalizeClass(className) {
                return typeof className === "string"
                  ? className.trim()
                  : String(className);
              })
              .filter(Boolean)
          : [];
      var dataset = {};
      if (entry && entry.dataset && typeof entry.dataset === "object") {
        Object.keys(entry.dataset).forEach(function copyDatasetKey(key) {
          var attrKey = String(key).trim();
          if (!attrKey) {
            return;
          }
          dataset[attrKey] = String(entry.dataset[key]);
        });
      }
      normalized.push({
        value: modeValue,
        attributeValue: attributeValue,
        classList: classList,
        dataset: dataset,
      });
    }
    if (!normalized.length) {
      return DEFAULT_THEME_MODES.slice().map(function cloneDefault(mode) {
        return {
          value: mode.value,
          attributeValue: mode.attributeValue,
          classList: [].concat(mode.classList || []),
          dataset: deepMergeOptions({}, mode.dataset || {}),
        };
      });
    }
    return normalized;
  }

  function normalizeThemeConfig(partialConfig) {
    var config = deepMergeOptions(
      {
        attribute: DEFAULT_THEME_ATTRIBUTE,
        targets: DEFAULT_THEME_TARGETS.slice(),
        modes: DEFAULT_THEME_MODES,
        initialMode: null,
      },
      partialConfig || {},
    );
    config.attribute =
      typeof config.attribute === "string" && config.attribute.trim()
        ? config.attribute.trim()
        : DEFAULT_THEME_ATTRIBUTE;
    config.targets = normalizeThemeTargets(config.targets);
    config.modes = normalizeThemeModes(config.modes);
    var normalizedInitial = null;
    if (
      partialConfig &&
      typeof partialConfig.mode === "string" &&
      partialConfig.mode.trim()
    ) {
      normalizedInitial = partialConfig.mode.trim();
    } else if (
      partialConfig &&
      typeof partialConfig.initialMode === "string" &&
      partialConfig.initialMode.trim()
    ) {
      normalizedInitial = partialConfig.initialMode.trim();
    }
    config.initialMode = normalizedInitial;
    return config;
  }

  function dedupeTargets(targets) {
    var seen = Object.create(null);
    var deduped = [];
    targets.forEach(function addTarget(target) {
      if (!target) {
        return;
      }
      if (!seen[target]) {
        seen[target] = true;
        deduped.push(target);
      }
    });
    return deduped.length ? deduped : DEFAULT_THEME_TARGETS.slice();
  }

  function resolveThemeTargets(targets) {
    if (!global.document) {
      return [];
    }
    var resolved = [];
    var seen = new WeakSet();
    targets.forEach(function resolveSingleTarget(target) {
      if (target === "document") {
        if (global.document.documentElement && !seen.has(global.document.documentElement)) {
          seen.add(global.document.documentElement);
          resolved.push(global.document.documentElement);
        }
        return;
      }
      if (target === "body") {
        if (global.document.body && !seen.has(global.document.body)) {
          seen.add(global.document.body);
          resolved.push(global.document.body);
        }
        return;
      }
      var nodeList = global.document.querySelectorAll(target);
      for (var index = 0; index < nodeList.length; index += 1) {
        var element = nodeList[index];
        if (!seen.has(element)) {
          seen.add(element);
          resolved.push(element);
        }
      }
    });
    return resolved;
  }

  function collectThemeClassNames(modes) {
    var classSet = Object.create(null);
    modes.forEach(function collectClasses(mode) {
      mode.classList.forEach(function markClass(className) {
        classSet[className] = true;
      });
    });
    return Object.keys(classSet);
  }

  function collectThemeDatasetKeys(modes) {
    var keySet = Object.create(null);
    modes.forEach(function collectKeys(mode) {
      Object.keys(mode.dataset).forEach(function markKey(key) {
        keySet[key] = true;
      });
    });
    return Object.keys(keySet);
  }

  function applyThemeDatasetAttribute(element, key, value) {
    var attributeName = key.indexOf("data-") === 0 ? key : "data-" + key;
    if (value === null || value === undefined || value === "") {
      element.removeAttribute(attributeName);
      return;
    }
    element.setAttribute(attributeName, String(value));
  }

  var themeManager = (function createThemeManager() {
    var currentConfig = normalizeThemeConfig({});
    var allModeClasses = collectThemeClassNames(currentConfig.modes);
    var allDatasetKeys = collectThemeDatasetKeys(currentConfig.modes);
    var listeners = [];
    var currentMode = currentConfig.modes[0].value;
    var resolvedTargets = resolveThemeTargets(currentConfig.targets);

    function getModeIndex(modeValue) {
      for (var index = 0; index < currentConfig.modes.length; index += 1) {
        if (currentConfig.modes[index].value === modeValue) {
          return index;
        }
      }
      return -1;
    }

    if (
      currentConfig.initialMode &&
      getModeIndex(currentConfig.initialMode) !== -1
    ) {
      currentMode = currentConfig.initialMode;
    }

    function applyMode(modeValue) {
      var modeIndex = getModeIndex(modeValue);
      if (modeIndex === -1) {
        modeIndex = 0;
        modeValue = currentConfig.modes[0].value;
      }
      var activeMode = currentConfig.modes[modeIndex];
      var targets = resolvedTargets;
      var documentElement =
        global.document && global.document.documentElement
          ? global.document.documentElement
          : null;
      var primaryAttribute = currentConfig.attribute || DEFAULT_THEME_ATTRIBUTE;
      if (documentElement) {
        documentElement.setAttribute(primaryAttribute, activeMode.attributeValue);
        if (primaryAttribute !== DEFAULT_THEME_ATTRIBUTE) {
          documentElement.setAttribute(
            DEFAULT_THEME_ATTRIBUTE,
            activeMode.attributeValue,
          );
        }
      }
      targets.forEach(function applyToElement(element) {
        if (primaryAttribute) {
          element.setAttribute(primaryAttribute, activeMode.attributeValue);
          if (primaryAttribute !== DEFAULT_THEME_ATTRIBUTE) {
            element.setAttribute(
              DEFAULT_THEME_ATTRIBUTE,
              activeMode.attributeValue,
            );
          }
        }
        if (element.classList) {
          allModeClasses.forEach(function removeClass(className) {
            element.classList.remove(className);
          });
          activeMode.classList.forEach(function addClass(className) {
            element.classList.add(className);
          });
        }
        allDatasetKeys.forEach(function clearDataset(key) {
          applyThemeDatasetAttribute(element, key, null);
        });
        Object.keys(activeMode.dataset).forEach(function assignDataset(key) {
          applyThemeDatasetAttribute(element, key, activeMode.dataset[key]);
        });
      });
    }

    function notifyListeners(source) {
      var detail = { mode: currentMode, source: source || null };
      for (var index = 0; index < listeners.length; index += 1) {
        try {
          listeners[index](detail);
        } catch (_error) {}
      }
      if (global.document) {
        dispatchEvent(global.document, "mpr-ui:theme-change", detail);
      }
    }

    function ensureInitialMode() {
      if (!global.document || !global.document.documentElement) {
        applyMode(currentMode);
        return;
      }
      var initialValue = global.document.documentElement.getAttribute(
        currentConfig.attribute,
      );
      if (initialValue && getModeIndex(initialValue) !== -1) {
        currentMode = initialValue;
      }
      applyMode(currentMode);
    }

    function configure(partialConfig) {
      if (!partialConfig || typeof partialConfig !== "object") {
        return {
          attribute: currentConfig.attribute,
          targets: currentConfig.targets.slice(),
          modes: currentConfig.modes.slice(),
        };
      }
      var normalized = normalizeThemeConfig(partialConfig);
      if (Object.prototype.hasOwnProperty.call(partialConfig, "attribute")) {
        currentConfig.attribute = normalized.attribute;
      }
      if (Object.prototype.hasOwnProperty.call(partialConfig, "targets")) {
        var mergedTargets = DEFAULT_THEME_TARGETS.concat(normalized.targets);
        currentConfig.targets = dedupeTargets(mergedTargets);
        resolvedTargets = resolveThemeTargets(currentConfig.targets);
      }
      if (!resolvedTargets || !resolvedTargets.length) {
        resolvedTargets = resolveThemeTargets(currentConfig.targets);
      }
      if (Object.prototype.hasOwnProperty.call(partialConfig, "modes")) {
        currentConfig.modes = normalized.modes;
      }
      if (
        Object.prototype.hasOwnProperty.call(partialConfig, "mode") ||
        Object.prototype.hasOwnProperty.call(partialConfig, "initialMode")
      ) {
        currentConfig.initialMode = normalized.initialMode;
        if (
          normalized.initialMode &&
          getModeIndex(normalized.initialMode) !== -1
        ) {
          currentMode = normalized.initialMode;
        }
      }
      allModeClasses = collectThemeClassNames(currentConfig.modes);
      allDatasetKeys = collectThemeDatasetKeys(currentConfig.modes);
      if (getModeIndex(currentMode) === -1) {
        currentMode = currentConfig.modes[0].value;
      }
      applyMode(currentMode);
      return {
        attribute: currentConfig.attribute,
        targets: currentConfig.targets.slice(),
        modes: currentConfig.modes.slice(),
      };
    }

    function setMode(modeValue, source) {
      if (typeof modeValue !== "string") {
        return currentMode;
      }
      var trimmed = modeValue.trim();
      if (!trimmed) {
        return currentMode;
      }
      var modeIndex = getModeIndex(trimmed);
      var resolvedMode =
        modeIndex === -1
          ? currentConfig.modes[0].value
          : currentConfig.modes[modeIndex].value;
      if (resolvedMode === currentMode) {
        notifyListeners(source);
        return currentMode;
      }
      currentMode = resolvedMode;
      applyMode(currentMode);
      notifyListeners(source);
      return currentMode;
    }

    function getMode() {
      return currentMode;
    }

    function on(listener) {
      if (typeof listener !== "function") {
        return function noop() {};
      }
      listeners.push(listener);
      return function unsubscribe() {
        for (var index = 0; index < listeners.length; index += 1) {
          if (listeners[index] === listener) {
            listeners.splice(index, 1);
            break;
          }
        }
      };
    }

    ensureInitialMode();

    return {
      configure: configure,
      setMode: setMode,
      getMode: getMode,
      on: on,
    };
  })();

  function normalizeThemeToggleCore(rawConfig, defaults) {
    var baseline = deepMergeOptions({}, defaults || {}, rawConfig || {});
    var enabled =
      baseline.enabled === undefined ? true : Boolean(baseline.enabled);
    var ariaLabel =
      typeof baseline.ariaLabel === "string" && baseline.ariaLabel.trim()
        ? baseline.ariaLabel.trim()
        : defaults && defaults.ariaLabel
        ? defaults.ariaLabel
        : "Toggle theme";
    var attribute =
      typeof baseline.attribute === "string" && baseline.attribute.trim()
        ? baseline.attribute.trim()
        : DEFAULT_THEME_ATTRIBUTE;
    var targets = normalizeThemeTargets(baseline.targets);
    var modes = normalizeThemeModes(baseline.modes);
    var initialMode = null;
    if (typeof baseline.mode === "string" && baseline.mode.trim()) {
      initialMode = baseline.mode.trim();
    } else if (
      typeof baseline.initialMode === "string" &&
      baseline.initialMode.trim()
    ) {
      initialMode = baseline.initialMode.trim();
    }
    return {
      enabled: enabled,
      ariaLabel: ariaLabel,
      attribute: attribute,
      targets: targets,
      modes: modes,
      initialMode: initialMode,
      raw: baseline,
    };
  }

  var THEME_TOGGLE_DEFAULT_ICONS = Object.freeze({
    light: "☀️",
    dark: "🌙",
    unknown: "🌗",
  });

  var THEME_TOGGLE_SQUARE_POSITIONS = Object.freeze([
    Object.freeze({ index: 0, col: 0, row: 0 }),
    Object.freeze({ index: 1, col: 1, row: 0 }),
    Object.freeze({ index: 2, col: 0, row: 1 }),
    Object.freeze({ index: 3, col: 1, row: 1 }),
  ]);

  function getThemeToggleModeIndex(modes, modeValue) {
    if (!Array.isArray(modes)) {
      return -1;
    }
    for (var index = 0; index < modes.length; index += 1) {
      if (modes[index] && modes[index].value === modeValue) {
        return index;
      }
    }
    return -1;
  }

  function resolveThemeModePolarity(mode) {
    if (!mode) {
      return null;
    }
    var candidate = "";
    if (typeof mode === "string") {
      candidate = mode;
    } else if (typeof mode === "object") {
      if (typeof mode.attributeValue === "string" && mode.attributeValue.trim()) {
        candidate = mode.attributeValue;
      } else if (typeof mode.value === "string" && mode.value.trim()) {
        candidate = mode.value;
      }
    }
    if (!candidate) {
      return null;
    }
    var normalized = String(candidate).trim().toLowerCase();
    if (!normalized) {
      return null;
    }
    if (normalized.indexOf("dark") === 0 || normalized.lastIndexOf("dark") === normalized.length - 4) {
      return "dark";
    }
    if (normalized.indexOf("light") === 0 || normalized.lastIndexOf("light") === normalized.length - 5) {
      return "light";
    }
    if (
      normalized.indexOf("-dark") !== -1 ||
      normalized.indexOf("dark-") !== -1 ||
      normalized.indexOf("_dark") !== -1
    ) {
      return "dark";
    }
    if (
      normalized.indexOf("-light") !== -1 ||
      normalized.indexOf("light-") !== -1 ||
      normalized.indexOf("_light") !== -1
    ) {
      return "light";
    }
    return null;
  }

  function deriveBinaryThemeToggleModes(candidateModes) {
    var modes = Array.isArray(candidateModes) && candidateModes.length
      ? candidateModes.slice()
      : DEFAULT_THEME_MODES.slice();
    var binary = [];
    var seen = Object.create(null);

    for (var index = 0; index < modes.length; index += 1) {
      var mode = modes[index];
      var polarity = resolveThemeModePolarity(mode);
      if (!polarity || seen[polarity]) {
        continue;
      }
      binary.push(mode);
      seen[polarity] = true;
      if (binary.length === 2) {
        break;
      }
    }

    if (binary.length === 2) {
      return binary;
    }

    if (!binary.length && modes.length) {
      binary.push(modes[0]);
    }

    for (var fillIndex = 0; fillIndex < modes.length; fillIndex += 1) {
      if (binary.length === 2) {
        break;
      }
      if (binary.indexOf(modes[fillIndex]) === -1) {
        binary.push(modes[fillIndex]);
      }
    }

    return binary;
  }

  function resolveNextThemeToggleMode(modes, currentValue) {
    if (!Array.isArray(modes) || !modes.length) {
      return currentValue || null;
    }
    var index = getThemeToggleModeIndex(modes, currentValue);
    if (index === -1) {
      return modes[0].value;
    }
    return modes[(index + 1) % modes.length].value;
  }

  function normalizeThemeToggleDisplayOptions(rawOptions, fallback) {
    var baseline = deepMergeOptions(
      {
        enabled: true,
        variant: "switch",
        label: "Theme",
        showLabel: true,
        wrapperClass: "",
        controlClass: "",
        iconClass: "",
        inputId: "",
        dataTheme: "",
        ariaLabel: "Toggle theme",
        icons: {},
        source: "theme-toggle",
        modes: DEFAULT_THEME_MODES.slice(),
      },
      fallback || {},
      rawOptions || {},
    );
    var normalizedIcons =
      baseline.icons && typeof baseline.icons === "object" ? baseline.icons : {};
    return {
      enabled: baseline.enabled !== false,
      variant:
        baseline.variant === "button"
          ? "button"
          : baseline.variant === "square"
          ? "square"
          : "switch",
      label:
        typeof baseline.label === "string" && baseline.label.trim()
          ? baseline.label.trim()
          : "Theme",
      showLabel: baseline.showLabel !== false,
      wrapperClass:
        typeof baseline.wrapperClass === "string"
          ? baseline.wrapperClass.trim()
          : "",
      controlClass:
        typeof baseline.controlClass === "string"
          ? baseline.controlClass.trim()
          : "",
      iconClass:
        typeof baseline.iconClass === "string" ? baseline.iconClass.trim() : "",
      inputId:
        typeof baseline.inputId === "string" ? baseline.inputId.trim() : "",
      dataTheme:
        typeof baseline.dataTheme === "string"
          ? baseline.dataTheme.trim()
          : "",
      ariaLabel:
        typeof baseline.ariaLabel === "string" && baseline.ariaLabel.trim()
          ? baseline.ariaLabel.trim()
          : "Toggle theme",
      icons: {
        light:
          typeof normalizedIcons.light === "string" &&
          normalizedIcons.light.trim()
            ? normalizedIcons.light.trim()
            : THEME_TOGGLE_DEFAULT_ICONS.light,
        dark:
          typeof normalizedIcons.dark === "string" && normalizedIcons.dark.trim()
            ? normalizedIcons.dark.trim()
            : THEME_TOGGLE_DEFAULT_ICONS.dark,
        unknown:
          typeof normalizedIcons.unknown === "string" &&
          normalizedIcons.unknown.trim()
            ? normalizedIcons.unknown.trim()
            : THEME_TOGGLE_DEFAULT_ICONS.unknown,
      },
      modes:
        Array.isArray(baseline.modes) && baseline.modes.length
          ? baseline.modes
          : DEFAULT_THEME_MODES.slice(),
      source:
        typeof baseline.source === "string" && baseline.source.trim()
          ? baseline.source.trim()
          : "theme-toggle",
    };
  }

  function buildThemeToggleMarkup(config) {
    var labelText = escapeHtml(config.label || "Theme");
    if (config.variant === "button") {
      var buttonClass = config.controlClass
        ? ' class="' + escapeHtml(config.controlClass) + '"'
        : "";
      var iconClass = config.iconClass
        ? ' class="' + escapeHtml(config.iconClass) + '"'
        : "";
      var labelMarkup = config.showLabel === false
        ? ""
        : '<span data-mpr-theme-toggle="label">' + labelText + "</span>";
      return (
        '<button type="button" data-mpr-theme-toggle="control"' +
        buttonClass +
        ' aria-label="' +
        escapeHtml(config.ariaLabel || config.label || "Toggle theme") +
        '">' +
        '<span data-mpr-theme-toggle="icon"' +
        iconClass +
        ' aria-hidden="true">' +
        escapeHtml(config.icons.dark) +
        "</span>" +
        labelMarkup +
        "</button>"
      );
    }
    if (config.variant === "square") {
      var squareClass = config.controlClass
        ? ' class="' + escapeHtml(config.controlClass) + '"'
        : "";
      var squareLabel = config.showLabel === false
        ? ""
        : '<span data-mpr-theme-toggle="label">' + labelText + "</span>";
      return (
        '<button type="button" data-mpr-theme-toggle="control"' +
        squareClass +
        ' data-variant="square" aria-live="polite" aria-label="' +
        escapeHtml(config.ariaLabel || config.label || "Toggle theme") +
        '">' +
        '<span data-mpr-theme-toggle="grid" aria-hidden="true">' +
        '<span data-mpr-theme-toggle="quad" data-quad-index="0" data-quad-enabled="false"></span>' +
        '<span data-mpr-theme-toggle="quad" data-quad-index="1" data-quad-enabled="false"></span>' +
        '<span data-mpr-theme-toggle="quad" data-quad-index="2" data-quad-enabled="false"></span>' +
        '<span data-mpr-theme-toggle="quad" data-quad-index="3" data-quad-enabled="false"></span>' +
        '<span data-mpr-theme-toggle="dot" data-contrast="dark"></span>' +
        "</span>" +
        squareLabel +
        "</button>"
      );
    }
    var inputClass = config.controlClass
      ? ' class="' + escapeHtml(config.controlClass) + '"'
      : "";
    var idAttribute = config.inputId
      ? ' id="' + escapeHtml(config.inputId) + '"'
      : "";
    var labelSpan = config.showLabel === false
      ? ""
      : '<span data-mpr-theme-toggle="label">' + labelText + "</span>";
    return (
      '<input type="checkbox" role="switch" data-mpr-theme-toggle="control"' +
      inputClass +
      idAttribute +
      ' aria-label="' +
      escapeHtml(config.ariaLabel || config.label || "Toggle theme") +
      '" />' +
      labelSpan
    );
  }

  function initializeThemeToggle(hostElement, config) {
    if (!hostElement || !config || !config.enabled) {
      if (hostElement) {
        hostElement.innerHTML = "";
        hostElement.removeAttribute("data-mpr-theme-mode");
        hostElement.removeAttribute("data-mpr-theme-toggle-variant");
      }
      return function noopToggle() {};
    }
    if (config.wrapperClass) {
      hostElement.className = config.wrapperClass;
    }
    if (config.dataTheme) {
      hostElement.setAttribute("data-bs-theme", config.dataTheme);
    } else {
      hostElement.removeAttribute("data-bs-theme");
    }
    hostElement.innerHTML = buildThemeToggleMarkup(config);
    var controlElement = hostElement.querySelector(
      '[data-mpr-theme-toggle="control"]',
    );
    var iconElement = hostElement.querySelector(
      '[data-mpr-theme-toggle="icon"]',
    );
    var variant = config.variant || "switch";
    if (typeof hostElement.setAttribute === "function") {
      hostElement.setAttribute("data-mpr-theme-toggle-variant", variant);
    }
    var squareGrid = variant === "square"
      ? hostElement.querySelector('[data-mpr-theme-toggle="grid"]')
      : null;
    var squareDot = variant === "square"
      ? hostElement.querySelector('[data-mpr-theme-toggle="dot"]')
      : null;
    if (variant === "square" && controlElement && controlElement.style) {
      if (typeof controlElement.style.removeProperty === "function") {
        controlElement.style.removeProperty("--mpr-theme-square-size");
        controlElement.style.removeProperty("--mpr-theme-square-dot-size");
      }
    }
    var squareQuads = [];
    if (variant === "square" && hostElement.querySelectorAll) {
      var quadNodeList = hostElement.querySelectorAll('[data-mpr-theme-toggle="quad"]');
      if (quadNodeList && typeof quadNodeList.length === "number") {
        for (var quadIndex = 0; quadIndex < quadNodeList.length; quadIndex += 1) {
          squareQuads.push(quadNodeList[quadIndex]);
        }
      }
    }
    if (!controlElement) {
      return function noopMissingControl() {};
    }
    var normalizedModes = Array.isArray(config.modes) && config.modes.length
      ? config.modes.slice()
      : DEFAULT_THEME_MODES.slice();
    var currentModes = variant === "switch"
      ? deriveBinaryThemeToggleModes(normalizedModes)
      : normalizedModes;
    var squareModeValues = variant === "square"
      ? currentModes
          .slice(0, THEME_TOGGLE_SQUARE_POSITIONS.length)
          .map(function extractModeValue(mode) {
            return mode.value;
          })
      : [];
    if (variant === "square") {
      for (var index = 0; index < squareQuads.length; index += 1) {
        var hasMode = squareModeValues[index] !== undefined;
        squareQuads[index].setAttribute("data-quad-enabled", hasMode ? "true" : "false");
      }
    }

    var travelTimeout = null;
    var rafId = null;
    var ownerWindow =
      controlElement.ownerDocument && controlElement.ownerDocument.defaultView
        ? controlElement.ownerDocument.defaultView
        : null;
    var travelResizeHandler = null;

    function resolveToggleTravel() {
      if (variant !== "switch") {
        return;
      }
      try {
        if (
          !controlElement ||
          typeof controlElement.getBoundingClientRect !== "function"
        ) {
          return;
        }
        var rect = controlElement.getBoundingClientRect();
        if (!rect || !rect.width) {
          return;
        }
        var ownerDocument = controlElement.ownerDocument;
        var computeWindow =
          ownerDocument && ownerDocument.defaultView
            ? ownerDocument.defaultView
            : null;
        if (!computeWindow || typeof computeWindow.getComputedStyle !== "function") {
          return;
        }
        var computed = computeWindow.getComputedStyle(controlElement);
        var pseudo = computeWindow.getComputedStyle(controlElement, "::before");
        var offset = 0;
        if (pseudo) {
          var offsetValue = parseFloat(pseudo.getPropertyValue("left"));
          if (Number.isFinite(offsetValue)) {
            offset = Math.max(0, offsetValue);
          }
        }
        var borderWidth = 0;
        if (computed) {
          var borderValue = parseFloat(computed.getPropertyValue("border-left-width"));
          if (Number.isFinite(borderValue)) {
            borderWidth = Math.max(0, borderValue);
          }
        }
        var knobSize = 0;
        if (pseudo) {
          var knobValue = parseFloat(pseudo.getPropertyValue("width"));
          if (Number.isFinite(knobValue)) {
            knobSize = Math.max(0, knobValue);
          }
        }
        var travel = rect.width - knobSize - (offset + borderWidth) * 2;
        if (travel > 0 && controlElement.style) {
          controlElement.style.setProperty("--mpr-theme-toggle-travel", travel + "px");
        }
      } catch (_error) {}
    }

    function scheduleTravelMeasurement() {
      if (variant !== "switch") {
        return;
      }
      if (
        ownerWindow &&
        typeof ownerWindow.requestAnimationFrame === "function"
      ) {
        if (rafId !== null && typeof ownerWindow.cancelAnimationFrame === "function") {
          ownerWindow.cancelAnimationFrame(rafId);
        }
        rafId = ownerWindow.requestAnimationFrame(function measureFrame() {
          resolveToggleTravel();
        });
      } else {
        travelTimeout = setTimeout(resolveToggleTravel, 16);
      }
    }

    if (variant === "switch") {
      resolveToggleTravel();
      scheduleTravelMeasurement();
      travelResizeHandler = function handleToggleResize() {
        resolveToggleTravel();
      };
      if (ownerWindow && typeof ownerWindow.addEventListener === "function") {
        ownerWindow.addEventListener("resize", travelResizeHandler);
      }
    }

    function syncSquareUi(resolvedModeValue) {
      if (variant !== "square" || !squareModeValues.length) {
        return;
      }
      var squareIndex = squareModeValues.indexOf(resolvedModeValue);
      if (squareIndex === -1) {
        squareIndex = 0;
        resolvedModeValue = squareModeValues[0];
      }
      var position =
        THEME_TOGGLE_SQUARE_POSITIONS[squareIndex] ||
        THEME_TOGGLE_SQUARE_POSITIONS[0];
      if (squareDot && squareDot.style) {
        squareDot.style.setProperty("--mpr-theme-square-col", String(position.col));
        squareDot.style.setProperty("--mpr-theme-square-row", String(position.row));
      }
      controlElement.setAttribute("data-square-index", String(squareIndex));
      controlElement.setAttribute("data-square-mode", resolvedModeValue);
      if (squareGrid && typeof squareGrid.setAttribute === "function") {
        squareGrid.setAttribute("data-square-active", String(squareIndex));
      }
      if (squareQuads.length) {
        for (var idx = 0; idx < squareQuads.length; idx += 1) {
          if (squareQuads[idx] && squareQuads[idx].classList) {
            squareQuads[idx].classList.toggle("is-active", idx === squareIndex);
          } else if (squareQuads[idx] && typeof squareQuads[idx].setAttribute === "function") {
            squareQuads[idx].setAttribute("data-square-active", idx === squareIndex ? "true" : "false");
          }
        }
      }
      var activeModeIndex = getThemeToggleModeIndex(currentModes, resolvedModeValue);
      var activeMode = activeModeIndex === -1 ? null : currentModes[activeModeIndex];
      var contrast = activeMode && activeMode.attributeValue === "dark" ? "light" : "dark";
      if (squareDot && typeof squareDot.setAttribute === "function") {
        squareDot.setAttribute("data-contrast", contrast);
      }
      controlElement.setAttribute(
        "aria-label",
        (config.ariaLabel || config.label || "Toggle theme") + " — " + resolvedModeValue,
      );
    }

    function syncToggleUi(modeValue) {
      var modeIndex = getThemeToggleModeIndex(currentModes, modeValue);
      var resolvedMode = modeIndex === -1 && currentModes.length ? currentModes[0].value : modeValue;
      if (modeIndex === -1 && currentModes.length) {
        modeIndex = 0;
      }
      hostElement.setAttribute("data-mpr-theme-mode", resolvedMode);
      controlElement.setAttribute("data-mpr-theme-mode", resolvedMode);
      if (variant === "button") {
        controlElement.setAttribute(
          "aria-pressed",
          modeIndex === 1 ? "true" : "false",
        );
        if (iconElement) {
          var iconSymbol = config.icons.unknown;
          if (resolvedMode === "light") {
            iconSymbol = config.icons.light;
          } else if (resolvedMode === "dark") {
            iconSymbol = config.icons.dark;
          }
          iconElement.textContent = iconSymbol;
        }
        return;
      }
      if (variant === "square") {
        syncSquareUi(resolvedMode);
        return;
      }
      var checked = modeIndex > 0;
      controlElement.checked = checked;
      controlElement.setAttribute("aria-checked", checked ? "true" : "false");
    }

    function resolveNextSwitchMode(currentValue) {
      if (variant !== "switch") {
        return resolveNextThemeToggleMode(currentModes, currentValue);
      }
      var currentIndex = getThemeToggleModeIndex(currentModes, currentValue);
      if (currentIndex !== -1) {
        return resolveNextThemeToggleMode(currentModes, currentValue);
      }
      var normalizedIndex = getThemeToggleModeIndex(normalizedModes, currentValue);
      if (normalizedIndex === -1) {
        return currentModes.length ? currentModes[0].value : currentValue;
      }
      var activeMode = normalizedModes[normalizedIndex];
      var activePolarity = resolveThemeModePolarity(activeMode);
      if (!activePolarity) {
        return resolveNextThemeToggleMode(currentModes, currentValue);
      }
      var targetPolarity = activePolarity === "dark" ? "light" : "dark";
      for (var modeIndex = 0; modeIndex < currentModes.length; modeIndex += 1) {
        var candidatePolarity = resolveThemeModePolarity(currentModes[modeIndex]);
        if (candidatePolarity === targetPolarity) {
          return currentModes[modeIndex].value;
        }
      }
      return resolveNextThemeToggleMode(currentModes, currentValue);
    }

    function handleActivation(eventObject) {
      if (
        variant === "button" &&
        eventObject &&
        typeof eventObject.preventDefault === "function"
      ) {
        eventObject.preventDefault();
      }
      var nextMode = resolveNextSwitchMode(themeManager.getMode());
      themeManager.setMode(nextMode, config.source || "theme-toggle");
    }

    function selectSquareMode(index, sourceSuffix) {
      if (variant !== "square" || !squareModeValues.length) {
        return;
      }
      var clampedIndex = index;
      if (clampedIndex < 0) {
        clampedIndex = 0;
      }
      if (clampedIndex >= squareModeValues.length) {
        clampedIndex = squareModeValues.length - 1;
      }
      var targetModeValue = squareModeValues[clampedIndex];
      if (!targetModeValue) {
        return;
      }
      var sourceLabel = config.source || "theme-toggle";
      if (sourceSuffix) {
        sourceLabel += sourceSuffix;
      }
      themeManager.setMode(targetModeValue, sourceLabel);
    }

    function resolveQuadrantIndex(eventObject) {
      if (
        !squareGrid ||
        typeof squareGrid.getBoundingClientRect !== "function" ||
        !squareModeValues.length
      ) {
        return null;
      }
      var rect = squareGrid.getBoundingClientRect();
      if (!rect || !rect.width || !rect.height) {
        return null;
      }
      var clientX = typeof eventObject.clientX === "number"
        ? eventObject.clientX
        : rect.left + rect.width / 2;
      var clientY = typeof eventObject.clientY === "number"
        ? eventObject.clientY
        : rect.top + rect.height / 2;
      var isRight = clientX - rect.left >= rect.width / 2;
      var isBottom = clientY - rect.top >= rect.height / 2;
      var candidateIndex = 0;
      if (!isBottom && !isRight) {
        candidateIndex = 0;
      } else if (!isBottom && isRight) {
        candidateIndex = 1;
      } else if (isBottom && !isRight) {
        candidateIndex = 2;
      } else {
        candidateIndex = 3;
      }
      if (candidateIndex >= squareModeValues.length) {
        candidateIndex = squareModeValues.length - 1;
      }
      if (candidateIndex < 0) {
        return null;
      }
      return candidateIndex;
    }

    function handleSquarePointer(eventObject) {
      if (!squareModeValues.length) {
        return;
      }
      if (eventObject && typeof eventObject.preventDefault === "function") {
        eventObject.preventDefault();
      }
      var targetIndex = resolveQuadrantIndex(eventObject);
      if (targetIndex === null) {
        var currentIndex = squareModeValues.indexOf(themeManager.getMode());
        var fallbackIndex = (currentIndex + 1) % squareModeValues.length;
        selectSquareMode(fallbackIndex, ":pointer");
        return;
      }
      selectSquareMode(targetIndex, ":pointer");
    }

    function handleSquareKey(eventObject) {
      if (
        !squareModeValues.length ||
        !eventObject ||
        typeof eventObject.key !== "string"
      ) {
        return;
      }
      var currentIndex = squareModeValues.indexOf(themeManager.getMode());
      if (currentIndex === -1) {
        currentIndex = 0;
      }
      if (eventObject.key === "ArrowRight" || eventObject.key === "ArrowDown") {
        eventObject.preventDefault();
        selectSquareMode((currentIndex + 1) % squareModeValues.length, ":key");
        return;
      }
      if (eventObject.key === "ArrowLeft" || eventObject.key === "ArrowUp") {
        eventObject.preventDefault();
        var previousIndex = currentIndex - 1;
        if (previousIndex < 0) {
          previousIndex = squareModeValues.length - 1;
        }
        selectSquareMode(previousIndex, ":key");
        return;
      }
      if (eventObject.key === " " || eventObject.key === "Enter") {
        eventObject.preventDefault();
        selectSquareMode((currentIndex + 1) % squareModeValues.length, ":key");
      }
    }

    if (variant === "square") {
      controlElement.addEventListener("click", handleSquarePointer);
      controlElement.addEventListener("keydown", handleSquareKey);
    } else {
      controlElement.addEventListener("click", handleActivation);
      if (variant === "switch") {
        controlElement.addEventListener("keydown", function handleToggleKey(event) {
          if (!event || typeof event.key !== "string") {
            return;
          }
          if (event.key === " " || event.key === "Enter") {
            handleActivation(event);
          }
        });
      }
    }

    syncToggleUi(themeManager.getMode());
    var unsubscribe = themeManager.on(function handleTheme(detail) {
      syncToggleUi(detail.mode);
    });
    return function cleanupThemeToggle() {
      if (rafId !== null && ownerWindow && typeof ownerWindow.cancelAnimationFrame === "function") {
        ownerWindow.cancelAnimationFrame(rafId);
      }
      if (travelTimeout !== null) {
        clearTimeout(travelTimeout);
      }
      if (variant === "switch" && controlElement && controlElement.style &&
        typeof controlElement.style.removeProperty === "function") {
        controlElement.style.removeProperty("--mpr-theme-toggle-travel");
      }
      if (variant === "switch" && ownerWindow && typeof ownerWindow.removeEventListener === "function" && travelResizeHandler) {
        ownerWindow.removeEventListener("resize", travelResizeHandler);
      }
      if (controlElement) {
        if (variant === "square") {
          controlElement.removeEventListener("click", handleSquarePointer);
          controlElement.removeEventListener("keydown", handleSquareKey);
        } else {
          controlElement.removeEventListener("click", handleActivation);
        }
      }
      unsubscribe();
    };
  }
function normalizeStandaloneThemeToggleOptions(rawOptions) {
    var base =
      rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var themeInput =
      base && typeof base.theme === "object" ? base.theme : {};
    var themeConfig = normalizeThemeToggleCore(themeInput, {
      enabled:
        base.enabled === undefined ? true : Boolean(base.enabled),
      ariaLabel:
        typeof base.ariaLabel === "string" && base.ariaLabel.trim()
          ? base.ariaLabel.trim()
          : "Toggle theme",
    });
    var displayConfig = normalizeThemeToggleDisplayOptions(
      Object.assign({}, base, {
        ariaLabel: themeConfig.ariaLabel,
        modes: themeConfig.modes,
      }),
    );
    return {
      component: displayConfig,
      theme: themeConfig,
    };
  }

  function mountThemeToggleComponent(hostElement, normalizedOptions, configureTheme, sourceLabel) {
    var toggleCleanup = null;

    function applyOptions(nextNormalized, label) {
      var effectiveLabel = label || "theme-toggle";
      if (configureTheme && nextNormalized.theme) {
        themeManager.configure({
          attribute: nextNormalized.theme.attribute,
          targets: nextNormalized.theme.targets,
          modes: nextNormalized.theme.modes,
        });
        if (
          nextNormalized.theme.initialMode &&
          nextNormalized.theme.initialMode !== themeManager.getMode()
        ) {
          themeManager.setMode(
            nextNormalized.theme.initialMode,
            effectiveLabel + ":init",
          );
        }
      }
      var displayOptions = deepMergeOptions({}, nextNormalized.component);
      if (nextNormalized.theme && nextNormalized.theme.modes) {
        displayOptions.modes = nextNormalized.theme.modes;
      }
      if (toggleCleanup) {
        toggleCleanup();
      }
      toggleCleanup = initializeThemeToggle(hostElement, displayOptions);
    }

    applyOptions(normalizedOptions, sourceLabel || "theme-toggle");

    return {
      update: function update(nextNormalized, label) {
        applyOptions(nextNormalized, label || "theme-toggle");
      },
      destroy: function destroy() {
        if (toggleCleanup) {
          toggleCleanup();
          toggleCleanup = null;
        }
      },
    };
  }

  function readHeaderOptionsFromDataset(rootElement) {
    if (!rootElement || !rootElement.dataset) {
      return {};
    }
    var dataset = rootElement.dataset;
    var options = {};
    if (dataset.brandLabel || dataset.brandHref) {
      options.brand = {
        label: dataset.brandLabel,
        href: dataset.brandHref,
      };
    }
    if (dataset.navLinks) {
      options.navLinks = parseJsonValue(dataset.navLinks, []);
    }
    if (dataset.horizontalLinks) {
      options.horizontalLinks = parseJsonValue(dataset.horizontalLinks, {});
    }
    if (dataset.authTransition !== undefined) {
      options.authTransition = parseHeaderAuthTransitionValue(
        dataset.authTransition,
      );
    }
    var datasetSettingsFlag = undefined;
    if (dataset.settingsEnabled !== undefined) {
      datasetSettingsFlag = dataset.settingsEnabled;
    }
    if (dataset.settingsLabel) {
      options.settings = options.settings || {};
      options.settings.label = dataset.settingsLabel;
    }
    if (datasetSettingsFlag !== undefined) {
      options.settings = options.settings || {};
      options.settings.enabled = String(datasetSettingsFlag).toLowerCase() === "true";
    }
    if (dataset.themeToggle) {
      options.themeToggle = parseJsonValue(dataset.themeToggle, {});
    }
    if (dataset.signOutLabel) {
      options.signOutLabel = dataset.signOutLabel;
    }
    if (dataset.signInRedirectUrl) {
      options.signInRedirectUrl = dataset.signInRedirectUrl;
    }
    if (dataset.profileLabel) {
      options.profileLabel = dataset.profileLabel;
    }
    if (dataset.logoutUrl) {
      options.userMenu = options.userMenu || {};
      options.userMenu.logoutUrl = dataset.logoutUrl;
    }
    if (dataset.userMenuDisplayMode) {
      options.userMenu = options.userMenu || {};
      options.userMenu.displayMode = dataset.userMenuDisplayMode;
    }
    if (dataset.userMenuAvatarUrl) {
      options.userMenu = options.userMenu || {};
      options.userMenu.avatarUrl = dataset.userMenuAvatarUrl;
    }
    if (dataset.userMenuAvatarLabel) {
      options.userMenu = options.userMenu || {};
      options.userMenu.avatarLabel = dataset.userMenuAvatarLabel;
    }
    if (dataset.sticky !== undefined) {
      options.sticky = normalizeBooleanAttribute(dataset.sticky, true);
    }
    if (dataset.size) {
      options.size = dataset.size;
    }
    return options;
  }

  var pendingGoogleInitializeQueue = [];
  var activeGoogleInitializeConfig = null;

  function recordGoogleInitializeConfig(config) {
    if (!config || typeof config !== "object") {
      return;
    }
    var clientId = normalizeGoogleSiteId(config.clientId);
    if (!clientId) {
      return;
    }
    var normalized = {
      client_id: clientId,
    };
    if (config.nonce) {
      normalized.nonce = String(config.nonce);
    }
    global.__googleInitConfig = normalized;
  }

  function enqueueGoogleInitialize(config) {
    if (!config || typeof config !== "object") {
      return;
    }
    recordGoogleInitializeConfig(config);
    pendingGoogleInitializeQueue.push(config);
  }

  function runGoogleInitializeQueue(googleClient) {
    if (
      !googleClient ||
      !googleClient.accounts ||
      !googleClient.accounts.id ||
      typeof googleClient.accounts.id.initialize !== "function"
    ) {
      return;
    }
    while (pendingGoogleInitializeQueue.length) {
      var config = pendingGoogleInitializeQueue.shift();
      if (!config) {
        continue;
      }
      if (
        activeGoogleInitializeConfig &&
        activeGoogleInitializeConfig.client === googleClient.accounts.id &&
        activeGoogleInitializeConfig.clientId === config.clientId &&
        activeGoogleInitializeConfig.nonce === config.nonce &&
        activeGoogleInitializeConfig.callback === config.callback
      ) {
        continue;
      }
      try {
        var initializeConfig = {
          client_id: config.clientId || undefined,
          callback: config.callback,
          auto_select: false,
          ux_mode: "popup",
          use_fedcm_for_button: false,
        };
        if (config.nonce) {
          initializeConfig.nonce = config.nonce;
        }
        googleClient.accounts.id.initialize(initializeConfig);
        currentGoogleNonceToken = config.nonce;
        activeGoogleInitializeConfig = {
          client: googleClient.accounts.id,
          clientId: config.clientId,
          nonce: config.nonce,
          callback: config.callback,
        };
      } catch (error) {
        if (typeof config.onError === "function") {
          config.onError(error);
        }
      }
    }
  }

  function ensureGoogleIdentityClient(documentObject) {
    if (
      global.google &&
      global.google.accounts &&
      global.google.accounts.id &&
      typeof global.google.accounts.id.renderButton === "function"
    ) {
      runGoogleInitializeQueue(global.google);
      return Promise.resolve(global.google);
    }
    if (googleIdentityPromise) {
      return googleIdentityPromise;
    }
    if (
      !documentObject ||
      !documentObject.head ||
      typeof documentObject.createElement !== "function"
    ) {
      return Promise.reject(new Error("google_identity_unavailable"));
    }
    googleIdentityPromise = new Promise(function loadGoogleIdentity(resolve, reject) {
      var scriptElement = documentObject.createElement("script");
      var resolved = false;
      scriptElement.src = GOOGLE_IDENTITY_SCRIPT_URL;
      scriptElement.async = true;
      scriptElement.defer = true;
      scriptElement.onload = function handleGoogleIdentityLoad() {
        resolved = true;
        if (global.google) {
          runGoogleInitializeQueue(global.google);
        }
        resolve(global.google || null);
      };
      scriptElement.onerror = function handleGoogleIdentityError() {
        if (!resolved) {
          reject(new Error("google_identity_script_failed"));
        }
      };
      documentObject.head.appendChild(scriptElement);
    });
    return googleIdentityPromise;
  }

  function createAuthHeader(rootElement, rawOptions) {
    if (!rootElement || typeof rootElement.dispatchEvent !== "function") {
      throw new Error("MPRUI.createAuthHeader requires a DOM element");
    }

    function normalizeAuthControllerOptions(optionsInput) {
      return createAuthOptions(optionsInput);
    }

    function authControllerOptionsMatch(leftOptions, rightOptions) {
      if (!leftOptions || !rightOptions) {
        return false;
      }
      return (
        leftOptions.tauthUrl === rightOptions.tauthUrl &&
        leftOptions.logoutPath === rightOptions.logoutPath &&
        leftOptions.sessionPath === rightOptions.sessionPath &&
        leftOptions.tenantId === rightOptions.tenantId &&
        JSON.stringify(leftOptions.providers) === JSON.stringify(rightOptions.providers) &&
        JSON.stringify(leftOptions.password) === JSON.stringify(rightOptions.password) &&
        JSON.stringify(leftOptions.account) === JSON.stringify(rightOptions.account)
      );
    }

    var options = normalizeAuthControllerOptions(rawOptions);
    /** @type {{ status: string, profile: object | null, options: AuthOptions }} */
    var state = {
      status: AUTH_CONTROLLER_STATUS.UNAUTHENTICATED,
      profile: null,
      options: options,
    };
    var pendingProfile = null;
    var hasEmittedUnauthenticated = false;
    var lastAuthenticatedSignature = null;
    var nonceRequestPromise = null;
    var appleSignInAttemptPromise = null;
    var appleSignInHintOptions = null;
    var authSignalVersion = 0;
    var lifecycleVersion = 0;
    var isDestroyed = false;
    var hasCompletedInitialBootstrap = false;
    var sessionSyncWindowTarget = null;
    var sessionSyncDocumentTarget = null;

    function isCurrentLifecycleVersion(candidateVersion) {
      return candidateVersion === lifecycleVersion;
    }

    function invalidateAuthLifecycle() {
      lifecycleVersion += 1;
    }

    function requireCurrentAuthRecoveryLifecycle(candidateVersion) {
      if (!isDestroyed && isCurrentLifecycleVersion(candidateVersion)) {
        return;
      }
      throw createAuthRecoveryError(
        AUTH_RECOVERY_LIFECYCLE_CHANGED_ERROR_CODE,
        "Authenticated fetch recovery belongs to an obsolete auth controller lifecycle",
      );
    }

    function assertStableTenantId(nextOptions) {
      if (nextOptions.tenantId === options.tenantId) {
        return;
      }
      throw createAuthTenantIdChangeError(options.tenantId, nextOptions.tenantId);
    }

    function configureTenantId() {
      if (typeof global.setAuthTenantId === "function") {
        global.setAuthTenantId(options.tenantId);
      }
    }

    function resolveAuthBaseUrl() {
      if (typeof options.tauthUrl === "string") {
        var trimmedBaseUrl = options.tauthUrl.trim();
        if (trimmedBaseUrl) {
          return trimmedBaseUrl;
        }
      }
      if (
        global.location &&
        typeof global.location.origin === "string" &&
        global.location.origin.trim() &&
        global.location.origin !== "null"
      ) {
        return global.location.origin;
      }
      return "";
    }

    function withTenantHeader(headers) {
      return withTenantHeaderValue(options.tenantId, headers);
    }

    function handleSessionFocus() {
      if (isDestroyed) {
        return;
      }
      bootstrapSession();
    }

    function handleSessionVisibilityChange() {
      if (isDestroyed) {
        return;
      }
      if (
        sessionSyncDocumentTarget &&
        typeof sessionSyncDocumentTarget.hidden === "boolean" &&
        sessionSyncDocumentTarget.hidden
      ) {
        return;
      }
      bootstrapSession();
    }

    function attachSessionSyncListeners() {
      if (
        !hasConfiguredAuthSessionPath(options) ||
        (typeof global.initAuthClient === "function" &&
          usesDefaultAuthSessionPath(options))
      ) {
        return;
      }
      if (
        !sessionSyncWindowTarget &&
        global.window &&
        typeof global.window.addEventListener === "function"
      ) {
        sessionSyncWindowTarget = global.window;
        sessionSyncWindowTarget.addEventListener("focus", handleSessionFocus);
      }
      if (
        !sessionSyncDocumentTarget &&
        global.document &&
        typeof global.document.addEventListener === "function"
      ) {
        sessionSyncDocumentTarget = global.document;
        sessionSyncDocumentTarget.addEventListener(
          "visibilitychange",
          handleSessionVisibilityChange,
        );
      }
    }

    function detachSessionSyncListeners() {
      if (
        sessionSyncWindowTarget &&
        typeof sessionSyncWindowTarget.removeEventListener === "function"
      ) {
        sessionSyncWindowTarget.removeEventListener("focus", handleSessionFocus);
      }
      if (
        sessionSyncDocumentTarget &&
        typeof sessionSyncDocumentTarget.removeEventListener === "function"
      ) {
        sessionSyncDocumentTarget.removeEventListener(
          "visibilitychange",
          handleSessionVisibilityChange,
        );
      }
      sessionSyncWindowTarget = null;
      sessionSyncDocumentTarget = null;
    }

    function requestNonceTokenWithFetch() {
      var googleProvider = options.providers.google;
      if (!googleProvider.enabled) {
        return Promise.reject(
          createAuthConfigError(
            AUTH_CONFIG_ERROR_CODES.PROVIDER_DISABLED,
            "Google authentication is disabled",
          ),
        );
      }
      return global
        .fetch(joinUrl(options.tauthUrl, googleProvider.noncePath), {
          method: "POST",
          credentials: "include",
          headers: withTenantHeader({
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
          }),
        })
        .then(function (response) {
          if (!response || typeof response.json !== "function") {
            throw new Error("invalid response from nonce endpoint");
          }
          if (!response.ok) {
            /** @type {MprUiError} */
            var nonceError = new Error("nonce issuance failed");
            nonceError.status = response.status;
            throw nonceError;
          }
          return response.json();
        })
        .then(function (payload) {
          var nonceToken =
            payload && payload.nonce ? String(payload.nonce) : "";
          if (!nonceToken) {
            throw new Error("nonce payload missing");
          }
          return nonceToken;
        });
    }

    function requestNonceToken() {
      configureTenantId();
      if (nonceRequestPromise) {
        return nonceRequestPromise;
      }
      nonceRequestPromise = Promise.resolve()
        .then(function () {
          if (typeof global.requestNonce === "function") {
            return Promise.resolve(global.requestNonce()).catch(function (error) {
              if (shouldFallbackToFetch(error)) {
                return requestNonceTokenWithFetch();
              }
              throw error;
            });
          }
          return requestNonceTokenWithFetch();
        })
        .finally(function () {
          nonceRequestPromise = null;
        });
      return nonceRequestPromise;
    }

    function configureGoogleIdentityClient(nonceToken, credentialHandler) {
      var googleProvider = options.providers.google;
      var clientIdValue = googleProvider.enabled
        ? normalizeGoogleSiteId(googleProvider.clientId)
        : null;
      var currentLifecycleVersion = lifecycleVersion;
      if (!clientIdValue) {
        throw createGoogleSiteIdError();
      }
      if (!nonceToken) {
        throw new Error("mpr-ui.auth.missing_nonce");
      }
      var initializeError = null;
      enqueueGoogleInitialize({
        clientId: clientIdValue,
        nonce: nonceToken,
        callback: credentialHandler === dispatchGoogleProviderCredential
          ? dispatchGoogleProviderCredential
          : function (payload) {
              if (!isCurrentLifecycleVersion(currentLifecycleVersion)) {
                return;
              }
              if (typeof credentialHandler === "function") {
                return credentialHandler(payload, nonceToken);
              }
              return handleCredential(payload, nonceToken);
            },
        onError: function handleGoogleInitializeError(error) {
          initializeError = error || new Error("google identity initialize failed");
        },
      });
      return ensureGoogleIdentityClient(global.document)
        .then(function initializeGoogleClient(googleClient) {
          runGoogleInitializeQueue(googleClient);
          if (initializeError) {
            throw initializeError;
          }
          if (!isCurrentLifecycleVersion(currentLifecycleVersion)) {
            throw new Error("mpr-ui.auth.stale_google_identity");
          }
          return null;
        });
    }

    function prepareGoogleNonce(credentialHandler) {
      var currentLifecycleVersion = lifecycleVersion;
      return requestNonceToken()
        .then(function configureNonceBoundGoogleClient(nonceToken) {
          if (!isCurrentLifecycleVersion(currentLifecycleVersion)) {
            throw new Error("mpr-ui.auth.stale_google_identity");
          }
          return configureGoogleIdentityClient(nonceToken, credentialHandler).then(function () {
            return nonceToken;
          });
        });
    }

    function prepareAppleSignIn() {
      return buildAppleProviderAction(options);
    }

    function startAppleSignIn() {
      if (appleSignInAttemptPromise) {
        return appleSignInAttemptPromise;
      }
      var currentLifecycleVersion = lifecycleVersion;
      var providerAction = prepareAppleSignIn();
      appleSignInHintOptions = options;
      rememberAuthRestoreHint(options);
      updateAuthStatus(AUTH_CONTROLLER_STATUS.AUTHENTICATING, {
        source: "redirect-provider",
        provider: AUTH_PROVIDER_IDS.APPLE,
      });
      appleSignInAttemptPromise = Promise.resolve().then(function navigateToApple() {
        if (isDestroyed || !isCurrentLifecycleVersion(currentLifecycleVersion)) {
          throw createAuthConfigError(
            AUTH_CONFIG_ERROR_CODES.REDIRECT_LIFECYCLE_CHANGED,
            "Apple sign-in belongs to an obsolete auth controller lifecycle",
          );
        }
        if (!global.location || typeof global.location.assign !== "function") {
          throw createAuthConfigError(
            AUTH_CONFIG_ERROR_CODES.REDIRECT_NAVIGATION_UNAVAILABLE,
            "Apple sign-in requires top-level navigation",
          );
        }
        global.location.assign(providerAction.url);
        return providerAction;
      }).catch(function handleAppleSignInFailure(error) {
        if (appleSignInHintOptions) {
          clearAuthRestoreHint(appleSignInHintOptions);
        }
        if (
          !isDestroyed &&
          isCurrentLifecycleVersion(currentLifecycleVersion) &&
          (!error || error.code !== AUTH_CONFIG_ERROR_CODES.REDIRECT_LIFECYCLE_CHANGED)
        ) {
          emitError(
            error && error.code
              ? error.code
              : AUTH_CONFIG_ERROR_CODES.REDIRECT_NAVIGATION_UNAVAILABLE,
            { message: error && error.message ? error.message : String(error) },
          );
          markUnauthenticated();
        }
        throw error;
      }).finally(function clearAppleSignInAttempt() {
        appleSignInHintOptions = null;
        appleSignInAttemptPromise = null;
      });
      return appleSignInAttemptPromise;
    }

    function updateDatasetFromProfile(profile) {
      Object.keys(ATTRIBUTE_MAP).forEach(function (key) {
        var attributeName = ATTRIBUTE_MAP[key];
        setAttributeOrRemove(
          rootElement,
          attributeName,
          profile ? profile[key] : null,
        );
      });
    }

    function updateAuthStatus(nextStatus, extraDetail) {
      if (typeof nextStatus !== "string" || !nextStatus) {
        return;
      }
      var previousStatus = state.status;
      state.status = nextStatus;
      setAttributeOrRemove(rootElement, "data-mpr-auth-status", nextStatus);
      if (previousStatus === nextStatus) {
        return;
      }
      dispatchEvent(rootElement, "mpr-ui:auth:status-change", Object.assign({
        status: nextStatus,
        previousStatus: previousStatus,
        profile: state.profile,
      }, extraDetail || {}));
    }

    function markAuthenticated(profile) {
      if (!profile || typeof profile !== "object") {
        emitError("mpr-ui.auth.invalid_profile", {
          message: "markAuthenticated called without valid profile",
        });
        markUnauthenticated();
        return;
      }
      var signature = JSON.stringify(profile);
      var shouldEmit =
        state.status !== AUTH_CONTROLLER_STATUS.AUTHENTICATED ||
        lastAuthenticatedSignature !== signature;
      state.profile = profile;
      lastAuthenticatedSignature = signature;
      hasEmittedUnauthenticated = false;
      rememberAuthRestoreHint(options);
      updateDatasetFromProfile(profile);
      updateAuthStatus(AUTH_CONTROLLER_STATUS.AUTHENTICATED);
      if (shouldEmit) {
        dispatchEvent(rootElement, "mpr-ui:auth:authenticated", {
          profile: profile,
        });
      }
    }

    function markUnauthenticated(config) {
      var parameters = config || {};
      var emit = parameters.emit !== false;
      var shouldEmit =
        emit &&
        (state.status !== AUTH_CONTROLLER_STATUS.UNAUTHENTICATED ||
          state.profile !== null ||
          !hasEmittedUnauthenticated);
      state.profile = null;
      lastAuthenticatedSignature = null;
      updateDatasetFromProfile(null);
      updateAuthStatus(AUTH_CONTROLLER_STATUS.UNAUTHENTICATED);
      if (shouldEmit) {
        dispatchEvent(rootElement, "mpr-ui:auth:unauthenticated", {
          profile: null,
        });
        hasEmittedUnauthenticated = true;
      }
    }

    function emitError(code, extra) {
      dispatchEvent(
        rootElement,
        "mpr-ui:auth:error",
        Object.assign({ code: code }, extra || {}),
      );
    }

    function requestCurrentProfile() {
      configureTenantId();
      return requestCurrentProfileFromRuntime(options);
    }

    function handleAuthenticatedCallback(profile) {
      if (isDestroyed) {
        return;
      }
      authSignalVersion += 1;
      var resolvedProfile = profile || pendingProfile || null;
      if (profile && pendingProfile) {
        resolvedProfile = Object.assign({}, pendingProfile, profile);
      }
      pendingProfile = null;
      markAuthenticated(resolvedProfile);
    }

    function handleUnauthenticatedCallback() {
      if (isDestroyed) {
        return;
      }
      authSignalVersion += 1;
      pendingProfile = null;
      markUnauthenticated();
    }

    function bootstrapSession() {
      if (isDestroyed) {
        return Promise.resolve();
      }
      var currentLifecycleVersion = lifecycleVersion;
      if (
        !hasCompletedInitialBootstrap &&
        state.status !== AUTH_CONTROLLER_STATUS.AUTHENTICATED
      ) {
        updateAuthStatus(AUTH_CONTROLLER_STATUS.BOOTSTRAPPING);
      }
      configureTenantId();
      attachSessionSyncListeners();
      function runBootstrapAttempt(attempt) {
        if (!isCurrentLifecycleVersion(currentLifecycleVersion)) {
          return Promise.resolve();
        }
        var bootstrapAuthSignalVersion = authSignalVersion;
        var bootstrapPromise = Promise.resolve();
        if (
          typeof global.initAuthClient === "function" &&
          usesDefaultAuthSessionPath(options)
        ) {
          var resolvedBaseUrl = resolveAuthBaseUrl();
          bootstrapPromise = Promise.resolve(
            global.initAuthClient({
              baseUrl: resolvedBaseUrl,
              bootstrapMode: AUTH_BOOTSTRAP_RESTORE_IF_HINTED,
              tenantId: options.tenantId,
              onAuthenticated: handleAuthenticatedCallback,
              onUnauthenticated: handleUnauthenticatedCallback,
            }),
          );
        }
        return bootstrapPromise.then(function reconcileCurrentProfile() {
          if (!isCurrentLifecycleVersion(currentLifecycleVersion)) {
            return null;
          }
          if (
            authSignalVersion !== bootstrapAuthSignalVersion ||
            state.status === AUTH_CONTROLLER_STATUS.AUTHENTICATED
          ) {
            return null;
          }
          return requestCurrentProfile();
        })
        .then(function applyRecoveredProfile(profile) {
          if (!isCurrentLifecycleVersion(currentLifecycleVersion)) {
            return;
          }
          if (
            authSignalVersion !== bootstrapAuthSignalVersion ||
            state.status === AUTH_CONTROLLER_STATUS.AUTHENTICATED
          ) {
            return;
          }
          if (profile) {
            markAuthenticated(profile);
            return;
          }
          markUnauthenticated({ emit: false });
        })
        .catch(function handleSessionVerificationFailure(error) {
          if (!isCurrentLifecycleVersion(currentLifecycleVersion)) {
            return;
          }
          if (!isRetryableAuthSessionError(error)) {
            clearAuthRestoreHint(options);
            markUnauthenticated({ emit: false });
            emitError("mpr-ui.auth.bootstrap_failed", {
              message: error && error.message ? error.message : String(error),
              status:
                error && typeof error.status === "number"
                  ? error.status
                  : null,
            });
            return;
          }
          updateAuthStatus(AUTH_CONTROLLER_STATUS.BOOTSTRAPPING, {
            source: "session-verification",
          });
          return waitForAuthSessionRetry(attempt).then(function retryBootstrap() {
            return runBootstrapAttempt(attempt + 1);
          });
        });
      }
      return runBootstrapAttempt(0).then(function finalizeBootstrapSession() {
          if (!isCurrentLifecycleVersion(currentLifecycleVersion)) {
            return;
          }
          hasCompletedInitialBootstrap = true;
        });
    }

    function exchangeCredentialWithFetch(credential, nonceToken) {
      var googleProvider = options.providers.google;
      if (!googleProvider.enabled) {
        return Promise.reject(
          createAuthConfigError(
            AUTH_CONFIG_ERROR_CODES.PROVIDER_DISABLED,
            "Google authentication is disabled",
          ),
        );
      }
      var payload = JSON.stringify({
        google_id_token: credential,
        nonce_token: nonceToken,
      });
      return global
        .fetch(joinUrl(options.tauthUrl, googleProvider.loginPath), {
          method: "POST",
          credentials: "include",
          headers: withTenantHeader({
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
          }),
          body: payload,
        })
        .then(function (response) {
          if (!response || typeof response.json !== "function") {
            throw new Error("invalid response from credential exchange");
          }
          if (!response.ok) {
            /** @type {MprUiError} */
            var errorObject = new Error("credential exchange failed");
            errorObject.status = response.status;
            throw errorObject;
          }
          return response.json();
        });
    }

    function exchangeCredential(credential, nonceToken) {
      if (!nonceToken) {
        return Promise.reject(new Error("mpr-ui.auth.missing_nonce"));
      }
      configureTenantId();
      if (typeof global.exchangeGoogleCredential === "function") {
        return Promise.resolve(
          global.exchangeGoogleCredential({
            credential: credential,
            nonceToken: nonceToken,
          }),
        ).catch(function (error) {
          if (shouldFallbackToFetch(error)) {
            return exchangeCredentialWithFetch(credential, nonceToken);
          }
          throw error;
        });
      }
      return exchangeCredentialWithFetch(credential, nonceToken);
    }

    function createTAuthActionError(code, message, status) {
      /** @type {MprUiError} */
      var actionError = new Error(message);
      actionError.code = code;
      if (typeof status === "number") {
        actionError.status = status;
      }
      return actionError;
    }

    function requireActionString(request, key, code) {
      var value = request && typeof request === "object" ? request[key] : null;
      if (typeof value !== "string" || value.trim() === "") {
        throw createTAuthActionError(code, key + " is required");
      }
      return value;
    }

    function readTAuthActionPayload(response, failureCode, acceptsNoContent) {
      if (acceptsNoContent && response && response.status === 204) {
        return Promise.resolve(null);
      }
      if (!response || typeof response.json !== "function") {
        return Promise.reject(
          createTAuthActionError(failureCode, "TAuth returned an invalid response"),
        );
      }
      return response.json().catch(function invalidActionPayload() {
        throw createTAuthActionError(
          failureCode,
          "TAuth returned an invalid JSON response",
          response.status,
        );
      });
    }

    function postTAuthAction(path, requestBody, failureCode, acceptsNoContent) {
      var requestLifecycleVersion = lifecycleVersion;
      configureTenantId();
      if (typeof global.fetch !== "function") {
        return Promise.reject(
          createTAuthActionError(
            "mpr-ui.auth.fetch_unavailable",
            "TAuth actions require the Fetch API",
          ),
        );
      }
      return global.fetch(joinUrl(options.tauthUrl, path), {
        method: "POST",
        credentials: "include",
        headers: withTenantHeader({
          "Content-Type": "application/json",
          "X-Requested-With": REQUESTED_WITH_HEADER,
        }),
        body: requestBody === null ? undefined : JSON.stringify(requestBody),
      }).then(function parseTAuthActionResponse(response) {
        return readTAuthActionPayload(
          response,
          failureCode,
          acceptsNoContent,
        ).then(function validateTAuthActionResponse(payload) {
          requireCurrentAuthRecoveryLifecycle(requestLifecycleVersion);
          if (!response.ok) {
            var responseCode =
              payload && typeof payload.error === "string"
                ? payload.error
                : failureCode;
            throw createTAuthActionError(
              responseCode,
              "TAuth action failed",
              response.status,
            );
          }
          if (!acceptsNoContent && (!payload || typeof payload !== "object")) {
            throw createTAuthActionError(
              failureCode,
              "TAuth action returned an invalid payload",
              response.status,
            );
          }
          return payload;
        });
      });
    }

    /**
     * @param {PasswordAuthAction|AccountAuthAction} action
     * @param {object|null} payload
     * @returns {NormalizedAuthActionResult}
     */
    function safeChallengeResult(action, payload) {
      return Object.freeze({
        action: action,
        status:
          payload && typeof payload.status === "string"
            ? payload.status
            : "accepted",
        expiresUnix:
          payload && typeof payload.expires_unix === "number"
            ? payload.expires_unix
            : null,
      });
    }

    /**
     * @param {PasswordAuthAction} action
     * @param {PasswordActionRequest} request
     * @returns {Promise<NormalizedAuthActionResult>}
     */
    function performPasswordAction(action, request) {
      if (!options.providers.password.enabled || !options.password) {
        return Promise.reject(
          createAuthConfigError(
            AUTH_CONFIG_ERROR_CODES.PROVIDER_DISABLED,
            "Password authentication is not configured",
          ),
        );
      }
      var actionDefinitions = {
        login: {
          path: options.password.loginPath,
          body: function createLoginBody() {
            return {
              email: requireActionString(request, "email", "mpr-ui.auth.email_required"),
              password: requireActionString(request, "password", "mpr-ui.auth.password_required"),
            };
          },
          profile: true,
          failureCode: "mpr-ui.auth.password_login_failed",
        },
        signup: {
          path: options.password.signupPath,
          body: function createSignupBody() {
            return {
              email: requireActionString(request, "email", "mpr-ui.auth.email_required"),
              password: requireActionString(request, "password", "mpr-ui.auth.password_required"),
              display_name: "",
              avatar_url: "",
            };
          },
          profile: false,
          failureCode: "mpr-ui.auth.password_signup_failed",
        },
        "verify-email": {
          path: options.password.verifyEmailPath,
          body: function createVerifyEmailBody() {
            return {
              token: requireActionString(request, "token", "mpr-ui.auth.challenge_required"),
            };
          },
          profile: true,
          failureCode: "mpr-ui.auth.password_verify_failed",
        },
        "reset-start": {
          path: options.password.resetStartPath,
          body: function createResetStartBody() {
            return {
              email: requireActionString(request, "email", "mpr-ui.auth.email_required"),
            };
          },
          profile: false,
          failureCode: "mpr-ui.auth.password_reset_start_failed",
        },
        "reset-complete": {
          path: options.password.resetCompletePath,
          body: function createResetCompleteBody() {
            return {
              token: requireActionString(request, "token", "mpr-ui.auth.challenge_required"),
              password: requireActionString(request, "password", "mpr-ui.auth.password_required"),
            };
          },
          profile: true,
          failureCode: "mpr-ui.auth.password_reset_complete_failed",
        },
      };
      var definition = actionDefinitions[action];
      if (!definition) {
        return Promise.reject(
          createTAuthActionError(
            "mpr-ui.auth.password_action_invalid",
            "Password action is invalid",
          ),
        );
      }
      var requestBody;
      try {
        requestBody = definition.body();
      } catch (error) {
        return Promise.reject(error);
      }
      if (definition.profile) {
        updateAuthStatus(AUTH_CONTROLLER_STATUS.AUTHENTICATING, {
          source: "password",
          action: action,
        });
      }
      return postTAuthAction(
        definition.path,
        requestBody,
        definition.failureCode,
        false,
      ).then(function applyPasswordAction(payload) {
        if (definition.profile) {
          markAuthenticated(payload);
          return Object.freeze({ action: action, status: "authenticated" });
        }
        var publicChallengeResult = safeChallengeResult(action, payload);
        dispatchEvent(
          rootElement,
          "mpr-ui:account:challenge-issued",
          publicChallengeResult,
        );
        return publicChallengeResult;
      }).catch(function handlePasswordActionFailure(error) {
        if (error && error.code === AUTH_RECOVERY_LIFECYCLE_CHANGED_ERROR_CODE) {
          throw error;
        }
        emitError(
          error && error.code ? error.code : definition.failureCode,
          {
            action: action,
            status: error && typeof error.status === "number" ? error.status : null,
          },
        );
        if (definition.profile && state.status !== AUTH_CONTROLLER_STATUS.AUTHENTICATED) {
          markUnauthenticated();
        }
        throw error;
      });
    }

    /**
     * @param {AccountAuthAction} action
     * @param {AccountActionRequest} request
     * @returns {Promise<NormalizedAuthActionResult>}
     */
    function performAccountAction(action, request) {
      if (!options.account) {
        return Promise.reject(
          createAuthConfigError(
            AUTH_CONFIG_ERROR_CODES.VALUE_REQUIRED,
            "Account management endpoints are not configured",
          ),
        );
      }
      if (state.status !== AUTH_CONTROLLER_STATUS.AUTHENTICATED || !state.profile) {
        return Promise.reject(
          createTAuthActionError(
            "mpr-ui.auth.authenticated_state_required",
            "Account management requires an authenticated session",
          ),
        );
      }
      var actionDefinitions = {
        "password-change": {
          path: options.account.passwordChangePath,
          body: function createPasswordChangeBody() {
            return {
              current_password: requireActionString(
                request,
                "currentPassword",
                "mpr-ui.auth.current_password_required",
              ),
              new_password: requireActionString(
                request,
                "newPassword",
                "mpr-ui.auth.new_password_required",
              ),
            };
          },
          challenge: false,
          failureCode: "mpr-ui.account.password_change_failed",
        },
        "password-link-start": {
          path: options.account.passwordLinkStartPath,
          body: function createPasswordLinkStartBody() {
            return {
              email: requireActionString(request, "email", "mpr-ui.auth.email_required"),
              password: requireActionString(request, "password", "mpr-ui.auth.password_required"),
              display_name: "",
              avatar_url: "",
            };
          },
          challenge: true,
          failureCode: "mpr-ui.account.password_link_start_failed",
        },
        "password-link-verify": {
          path: options.account.passwordLinkVerifyPath,
          body: function createPasswordLinkVerifyBody() {
            return {
              token: requireActionString(request, "token", "mpr-ui.auth.challenge_required"),
            };
          },
          challenge: false,
          failureCode: "mpr-ui.account.password_link_verify_failed",
        },
        "google-link": {
          path: options.account.googleLinkPath,
          body: function createGoogleLinkBody() {
            return {
              google_id_token: requireActionString(
                request,
                "credential",
                "mpr-ui.auth.missing_credential",
              ),
              nonce_token: requireActionString(
                request,
                "nonceToken",
                "mpr-ui.auth.missing_nonce",
              ),
            };
          },
          challenge: false,
          failureCode: "mpr-ui.account.google_link_failed",
        },
        unlink: {
          path: options.account.unlinkPath,
          body: function createUnlinkBody() {
            return {
              provider: requireActionString(request, "provider", "mpr-ui.account.provider_required"),
              provider_id: requireActionString(request, "providerId", "mpr-ui.account.provider_id_required"),
            };
          },
          challenge: false,
          failureCode: "mpr-ui.account.unlink_failed",
        },
        disable: {
          path: options.account.disablePath,
          body: function createDisableBody() {
            return null;
          },
          challenge: false,
          disable: true,
          failureCode: "mpr-ui.account.disable_failed",
        },
      };
      var definition = actionDefinitions[action];
      if (!definition) {
        return Promise.reject(
          createTAuthActionError(
            "mpr-ui.account.action_invalid",
            "Account action is invalid",
          ),
        );
      }
      var requestBody;
      try {
        requestBody = definition.body();
      } catch (error) {
        return Promise.reject(error);
      }
      return postTAuthAction(
        definition.path,
        requestBody,
        definition.failureCode,
        definition.disable === true,
      ).then(function applyAccountAction(payload) {
        if (definition.disable) {
          clearAuthRestoreHint(options);
          markUnauthenticated();
          var disabledResult = Object.freeze({ action: action, status: "disabled" });
          dispatchEvent(rootElement, "mpr-ui:account:disabled", disabledResult);
          return disabledResult;
        }
        if (definition.challenge) {
          var publicChallengeResult = safeChallengeResult(action, payload);
          dispatchEvent(
            rootElement,
            "mpr-ui:account:challenge-issued",
            publicChallengeResult,
          );
          return publicChallengeResult;
        }
        markAuthenticated(payload);
        var updatedResult = Object.freeze({ action: action, status: "updated" });
        dispatchEvent(rootElement, "mpr-ui:account:updated", updatedResult);
        return updatedResult;
      }).catch(function handleAccountActionFailure(error) {
        if (error && error.code === AUTH_RECOVERY_LIFECYCLE_CHANGED_ERROR_CODE) {
          throw error;
        }
        emitError(
          error && error.code ? error.code : definition.failureCode,
          {
            action: action,
            status: error && typeof error.status === "number" ? error.status : null,
          },
        );
        throw error;
      });
    }

    function startGoogleLink(credentialResponse, nonceToken) {
      if (!options.providers.google.enabled || !options.account) {
        return Promise.reject(
          createAuthConfigError(
            AUTH_CONFIG_ERROR_CODES.PROVIDER_DISABLED,
            "Google account linking is not configured",
          ),
        );
      }
      if (!credentialResponse || !credentialResponse.credential) {
        return Promise.reject(
          createTAuthActionError(
            "mpr-ui.auth.missing_credential",
            "Google account linking did not return a credential",
          ),
        );
      }
      return performAccountAction("google-link", {
        credential: credentialResponse.credential,
        nonceToken: nonceToken,
      });
    }

    /**
     * @param {{ scope: string, generation: number }} observedRecovery
     * @param {number} recoveryLifecycleVersion
     * @returns {Promise<AuthRecoveryResult>}
     */
    function recoverSessionAfterUnauthorized(
      observedRecovery,
      recoveryLifecycleVersion,
    ) {
      requireCurrentAuthRecoveryLifecycle(recoveryLifecycleVersion);
      updateAuthStatus(AUTH_CONTROLLER_STATUS.AUTHENTICATING, {
        source: "session-recovery",
      });
      return coordinateAuthSessionRecovery(options, observedRecovery)
        .then(function applySessionRecoveryResult(result) {
          requireCurrentAuthRecoveryLifecycle(recoveryLifecycleVersion);
          if (result.status === "authenticated") {
            markAuthenticated(result.profile || state.profile);
            return result;
          }
          if (result.status === "unauthenticated") {
            clearAuthRestoreHint(options);
            markUnauthenticated();
            return result;
          }
          throw createAuthRecoveryError(
            "mpr-ui.auth.session_recovery_result_invalid",
            "TAuth session recovery returned an invalid result",
          );
        })
        .catch(function handleSessionRecoveryCoordinationFailure(error) {
          requireCurrentAuthRecoveryLifecycle(recoveryLifecycleVersion);
          var coordinationError =
            error && error.code
              ? error
              : createAuthRecoveryError(
                  "mpr-ui.auth.session_recovery_failed",
                  "TAuth session recovery failed",
                );
          clearAuthRestoreHint(options);
          markUnauthenticated();
          emitError(coordinationError.code, {
            message: coordinationError.message,
            status:
              typeof coordinationError.status === "number"
                ? coordinationError.status
                : null,
          });
          throw coordinationError;
        });
    }

    /**
     * @param {unknown} input
     * @returns {boolean}
     */
    function isBrandedRequestInput(input) {
      var bodyUsedGetter = Object.getOwnPropertyDescriptor(
        global.Request.prototype,
        "bodyUsed",
      ).get;
      try {
        bodyUsedGetter.call(input);
        return true;
      } catch {
        return false;
      }
    }

    /**
     * @param {RequestInfo|URL} input
     * @param {RequestInit=} init
     * @param {AuthenticatedFetchPolicy=} fetchPolicy
     * @returns {Promise<Response>}
     */
    function authenticatedFetchWithController(input, init, fetchPolicy) {
      var policy = fetchPolicy || {};
      if (
        policy.mutationReplay !== undefined &&
        policy.mutationReplay !== AUTH_MUTATION_REPLAY_POLICY
      ) {
        var policyError = createAuthRecoveryError(
          "mpr-ui.auth.mutation_replay_policy_invalid",
          "Mutation replay requires the authorization-before-domain-work policy",
        );
        emitError(policyError.code || "mpr-ui.auth.mutation_replay_policy_invalid", {
          message: policyError.message,
        });
        return Promise.reject(policyError);
      }
      if (!state.profile || typeof state.profile !== "object") {
        var stateError = createAuthRecoveryError(
          "mpr-ui.auth.authenticated_state_required",
          "Wait for mpr-ui:auth:authenticated before an authenticated fetch",
        );
        emitError(stateError.code || "mpr-ui.auth.authenticated_state_required", {
          message: stateError.message,
        });
        return Promise.reject(stateError);
      }
      if (!global.fetch || typeof global.Request !== "function") {
        var fetchError = createAuthRecoveryError(
          "mpr-ui.auth.fetch_unavailable",
          "Authenticated fetch requires the browser Fetch API",
        );
        emitError(fetchError.code || "mpr-ui.auth.fetch_unavailable", {
          message: fetchError.message,
        });
        return Promise.reject(fetchError);
      }

      var observedRecovery;
      var firstRequest;
      var initialFetchInput;
      var initialFetchInit;
      var requestLifecycleVersion = lifecycleVersion;
      try {
        observedRecovery = captureAuthRecoveryGeneration(options);
        var requestInit = Object.assign({}, init || {}, {
          credentials: "include",
        });
        var inputIsBrandedRequest = isBrandedRequestInput(input);
        firstRequest = new global.Request(input, requestInit);
        var requestInitHasReadableStreamBody =
          requestInit.body !== undefined &&
          requestInit.body !== null &&
          firstRequest.body === requestInit.body;
        if (inputIsBrandedRequest || requestInitHasReadableStreamBody) {
          initialFetchInput = firstRequest;
          initialFetchInit = undefined;
        } else {
          initialFetchInput = input;
          initialFetchInit = requestInit;
        }
      } catch (error) {
        var preparationError =
          error && error.code
            ? error
            : createAuthRecoveryError(
                "mpr-ui.auth.request_invalid",
                error && error.message
                  ? error.message
                  : "Authenticated fetch could not create the request",
              );
        emitError(preparationError.code, {
          message: preparationError.message,
        });
        return Promise.reject(preparationError);
      }

      var method = String(firstRequest.method || "GET").toUpperCase();
      var isSafeMethod = ["GET", "HEAD", "OPTIONS"].indexOf(method) !== -1;
      var mutationReplayAllowed =
        policy.mutationReplay === AUTH_MUTATION_REPLAY_POLICY;
      var retryRequest = null;
      if (isSafeMethod || mutationReplayAllowed) {
        try {
          retryRequest = firstRequest.clone();
        } catch (error) {
          retryRequest = null;
        }
      }

      return global
        .fetch(initialFetchInput, initialFetchInit)
        .then(function handleProtectedResponse(response) {
          if (!response || response.status !== 401) {
            return response;
          }
          return recoverSessionAfterUnauthorized(
            observedRecovery,
            requestLifecycleVersion,
          ).then(
            function retryProtectedRequest(result) {
              requireCurrentAuthRecoveryLifecycle(requestLifecycleVersion);
              if (result.status !== "authenticated" || !retryRequest) {
                return response;
              }
              return global.fetch(retryRequest);
            },
          );
        });
    }

    function updateOptions(rawNextOptions) {
      if (isDestroyed) {
        return;
      }
      var nextOptions = normalizeAuthControllerOptions(rawNextOptions);
      assertStableTenantId(nextOptions);
      if (authControllerOptionsMatch(options, nextOptions)) {
        options = nextOptions;
        state.options = options;
        return;
      }
      invalidateAuthLifecycle();
      detachSessionSyncListeners();
      if (appleSignInHintOptions) {
        clearAuthRestoreHint(appleSignInHintOptions);
        appleSignInHintOptions = null;
      }
      options = nextOptions;
      state.options = options;
      pendingProfile = null;
      nonceRequestPromise = null;
      appleSignInAttemptPromise = null;
      hasCompletedInitialBootstrap = false;
      markUnauthenticated({ emit: false });
      bootstrapSession();
    }

    function destroy() {
      isDestroyed = true;
      invalidateAuthLifecycle();
      if (appleSignInHintOptions) {
        clearAuthRestoreHint(appleSignInHintOptions);
        appleSignInHintOptions = null;
      }
      pendingProfile = null;
      nonceRequestPromise = null;
      appleSignInAttemptPromise = null;
      detachSessionSyncListeners();
      setAttributeOrRemove(rootElement, "data-mpr-auth-status", null);
    }

    function performLogoutWithFetch() {
      return performLogoutRequestWithFetch(options);
    }

    function performLogout() {
      configureTenantId();
      return performLogoutFromRuntime(options).catch(function () {
        return null;
      });
    }

    function handleCredential(credentialResponse, credentialNonceToken) {
      if (!credentialResponse || !credentialResponse.credential) {
        emitError("mpr-ui.auth.missing_credential", {});
        markUnauthenticated();
        return Promise.resolve();
      }
      if (credentialNonceToken) {
        var currentLifecycleVersion = lifecycleVersion;
        updateAuthStatus(AUTH_CONTROLLER_STATUS.AUTHENTICATING, {
          source: "credential",
        });
        return exchangeCredential(credentialResponse.credential, credentialNonceToken)
          .then(function (profile) {
            if (!isCurrentLifecycleVersion(currentLifecycleVersion)) {
              return null;
            }
            // Always mark authenticated directly after successful credential exchange.
            markAuthenticated(profile);
            return profile;
          })
          .catch(function (error) {
            if (!isCurrentLifecycleVersion(currentLifecycleVersion)) {
              return Promise.resolve();
            }
            emitError("mpr-ui.auth.exchange_failed", {
              message: error && error.message ? error.message : String(error),
              status: error && error.status ? error.status : null,
            });
            markUnauthenticated();
            return Promise.resolve();
          });
      }
      emitError("mpr-ui.auth.missing_nonce", {
        message: "Google credential callback is missing the sign-in attempt nonce",
      });
      markUnauthenticated();
      return Promise.resolve();
    }

    function completeLogout() {
      invalidateAuthLifecycle();
      clearAuthRestoreHint(options);
      pendingProfile = null;
      markUnauthenticated();
    }

    function signOut() {
      invalidateAuthLifecycle();
      return performLogout().then(function () {
        clearAuthRestoreHint(options);
        pendingProfile = null;
        if (typeof global.initAuthClient !== "function") {
          markUnauthenticated();
          return null;
        }
        return bootstrapSession();
      });
    }

    markUnauthenticated({ emit: false });
    bootstrapSession();

    return {
      host: rootElement,
      state: state,
      prepareGoogleNonce: prepareGoogleNonce,
      refreshGoogleNonce: prepareGoogleNonce,
      prepareAppleSignIn: prepareAppleSignIn,
      startAppleSignIn: startAppleSignIn,
      handleCredential: handleCredential,
      performPasswordAction: performPasswordAction,
      performAccountAction: performAccountAction,
      startGoogleLink: startGoogleLink,
      authenticatedFetch: authenticatedFetchWithController,
      signOut: signOut,
      completeLogout: completeLogout,
      updateOptions: updateOptions,
      destroy: destroy,
      restartSessionWatcher: bootstrapSession,
      setAuthenticatedForTesting: function setAuthenticatedForTesting(profile) {
        markAuthenticated(profile);
        return state;
      },
      setUnauthenticatedForTesting: function setUnauthenticatedForTesting() {
        markUnauthenticated();
        return state;
      },
    };
  }

  function createTestingError(code, message) {
    /** @type {MprUiError} */
    var error = new Error(message);
    error.code = code;
    return error;
  }

  function resolveAuthenticatedFetchController(authTarget) {
    if (!authTarget || typeof authTarget !== "object") {
      throw createAuthRecoveryError(
        "mpr-ui.auth.auth_host_required",
        "MPRUI.authenticatedFetch requires an auth host element",
      );
    }
    if (typeof authTarget.authenticatedFetch === "function") {
      return authTarget;
    }
    var headerController =
      authTarget.__headerController &&
      typeof authTarget.__headerController.getAuthController === "function"
        ? authTarget.__headerController.getAuthController()
        : null;
    if (headerController && typeof headerController.authenticatedFetch === "function") {
      return headerController;
    }
    if (
      authTarget.__authController &&
      typeof authTarget.__authController.authenticatedFetch === "function"
    ) {
      return authTarget.__authController;
    }
    throw createAuthRecoveryError(
      "mpr-ui.auth.auth_controller_missing",
      "MPRUI.authenticatedFetch requires a mounted mpr-ui auth controller",
    );
  }

  /**
   * @param {object} authTarget
   * @param {RequestInfo|URL} input
   * @param {RequestInit=} init
   * @param {AuthenticatedFetchPolicy=} fetchPolicy
   * @returns {Promise<Response>}
   */
  function authenticatedFetch(authTarget, input, init, fetchPolicy) {
    var authController;
    try {
      authController = resolveAuthenticatedFetchController(authTarget);
    } catch (error) {
      return Promise.reject(error);
    }
    return authController.authenticatedFetch(input, init, fetchPolicy);
  }

  function requireTestingProfile(profile) {
    if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
      throw createTestingError(
        "mpr-ui.testing.auth_profile_required",
        "MPRUI.testing.authenticate requires a profile object",
      );
    }
    return profile;
  }

  function resolveTestingAuthController(authTarget) {
    if (!authTarget || typeof authTarget !== "object") {
      throw createTestingError(
        "mpr-ui.testing.auth_host_required",
        "MPRUI.testing auth helpers require an auth host element",
      );
    }
    if (typeof authTarget.setAuthenticatedForTesting === "function") {
      return authTarget;
    }
    var headerController =
      authTarget.__headerController &&
      typeof authTarget.__headerController.getAuthController === "function"
        ? authTarget.__headerController.getAuthController()
        : null;
    if (headerController) {
      return headerController;
    }
    if (authTarget.__authController) {
      return authTarget.__authController;
    }
    throw createTestingError(
      "mpr-ui.testing.auth_controller_missing",
      "MPRUI.testing auth helpers require a mounted mpr-ui auth controller",
    );
  }

  function safeAuthProfile(profile) {
    if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
      return null;
    }
    var snapshot = {};
    SAFE_AUTH_PROFILE_FIELDS.forEach(function copySafeProfileField(fieldName) {
      if (Object.prototype.hasOwnProperty.call(profile, fieldName)) {
        snapshot[fieldName] = profile[fieldName];
      }
    });
    return Object.freeze(snapshot);
  }

  function resolveAuthProfileSnapshot(authTarget) {
    var resolvedTarget = resolveHost(authTarget);
    var authController = resolveTestingAuthController(resolvedTarget);
    return Promise.resolve(Object.freeze({
      status: authController.state.status,
      profile: safeAuthProfile(authController.state.profile),
    }));
  }

  function prepareRedirectProviderForTesting(authTarget, providerId) {
    var resolvedTarget = resolveHost(authTarget);
    var authController = resolveTestingAuthController(resolvedTarget);
    if (providerId !== AUTH_PROVIDER_IDS.APPLE) {
      throw createTestingError(
        "mpr-ui.testing.redirect_provider_unsupported",
        "MPRUI.testing redirect helpers support Apple sign-in",
      );
    }
    return authController.prepareAppleSignIn();
  }

  function navigateRedirectProviderForTesting(authTarget, providerId) {
    var resolvedTarget = resolveHost(authTarget);
    var authController = resolveTestingAuthController(resolvedTarget);
    if (providerId !== AUTH_PROVIDER_IDS.APPLE) {
      return Promise.reject(
        createTestingError(
          "mpr-ui.testing.redirect_provider_unsupported",
          "MPRUI.testing redirect helpers support Apple sign-in",
        ),
      );
    }
    return authController.startAppleSignIn();
  }

  function authenticateForTesting(authTarget, profile) {
    var authController = resolveTestingAuthController(authTarget);
    if (typeof authController.setAuthenticatedForTesting !== "function") {
      throw createTestingError(
        "mpr-ui.testing.auth_controller_unsupported",
        "MPRUI.testing.authenticate requires a compatible auth controller",
      );
    }
    return authController.setAuthenticatedForTesting(
      requireTestingProfile(profile),
    );
  }

  function unauthenticateForTesting(authTarget) {
    var authController = resolveTestingAuthController(authTarget);
    if (typeof authController.setUnauthenticatedForTesting !== "function") {
      throw createTestingError(
        "mpr-ui.testing.auth_controller_unsupported",
        "MPRUI.testing.unauthenticate requires a compatible auth controller",
      );
    }
    return authController.setUnauthenticatedForTesting();
  }

  function resolveGoogleIdentityTestingDriver() {
    var googleIdentity =
      global.google &&
      global.google.accounts &&
      global.google.accounts.id
        ? global.google.accounts.id
        : null;
    var driver =
      googleIdentity &&
      googleIdentity.__mprUiTesting &&
      typeof googleIdentity.__mprUiTesting === "object"
        ? googleIdentity.__mprUiTesting
        : null;
    return driver;
  }

  function requireGoogleIdentityTestingDriver() {
    var driver = resolveGoogleIdentityTestingDriver();
    if (!driver) {
      throw createTestingError(
        "mpr-ui.testing.google_identity_driver_missing",
        "MPRUI.testing.googleIdentity requires a Google Identity test driver",
      );
    }
    return driver;
  }

  function isGoogleIdentityTestingDriverAvailable() {
    return Boolean(resolveGoogleIdentityTestingDriver());
  }

  function requireGoogleIdentityTestingMethod(driver, methodName) {
    if (!driver || typeof driver[methodName] !== "function") {
      throw createTestingError(
        "mpr-ui.testing.google_identity_driver_unsupported",
        "MPRUI.testing.googleIdentity requires a compatible Google Identity test driver",
      );
    }
    return driver[methodName];
  }

  function isGoogleIdentityTestingInitialized() {
    var driver = resolveGoogleIdentityTestingDriver();
    if (!driver) {
      return false;
    }
    var isInitialized = requireGoogleIdentityTestingMethod(
      driver,
      "isInitialized",
    );
    return isInitialized.call(driver) === true;
  }

  function requireInitializedGoogleIdentityTestingDriver() {
    var driver = requireGoogleIdentityTestingDriver();
    var isInitialized = requireGoogleIdentityTestingMethod(
      driver,
      "isInitialized",
    );
    if (isInitialized.call(driver) !== true) {
      throw createTestingError(
        "mpr-ui.testing.google_identity_not_initialized",
        "MPRUI.testing.googleIdentity requires an initialized Google Identity stub",
      );
    }
    return driver;
  }

  function getGoogleIdentityTestingInitializedNonce() {
    var driver = requireInitializedGoogleIdentityTestingDriver();
    var getInitializedNonce = requireGoogleIdentityTestingMethod(
      driver,
      "getInitializedNonce",
    );
    return String(getInitializedNonce.call(driver));
  }

  function getGoogleIdentityTestingInitializeCallCount() {
    var driver = requireGoogleIdentityTestingDriver();
    var getInitializeCallCount = requireGoogleIdentityTestingMethod(
      driver,
      "getInitializeCallCount",
    );
    return Number(getInitializeCallCount.call(driver));
  }

  function enableGoogleIdentityTestingAutoCredentialOnClick() {
    var driver = requireGoogleIdentityTestingDriver();
    var enableAutoCredentialOnClick = requireGoogleIdentityTestingMethod(
      driver,
      "enableAutoCredentialOnClick",
    );
    return enableAutoCredentialOnClick.call(driver);
  }

  function renderAuthHeader(target, options) {
    var host = target;
    if (typeof target === "string" && global.document) {
      host = global.document.querySelector(target);
    }
    if (!host) {
      throw new Error("renderAuthHeader requires a host element");
    }
    return createAuthHeader(host, options || {});
  }

  var HEADER_ROOT_CLASS = "mpr-header";
  var HEADER_STYLE_ID = "mpr-ui-header-styles";
  var HEADER_STYLE_MARKUP =
    "mpr-header{display:block;position:sticky;top:0;width:100%;z-index:1200}" +
    'mpr-header[data-mpr-sticky="false"]{position:static;top:auto}' +
    "." +
    HEADER_ROOT_CLASS +
    "{width:100%;background:var(--mpr-color-surface-primary,#0f1114);color:var(--mpr-color-text-primary,#e3e5ec);border-bottom:1px solid var(--mpr-color-border,#2c2f36);--mpr-header-scale:1;--mpr-header-google-scale:1}" +
    "." +
    HEADER_ROOT_CLASS +
    '[data-mpr-sticky="false"]{box-shadow:none}' +
    "." +
    HEADER_ROOT_CLASS +
    "__inner{max-width:var(--mpr-content-width-expanded,1180px);margin:0 auto;padding:calc(0.5rem * var(--mpr-header-scale,1)) calc(0.75rem * var(--mpr-header-scale,1));display:flex;flex-wrap:wrap;align-items:center;gap:calc(0.75rem * var(--mpr-header-scale,1));min-width:0;overflow:visible}" +
    "." +
    HEADER_ROOT_CLASS +
    "__brand{font-size:max(0.78rem,calc(0.95rem * var(--mpr-header-scale,1)));font-weight:650;letter-spacing:0.01em;white-space:nowrap}" +
    "." +
    HEADER_ROOT_CLASS +
    "__brand-link{color:inherit;text-decoration:none}" +
    "." +
    HEADER_ROOT_CLASS +
    "__brand-link:hover{text-decoration:underline}" +
    "." +
    HEADER_ROOT_CLASS +
    "__nav{margin-left:auto;display:flex;flex:0 1 auto;min-width:0;max-width:100%;overflow-x:auto;flex-wrap:nowrap;gap:calc(0.65rem * var(--mpr-header-scale,1));align-items:center;font-size:max(0.72rem,calc(0.78rem * var(--mpr-header-scale,1)));white-space:nowrap}" +
    "." +
    HEADER_ROOT_CLASS +
    "__nav a{color:inherit;text-decoration:none;font-weight:500}" +
    "." +
    HEADER_ROOT_CLASS +
    "__nav a:hover{text-decoration:underline}" +
    "." +
    HEADER_ROOT_CLASS +
    "__horizontal-links{display:flex;flex:1 1 auto;min-width:0;max-width:100%;overflow-x:auto;overscroll-behavior-inline:contain;flex-wrap:nowrap;align-items:center;justify-content:center;gap:calc(0.6rem * var(--mpr-header-scale,1));font-size:max(0.72rem,calc(0.78rem * var(--mpr-header-scale,1)));color:var(--mpr-color-text-muted,#c4c7d1);white-space:nowrap}" +
    "." +
    HEADER_ROOT_CLASS +
    '__horizontal-links[data-mpr-align="left"]{justify-content:flex-start}' +
    "." +
    HEADER_ROOT_CLASS +
    '__horizontal-links[data-mpr-align="right"]{justify-content:flex-end}' +
    "." +
    HEADER_ROOT_CLASS +
    "__horizontal-links a{color:inherit;text-decoration:none;font-weight:500}" +
    "." +
    HEADER_ROOT_CLASS +
    "__horizontal-links a:hover{text-decoration:underline}" +
    "." +
    HEADER_ROOT_CLASS +
    "__actions{display:flex;margin-left:auto;gap:calc(0.5rem * var(--mpr-header-scale,1));align-items:center;flex:0 1 auto;min-width:0;max-width:100%;white-space:nowrap}" +
    "." +
    HEADER_ROOT_CLASS +
    "__auth-transition{position:fixed;inset:0;z-index:1900;display:none;align-items:center;justify-content:center;padding:1.5rem;background:rgba(15,23,42,0.78);backdrop-filter:blur(10px)}" +
    "." +
    HEADER_ROOT_CLASS +
    '__auth-transition[data-mpr-visible="true"]{display:flex}' +
    "." +
    HEADER_ROOT_CLASS +
    "__auth-transition-panel{width:min(28rem,92vw);display:flex;flex-direction:column;align-items:center;gap:0.85rem;padding:2rem 1.75rem;border-radius:1.25rem;border:1px solid var(--mpr-color-border,rgba(148,163,184,0.25));background:var(--mpr-color-surface-elevated,rgba(15,23,42,0.96));box-shadow:var(--mpr-shadow-flyout,0 16px 32px rgba(15,23,42,0.28));text-align:center}" +
    "." +
    HEADER_ROOT_CLASS +
    "__auth-transition-spinner{width:calc(2.5rem * var(--mpr-header-scale,1));height:calc(2.5rem * var(--mpr-header-scale,1));border-radius:50%;border:3px solid rgba(148,163,184,0.24);border-top-color:var(--mpr-color-accent,#38bdf8);animation:mpr-header-auth-transition-spin 0.9s linear infinite}" +
    "." +
    HEADER_ROOT_CLASS +
    "__auth-transition-title{margin:0;font-size:calc(1.15rem * var(--mpr-header-scale,1));font-weight:700;color:var(--mpr-color-text-primary,#e2e8f0)}" +
    "." +
    HEADER_ROOT_CLASS +
    "__auth-transition-message{margin:0;line-height:1.5;font-size:calc(0.95rem * var(--mpr-header-scale,1));color:var(--mpr-color-text-muted,#cbd5f5)}" +
    "." +
    HEADER_ROOT_CLASS +
    "__auth-transition-message:empty{display:none}" +
    "." +
    HEADER_ROOT_CLASS +
    "__auth-actions{display:none;align-items:center;min-inline-size:0;flex-shrink:1}" +
    "." +
    HEADER_ROOT_CLASS +
    "__auth-actions:has([data-mpr-auth-actions]){display:inline-flex}" +
    "." +
    HEADER_ROOT_CLASS +
    "__user{display:none;align-items:center}" +
    "." +
    HEADER_ROOT_CLASS +
    "__button{border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);padding:calc(0.35rem * var(--mpr-header-scale,1)) calc(0.55rem * var(--mpr-header-scale,1));font-size:max(0.72rem,calc(0.78rem * var(--mpr-header-scale,1)));font-weight:600;cursor:pointer;background:var(--mpr-chip-bg,rgba(114,120,135,0.16));color:var(--mpr-color-text-primary,#e3e5ec)}" +
    "." +
    HEADER_ROOT_CLASS +
    "__button:hover{background:var(--mpr-chip-hover-bg,rgba(148,163,184,0.32))}" +
    "." +
    HEADER_ROOT_CLASS +
    "__button--primary{background:var(--mpr-color-accent,#38bdf8);color:var(--mpr-color-accent-contrast,#0f172a)}" +
    "." +
    HEADER_ROOT_CLASS +
    "__button--primary:hover{background:var(--mpr-color-accent-alt,#22d3ee)}" +
    "." +
    HEADER_ROOT_CLASS +
    "__icon-btn{display:inline-flex;align-items:center;gap:0.35rem}" +
    "." +
    HEADER_ROOT_CLASS +
    "--authenticated [data-mpr-header=\"user-menu\"]{display:inline-flex}" +
    "." +
    HEADER_ROOT_CLASS +
    "--authenticated [data-mpr-header=\"auth-actions\"]{display:none}" +
    "." +
    HEADER_ROOT_CLASS +
    "--no-settings [data-mpr-header=\"settings-button\"]{display:none}" +
    "." +
    HEADER_ROOT_CLASS +
    "--no-auth [data-mpr-header=\"auth-actions\"]{display:none}" +
    "." +
    HEADER_ROOT_CLASS +
    "__nav:empty{display:none}" +
    "." +
    HEADER_ROOT_CLASS +
    "__horizontal-links:empty{display:none}" +
    ".mpr-header--small{--mpr-header-scale:0.82}" +
    "@keyframes mpr-header-auth-transition-spin{to{transform:rotate(360deg)}}";

  var HEADER_SETTINGS_PLACEHOLDER_MARKUP =
    '<div data-mpr-header="settings-modal-placeholder">' +
    '<p data-mpr-header="settings-modal-placeholder-title">Add your settings controls here.</p>' +
    '<p data-mpr-header="settings-modal-placeholder-subtext">Listen for the "mpr-ui:header:settings-click" event or query [data-mpr-header="settings-modal-body"] to mount custom UI.</p>' +
    "</div>";
  var HEADER_LINK_DEFAULT_TARGET = "_blank";
  var HEADER_LINK_DEFAULT_REL = "noopener noreferrer";
  var HEADER_INVALID_SIGN_IN_REDIRECT_URL =
    "mpr-ui.header.invalid_sign_in_redirect_url";
  var HEADER_ALLOWED_REDIRECT_PROTOCOLS = Object.freeze(["http:", "https:"]);
  var HEADER_USER_MENU_OVERRIDE_ATTRIBUTE =
    "data-mpr-header-user-menu-overrides";
  var HEADER_USER_MENU_OVERRIDE_SEPARATOR = ",";
  var HEADER_USER_MENU_OVERRIDE_ATTRIBUTES = Object.freeze([
    "display-mode",
    "logout-url",
    "logout-label",
    AUTH_CONFIG_ATTRIBUTE,
    "avatar-url",
    "avatar-label",
  ]);

  var HEADER_DEFAULTS = Object.freeze({
    brand: Object.freeze({
      label: "Marco Polo Research Lab",
      href: "/",
    }),
    navLinks: Object.freeze([]),
    horizontalLinks: Object.freeze({
      alignment: "center",
      links: Object.freeze([]),
    }),
    authTransition: Object.freeze({
      enabled: false,
      title: "Opening your workspace…",
      message: "Preparing the authenticated app surface.",
      completionEvent: "",
    }),
    settings: Object.freeze({
      enabled: false,
      label: "Settings",
    }),
    themeToggle: Object.freeze({
      attribute: DEFAULT_THEME_ATTRIBUTE,
      targets: DEFAULT_THEME_TARGETS.slice(),
      modes: DEFAULT_THEME_MODES,
      initialMode: null,
    }),
    signOutLabel: "Sign out",
    signInRedirectUrl: "",
    profileLabel: "",
    userMenu: Object.freeze({
      displayMode: USER_MENU_DISPLAY_MODES.AVATAR_NAME,
      logoutUrl: "",
      avatarUrl: "",
      avatarLabel: "",
    }),
    initialTheme: "light",
    auth: null,
    sticky: true,
  });

  function normalizeHeaderUserMenuDisplayMode(value) {
    var normalized = normalizeUserMenuDisplayMode(value);
    return normalized || USER_MENU_DISPLAY_MODES.AVATAR_NAME;
  }

  function normalizeHeaderUserMenuLogoutUrl(value, fallbackUrl) {
    var candidate =
      typeof value === "string" && value.trim() ? value.trim() : "";
    if (!candidate) {
      candidate =
        typeof fallbackUrl === "string" && fallbackUrl.trim()
          ? fallbackUrl.trim()
          : "";
    }
    if (!candidate) {
      candidate = HEADER_DEFAULTS.brand.href;
    }
    var sanitized = sanitizeHref(candidate);
    if (sanitized === "#" && candidate !== "#") {
      return HEADER_DEFAULTS.brand.href;
    }
    return sanitized;
  }

  function normalizeHeaderUserMenuOptionalValue(value) {
    if (typeof value !== "string") {
      return "";
    }
    var trimmed = value.trim();
    return trimmed ? trimmed : "";
  }

  function normalizeHeaderSignInRedirectUrl(value) {
    if (typeof value !== "string") {
      return "";
    }
    var candidate = value.trim();
    if (!candidate) {
      return "";
    }
    if (candidate[0] === "#" || candidate.indexOf("//") === 0) {
      throw new Error(HEADER_INVALID_SIGN_IN_REDIRECT_URL);
    }
    var protocolMatch = candidate.match(/^([a-z0-9.+-]+):/i);
    if (
      protocolMatch &&
      HEADER_ALLOWED_REDIRECT_PROTOCOLS.indexOf(
        protocolMatch[1].toLowerCase() + ":",
      ) === -1
    ) {
      throw new Error(HEADER_INVALID_SIGN_IN_REDIRECT_URL);
    }
    var currentOrigin =
      global.location && typeof global.location.origin === "string"
        ? global.location.origin
        : "";
    var currentHref =
      global.location && typeof global.location.href === "string"
        ? global.location.href
        : "";
    var baseUrl =
      currentHref ||
      (currentOrigin && currentOrigin !== "null" ? currentOrigin + "/" : "");
    if (protocolMatch && (!baseUrl || typeof global.URL !== "function")) {
      throw new Error(HEADER_INVALID_SIGN_IN_REDIRECT_URL);
    }
    if (baseUrl && typeof global.URL === "function") {
      try {
        var parsedUrl = new global.URL(candidate, baseUrl);
        if (
          currentOrigin &&
          currentOrigin !== "null" &&
          parsedUrl.origin !== currentOrigin
        ) {
          throw new Error(HEADER_INVALID_SIGN_IN_REDIRECT_URL);
        }
        if (
          HEADER_ALLOWED_REDIRECT_PROTOCOLS.indexOf(parsedUrl.protocol) === -1
        ) {
          throw new Error(HEADER_INVALID_SIGN_IN_REDIRECT_URL);
        }
      } catch (_error) {
        throw new Error(HEADER_INVALID_SIGN_IN_REDIRECT_URL);
      }
    }
    return candidate;
  }

  function normalizeHeaderAuthTransitionOptionalValue(value, fallbackValue) {
    if (typeof value !== "string") {
      return fallbackValue;
    }
    var trimmed = value.trim();
    return trimmed ? trimmed : fallbackValue;
  }

  function normalizeHeaderAuthTransitionCompletionEvent(value) {
    if (typeof value !== "string") {
      return "";
    }
    var trimmed = value.trim();
    return trimmed ? trimmed : "";
  }

  function normalizeHeaderAuthTransition(rawValue) {
    var parsedValue = parseHeaderAuthTransitionValue(rawValue);
    if (!parsedValue) {
      return deepMergeOptions({}, HEADER_DEFAULTS.authTransition);
    }
    var normalized = {
      enabled: normalizeBooleanAttribute(parsedValue.enabled, true),
      title: normalizeHeaderAuthTransitionOptionalValue(
        parsedValue.title,
        HEADER_DEFAULTS.authTransition.title,
      ),
      message: normalizeHeaderAuthTransitionOptionalValue(
        parsedValue.message,
        HEADER_DEFAULTS.authTransition.message,
      ),
      completionEvent: normalizeHeaderAuthTransitionCompletionEvent(
        parsedValue.completionEvent,
      ),
    };
    return normalized;
  }

  function captureHeaderUserMenuOverrides(userMenuElement) {
    if (
      !userMenuElement ||
      typeof userMenuElement.setAttribute !== "function" ||
      typeof userMenuElement.hasAttribute !== "function"
    ) {
      return;
    }
    var overrideAttributes = [];
    for (
      var index = 0;
      index < HEADER_USER_MENU_OVERRIDE_ATTRIBUTES.length;
      index += 1
    ) {
      var attributeName = HEADER_USER_MENU_OVERRIDE_ATTRIBUTES[index];
      if (userMenuElement.hasAttribute(attributeName)) {
        overrideAttributes.push(attributeName);
      }
    }
    if (!overrideAttributes.length) {
      return;
    }
    userMenuElement.setAttribute(
      HEADER_USER_MENU_OVERRIDE_ATTRIBUTE,
      overrideAttributes.join(HEADER_USER_MENU_OVERRIDE_SEPARATOR),
    );
  }

  function resolveHeaderUserMenuOverrides(userMenuElement) {
    if (
      !userMenuElement ||
      typeof userMenuElement.getAttribute !== "function"
    ) {
      return null;
    }
    var overrideValue = userMenuElement.getAttribute(
      HEADER_USER_MENU_OVERRIDE_ATTRIBUTE,
    );
    if (!overrideValue) {
      return null;
    }
    var overrideEntries = overrideValue
      .split(HEADER_USER_MENU_OVERRIDE_SEPARATOR)
      .map(function trimEntry(entry) {
        return entry.trim();
      })
      .filter(Boolean);
    return overrideEntries.length ? overrideEntries : null;
  }

  function isHeaderUserMenuOverride(overrideEntries, attributeName) {
    if (!overrideEntries) {
      return false;
    }
    return overrideEntries.indexOf(attributeName) !== -1;
  }

  function setHeaderUserMenuAttribute(
    userMenuElement,
    attributeName,
    value,
    overrideEntries,
  ) {
    if (isHeaderUserMenuOverride(overrideEntries, attributeName)) {
      return;
    }
    setAttributeOrRemove(userMenuElement, attributeName, value);
  }

  function ensureHeaderStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(HEADER_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = HEADER_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = HEADER_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(HEADER_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  var AUTH_PROVIDER_CHOOSER_STYLE_MARKUP =
    "mpr-auth-provider-chooser{display:block;inline-size:100%;max-inline-size:20rem;color:var(--mpr-color-text-primary,#e3e5ec);--mpr-auth-provider-radius:var(--mpr-radius-control,6px);--mpr-auth-provider-scale:1}" +
    "mpr-header mpr-auth-provider-chooser{--mpr-auth-provider-scale:var(--mpr-header-scale,1)}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "{display:flex;flex-direction:column;gap:calc(0.35rem * var(--mpr-auth-provider-scale,1));inline-size:100%}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__actions{display:flex;flex-direction:column;gap:calc(0.35rem * var(--mpr-auth-provider-scale,1));inline-size:100%}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__action{display:inline-grid;grid-template-columns:calc(1.15rem * var(--mpr-auth-provider-scale,1)) minmax(0,1fr) calc(1.15rem * var(--mpr-auth-provider-scale,1));align-items:center;column-gap:calc(0.5rem * var(--mpr-auth-provider-scale,1));min-block-size:calc(2.125rem * var(--mpr-auth-provider-scale,1));inline-size:100%;padding:calc(0.35rem * var(--mpr-auth-provider-scale,1)) calc(0.55rem * var(--mpr-auth-provider-scale,1));border-radius:var(--mpr-auth-provider-radius);border:1px solid var(--mpr-color-border,#2c2f36);background:var(--mpr-color-surface-elevated,#1f2126);color:var(--mpr-color-text-primary,#e3e5ec);font:inherit;font-size:calc(0.78rem * var(--mpr-auth-provider-scale,1));font-weight:700;line-height:1.2;text-align:center;cursor:pointer;box-sizing:border-box}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__mark{display:inline-flex;grid-column:1;align-items:center;justify-content:center;inline-size:calc(1.15rem * var(--mpr-auth-provider-scale,1));block-size:calc(1.15rem * var(--mpr-auth-provider-scale,1))}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__mark svg{display:block;inline-size:100%;block-size:100%}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__label{grid-column:2;min-inline-size:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__action:hover{background:var(--mpr-chip-hover-bg,rgba(148,163,184,0.32))}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__action:focus-visible{outline:none;box-shadow:0 0 0 2px rgba(56,189,248,0.4)}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__action--apple{background:#020617;color:#f8fafc}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__action--apple:hover{background:#111827}" +
    "mpr-auth-provider-chooser[variant='icon-row'],mpr-auth-provider-chooser[data-mpr-auth-provider-variant='icon-row']{inline-size:max-content;max-inline-size:100%;--mpr-auth-provider-radius:6px}" +
    "mpr-auth-provider-chooser[variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__actions,mpr-auth-provider-chooser[data-mpr-auth-provider-variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__actions,." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "[data-mpr-auth-provider-variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__actions{display:inline-grid;grid-auto-flow:column;grid-auto-columns:calc(2.25rem * var(--mpr-auth-provider-scale,1));grid-template-columns:none;gap:calc(0.3rem * var(--mpr-auth-provider-scale,1));inline-size:max-content;max-inline-size:100%}" +
    "mpr-auth-provider-chooser[variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__action,mpr-auth-provider-chooser[data-mpr-auth-provider-variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__action,." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "[data-mpr-auth-provider-variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__action{position:relative;grid-template-columns:1fr;place-items:center;justify-items:center;inline-size:calc(2.25rem * var(--mpr-auth-provider-scale,1));block-size:calc(2.25rem * var(--mpr-auth-provider-scale,1));min-inline-size:calc(2.25rem * var(--mpr-auth-provider-scale,1));min-block-size:calc(2.25rem * var(--mpr-auth-provider-scale,1));padding:0;aspect-ratio:1/1;overflow:hidden}" +
    "mpr-auth-provider-chooser[variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__mark,mpr-auth-provider-chooser[data-mpr-auth-provider-variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__mark,." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "[data-mpr-auth-provider-variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__mark{grid-column:1;inline-size:calc(1.1rem * var(--mpr-auth-provider-scale,1));block-size:calc(1.1rem * var(--mpr-auth-provider-scale,1))}" +
    "mpr-auth-provider-chooser[variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__label,mpr-auth-provider-chooser[data-mpr-auth-provider-variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__label,." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "[data-mpr-auth-provider-variant='icon-row'] ." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__label{position:absolute;inline-size:1px;block-size:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__email-panel{display:flex;flex-direction:column;gap:calc(0.45rem * var(--mpr-auth-provider-scale,1));padding:calc(0.55rem * var(--mpr-auth-provider-scale,1));border-radius:var(--mpr-auth-provider-radius);border:1px solid var(--mpr-color-border,#2c2f36);background:var(--mpr-color-surface-elevated,#1f2126);box-sizing:border-box}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__email-form{display:flex;flex-direction:column;gap:calc(0.45rem * var(--mpr-auth-provider-scale,1));margin:0}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__field{display:flex;flex-direction:column;gap:calc(0.22rem * var(--mpr-auth-provider-scale,1));font-size:calc(0.78rem * var(--mpr-auth-provider-scale,1));font-weight:700;color:var(--mpr-color-text-muted,#cbd5f5)}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__input{inline-size:100%;min-block-size:calc(2rem * var(--mpr-auth-provider-scale,1));padding:calc(0.35rem * var(--mpr-auth-provider-scale,1)) calc(0.5rem * var(--mpr-auth-provider-scale,1));border-radius:var(--mpr-auth-provider-radius);border:1px solid var(--mpr-color-border,rgba(148,163,184,0.35));background:var(--mpr-color-surface-primary,rgba(15,23,42,0.92));color:var(--mpr-color-text-primary,#e2e8f0);font:inherit;font-size:calc(0.9rem * var(--mpr-auth-provider-scale,1));box-sizing:border-box}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__input:focus{outline:none;box-shadow:0 0 0 2px rgba(56,189,248,0.35)}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__submit{min-block-size:calc(2.1rem * var(--mpr-auth-provider-scale,1));border:none;border-radius:var(--mpr-auth-provider-radius);background:var(--mpr-color-accent,#38bdf8);color:var(--mpr-color-accent-contrast,#0f172a);font:inherit;font-size:calc(0.9rem * var(--mpr-auth-provider-scale,1));font-weight:800;cursor:pointer}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__submit:hover{filter:brightness(1.05)}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__submit:focus-visible{outline:none;box-shadow:0 0 0 2px rgba(56,189,248,0.4)}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__secondary-actions{display:flex;align-items:center;justify-content:space-between;gap:0.5rem;flex-wrap:wrap}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__link-button{border:none;background:transparent;color:var(--mpr-color-text-muted,#cbd5f5);font:inherit;font-size:calc(0.78rem * var(--mpr-auth-provider-scale,1));font-weight:700;padding:0;cursor:pointer}" +
    "." +
    AUTH_PROVIDER_CHOOSER_ROOT_CLASS +
    "__link-button:hover{color:var(--mpr-color-text-primary,#e2e8f0);text-decoration:underline}" +
    "@keyframes mpr-auth-progress-spin{to{transform:rotate(360deg)}}" +
    ".mpr-auth-actions{display:grid;gap:.25rem;min-inline-size:0;max-inline-size:100%;--mpr-auth-action-block-size:1.875rem;--mpr-auth-action-inline-size:11.25rem}" +
    ".mpr-auth-actions__controls{display:flex;flex-wrap:nowrap;gap:.35rem;align-items:stretch;min-inline-size:0;max-inline-size:100%}" +
    ".mpr-auth-actions__controls .mpr-auth-provider-chooser__action{inline-size:var(--mpr-auth-action-inline-size);min-inline-size:var(--mpr-auth-action-inline-size);block-size:var(--mpr-auth-action-block-size);min-block-size:var(--mpr-auth-action-block-size);padding:.1875rem .5rem}" +
    ".mpr-auth-google-button{display:inline-flex;align-items:center;justify-content:center;min-inline-size:var(--mpr-auth-action-block-size);min-block-size:var(--mpr-auth-action-block-size);overflow:hidden;box-sizing:border-box}" +
    ".mpr-auth-google-button>div{display:flex!important;align-items:center;justify-content:center}" +
    '.mpr-auth-google-button[aria-busy="true"]:empty::before{inline-size:.75rem;block-size:.75rem;border:1px solid currentColor;border-right-color:transparent;border-radius:50%;content:"";animation:mpr-auth-progress-spin 700ms linear infinite}' +
    ".mpr-auth-actions__controls .mpr-auth-provider-chooser__action--apple{padding:.1875rem .5rem;border-color:#000;background:#000;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:.8125rem}" +
    ".mpr-auth-actions__controls .mpr-auth-provider-chooser__action--apple:hover{background:#111}" +
    ".mpr-auth-actions__controls .mpr-auth-provider-chooser__action--google{border-color:#8e918f;background:#131314;color:#e3e3e3;font-family:'Google Sans',Roboto,Arial,sans-serif;font-size:.875rem;line-height:1.25rem}" +
    ".mpr-auth-actions__controls .mpr-auth-provider-chooser__action--google:hover{background:#202124}" +
    ".mpr-auth-actions__status{min-block-size:1.2em;margin:0;color:var(--mpr-color-text-muted,#cbd5f5);font-size:.78rem;line-height:1.2}" +
    "mpr-header .mpr-auth-actions__status{min-inline-size:0;white-space:normal;overflow-wrap:anywhere}" +
    ".mpr-auth-actions__status:empty{display:none}" +
    ".mpr-auth-actions[data-mpr-auth-action-status='authenticating'] > .mpr-auth-actions__status {position: absolute;inline-size: 1px;block-size: 1px;min-block-size: 0;padding: 0;overflow: hidden;clip-path: inset(50%);white-space: nowrap;}.mpr-auth-google-button[aria-busy='true']:not(:empty) {position: relative;pointer-events: none;}.mpr-auth-google-button[aria-busy='true']:not(:empty) > * {opacity: 0.35;}.mpr-auth-google-button[aria-busy='true']:not(:empty)::after {position: absolute;inline-size: 0.875rem;block-size: 0.875rem;border: 2px solid currentColor;border-right-color: transparent;border-radius: 50%;content: '';animation: mpr-auth-progress-spin 700ms linear infinite;}" +
    "mpr-header .mpr-auth-actions{position:relative;--mpr-auth-provider-scale:var(--mpr-header-scale,1);max-inline-size:100%}" +
    "mpr-header .mpr-auth-actions__controls{overflow:visible}" +
    ".mpr-auth-actions__email-panel{display:grid;box-sizing:border-box;gap:.35rem;min-inline-size:0}" +
    ".mpr-auth-actions__email-modes{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.25rem}" +
    ".mpr-auth-actions__email-mode{min-block-size:1.75rem;padding:.25rem .45rem;border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);background:var(--mpr-color-surface-elevated,#1f2126);color:var(--mpr-color-text-muted,#cbd5f5);font:inherit;font-size:.75rem;font-weight:700;cursor:pointer}" +
    ".mpr-auth-actions__email-mode[aria-selected='true']{border-color:var(--mpr-color-accent,#5d93ff);background:rgba(93,147,255,.14);color:var(--mpr-color-text-primary,#e3e5ec)}" +
    ".mpr-auth-actions__email-mode:focus-visible{outline:2px solid var(--mpr-color-accent,#5d93ff);outline-offset:1px}" +
    "mpr-header .mpr-auth-actions>.mpr-auth-actions__email-panel{position:absolute;z-index:1000;inset-block-start:calc(100% + .35rem);inset-inline-end:0;inline-size:min(20rem,calc(100vw - 1.5rem));max-inline-size:none;box-shadow:var(--mpr-shadow-flyout,0 16px 32px rgba(15,23,42,.28))}" +
    "mpr-header .mpr-auth-google-button{inline-size:var(--mpr-auth-action-block-size);block-size:var(--mpr-auth-action-block-size);min-inline-size:var(--mpr-auth-action-block-size);min-block-size:var(--mpr-auth-action-block-size);border:1px solid #8e918f;border-radius:var(--mpr-radius-control,6px);background:#000;color:#e3e5ec}" +
    "mpr-header .mpr-auth-actions__controls .mpr-auth-provider-chooser__action{position:relative;grid-template-columns:1fr;place-items:center;inline-size:var(--mpr-auth-action-block-size);min-inline-size:var(--mpr-auth-action-block-size);padding:0;border-color:#8e918f;border-style:solid;border-width:1px;aspect-ratio:1/1;overflow:hidden}" +
    "mpr-header .mpr-auth-actions__controls .mpr-auth-provider-chooser__mark{grid-column:1;grid-row:1}" +
    "mpr-header .mpr-auth-actions__controls .mpr-auth-provider-chooser__label{position:absolute;inline-size:1px;block-size:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}" +
    ".mpr-auth-diagnostics{display:grid;gap:.5rem;padding:.75rem;border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);background:var(--mpr-color-surface-elevated,#1f2126);color:var(--mpr-color-text-primary,#e3e5ec)}" +
    ".mpr-auth-diagnostics__heading{margin:0;font-size:.86rem}" +
    ".mpr-auth-diagnostics__list{display:grid;gap:.35rem;margin:0}" +
    ".mpr-auth-diagnostics__list>div{display:grid;grid-template-columns:minmax(7rem,auto) minmax(0,1fr);gap:.5rem}" +
    ".mpr-auth-diagnostics__list dt{font-weight:700}" +
    ".mpr-auth-diagnostics__list dd{margin:0;overflow-wrap:anywhere}";

  function ensureAuthProviderChooserStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(AUTH_PROVIDER_CHOOSER_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = AUTH_PROVIDER_CHOOSER_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = AUTH_PROVIDER_CHOOSER_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(AUTH_PROVIDER_CHOOSER_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  var LOGIN_BUTTON_STYLE_MARKUP =
    'mpr-login-button[data-mpr-login-mounted="true"]{display:contents}' +
    ".mpr-login-button{display:inline-flex;flex-direction:column;gap:0.5rem;inline-size:var(--mpr-login-button-inline-size,auto);max-inline-size:100%;--mpr-login-button-theme-background:#fff;--mpr-login-button-theme-border-color:#dadce0;--mpr-login-button-theme-color:#1f1f1f;--mpr-login-button-theme-hover-background:#f8faff;--mpr-login-button-focus-color:rgba(66,133,244,0.5);--mpr-login-button-radius:0.5rem;--mpr-login-button-height:32px;--mpr-login-button-padding-inline:0.95rem;--mpr-login-button-font-size:0.95rem}" +
    ".mpr-login-button .mpr-auth-actions{inline-size:100%;padding:0}" +
    ".mpr-login-button .mpr-auth-actions__controls{inline-size:100%}" +
    ".mpr-login-button .mpr-auth-google-button{min-block-size:var(--mpr-login-button-height);max-inline-size:100%;border-radius:var(--mpr-login-button-radius)}" +
    ".mpr-login-button .mpr-auth-provider-chooser__action{inline-size:100%;min-inline-size:0;min-block-size:var(--mpr-login-button-height);padding:0 var(--mpr-login-button-padding-inline);border-radius:var(--mpr-login-button-radius);font-size:var(--mpr-login-button-font-size);transition:background-color 140ms ease,border-color 140ms ease,box-shadow 140ms ease}" +
    ".mpr-login-button .mpr-auth-provider-chooser__action--apple{min-inline-size:140px;min-block-size:44px;padding:4.4px}" +
    ".mpr-login-button .mpr-auth-provider-chooser__action--google{border-color:var(--mpr-login-button-border-color,var(--mpr-login-button-theme-border-color));background:var(--mpr-login-button-background,var(--mpr-login-button-theme-background));color:var(--mpr-login-button-color,var(--mpr-login-button-theme-color))}" +
    ".mpr-login-button .mpr-auth-provider-chooser__action--google:hover{background:var(--mpr-login-button-hover-background,var(--mpr-login-button-theme-hover-background))}" +
    ".mpr-login-button .mpr-auth-provider-chooser__action:focus-visible{outline:3px solid var(--mpr-login-button-focus-color);outline-offset:2px}" +
    ".mpr-login-button .mpr-auth-provider-chooser__action:disabled{cursor:progress;opacity:0.82}" +
    ".mpr-login-button .mpr-auth-actions[data-mpr-auth-action-status='error'] .mpr-auth-actions__status{color:var(--mpr-color-error,#dc2626)}" +
    ".mpr-login-button" +
    '[data-mpr-login-theme="outline"]{--mpr-login-button-theme-background:#fff;--mpr-login-button-theme-border-color:#dadce0;--mpr-login-button-theme-color:#1f1f1f;--mpr-login-button-theme-hover-background:#f8faff}' +
    ".mpr-login-button" +
    '[data-mpr-login-theme="filled_blue"]{--mpr-login-button-theme-background:#4285f4;--mpr-login-button-theme-border-color:#4285f4;--mpr-login-button-theme-color:#fff;--mpr-login-button-theme-hover-background:#1a73e8}' +
    ".mpr-login-button" +
    '[data-mpr-login-theme="filled_black"]{--mpr-login-button-theme-background:#202124;--mpr-login-button-theme-border-color:#202124;--mpr-login-button-theme-color:#fff;--mpr-login-button-theme-hover-background:#000}' +
    ".mpr-login-button" +
    '[data-mpr-login-size="small"]{--mpr-login-button-height:20px;--mpr-login-button-padding-inline:0.7rem;--mpr-login-button-font-size:0.84rem}' +
    ".mpr-login-button" +
    '[data-mpr-login-size="large"]{--mpr-login-button-height:40px;--mpr-login-button-padding-inline:1.1rem;--mpr-login-button-font-size:1rem}' +
    ".mpr-login-button" +
    '[data-mpr-login-shape="pill"]{--mpr-login-button-radius:999px}' +
    "mpr-login-button[data-mpr-auth-providers='google'] .mpr-login-button" +
    '[data-mpr-login-shape="square"]{--mpr-login-button-radius:0.4rem;inline-size:var(--mpr-login-button-height)}' +
    "mpr-login-button[data-mpr-auth-providers='google'] .mpr-login-button" +
    '[data-mpr-login-shape="circle"]{--mpr-login-button-radius:50%;inline-size:var(--mpr-login-button-height)}' +
    ".mpr-login-button[data-mpr-login-shape='square'] .mpr-auth-provider-chooser__action--google,.mpr-login-button[data-mpr-login-shape='circle'] .mpr-auth-provider-chooser__action--google{inline-size:var(--mpr-login-button-height);min-inline-size:var(--mpr-login-button-height);padding:0;grid-template-columns:1fr;place-items:center;column-gap:0}" +
    ".mpr-login-button[data-mpr-login-shape='square'] .mpr-auth-google-button,.mpr-login-button[data-mpr-login-shape='circle'] .mpr-auth-google-button{inline-size:var(--mpr-login-button-height);block-size:var(--mpr-login-button-height);min-inline-size:var(--mpr-login-button-height);min-block-size:var(--mpr-login-button-height)}" +
    ".mpr-login-button[data-mpr-login-shape='square'] .mpr-auth-provider-chooser__mark--google,.mpr-login-button[data-mpr-login-shape='circle'] .mpr-auth-provider-chooser__mark--google{grid-column:1;grid-row:1}" +
    ".mpr-login-button[data-mpr-login-shape='square'] .mpr-auth-provider-chooser__action--google .mpr-auth-provider-chooser__label,.mpr-login-button[data-mpr-login-shape='circle'] .mpr-auth-provider-chooser__action--google .mpr-auth-provider-chooser__label{position:absolute;inline-size:1px;block-size:1px;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap}" +
    "@media (prefers-reduced-motion:reduce){.mpr-login-button .mpr-auth-provider-chooser__action{transition:none}}";

  function ensureLoginButtonStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    ensureAuthProviderChooserStyles(documentObject);
    if (documentObject.getElementById(LOGIN_BUTTON_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = LOGIN_BUTTON_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = LOGIN_BUTTON_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(LOGIN_BUTTON_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function normalizeHeaderOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var brandSource = deepMergeOptions({}, HEADER_DEFAULTS.brand, options.brand || {});
    var settingsSource = deepMergeOptions(
      {},
      HEADER_DEFAULTS.settings,
      options.settings || {},
    );
    var themeSource = deepMergeOptions(
      {},
      HEADER_DEFAULTS.themeToggle,
      options.themeToggle || {},
    );

    var stickyValue = HEADER_DEFAULTS.sticky;
    if (Object.prototype.hasOwnProperty.call(options, "sticky")) {
      stickyValue = normalizeBooleanAttribute(
        options.sticky,
        HEADER_DEFAULTS.sticky,
      );
    }

    var sizeValue = "normal";
    if (
      typeof options.size === "string" &&
      options.size.trim().toLowerCase() === "small"
    ) {
      sizeValue = "small";
    }

    var navLinksSource = Array.isArray(options.navLinks)
      ? options.navLinks
      : [];
    var navLinks = navLinksSource
      .map(function (link) {
        if (!link || typeof link !== "object") {
          return null;
        }
        var label =
          typeof link.label === "string" && link.label.trim()
            ? link.label.trim()
            : null;
        var hrefValue = null;
        if (typeof link.href === "string" && link.href.trim()) {
          hrefValue = link.href.trim();
        } else if (typeof link.url === "string" && link.url.trim()) {
          hrefValue = link.url.trim();
        }
        if (!label || !hrefValue) {
          return null;
        }
        return {
          label: label,
          href: hrefValue,
        };
      })
      .filter(Boolean);

    var horizontalLinks = normalizeHorizontalLinksConfig(
      options.horizontalLinks,
      HEADER_DEFAULTS.horizontalLinks,
    );
    var authTransition = normalizeHeaderAuthTransition(options.authTransition);

    var authOptions = options.auth ? createAuthOptions(options.auth) : null;
    var derivedTenantId = authOptions ? authOptions.tenantId : null;

    var themeDefaults = {
      enabled: true,
      ariaLabel: "Toggle theme",
    };
    var themeNormalized = normalizeThemeToggleCore(themeSource, themeDefaults);
    if (
      typeof options.initialTheme === "string" &&
      !themeNormalized.initialMode
    ) {
      themeNormalized.initialMode = options.initialTheme.trim();
    }

    var brandLabel =
      typeof brandSource.label === "string" && brandSource.label.trim()
        ? brandSource.label.trim()
        : HEADER_DEFAULTS.brand.label;
    var brandHref =
      typeof brandSource.href === "string" && brandSource.href.trim()
        ? brandSource.href.trim()
        : HEADER_DEFAULTS.brand.href;
    var signOutLabel =
      typeof options.signOutLabel === "string" && options.signOutLabel.trim()
        ? options.signOutLabel.trim()
        : HEADER_DEFAULTS.signOutLabel;
    var signInRedirectUrl =
      normalizeHeaderSignInRedirectUrl(options.signInRedirectUrl);
    var profileLabel =
      typeof options.profileLabel === "string" && options.profileLabel.trim()
        ? options.profileLabel.trim()
        : HEADER_DEFAULTS.profileLabel;
    var userMenuSource =
      options.userMenu && typeof options.userMenu === "object"
        ? options.userMenu
        : {};
    var userMenuDisplayMode = normalizeHeaderUserMenuDisplayMode(
      userMenuSource.displayMode,
    );
    var userMenuLogoutUrl = normalizeHeaderUserMenuLogoutUrl(
      userMenuSource.logoutUrl,
      brandHref,
    );
    var userMenuAvatarUrl = normalizeHeaderUserMenuOptionalValue(
      userMenuSource.avatarUrl,
    );
    var userMenuAvatarLabel = normalizeHeaderUserMenuOptionalValue(
      userMenuSource.avatarLabel,
    );

    return {
      brand: {
        label: brandLabel,
        href: brandHref,
      },
      navLinks: navLinks,
      horizontalLinks: horizontalLinks,
      authTransition: authTransition,
      signInRedirectUrl: signInRedirectUrl,
      settings: {
        enabled: Boolean(settingsSource.enabled),
        label:
          typeof settingsSource.label === "string" && settingsSource.label.trim()
            ? settingsSource.label.trim()
            : HEADER_DEFAULTS.settings.label,
      },
      themeToggle: {
        attribute: themeNormalized.attribute,
        targets: themeNormalized.targets,
        modes: themeNormalized.modes,
        initialMode: themeNormalized.initialMode,
      },
      signOutLabel: signOutLabel,
      profileLabel: profileLabel,
      userMenu: {
        displayMode: userMenuDisplayMode,
        logoutUrl: userMenuLogoutUrl,
        logoutLabel: signOutLabel,
        avatarUrl: userMenuAvatarUrl,
        avatarLabel: userMenuAvatarLabel,
      },
      tenantId: derivedTenantId,
      auth: authOptions,
      sticky: stickyValue,
      size: sizeValue,
    };
  }

  function buildHeaderMarkup(options, renderUserMenu) {
    var brandHref = escapeHtml(options.brand.href);
    var brandLabel = escapeHtml(options.brand.label);
    var stickyAttribute =
      options && options.sticky === false
        ? ' data-mpr-sticky="false"'
        : "";
    var rootClass = HEADER_ROOT_CLASS;
    if (options.size === "small") {
      rootClass += " " + HEADER_ROOT_CLASS + "--small";
    }
    var navMarkup = options.navLinks
      .map(function (link) {
        var normalizedLink = normalizeLinkForRendering(link, {
          target: HEADER_LINK_DEFAULT_TARGET,
          rel: HEADER_LINK_DEFAULT_REL,
        });
        if (!normalizedLink) {
          return "";
        }
        var linkHref = escapeHtml(normalizedLink.href);
        var linkLabel = escapeHtml(normalizedLink.label);
        var linkTarget = escapeHtml(
          normalizedLink.target || HEADER_LINK_DEFAULT_TARGET,
        );
        var linkRel = escapeHtml(normalizedLink.rel || HEADER_LINK_DEFAULT_REL);
        return (
          '<a href="' +
          linkHref +
          '" target="' +
          linkTarget +
          '" rel="' +
          linkRel +
          '">' +
          linkLabel +
          "</a>"
        );
      })
      .filter(Boolean)
      .join("");
    var horizontalLinksConfig =
      options.horizontalLinks && typeof options.horizontalLinks === "object"
        ? options.horizontalLinks
        : HEADER_DEFAULTS.horizontalLinks;
    var horizontalLinksAlignment = horizontalLinksConfig.alignment
      ? escapeHtml(horizontalLinksConfig.alignment)
      : escapeHtml(HEADER_DEFAULTS.horizontalLinks.alignment);
    var horizontalLinksMarkup = Array.isArray(horizontalLinksConfig.links)
      ? horizontalLinksConfig.links
          .map(function (link) {
            var normalizedLink = normalizeLinkForRendering(link, {});
            if (!normalizedLink) {
              return "";
            }
            var linkHref = escapeHtml(normalizedLink.href);
            var linkLabel = escapeHtml(normalizedLink.label);
            var linkTarget = normalizedLink.target
              ? escapeHtml(normalizedLink.target)
              : "";
            var linkRel = normalizedLink.rel ? escapeHtml(normalizedLink.rel) : "";
            if (linkTarget === "_blank" && !linkRel) {
              linkRel = HEADER_LINK_DEFAULT_REL;
            }
            var extraAttributes = "";
            if (linkTarget) {
              extraAttributes += ' target="' + linkTarget + '"';
            }
            if (linkRel) {
              extraAttributes += ' rel="' + linkRel + '"';
            }
            return (
              '<a href="' +
              linkHref +
              '"' +
              extraAttributes +
              ">" +
              linkLabel +
              "</a>"
            );
          })
          .filter(Boolean)
          .join("")
      : "";
    var userMenuMarkup = "";
    if (renderUserMenu !== false && options && options.userMenu && options.tenantId) {
      var userMenuAttributes =
        ' class="' +
        HEADER_ROOT_CLASS +
        '__user" data-mpr-header="user-menu" display-mode="' +
        escapeHtml(options.userMenu.displayMode) +
        '" logout-url="' +
        escapeHtml(options.userMenu.logoutUrl) +
        '" logout-label="' +
        escapeHtml(options.userMenu.logoutLabel) +
        '" auth-config="' +
        escapeHtml(JSON.stringify(options.auth)) +
        '"';
      if (options.userMenu.avatarUrl) {
        userMenuAttributes +=
          ' avatar-url="' + escapeHtml(options.userMenu.avatarUrl) + '"';
      }
      if (options.userMenu.avatarLabel) {
        userMenuAttributes +=
          ' avatar-label="' + escapeHtml(options.userMenu.avatarLabel) + '"';
      }
      userMenuMarkup = "<mpr-user" + userMenuAttributes + "></mpr-user>";
    }
    var authTransitionMarkup = buildHeaderAuthTransitionMarkup(
      options.authTransition,
    );

    return (
      '<header class="' +
      rootClass +
      '" role="banner"' +
      stickyAttribute +
      ">" +
      '<div class="' +
      HEADER_ROOT_CLASS +
      '__inner">' +
      '<div class="' +
      HEADER_ROOT_CLASS +
      '__brand">' +
      '<a data-mpr-header="brand" class="' +
      HEADER_ROOT_CLASS +
      '__brand-link" href="' +
      brandHref +
      '" target="_blank" rel="noopener noreferrer">' +
      brandLabel +
      "</a>" +
      "</div>" +
      '<nav data-mpr-header="nav" class="' +
      HEADER_ROOT_CLASS +
      '__nav" aria-label="Primary navigation">' +
      navMarkup +
      "</nav>" +
      '<nav data-mpr-header="horizontal-links" class="' +
      HEADER_ROOT_CLASS +
      '__horizontal-links" aria-label="Utility links" data-mpr-align="' +
      horizontalLinksAlignment +
      '">' +
      horizontalLinksMarkup +
      "</nav>" +
      '<div class="' +
      HEADER_ROOT_CLASS +
      '__actions">' +
      '<button type="button" class="' +
      HEADER_ROOT_CLASS +
      '__button" data-mpr-header="settings-button">Settings</button>' +
      '<div class="' +
      HEADER_ROOT_CLASS +
      '__auth-actions" data-mpr-header="auth-actions"></div>' +
      userMenuMarkup +
      "</div>" +
      "</div>" +
      "</header>" +
      authTransitionMarkup +
      buildHeaderSettingsModalMarkup(options.settings.label)
    );
  }

  function buildHeaderAuthTransitionMarkup(authTransition) {
    var config =
      authTransition && typeof authTransition === "object"
        ? authTransition
        : HEADER_DEFAULTS.authTransition;
    var title = escapeHtml(
      normalizeHeaderAuthTransitionOptionalValue(
        config.title,
        HEADER_DEFAULTS.authTransition.title,
      ),
    );
    var message = escapeHtml(
      normalizeHeaderAuthTransitionOptionalValue(
        config.message,
        HEADER_DEFAULTS.authTransition.message,
      ),
    );
    return (
      '<div data-mpr-header="auth-transition" class="' +
      HEADER_ROOT_CLASS +
      '__auth-transition" aria-hidden="true" data-mpr-visible="false">' +
      '<div class="' +
      HEADER_ROOT_CLASS +
      '__auth-transition-panel" role="status" aria-live="polite">' +
      '<div class="' +
      HEADER_ROOT_CLASS +
      '__auth-transition-spinner" data-mpr-header="auth-transition-spinner" aria-hidden="true"></div>' +
      '<p class="' +
      HEADER_ROOT_CLASS +
      '__auth-transition-title" data-mpr-header="auth-transition-title">' +
      title +
      "</p>" +
      '<p class="' +
      HEADER_ROOT_CLASS +
      '__auth-transition-message" data-mpr-header="auth-transition-message">' +
      message +
      "</p>" +
      "</div>" +
      "</div>"
    );
  }

  function buildHeaderSettingsModalMarkup(label) {
    var heading = escapeHtml(label || HEADER_DEFAULTS.settings.label);
    return (
      '<div data-mpr-header="settings-modal" data-mpr-modal="container" aria-hidden="true" data-mpr-modal-open="false">' +
      '<div data-mpr-modal="backdrop" data-mpr-header="settings-modal-backdrop"></div>' +
      '<div data-mpr-modal="dialog" data-mpr-header="settings-modal-dialog" role="dialog" aria-modal="true" tabindex="-1">' +
      '<header data-mpr-modal="header" data-mpr-header="settings-modal-header">' +
      '<h1 data-mpr-modal="title" data-mpr-header="settings-modal-title">' +
      heading +
      "</h1>" +
      '<button type="button" data-mpr-modal="close" data-mpr-header="settings-modal-close" aria-label="Close settings">&times;</button>' +
      "</header>" +
      '<div data-mpr-modal="body" data-mpr-header="settings-modal-body">' +
      HEADER_SETTINGS_PLACEHOLDER_MARKUP +
      "</div>" +
      "</div>" +
      "</div>"
    );
  }

  function resolveHeaderElements(hostElement) {
    return {
      root: hostElement.querySelector("header." + HEADER_ROOT_CLASS),
      nav: hostElement.querySelector('[data-mpr-header="nav"]'),
      horizontalLinks: hostElement.querySelector('[data-mpr-header="horizontal-links"]'),
      brand: hostElement.querySelector('[data-mpr-header="brand"]'),
      brandContainer: hostElement.querySelector("." + HEADER_ROOT_CLASS + "__brand"),
      authActions: hostElement.querySelector(
        '[data-mpr-header="auth-actions"]',
      ),
      settingsButton: hostElement.querySelector(
        '[data-mpr-header="settings-button"]',
      ),
      authTransition: hostElement.querySelector(
        '[data-mpr-header="auth-transition"]',
      ),
      authTransitionTitle: hostElement.querySelector(
        '[data-mpr-header="auth-transition-title"]',
      ),
      authTransitionMessage: hostElement.querySelector(
        '[data-mpr-header="auth-transition-message"]',
      ),
      userMenu: hostElement.querySelector(
        '[data-mpr-header="user-menu"]',
      ),
      settingsModal: hostElement.querySelector(
        '[data-mpr-header="settings-modal"]',
      ),
      settingsModalDialog: hostElement.querySelector(
        '[data-mpr-header="settings-modal-dialog"]',
      ),
      settingsModalClose: hostElement.querySelector(
        '[data-mpr-header="settings-modal-close"]',
      ),
      settingsModalBackdrop: hostElement.querySelector(
        '[data-mpr-header="settings-modal-backdrop"]',
      ),
      settingsModalTitle: hostElement.querySelector(
        '[data-mpr-header="settings-modal-title"]',
      ),
      actions: hostElement.querySelector("." + HEADER_ROOT_CLASS + "__actions"),
    };
  }

  function appendHeaderSlotNodes(target, nodes, mode) {
    if (!target || !nodes || !nodes.length) {
      return;
    }
    var usePrepend = mode === "prepend";
    nodes.forEach(function appendNode(node) {
      if (!node) {
        return;
      }
      if (
        usePrepend &&
        typeof target.insertBefore === "function" &&
        target.firstChild
      ) {
        target.insertBefore(node, target.firstChild);
        return;
      }
      if (typeof target.appendChild === "function") {
        target.appendChild(node);
      }
    });
  }

  function applyHeaderSlotContent(slotMap, elements) {
    if (!slotMap || !elements) {
      return;
    }
    if (
      slotMap.brand &&
      slotMap.brand.length &&
      elements.brandContainer &&
      typeof elements.brandContainer.appendChild === "function"
    ) {
      clearNodeContents(elements.brandContainer);
      slotMap.brand.forEach(function appendBrand(node) {
        elements.brandContainer.appendChild(node);
      });
    }
    if (slotMap["nav-left"] && elements.nav) {
      appendHeaderSlotNodes(elements.nav, slotMap["nav-left"], "prepend");
    }
    if (slotMap["nav-right"] && elements.nav) {
      appendHeaderSlotNodes(elements.nav, slotMap["nav-right"], "append");
    }
    if (slotMap.aux && elements.actions) {
      appendHeaderSlotNodes(elements.actions, slotMap.aux, "append");
    }
  }

  function isUserMenuElement(node) {
    var tagName = node ? node.tagName || node.nodeName : null;
    return typeof tagName === "string" && tagName.toLowerCase() === "mpr-user";
  }

  function findUserMenuNode(node) {
    if (!node) {
      return null;
    }
    if (isUserMenuElement(node)) {
      return node;
    }
    if (typeof node.querySelector === "function") {
      var nested = node.querySelector("mpr-user");
      if (nested) {
        return nested;
      }
    }
    return null;
  }

  function resolveHeaderUserMenuSlot(slotMap) {
    if (!slotMap || !Array.isArray(slotMap.aux)) {
      return null;
    }
    for (var index = 0; index < slotMap.aux.length; index += 1) {
      var candidate = findUserMenuNode(slotMap.aux[index]);
      if (candidate) {
        return candidate;
      }
    }
    return null;
  }

  function prepareHeaderUserMenuSlotElement(userMenuElement) {
    if (!userMenuElement || typeof userMenuElement.setAttribute !== "function") {
      return;
    }
    captureHeaderUserMenuOverrides(userMenuElement);
    userMenuElement.setAttribute("data-mpr-header", "user-menu");
    if (
      userMenuElement.classList &&
      typeof userMenuElement.classList.add === "function"
    ) {
      userMenuElement.classList.add(HEADER_ROOT_CLASS + "__user");
      return;
    }
    if (typeof userMenuElement.className === "string") {
      var className = userMenuElement.className;
      if (className.indexOf(HEADER_ROOT_CLASS + "__user") === -1) {
        userMenuElement.className = className
          ? className + " " + HEADER_ROOT_CLASS + "__user"
          : HEADER_ROOT_CLASS + "__user";
      }
    }
  }

  function createViewportModalController(config) {
    if (
      !config ||
      !config.modalElement ||
      !config.dialogElement
    ) {
      return null;
    }
    var modal = config.modalElement;
    var dialog = config.dialogElement;
    var closeButton = config.closeButton;
    var backdrop = config.backdropElement;
    var labelElement = config.labelElement;
    var ownerDocument =
      config.ownerDocument ||
      modal.ownerDocument ||
      global.document ||
      null;
    var bodyElement = ownerDocument ? ownerDocument.body : null;
    var previousFocus = null;
    var previousOverflow = null;
    var resizeHandler = null;
    var scrollHandler = null;
    var pendingOffsetFrame = null;
    var defaultLabel =
      typeof config.defaultLabel === "string" && config.defaultLabel.trim()
        ? config.defaultLabel.trim()
        : "";

    function safeCall(fn) {
      if (typeof fn === "function") {
        try {
          return fn();
        } catch (_error) {
          return 0;
        }
      }
      return 0;
    }

    function updateLabel(nextLabel) {
      var labelValue =
        typeof nextLabel === "string" && nextLabel.trim()
          ? nextLabel.trim()
          : defaultLabel;
      if (labelElement) {
        labelElement.textContent = labelValue;
      }
      dialog.setAttribute("aria-label", labelValue || defaultLabel || "");
    }

    function computeOffsets() {
      var headerOffset = safeCall(config.getHeaderOffset) || 0;
      var footerOffset = safeCall(config.getFooterOffset) || 0;
      var topOffset = Math.max(0, Math.round(headerOffset));
      var bottomOffset = Math.max(0, Math.round(footerOffset));
      modal.style.setProperty("--mpr-modal-top-offset", topOffset + "px");
      modal.style.setProperty("--mpr-modal-bottom-offset", bottomOffset + "px");
    }

    function applyModalOffsets() {
      if (
        global.window &&
        typeof global.window.requestAnimationFrame === "function"
      ) {
        if (pendingOffsetFrame) {
          global.window.cancelAnimationFrame(pendingOffsetFrame);
        }
        pendingOffsetFrame = global.window.requestAnimationFrame(function () {
          pendingOffsetFrame = null;
          computeOffsets();
        });
        return;
      }
      computeOffsets();
    }

    function subscribeToResize() {
      if (
        !global.window ||
        typeof global.window.addEventListener !== "function" ||
        resizeHandler
      ) {
        return;
      }
      resizeHandler = function handleViewportModalResize() {
        if (modal.getAttribute("data-mpr-modal-open") === "true") {
          applyModalOffsets();
        }
      };
      global.window.addEventListener("resize", resizeHandler);
    }

    function subscribeToScroll() {
      var view =
        (ownerDocument && ownerDocument.defaultView) ||
        global.window ||
        null;
      if (!view || typeof view.addEventListener !== "function" || scrollHandler) {
        return;
      }
      scrollHandler = function handleViewportModalScroll() {
        if (modal.getAttribute("data-mpr-modal-open") === "true") {
          applyModalOffsets();
        }
      };
      view.addEventListener("scroll", scrollHandler, { passive: true });
    }

    function unsubscribeFromScroll() {
      var view =
        (ownerDocument && ownerDocument.defaultView) ||
        global.window ||
        null;
      if (scrollHandler && view && typeof view.removeEventListener === "function") {
        view.removeEventListener("scroll", scrollHandler);
      }
      scrollHandler = null;
    }

    function unsubscribeFromResize() {
      if (
        resizeHandler &&
        global.window &&
        typeof global.window.removeEventListener === "function"
      ) {
        global.window.removeEventListener("resize", resizeHandler);
      }
      resizeHandler = null;
    }

    function lockScroll() {
      if (!bodyElement) {
        return;
      }
      if (previousOverflow === null) {
        previousOverflow =
          typeof bodyElement.style.overflow === "string"
            ? bodyElement.style.overflow
            : "";
      }
      bodyElement.style.overflow = "hidden";
    }

    function unlockScroll() {
      if (!bodyElement || previousOverflow === null) {
        return;
      }
      bodyElement.style.overflow = previousOverflow;
      previousOverflow = null;
    }

    function setModalState(isOpen) {
      modal.setAttribute("data-mpr-modal-open", isOpen ? "true" : "false");
      modal.setAttribute("aria-hidden", isOpen ? "false" : "true");
      if (isOpen) {
        lockScroll();
        applyModalOffsets();
        subscribeToResize();
        subscribeToScroll();
      } else {
        unlockScroll();
        unsubscribeFromResize();
        unsubscribeFromScroll();
      }
    }

    function restoreFocus() {
      if (
        previousFocus &&
        typeof previousFocus.focus === "function" &&
        previousFocus.ownerDocument
      ) {
        previousFocus.focus();
      }
      previousFocus = null;
    }

    function openModal() {
      previousFocus =
        ownerDocument && ownerDocument.activeElement
          ? ownerDocument.activeElement
          : null;
      setModalState(true);
      if (typeof dialog.focus === "function") {
        dialog.focus();
      }
    }

    function closeModal() {
      if (modal.getAttribute("data-mpr-modal-open") === "true") {
        setModalState(false);
      } else {
        unsubscribeFromResize();
      }
      restoreFocus();
    }

    function handleBackdrop(eventObject) {
      if (!eventObject) {
        return;
      }
      if (
        eventObject.target === modal ||
        (backdrop && eventObject.target === backdrop)
      ) {
        eventObject.preventDefault();
        closeModal();
      }
    }

    function handleKeydown(eventObject) {
      if (!eventObject || typeof eventObject.key !== "string") {
        return;
      }
      if (eventObject.key === "Escape") {
        eventObject.preventDefault();
        closeModal();
      }
    }

    if (closeButton && typeof closeButton.addEventListener === "function") {
      closeButton.addEventListener("click", closeModal);
    }
    if (backdrop && typeof backdrop.addEventListener === "function") {
      backdrop.addEventListener("click", handleBackdrop);
    }
    modal.addEventListener("click", handleBackdrop);
    modal.addEventListener("keydown", handleKeydown);
    updateLabel(config.labelText);
    applyModalOffsets();

    return {
      open: openModal,
      close: closeModal,
      updateLabel: updateLabel,
      destroy: function destroy() {
        if (modal) {
          setModalState(false);
        }
        restoreFocus();
        if (closeButton && typeof closeButton.removeEventListener === "function") {
          closeButton.removeEventListener("click", closeModal);
        }
        if (backdrop && typeof backdrop.removeEventListener === "function") {
          backdrop.removeEventListener("click", handleBackdrop);
        }
        modal.removeEventListener("click", handleBackdrop);
        modal.removeEventListener("keydown", handleKeydown);
        unsubscribeFromResize();
        unsubscribeFromScroll();
        if (
          pendingOffsetFrame &&
          global.window &&
          typeof global.window.cancelAnimationFrame === "function"
        ) {
          global.window.cancelAnimationFrame(pendingOffsetFrame);
        }
        pendingOffsetFrame = null;
      },
    };
  }

  function createHeaderSettingsModalController(elements, labelText) {
    if (!elements) {
      return null;
    }
    return createViewportModalController({
      modalElement: elements.settingsModal,
      dialogElement: elements.settingsModalDialog,
      closeButton: elements.settingsModalClose,
      backdropElement: elements.settingsModalBackdrop,
      labelElement: elements.settingsModalTitle,
      labelText: labelText || HEADER_DEFAULTS.settings.label,
      ownerDocument:
        (elements.settingsModal && elements.settingsModal.ownerDocument) ||
        global.document ||
        null,
      getHeaderOffset: function getHeaderOffset() {
        if (!elements.root) {
          return 0;
        }
        if (typeof elements.root.getBoundingClientRect === "function") {
          var rect = elements.root.getBoundingClientRect();
          return Math.max(0, Math.round(rect.bottom));
        }
        if (typeof elements.root.offsetHeight === "number") {
          return Math.max(0, elements.root.offsetHeight);
        }
        return 0;
      },
      getFooterOffset: function getFooterOffset() {
        var doc =
          (elements.settingsModal && elements.settingsModal.ownerDocument) ||
          global.document ||
          null;
        if (!doc) {
          return 0;
        }
        var footerElement =
          doc.querySelector('[data-mpr-footer="root"]') ||
          doc.querySelector("footer.mpr-footer");
        if (!footerElement) {
          return 0;
        }
        if (typeof footerElement.getBoundingClientRect === "function") {
          var rect = footerElement.getBoundingClientRect();
          return Math.max(0, Math.round(rect.height));
        }
        if (typeof footerElement.offsetHeight === "number") {
          return Math.max(0, footerElement.offsetHeight);
        }
        return 0;
      },
    });
  }

  function mountHeaderDom(hostElement, options, renderUserMenu) {
    if (!hostElement || typeof hostElement !== "object") {
      throw new Error("mountHeaderDom requires a host element");
    }
    hostElement.innerHTML = buildHeaderMarkup(options, renderUserMenu);
    var elements = resolveHeaderElements(hostElement);
    if (!elements.root) {
      throw new Error("mountHeaderDom failed to locate the header root");
    }
    applyHeaderStickyState(elements.root, options && options.sticky, hostElement);
    return elements;
  }

  function renderHeaderNav(navElement, navLinks) {
    if (!navElement) {
      return;
    }
    navElement.innerHTML = navLinks
      .map(function (link) {
        var normalizedLink = normalizeLinkForRendering(link, {
          target: HEADER_LINK_DEFAULT_TARGET,
          rel: HEADER_LINK_DEFAULT_REL,
        });
        if (!normalizedLink) {
          return "";
        }
        var hrefValue = escapeHtml(normalizedLink.href);
        var labelValue = escapeHtml(normalizedLink.label);
        var targetValue = escapeHtml(
          normalizedLink.target || HEADER_LINK_DEFAULT_TARGET,
        );
        var relValue = escapeHtml(normalizedLink.rel || HEADER_LINK_DEFAULT_REL);
        return (
          '<a href="' +
          hrefValue +
          '" target="' +
          targetValue +
          '" rel="' +
          relValue +
          '">' +
          labelValue +
          "</a>"
        );
      })
      .filter(Boolean)
      .join("");
  }

  function renderHeaderHorizontalLinks(containerElement, horizontalLinks) {
    if (!containerElement) {
      return;
    }
    var config =
      horizontalLinks && typeof horizontalLinks === "object"
        ? horizontalLinks
        : HEADER_DEFAULTS.horizontalLinks;
    var alignment =
      typeof config.alignment === "string" && config.alignment.trim()
        ? config.alignment.trim()
        : HEADER_DEFAULTS.horizontalLinks.alignment;
    if (typeof containerElement.setAttribute === "function") {
      containerElement.setAttribute("data-mpr-align", alignment);
    }
    var items = Array.isArray(config.links) ? config.links : [];
    containerElement.innerHTML = items
      .map(function (link) {
        var normalizedLink = normalizeLinkForRendering(link, {});
        if (!normalizedLink) {
          return "";
        }
        var hrefValue = escapeHtml(normalizedLink.href);
        var labelValue = escapeHtml(normalizedLink.label);
        var targetValue = normalizedLink.target
          ? escapeHtml(normalizedLink.target)
          : "";
        var relValue = normalizedLink.rel ? escapeHtml(normalizedLink.rel) : "";
        if (targetValue === "_blank" && !relValue) {
          relValue = HEADER_LINK_DEFAULT_REL;
        }
        var extraAttributes = "";
        if (targetValue) {
          extraAttributes += ' target="' + targetValue + '"';
        }
        if (relValue) {
          extraAttributes += ' rel="' + relValue + '"';
        }
        return (
          '<a href="' +
          hrefValue +
          '"' +
          extraAttributes +
          ">" +
          labelValue +
          "</a>"
        );
      })
      .filter(Boolean)
      .join("");
  }

  function shouldShowHeaderAuthTransition(
    authTransition,
    status,
    isReady,
    signInRedirectPending,
  ) {
    if (!authTransition || authTransition.enabled !== true) {
      return false;
    }
    if (
      status === AUTH_CONTROLLER_STATUS.BOOTSTRAPPING ||
      status === AUTH_CONTROLLER_STATUS.AUTHENTICATING
    ) {
      return true;
    }
    if (
      status === AUTH_CONTROLLER_STATUS.AUTHENTICATED &&
      signInRedirectPending === true
    ) {
      return true;
    }
    if (
      status === AUTH_CONTROLLER_STATUS.AUTHENTICATED &&
      authTransition.completionEvent &&
      !isReady
    ) {
      return true;
    }
    return false;
  }

  function updateHeaderAuthView(
    hostElement,
    elements,
    options,
    state,
    authTransitionReady,
    signInRedirectPending,
  ) {
    if (!elements.root) {
      return;
    }
    var authStatus =
      state && typeof state.status === "string"
        ? state.status
        : AUTH_CONTROLLER_STATUS.UNAUTHENTICATED;
    elements.root.setAttribute("data-mpr-auth-status", authStatus);
    if (hostElement && typeof hostElement.setAttribute === "function") {
      hostElement.setAttribute("data-mpr-auth-status", authStatus);
    }
    var authTransitionVisible = shouldShowHeaderAuthTransition(
      options.authTransition,
      authStatus,
      authTransitionReady,
      signInRedirectPending,
    );
    elements.root.classList.toggle(
      HEADER_ROOT_CLASS + "--auth-transition-active",
      authTransitionVisible,
    );
    if (elements.authTransition) {
      elements.authTransition.setAttribute(
        "data-mpr-visible",
        authTransitionVisible ? "true" : "false",
      );
      elements.authTransition.setAttribute(
        "aria-hidden",
        authTransitionVisible ? "false" : "true",
      );
    }
    if (!state || !state.profile) {
      elements.root.classList.remove(
        HEADER_ROOT_CLASS + "--authenticated",
        HEADER_ROOT_CLASS + "--no-auth",
      );
      return;
    }
    elements.root.classList.add(HEADER_ROOT_CLASS + "--authenticated");
  }

  function applyHeaderStickyState(headerRootElement, sticky, hostElement) {
    if (!headerRootElement) {
      return;
    }
    if (sticky === false) {
      if (typeof headerRootElement.setAttribute === "function") {
        headerRootElement.setAttribute("data-mpr-sticky", "false");
      }
    } else if (typeof headerRootElement.removeAttribute === "function") {
      headerRootElement.removeAttribute("data-mpr-sticky");
    }
    if (!hostElement) {
      return;
    }
    if (sticky === false) {
      if (typeof hostElement.setAttribute === "function") {
        hostElement.setAttribute("data-mpr-sticky", "false");
      }
    } else if (typeof hostElement.removeAttribute === "function") {
      hostElement.removeAttribute("data-mpr-sticky");
    }
  }

  function applyHeaderUserMenuAttributes(userMenuElement, options) {
    if (
      !userMenuElement ||
      !options ||
      !options.userMenu ||
      typeof userMenuElement.setAttribute !== "function"
    ) {
      return;
    }
    var overrideEntries = resolveHeaderUserMenuOverrides(userMenuElement);
    setHeaderUserMenuAttribute(
      userMenuElement,
      "display-mode",
      options.userMenu.displayMode,
      overrideEntries,
    );
    setHeaderUserMenuAttribute(
      userMenuElement,
      "logout-url",
      options.userMenu.logoutUrl,
      overrideEntries,
    );
    setHeaderUserMenuAttribute(
      userMenuElement,
      "logout-label",
      options.userMenu.logoutLabel,
      overrideEntries,
    );
    setHeaderUserMenuAttribute(
      userMenuElement,
      AUTH_CONFIG_ATTRIBUTE,
      options.auth ? JSON.stringify(options.auth) : null,
      overrideEntries,
    );
    setHeaderUserMenuAttribute(
      userMenuElement,
      "avatar-url",
      options.userMenu.avatarUrl,
      overrideEntries,
    );
    setHeaderUserMenuAttribute(
      userMenuElement,
      "avatar-label",
      options.userMenu.avatarLabel,
      overrideEntries,
    );
  }

  function applyHeaderOptions(hostElement, elements, options) {
    if (!elements.root) {
      return;
    }
    applyHeaderStickyState(elements.root, options.sticky, hostElement);
    if (elements.brand) {
      elements.brand.textContent = options.brand.label;
      elements.brand.setAttribute("href", sanitizeHref(options.brand.href));
      elements.brand.setAttribute("target", "_blank");
      elements.brand.setAttribute("rel", "noopener noreferrer");
    }
    renderHeaderNav(elements.nav, options.navLinks);
    renderHeaderHorizontalLinks(elements.horizontalLinks, options.horizontalLinks);

    elements.root.classList.toggle(
      HEADER_ROOT_CLASS + "--no-settings",
      !options.settings.enabled,
    );
    elements.root.classList.toggle(
      HEADER_ROOT_CLASS + "--small",
      options.size === "small",
    );

    if (elements.settingsButton) {
      elements.settingsButton.textContent = options.settings.label;
    }
    if (elements.authTransitionTitle) {
      elements.authTransitionTitle.textContent = options.authTransition.title;
    }
    if (elements.authTransitionMessage) {
      elements.authTransitionMessage.textContent = options.authTransition.message;
    }
    if (elements.userMenu) {
      applyHeaderUserMenuAttributes(elements.userMenu, options);
    }
  }

  function createSiteHeaderController(target, rawOptions, slotConfig) {
    var hostElement = resolveHost(target);
    if (!hostElement || typeof hostElement !== "object") {
      throw new Error("createSiteHeaderController requires a host element");
    }
    var userMenuElement =
      slotConfig && slotConfig.userMenuElement
        ? slotConfig.userMenuElement
        : null;
    if (userMenuElement) {
      prepareHeaderUserMenuSlotElement(userMenuElement);
    }

    var datasetOptions = readHeaderOptionsFromDataset(hostElement);
    var latestExternalOptions = deepMergeOptions({}, rawOptions || {});
    var combinedOptions = deepMergeOptions(
      {},
      datasetOptions,
      latestExternalOptions,
    );
    var options = normalizeHeaderOptions(combinedOptions);
    var cleanupHandlers = [];
    ensureHeaderStyles(global.document || (global.window && global.window.document));

    var elements = mountHeaderDom(hostElement, options, !userMenuElement);
    if (userMenuElement) {
      elements.userMenu = userMenuElement;
    }

    applyHeaderOptions(hostElement, elements, options);
    var settingsModalController = createHeaderSettingsModalController(
      elements,
      options.settings.label,
    );
    var authController = null;
    var authListenersAttached = false;
    var authTransitionReady = false;
    var authTransitionEventTarget = null;
    var authTransitionEventName = "";
    var providerActionsCleanup = null;
    var signInRedirectPending = false;
    var signInRedirectTarget = "";
    var isDestroyed = false;

    var headerThemeConfig = options.themeToggle;

    themeManager.configure({
      attribute: headerThemeConfig.attribute,
      targets: headerThemeConfig.targets,
      modes: headerThemeConfig.modes,
    });

    function updateThemeHost(modeValue) {
      hostElement.setAttribute("data-mpr-theme-mode", modeValue);
    }

    function destroyProviderActions() {
      if (providerActionsCleanup) {
        providerActionsCleanup();
        providerActionsCleanup = null;
      }
      if (elements.authActions) {
        clearNodeContents(elements.authActions);
      }
    }

    cleanupHandlers.push(destroyProviderActions);
    cleanupHandlers.push(function destroySettingsModal() {
      if (settingsModalController) {
        settingsModalController.destroy();
        settingsModalController = null;
      }
    });
    cleanupHandlers.push(function destroyAuthTransitionListener() {
      detachAuthTransitionCompletionListener();
    });

    function markSignInRedirectPending() {
      if (!options.signInRedirectUrl) {
        return;
      }
      signInRedirectPending = true;
      refreshAuthState();
    }

    function clearSignInRedirectPending() {
      signInRedirectPending = false;
      signInRedirectTarget = "";
    }

    function redirectAfterSignIn() {
      if (!signInRedirectPending || !options.signInRedirectUrl) {
        clearSignInRedirectPending();
        return;
      }
      if (
        signInRedirectTarget === options.signInRedirectUrl ||
        !global.location ||
        typeof global.location.assign !== "function"
      ) {
        return;
      }
      signInRedirectTarget = options.signInRedirectUrl;
      global.location.assign(options.signInRedirectUrl);
    }

    function mountProviderActions() {
      destroyProviderActions();
      if (!elements.authActions || !options.auth || !authController) {
        return;
      }
      var providerActions = mountAuthProviderActions(
        hostElement,
        elements.authActions,
        options.auth,
        authController,
          {
            googleLabel: AUTH_ACTION_LABELS.google,
            googleButtonOptions: {
              type: "icon",
              theme: LOGIN_BUTTON_THEME.FILLED_BLACK,
              size: LOGIN_BUTTON_SIZE.SMALL,
              shape: LOGIN_BUTTON_SHAPE.SQUARE,
            },
          handleStart: function handleProviderStart(providerId) {
            if (providerId === AUTH_PROVIDER_IDS.GOOGLE) {
              markSignInRedirectPending();
            }
            dispatchHeaderEvent("mpr-ui:header:signin-click", {
              provider: providerId,
              reason: providerId + "-attempt",
            });
          },
          handleError: function handleProviderError(providerId, error) {
            if (isDestroyed) {
              return;
            }
            dispatchHeaderEvent("mpr-ui:header:error", {
              code:
                error && error.code
                  ? error.code
                  : "mpr-ui.header.provider_attempt_failed",
              provider: providerId,
              message:
                error && error.message
                  ? String(error.message)
                  : "Authentication provider action failed",
            });
          },
        },
      );
      providerActionsCleanup = providerActions.cleanup;
    }

    if (options.auth) {
      authController = createAuthHeader(hostElement, options.auth);
    } else if (elements.root) {
      elements.root.classList.add(HEADER_ROOT_CLASS + "--no-auth");
    }

    if (
      headerThemeConfig.initialMode &&
      headerThemeConfig.initialMode !== themeManager.getMode()
    ) {
      themeManager.setMode(headerThemeConfig.initialMode, "header:init");
    }

    mountProviderActions();
    updateThemeHost(themeManager.getMode());

    var unsubscribeTheme = themeManager.on(function handleThemeChange(detail) {
      updateThemeHost(detail.mode);
      dispatchHeaderEvent("mpr-ui:header:theme-change", {
        theme: detail.mode,
        source: detail.source || null,
      });
    });
    cleanupHandlers.push(unsubscribeTheme);

    function dispatchHeaderEvent(type, detail) {
      dispatchEvent(hostElement, type, detail || {});
    }

    function detachAuthTransitionCompletionListener() {
      if (
        authTransitionEventTarget &&
        authTransitionEventName &&
        typeof authTransitionEventTarget.removeEventListener === "function"
      ) {
        authTransitionEventTarget.removeEventListener(
          authTransitionEventName,
          handleAuthTransitionCompletionEvent,
        );
      }
      authTransitionEventTarget = null;
      authTransitionEventName = "";
    }

    function handleAuthTransitionCompletionEvent() {
      authTransitionReady = true;
      refreshAuthState();
    }

    function resolveAuthTransitionCompletionEvent() {
      var transitionEnabled =
        options.authTransition && options.authTransition.enabled === true;
      if (
        !transitionEnabled ||
        !options.authTransition ||
        !options.authTransition.completionEvent
      ) {
        return "";
      }
      return options.authTransition.completionEvent;
    }

    function ensureAuthTransitionCompletionListener() {
      var completionEvent = resolveAuthTransitionCompletionEvent();
      if (
        authTransitionEventTarget &&
        authTransitionEventName === completionEvent
      ) {
        return;
      }
      detachAuthTransitionCompletionListener();
      if (!completionEvent) {
        return;
      }
      var documentTarget =
        hostElement.ownerDocument ||
        global.document ||
        (global.window && global.window.document) ||
        null;
      if (
        !documentTarget ||
        typeof documentTarget.addEventListener !== "function"
      ) {
        return;
      }
      authTransitionEventTarget = documentTarget;
      authTransitionEventName = completionEvent;
      authTransitionEventTarget.addEventListener(
        authTransitionEventName,
        handleAuthTransitionCompletionEvent,
      );
    }

    function refreshAuthState() {
      if (!authController) {
        return;
      }
      updateHeaderAuthView(
        hostElement,
        elements,
        options,
        authController.state,
        authTransitionReady,
        signInRedirectPending,
      );
    }

    function handleAuthenticatedEvent() {
      refreshAuthState();
      redirectAfterSignIn();
    }

    function handleAuthStatusChangeEvent(eventObject) {
      var nextStatus =
        eventObject &&
        eventObject.detail &&
        typeof eventObject.detail.status === "string"
          ? eventObject.detail.status
          : "";
      if (
        nextStatus === AUTH_CONTROLLER_STATUS.BOOTSTRAPPING ||
        nextStatus === AUTH_CONTROLLER_STATUS.AUTHENTICATING ||
        nextStatus === AUTH_CONTROLLER_STATUS.UNAUTHENTICATED
      ) {
        authTransitionReady = false;
      }
      if (
        nextStatus === AUTH_CONTROLLER_STATUS.AUTHENTICATING &&
        eventObject &&
        eventObject.detail &&
        (eventObject.detail.source === "credential" ||
          eventObject.detail.source === "password")
      ) {
        markSignInRedirectPending();
      }
      if (nextStatus === AUTH_CONTROLLER_STATUS.UNAUTHENTICATED) {
        clearSignInRedirectPending();
      }
      refreshAuthState();
    }

    function handleUnauthenticatedEvent() {
      clearSignInRedirectPending();
      refreshAuthState();
    }

    function ensureAuthEventListeners() {
      if (
        authListenersAttached ||
        !hostElement ||
        typeof hostElement.addEventListener !== "function"
      ) {
        return;
      }
      hostElement.addEventListener(
        "mpr-ui:auth:authenticated",
        handleAuthenticatedEvent,
      );
      hostElement.addEventListener(
        "mpr-ui:auth:unauthenticated",
        handleUnauthenticatedEvent,
      );
      hostElement.addEventListener(
        "mpr-ui:auth:status-change",
        handleAuthStatusChangeEvent,
      );
      authListenersAttached = true;
    }

    if (
      elements.userMenu &&
      typeof elements.userMenu.addEventListener === "function"
    ) {
      elements.userMenu.addEventListener("mpr-user:logout", function (eventObject) {
        if (authController) {
          authController.completeLogout();
        }
        dispatchHeaderEvent("mpr-ui:header:signout-click", {
          source: "user-menu",
          redirectUrl:
            eventObject && eventObject.detail ? eventObject.detail.redirectUrl : null,
        });
      });
    }

    if (elements.settingsButton) {
      elements.settingsButton.addEventListener("click", function () {
        if (!options.settings.enabled) {
          return;
        }
        if (settingsModalController) {
          settingsModalController.open();
        }
        dispatchHeaderEvent("mpr-ui:header:settings-click", {});
      });
    }

    if (authController) {
      ensureAuthTransitionCompletionListener();
      ensureAuthEventListeners();
      refreshAuthState();
    }

    return {
      update: function update(nextOptions) {
        latestExternalOptions = deepMergeOptions(
          {},
          latestExternalOptions,
          nextOptions || {},
        );
        var updatedDatasetOptions = readHeaderOptionsFromDataset(hostElement);
        var updatedCombined = deepMergeOptions(
          {},
          updatedDatasetOptions,
          latestExternalOptions,
        );
        options = normalizeHeaderOptions(updatedCombined);
        if (
          options.auth &&
          authController &&
          authController.state &&
          authController.state.options &&
          authController.state.options.tenantId !== options.auth.tenantId
        ) {
          throw createAuthTenantIdChangeError(
            authController.state.options.tenantId,
            options.auth.tenantId,
          );
        }
        headerThemeConfig = options.themeToggle;
        applyHeaderOptions(hostElement, elements, options);
        if (!options.settings.enabled && settingsModalController) {
          settingsModalController.close();
        }
        if (settingsModalController) {
          settingsModalController.updateLabel(options.settings.label);
        }
        themeManager.configure({
          attribute: headerThemeConfig.attribute,
          targets: headerThemeConfig.targets,
          modes: headerThemeConfig.modes,
        });
        if (
          headerThemeConfig.initialMode &&
          headerThemeConfig.initialMode !== themeManager.getMode()
        ) {
          themeManager.setMode(headerThemeConfig.initialMode, "header:update");
        }
        if (options.auth && !authController) {
          authController = createAuthHeader(hostElement, options.auth);
        }
        if (options.auth && authController && typeof authController.updateOptions === "function") {
          authController.updateOptions(options.auth);
        }
        if (
          resolveAuthTransitionCompletionEvent() &&
          authTransitionEventName !== resolveAuthTransitionCompletionEvent()
        ) {
          authTransitionReady = false;
        }
        ensureAuthTransitionCompletionListener();
        mountProviderActions();
        updateThemeHost(themeManager.getMode());
        if (options.auth && elements.root) {
          elements.root.classList.remove(HEADER_ROOT_CLASS + "--no-auth");
        }
        if (options.auth) {
          ensureAuthEventListeners();
          if (elements.root) {
            elements.root.classList.remove(HEADER_ROOT_CLASS + "--no-auth");
          }
          refreshAuthState();
        }
        if (!options.auth && authController) {
          if (typeof authController.destroy === "function") {
            authController.destroy();
          }
          authController = null;
          authTransitionReady = false;
          detachAuthTransitionCompletionListener();
        }
        if (!options.auth && elements.root) {
          elements.root.classList.add(HEADER_ROOT_CLASS + "--no-auth");
        }
      },
      destroy: function destroy() {
        isDestroyed = true;
        cleanupHandlers.forEach(function invoke(handler) {
          if (typeof handler === "function") {
            handler();
          }
        });
        cleanupHandlers = [];
        if (authController && typeof authController.destroy === "function") {
          authController.destroy();
        }
        authController = null;
        hostElement.innerHTML = "";
      },
      getAuthController: function getAuthController() {
        return authController;
      },
    };
  }

  function escapeHtml(value) {
    if (value === null || value === undefined) {
      return "";
    }
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  var USER_MENU_ROOT_CLASS = "mpr-user";
  var POPOVER_VIEWPORT_MARGIN_PIXELS = 8;
  var USER_MENU_VIEWPORT_OFFSET_PROPERTY = "--mpr-user-viewport-offset-x";
  var USER_MENU_STYLE_ID = "mpr-ui-user-styles";
  var USER_MENU_STYLE_MARKUP =
    "mpr-user{display:inline-flex;align-items:center;position:relative;--mpr-user-scale:1}" +
    'mpr-user[data-mpr-user-status="unauthenticated"],mpr-user[data-mpr-user-status="error"]{display:none}' +
    "mpr-header mpr-user{--mpr-user-scale:var(--mpr-header-scale,1)}" +
    "mpr-footer mpr-user{--mpr-user-scale:var(--mpr-footer-scale,1)}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__layout{display:flex;align-items:center;position:relative}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__trigger{display:inline-flex;align-items:center;gap:calc(0.35rem * var(--mpr-user-scale,1));padding:calc(0.3rem * var(--mpr-user-scale,1)) calc(0.5rem * var(--mpr-user-scale,1));border-radius:var(--mpr-radius-control,6px);border:1px solid var(--mpr-color-border,#2c2f36);background:var(--mpr-color-surface-elevated,#1f2126);color:var(--mpr-color-text-primary,#e3e5ec);cursor:pointer;font-weight:600;font-size:calc(0.78rem * var(--mpr-user-scale,1));}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__trigger:hover{background:var(--mpr-chip-hover-bg,rgba(148,163,184,0.32))}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__avatar{width:calc(28px * var(--mpr-user-scale,1));height:calc(28px * var(--mpr-user-scale,1));border-radius:50%;overflow:hidden;background:var(--mpr-chip-bg,rgba(93,147,255,0.12));display:inline-flex;align-items:center;justify-content:center}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__avatar-image{width:100%;height:100%;object-fit:cover;display:block}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__name{white-space:nowrap}" +
    'mpr-user[data-mpr-user-mode="avatar"] .' +
    USER_MENU_ROOT_CLASS +
    "__name{display:none}" +
    'mpr-user[data-mpr-user-mode="custom-avatar"] .' +
    USER_MENU_ROOT_CLASS +
    "__name{display:none}" +
    'mpr-user[data-mpr-user-mode="avatar"] .' +
    USER_MENU_ROOT_CLASS +
    "__trigger{padding:0;border:none;background:transparent}" +
    'mpr-user[data-mpr-user-mode="avatar"] .' +
    USER_MENU_ROOT_CLASS +
    "__trigger:hover{background:transparent}" +
    'mpr-user[data-mpr-user-mode="avatar"] .' +
    USER_MENU_ROOT_CLASS +
    "__avatar{border:1px solid var(--mpr-color-border,rgba(148,163,184,0.35));background:var(--mpr-color-surface-elevated,rgba(255,255,255,0.98))}" +
    'mpr-user[data-mpr-user-mode="avatar"] .' +
    USER_MENU_ROOT_CLASS +
    "__trigger:hover ." +
    USER_MENU_ROOT_CLASS +
    "__avatar{border-color:var(--mpr-color-accent,#38bdf8);box-shadow:0 0 0 2px rgba(56,189,248,0.35)}" +
    'mpr-user[data-mpr-user-mode="avatar"] .' +
    USER_MENU_ROOT_CLASS +
    "__trigger:focus-visible ." +
    USER_MENU_ROOT_CLASS +
    "__avatar{border-color:var(--mpr-color-accent,#38bdf8);box-shadow:0 0 0 2px rgba(56,189,248,0.35)}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__menu{position:absolute;right:0;top:calc(100% + (6px * var(--mpr-user-scale,1)));min-width:min(calc(168px * var(--mpr-user-scale,1)),calc(100vw - 16px));max-width:calc(100vw - 16px);box-sizing:border-box;transform:translateX(var(--mpr-user-viewport-offset-x,0px));padding:calc(0.4rem * var(--mpr-user-scale,1));border-radius:8px;border:1px solid var(--mpr-color-border,#2c2f36);background:var(--mpr-color-surface-elevated,#1f2126);box-shadow:var(--mpr-shadow-flyout,0 8px 20px rgba(0,0,0,0.35));display:none;flex-direction:column;gap:0.25rem;z-index:1300}" +
    'mpr-user[data-mpr-user-open="true"] .' +
    USER_MENU_ROOT_CLASS +
    "__menu{display:flex}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__menu-item{display:flex;align-items:center;gap:0.35rem;padding:calc(0.35rem * var(--mpr-user-scale,1)) calc(0.5rem * var(--mpr-user-scale,1));border-radius:4px;text-decoration:none;background:transparent;color:var(--mpr-color-text-primary,#e3e5ec);font-weight:600;font-size:calc(0.78rem * var(--mpr-user-scale,1));border:none;cursor:pointer;text-align:left;width:100%;appearance:none}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__menu-item:hover{background:var(--mpr-chip-hover-bg,rgba(148,163,184,0.32))}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__menu-item:focus-visible{outline:none;box-shadow:0 0 0 2px rgba(56,189,248,0.4)}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__logout{border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);padding:calc(0.35rem * var(--mpr-user-scale,1)) calc(0.5rem * var(--mpr-user-scale,1));background:var(--mpr-chip-bg,rgba(93,147,255,0.12));color:var(--mpr-color-text-primary,#e3e5ec);cursor:pointer;font-size:calc(0.78rem * var(--mpr-user-scale,1));font-weight:600;text-align:left}" +
    "." +
    USER_MENU_ROOT_CLASS +
    "__logout:hover{background:var(--mpr-chip-hover-bg,rgba(148,163,184,0.32))}";

  var USER_MENU_MENU_ID_PREFIX = "mpr-user-menu-";
  var userMenuCounter = 0;

  function ensureUserMenuStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(USER_MENU_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = USER_MENU_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = USER_MENU_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(USER_MENU_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildUserMenuOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var displayMode = hostElement.getAttribute("display-mode");
    if (displayMode !== null) {
      options.displayMode = displayMode;
    }
    var logoutUrl = hostElement.getAttribute("logout-url");
    if (logoutUrl !== null) {
      options.logoutUrl = logoutUrl;
    }
    var logoutLabel = hostElement.getAttribute("logout-label");
    if (logoutLabel !== null) {
      options.logoutLabel = logoutLabel;
    }
    if (hasAttributeValue(hostElement, AUTH_CONFIG_ATTRIBUTE)) {
      options.auth = parseAuthConfigAttribute(hostElement);
    }
    var avatarUrl = hostElement.getAttribute("avatar-url");
    if (avatarUrl !== null) {
      options.avatarUrl = avatarUrl;
    }
    var avatarLabel = hostElement.getAttribute("avatar-label");
    if (avatarLabel !== null) {
      options.avatarLabel = avatarLabel;
    }
    var menuItems = hostElement.getAttribute("menu-items");
    if (menuItems !== null) {
      options.menuItems = menuItems;
    }
    var inheritedOptions = readInheritedHeaderUserMenuOptions(hostElement);
    if (inheritedOptions) {
      if (!Object.prototype.hasOwnProperty.call(options, "displayMode")) {
        options.displayMode = inheritedOptions.displayMode;
      }
      if (!Object.prototype.hasOwnProperty.call(options, "logoutUrl")) {
        options.logoutUrl = inheritedOptions.logoutUrl;
      }
      if (!Object.prototype.hasOwnProperty.call(options, "logoutLabel")) {
        options.logoutLabel = inheritedOptions.logoutLabel;
      }
      if (!Object.prototype.hasOwnProperty.call(options, "auth")) {
        options.auth = inheritedOptions.auth;
      }
      if (!Object.prototype.hasOwnProperty.call(options, "avatarUrl")) {
        options.avatarUrl = inheritedOptions.avatarUrl;
      }
      if (!Object.prototype.hasOwnProperty.call(options, "avatarLabel")) {
        options.avatarLabel = inheritedOptions.avatarLabel;
      }
    }
    return options;
  }

  function readInheritedHeaderUserMenuOptions(hostElement) {
    var headerElement = findClosestHostByTagName(hostElement, ["mpr-header"]);
    if (!headerElement || typeof headerElement.getAttribute !== "function") {
      return null;
    }
    var headerDataset =
      headerElement.dataset && typeof headerElement.dataset === "object"
        ? headerElement.dataset
        : {};
    var brandHref = headerElement.getAttribute("brand-href");
    if (brandHref === null && headerDataset.brandHref) {
      brandHref = headerDataset.brandHref;
    }
    var displayMode = headerElement.getAttribute("user-menu-display-mode");
    if (displayMode === null && headerDataset.userMenuDisplayMode) {
      displayMode = headerDataset.userMenuDisplayMode;
    }
    var logoutUrl = headerElement.getAttribute("logout-url");
    if (logoutUrl === null && headerDataset.logoutUrl) {
      logoutUrl = headerDataset.logoutUrl;
    }
    var logoutLabel = headerElement.getAttribute("sign-out-label");
    if (logoutLabel === null && headerDataset.signOutLabel) {
      logoutLabel = headerDataset.signOutLabel;
    }
    var authOptions = parseAuthConfigAttribute(headerElement);
    var avatarUrl = headerElement.getAttribute("user-menu-avatar-url");
    if (avatarUrl === null && headerDataset.userMenuAvatarUrl) {
      avatarUrl = headerDataset.userMenuAvatarUrl;
    }
    var avatarLabel = headerElement.getAttribute("user-menu-avatar-label");
    if (avatarLabel === null && headerDataset.userMenuAvatarLabel) {
      avatarLabel = headerDataset.userMenuAvatarLabel;
    }
    return {
      displayMode: normalizeHeaderUserMenuDisplayMode(displayMode),
      logoutUrl: normalizeHeaderUserMenuLogoutUrl(
        logoutUrl,
        typeof brandHref === "string" && brandHref.trim()
          ? brandHref.trim()
          : HEADER_DEFAULTS.brand.href,
      ),
      logoutLabel:
        typeof logoutLabel === "string" && logoutLabel.trim()
          ? logoutLabel.trim()
          : HEADER_DEFAULTS.signOutLabel,
      auth: authOptions,
      avatarUrl: normalizeHeaderUserMenuOptionalValue(avatarUrl),
      avatarLabel: normalizeHeaderUserMenuOptionalValue(avatarLabel),
    };
  }

  /**
   * @param {string} code
   * @param {string} message
   * @returns {MprUiError}
   */
  function createUserMenuError(code, message) {
    /** @type {MprUiError} */
    var error = new Error(message);
    error.code = code;
    return error;
  }

  function normalizeUserMenuDisplayMode(value) {
    if (typeof value !== "string") {
      return null;
    }
    var normalized = value.trim().toLowerCase();
    if (USER_MENU_DISPLAY_MODE_VALUES.indexOf(normalized) === -1) {
      return null;
    }
    return normalized;
  }

  function normalizeRequiredString(value, code, message) {
    if (typeof value !== "string") {
      throw createUserMenuError(code, message);
    }
    var trimmed = value.trim();
    if (!trimmed) {
      throw createUserMenuError(code, message);
    }
    return trimmed;
  }

  function normalizeUserMenuLogoutUrl(value) {
    var trimmed = normalizeRequiredString(
      value,
      USER_MENU_LOGOUT_URL_ERROR_CODE,
      "Logout URL is required",
    );
    var sanitized = sanitizeHref(trimmed);
    if (sanitized === "#" && trimmed !== "#") {
      throw createUserMenuError(
        USER_MENU_LOGOUT_URL_ERROR_CODE,
        "Logout URL is invalid",
      );
    }
    return sanitized;
  }

  function normalizeUserMenuLabel(value) {
    return normalizeRequiredString(
      value,
      USER_MENU_LOGOUT_LABEL_ERROR_CODE,
      "Logout label is required",
    );
  }

  function parseUserMenuItemsValue(rawValue) {
    if (rawValue === null || rawValue === undefined) {
      return null;
    }
    if (Array.isArray(rawValue)) {
      return rawValue.slice();
    }
    if (typeof rawValue === "string") {
      var trimmed = rawValue.trim();
      if (!trimmed) {
        return null;
      }
      try {
        return JSON.parse(trimmed);
      } catch (_error) {
        throw createUserMenuError(
          USER_MENU_ITEMS_ERROR_CODE,
          "User menu items must be valid JSON",
        );
      }
    }
    if (typeof rawValue === "object") {
      return rawValue;
    }
    throw createUserMenuError(
      USER_MENU_ITEMS_ERROR_CODE,
      "User menu items must be an array",
    );
  }

  function normalizeUserMenuItemHref(value) {
    var href = normalizeRequiredString(
      value,
      USER_MENU_ITEMS_ERROR_CODE,
      "User menu item href is required",
    );
    var sanitizedHref = sanitizeHref(href);
    if (sanitizedHref === "#" && href !== "#") {
      throw createUserMenuError(
        USER_MENU_ITEMS_ERROR_CODE,
        "User menu item href is invalid",
      );
    }
    return sanitizedHref;
  }

  function normalizeUserMenuItemAction(value) {
    return normalizeRequiredString(
      value,
      USER_MENU_ITEMS_ERROR_CODE,
      "User menu item action is required",
    );
  }

  function normalizeUserMenuItem(rawItem, index) {
    if (!rawItem || typeof rawItem !== "object") {
      throw createUserMenuError(
        USER_MENU_ITEMS_ERROR_CODE,
        "User menu item at index " + index + " is invalid",
      );
    }
    var label = normalizeRequiredString(
      rawItem.label,
      USER_MENU_ITEMS_ERROR_CODE,
      "User menu item label is required",
    );
    var hasHref = Object.prototype.hasOwnProperty.call(rawItem, "href");
    var hasAction = Object.prototype.hasOwnProperty.call(rawItem, "action");
    if (hasHref && hasAction) {
      throw createUserMenuError(
        USER_MENU_ITEMS_ERROR_CODE,
        "User menu item cannot include both href and action",
      );
    }
    if (!hasHref && !hasAction) {
      throw createUserMenuError(
        USER_MENU_ITEMS_ERROR_CODE,
        "User menu item must include href or action",
      );
    }
    if (hasHref) {
      return {
        label: label,
        href: normalizeUserMenuItemHref(rawItem.href),
      };
    }
    return {
      label: label,
      action: normalizeUserMenuItemAction(rawItem.action),
    };
  }

  function normalizeUserMenuItems(rawValue) {
    var parsedItems = parseUserMenuItemsValue(rawValue);
    if (parsedItems === null) {
      return null;
    }
    if (!Array.isArray(parsedItems)) {
      throw createUserMenuError(
        USER_MENU_ITEMS_ERROR_CODE,
        "User menu items must be an array",
      );
    }
    if (!parsedItems.length) {
      return null;
    }
    return parsedItems.map(function normalizeEntry(entry, index) {
      return normalizeUserMenuItem(entry, index);
    });
  }

  function normalizeUserMenuAvatarUrl(value, errorCode, message) {
    var trimmed = normalizeRequiredString(value, errorCode, message);
    if (trimmed.indexOf("data:") === 0 || trimmed.indexOf("blob:") === 0) {
      return trimmed;
    }
    var sanitized = sanitizeHref(trimmed);
    if (sanitized === "#" || !sanitized) {
      throw createUserMenuError(errorCode, message);
    }
    return sanitized;
  }

  function normalizeUserMenuOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var displayMode = normalizeUserMenuDisplayMode(options.displayMode);
    if (!displayMode) {
      throw createUserMenuError(
        USER_MENU_DISPLAY_MODE_ERROR_CODE,
        "User menu display mode is required",
      );
    }
    var authOptions = createAuthOptions(options.auth);
    var logoutUrl = normalizeUserMenuLogoutUrl(options.logoutUrl);
    var logoutLabel = normalizeUserMenuLabel(options.logoutLabel);
    var avatarUrl = null;
    if (displayMode === USER_MENU_DISPLAY_MODES.CUSTOM_AVATAR) {
      avatarUrl = normalizeUserMenuAvatarUrl(
        options.avatarUrl,
        USER_MENU_CUSTOM_AVATAR_ERROR_CODE,
        "Custom avatar URL is required",
      );
    }
    var avatarLabel =
      typeof options.avatarLabel === "string" && options.avatarLabel.trim()
        ? options.avatarLabel.trim()
        : null;
    var menuItems = normalizeUserMenuItems(options.menuItems);
    return {
      displayMode: displayMode,
      auth: authOptions,
      tenantId: authOptions.tenantId,
      tauthUrl: authOptions.tauthUrl,
      logoutPath: authOptions.logoutPath,
      sessionPath: authOptions.sessionPath,
      providers: authOptions.providers,
      logoutUrl: logoutUrl,
      logoutLabel: logoutLabel,
      avatarUrl: avatarUrl,
      avatarLabel: avatarLabel,
      menuItems: menuItems,
    };
  }

  function createUserMenuDomId() {
    userMenuCounter += 1;
    return USER_MENU_MENU_ID_PREFIX + userMenuCounter;
  }

  function buildUserMenuItemsMarkup(menuItems) {
    if (!menuItems || !menuItems.length) {
      return "";
    }
    return menuItems
      .map(function buildItemMarkup(item, index) {
        var label = escapeHtml(item.label);
        var indexValue = escapeHtml(String(index));
        var baseAttributes =
          'class="' +
          USER_MENU_ROOT_CLASS +
          '__menu-item" data-mpr-user="menu-item" role="menuitem" ' +
          USER_MENU_ITEM_INDEX_ATTRIBUTE +
          '="' +
          indexValue +
          '"';
        if (item.action) {
          return (
            '<button type="button" ' +
            baseAttributes +
            " " +
            USER_MENU_ITEM_ACTION_ATTRIBUTE +
            '="' +
            escapeHtml(item.action) +
            '">' +
            label +
            "</button>"
          );
        }
        return (
          '<a ' +
          baseAttributes +
          ' href="' +
          escapeHtml(item.href) +
          '">' +
          label +
          "</a>"
        );
      })
      .join("");
  }

  function buildUserMenuMarkup(config, menuId) {
    var logoutLabel = escapeHtml(config.logoutLabel);
    var menuIdValue = escapeHtml(menuId);
    var menuItemsMarkup = buildUserMenuItemsMarkup(config.menuItems);
    return (
      '<div class="' +
      USER_MENU_ROOT_CLASS +
      '__layout">' +
      '<button type="button" class="' +
      USER_MENU_ROOT_CLASS +
      '__trigger" data-mpr-user="trigger" aria-haspopup="true" aria-expanded="false" aria-controls="' +
      menuIdValue +
      '">' +
      '<span class="' +
      USER_MENU_ROOT_CLASS +
      '__avatar" data-mpr-user="avatar">' +
      '<img class="' +
      USER_MENU_ROOT_CLASS +
      '__avatar-image" data-mpr-user="avatar-image" alt="" />' +
      "</span>" +
      '<span class="' +
      USER_MENU_ROOT_CLASS +
      '__name" data-mpr-user="name"></span>' +
      "</button>" +
      '<div class="' +
      USER_MENU_ROOT_CLASS +
      '__menu" data-mpr-user="menu" id="' +
      menuIdValue +
      '" role="menu" aria-hidden="true">' +
      menuItemsMarkup +
      '<button type="button" class="' +
      USER_MENU_ROOT_CLASS +
      '__logout" data-mpr-user="logout" role="menuitem">' +
      logoutLabel +
      "</button>" +
      "</div>" +
      "</div>"
    );
  }

  function resolveUserMenuElements(hostElement) {
    return {
      trigger: hostElement.querySelector('[data-mpr-user="trigger"]'),
      avatarWrapper: hostElement.querySelector('[data-mpr-user="avatar"]'),
      avatarImage: hostElement.querySelector('[data-mpr-user="avatar-image"]'),
      name: hostElement.querySelector('[data-mpr-user="name"]'),
      menu: hostElement.querySelector('[data-mpr-user="menu"]'),
      logoutButton: hostElement.querySelector('[data-mpr-user="logout"]'),
      menuItems: Array.prototype.slice.call(
        hostElement.querySelectorAll(USER_MENU_ITEM_SELECTOR),
      ),
    };
  }

  function normalizeProfileString(value) {
    if (typeof value !== "string") {
      return "";
    }
    return value.trim();
  }

  function resolveProfileField(profile, fieldNames) {
    if (!profile || typeof profile !== "object") {
      return "";
    }
    for (var index = 0; index < fieldNames.length; index += 1) {
      var fieldName = fieldNames[index];
      if (!Object.prototype.hasOwnProperty.call(profile, fieldName)) {
        continue;
      }
      var normalized = normalizeProfileString(profile[fieldName]);
      if (normalized) {
        return normalized;
      }
    }
    return "";
  }

  function resolveProfileFullName(profile) {
    return resolveProfileField(profile, USER_MENU_PROFILE_FULL_NAME_FIELDS);
  }

  function resolveProfileShortName(profile, fullName) {
    var shortName = resolveProfileField(profile, USER_MENU_PROFILE_SHORT_NAME_FIELDS);
    if (shortName) {
      return shortName;
    }
    if (!fullName) {
      return "";
    }
    var parts = fullName.split(/\s+/);
    return parts.length ? parts[0] : "";
  }

  function resolveProfileAvatar(profile) {
    return resolveProfileField(profile, USER_MENU_PROFILE_AVATAR_FIELDS);
  }

  function buildUserMenuProfile(profile, config) {
    if (!profile || typeof profile !== "object") {
      return null;
    }
    var fullName = resolveProfileFullName(profile);
    var shortName = resolveProfileShortName(profile, fullName);
    var avatarUrl =
      config.displayMode === USER_MENU_DISPLAY_MODES.CUSTOM_AVATAR
        ? config.avatarUrl
        : normalizeUserMenuAvatarUrl(
            resolveProfileAvatar(profile) || USER_MENU_DEFAULT_AVATAR_URL,
            USER_MENU_PROFILE_ERROR_CODE,
            "Profile avatar URL is invalid",
          );
    if (
      config.displayMode === USER_MENU_DISPLAY_MODES.AVATAR_NAME &&
      !shortName
    ) {
      throw createUserMenuError(
        USER_MENU_PROFILE_ERROR_CODE,
        "Profile short name is required",
      );
    }
    if (
      config.displayMode === USER_MENU_DISPLAY_MODES.AVATAR_FULL_NAME &&
      !fullName
    ) {
      throw createUserMenuError(
        USER_MENU_PROFILE_ERROR_CODE,
        "Profile full name is required",
      );
    }
    var displayName = "";
    if (config.displayMode === USER_MENU_DISPLAY_MODES.AVATAR_NAME) {
      displayName = shortName;
    } else if (config.displayMode === USER_MENU_DISPLAY_MODES.AVATAR_FULL_NAME) {
      displayName = fullName;
    }
    var altLabel =
      config.avatarLabel ||
      fullName ||
      shortName ||
      resolveProfileField(profile, USER_MENU_PROFILE_FULL_NAME_FIELDS);
    return {
      avatarUrl: avatarUrl,
      displayName: displayName,
      altLabel: altLabel,
      profile: profile,
    };
  }

  function applyUserProfileDataset(hostElement, profile) {
    Object.keys(ATTRIBUTE_MAP).forEach(function (key) {
      var attributeName = ATTRIBUTE_MAP[key];
      setAttributeOrRemove(
        hostElement,
        attributeName,
        profile ? profile[key] : null,
      );
    });
  }

  function resolveUserMenuScopedAuthHost(hostElement) {
    if (!hostElement) {
      return null;
    }
    var targetSelector = hostElement.getAttribute(AUTH_COMPONENT_TARGET_ATTRIBUTE);
    if (targetSelector !== null) {
      var documentObject = hostElement.ownerDocument;
      var targetElement;
      try {
        targetElement = documentObject.querySelector(targetSelector);
      } catch (_error) {
        throw createUserMenuError(
          USER_MENU_AUTH_TARGET_ERROR_CODE,
          "User menu auth-target must be a valid selector",
        );
      }
      if (!targetElement || !targetElement.matches("mpr-header,mpr-login-button")) {
        throw createUserMenuError(
          USER_MENU_AUTH_TARGET_ERROR_CODE,
          "User menu auth-target must select an authentication surface",
        );
      }
      return targetElement;
    }
    return findClosestHostByTagName(hostElement, [
      "mpr-header",
      "mpr-login-button",
    ]);
  }

  function readUserMenuProfileFromAuthHost(authHost) {
    if (!authHost || typeof authHost.getAttribute !== "function") {
      return null;
    }
    if (authHost.getAttribute("data-mpr-auth-status") !== AUTH_CONTROLLER_STATUS.AUTHENTICATED) {
      return null;
    }
    var profile = {};
    var hasProfileValue = false;
    Object.keys(ATTRIBUTE_MAP).forEach(function readProfileAttribute(key) {
      var attributeName = ATTRIBUTE_MAP[key];
      var value = authHost.getAttribute(attributeName);
      if (typeof value === "string" && value.trim()) {
        profile[key] = value;
        hasProfileValue = true;
      }
    });
    return hasProfileValue ? profile : null;
  }

  function resolveUserMenuEventTarget(hostElement) {
    var scopedHost = hostElement.__userMenuConfig.authHost;
    if (scopedHost && typeof scopedHost.addEventListener === "function") {
      return scopedHost;
    }
    var documentObject =
      hostElement.ownerDocument ||
      global.document ||
      (global.window && global.window.document) ||
      null;
    if (documentObject && typeof documentObject.addEventListener === "function") {
      return documentObject;
    }
    return null;
  }

  function isUserMenuEventTarget(hostElement, elements, target) {
    if (!target) {
      return false;
    }
    if (hostElement && typeof hostElement.contains === "function") {
      return hostElement.contains(target);
    }
    if (target === hostElement) {
      return true;
    }
    if (!elements) {
      return false;
    }
    return (
      target === elements.trigger ||
      target === elements.avatarWrapper ||
      target === elements.avatarImage ||
      target === elements.name ||
      target === elements.menu ||
      target === elements.logoutButton ||
      (elements.menuItems && elements.menuItems.indexOf(target) !== -1)
    );
  }

  function resolveLocationTarget(hostElement) {
    var documentObject =
      hostElement &&
      hostElement.ownerDocument &&
      hostElement.ownerDocument.defaultView
        ? hostElement.ownerDocument.defaultView
        : null;
    if (documentObject && documentObject.location) {
      return documentObject.location;
    }
    if (global.location) {
      return global.location;
    }
    if (global.window && global.window.location) {
      return global.window.location;
    }
    return null;
  }

  function requestTauthProfile(config) {
    if (!config) {
      throw createUserMenuError(
        USER_MENU_TAUTH_MISSING_ERROR_CODE,
        "User menu auth configuration is required",
      );
    }
    return requestCurrentProfileFromRuntime(config.auth);
  }

  function requestTauthLogout(config) {
    if (!config) {
      throw createUserMenuError(
        USER_MENU_TAUTH_MISSING_ERROR_CODE,
        "User menu auth configuration is required",
      );
    }
    return performLogoutFromRuntime(config.auth);
  }

  function configureAuthTenant(tenantId) {
    if (typeof global.setAuthTenantId === "function") {
      global.setAuthTenantId(tenantId);
    }
  }

  function applyUserMenuStatus(hostElement, status) {
    hostElement.setAttribute("data-mpr-user-status", status);
  }

  function positionPanelInViewport(panel, ownerWindow, offsetProperty) {
    if (
      !panel ||
      !panel.style ||
      typeof panel.style.setProperty !== "function" ||
      typeof panel.getBoundingClientRect !== "function" ||
      !ownerWindow ||
      typeof ownerWindow.innerWidth !== "number"
    ) {
      return;
    }
    panel.style.setProperty(offsetProperty, "0px");
    var panelRect = panel.getBoundingClientRect();
    var viewportRightEdge =
      ownerWindow.innerWidth - POPOVER_VIEWPORT_MARGIN_PIXELS;
    var horizontalOffset = 0;
    if (panelRect.left < POPOVER_VIEWPORT_MARGIN_PIXELS) {
      horizontalOffset = POPOVER_VIEWPORT_MARGIN_PIXELS - panelRect.left;
    } else if (panelRect.right > viewportRightEdge) {
      horizontalOffset = viewportRightEdge - panelRect.right;
    }
    panel.style.setProperty(
      offsetProperty,
      String(horizontalOffset) + "px",
    );
  }

  function applyUserMenuOpenState(hostElement, elements, isOpen) {
    hostElement.setAttribute("data-mpr-user-open", isOpen ? "true" : "false");
    if (elements.trigger) {
      elements.trigger.setAttribute("aria-expanded", isOpen ? "true" : "false");
    }
    if (elements.menu) {
      elements.menu.setAttribute("aria-hidden", isOpen ? "false" : "true");
      if (isOpen) {
        positionPanelInViewport(
          elements.menu,
          resolveOwnerWindow(hostElement),
          USER_MENU_VIEWPORT_OFFSET_PROPERTY,
        );
      }
    }
  }

  function clearUserMenuContent(elements) {
    if (elements.avatarImage) {
      elements.avatarImage.removeAttribute("src");
      elements.avatarImage.removeAttribute("alt");
    }
    if (elements.name) {
      elements.name.textContent = "";
    }
  }

  function applyUserMenuProfile(hostElement, elements, config, profile) {
    hostElement.setAttribute("data-mpr-user-mode", config.displayMode);
    if (!profile) {
      applyUserMenuStatus(hostElement, "unauthenticated");
      applyUserProfileDataset(hostElement, null);
      clearUserMenuContent(elements);
      return;
    }
    var view = buildUserMenuProfile(profile, config);
    if (!view) {
      applyUserMenuStatus(hostElement, "unauthenticated");
      applyUserProfileDataset(hostElement, null);
      clearUserMenuContent(elements);
      return;
    }
    applyUserMenuStatus(hostElement, "authenticated");
    applyUserProfileDataset(hostElement, view.profile);
    if (elements.avatarImage) {
      elements.avatarImage.setAttribute("src", view.avatarUrl);
      if (view.altLabel) {
        elements.avatarImage.setAttribute("alt", view.altLabel);
      } else {
        elements.avatarImage.setAttribute("alt", "");
      }
    }
    if (elements.name) {
      elements.name.textContent = view.displayName;
    }
    if (elements.trigger && view.altLabel) {
      elements.trigger.setAttribute("aria-label", view.altLabel);
    }
  }

  function clearUserMenuError(hostElement) {
    if (!hostElement || typeof hostElement.removeAttribute !== "function") {
      return;
    }
    hostElement.removeAttribute("data-mpr-user-error");
  }

  function reportUserMenuError(hostElement, error) {
    if (!hostElement) {
      return;
    }
    /** @type {MprUiError} */
    var errorObject =
      error instanceof Error ? error : new Error(String(error));
    var errorCode = errorObject.code || USER_MENU_GENERIC_ERROR_CODE;
    hostElement.setAttribute("data-mpr-user-error", errorCode);
    applyUserMenuStatus(hostElement, "error");
    logError(errorCode, errorObject.message);
    dispatchEvent(hostElement, "mpr-user:error", {
      code: errorCode,
      message: errorObject.message,
    });
  }

  var SETTINGS_ROOT_CLASS = "mpr-settings";
  var SETTINGS_STYLE_ID = "mpr-ui-settings-styles";
  var SETTINGS_STYLE_MARKUP =
    ".mpr-settings{display:flex;flex-direction:column;gap:0.5rem}" +
    ".mpr-settings__trigger{display:flex;align-items:center;gap:0.35rem}" +
    ".mpr-settings__button{appearance:none;border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);padding:0.35rem 0.55rem;font-size:0.78rem;font-weight:600;background:var(--mpr-chip-bg,rgba(93,147,255,0.12));color:var(--mpr-color-text-primary,#e3e5ec);cursor:pointer;display:inline-flex;align-items:center;gap:0.35rem}" +
    ".mpr-settings__button:hover{background:var(--mpr-chip-hover-bg,rgba(148,163,184,0.32))}" +
    ".mpr-settings__icon{font-size:0.8rem}" +
    ".mpr-settings__panel{border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);padding:0.75rem;background:var(--mpr-color-surface-elevated,#1f2126);color:var(--mpr-color-text-primary,#e3e5ec)}" +
    '.mpr-settings__panel[hidden]{display:none!important}';
  var SETTINGS_DEFAULTS = Object.freeze({
    label: "Settings",
    icon: "⚙",
    buttonClass: SETTINGS_ROOT_CLASS + "__button",
    panelClass: SETTINGS_ROOT_CLASS + "__panel",
  });
  var SETTINGS_EMPTY_PANEL_ID_PREFIX = "mpr-settings-panel-";
  var settingsPanelCounter = 0;

  function ensureSettingsStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(SETTINGS_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = SETTINGS_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = SETTINGS_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(SETTINGS_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildSettingsOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var labelAttr = hostElement.getAttribute("label");
    if (labelAttr) {
      options.label = labelAttr;
    }
    var iconAttr = hostElement.getAttribute("icon");
    if (iconAttr) {
      options.icon = iconAttr;
    }
    var panelIdAttr = hostElement.getAttribute("panel-id");
    if (panelIdAttr) {
      options.panelId = panelIdAttr;
    }
    var buttonClassAttr = hostElement.getAttribute("button-class");
    if (buttonClassAttr) {
      options.buttonClass = buttonClassAttr;
    }
    var panelClassAttr = hostElement.getAttribute("panel-class");
    if (panelClassAttr) {
      options.panelClass = panelClassAttr;
    }
    var openAttr = hostElement.getAttribute("open");
    if (openAttr !== null) {
      options.open = normalizeBooleanAttribute(openAttr, true);
    }
    return options;
  }

  function normalizeSettingsOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var label =
      typeof options.label === "string" && options.label.trim()
        ? options.label.trim()
        : SETTINGS_DEFAULTS.label;
    var icon =
      typeof options.icon === "string" && options.icon.trim()
        ? options.icon.trim()
        : SETTINGS_DEFAULTS.icon;
    var panelId =
      typeof options.panelId === "string" && options.panelId.trim()
        ? options.panelId.trim()
        : "";
    var buttonClass =
      typeof options.buttonClass === "string" && options.buttonClass.trim()
        ? options.buttonClass.trim()
        : SETTINGS_DEFAULTS.buttonClass;
    var panelClass =
      typeof options.panelClass === "string" && options.panelClass.trim()
        ? options.panelClass.trim()
        : SETTINGS_DEFAULTS.panelClass;
    return {
      label: label,
      icon: icon,
      panelId: panelId,
      buttonClass: buttonClass,
      panelClass: panelClass,
      open: Boolean(options.open),
    };
  }

  function buildSettingsMarkup(config, panelDomId, ariaControls) {
    var iconMarkup = config.icon
      ? '<span class="' +
        SETTINGS_ROOT_CLASS +
        '__icon" aria-hidden="true">' +
        escapeHtml(config.icon) +
        "</span>"
      : "";
    var ariaControlMarkup = ariaControls
      ? ' aria-controls="' + escapeHtml(ariaControls) + '"'
      : "";
    return (
      '<div class="' +
      SETTINGS_ROOT_CLASS +
      '__trigger" data-mpr-settings="trigger">' +
      '<button type="button" class="' +
      escapeHtml(config.buttonClass) +
      '" data-mpr-settings="toggle" aria-expanded="' +
      (config.open ? "true" : "false") +
      '"' +
      ariaControlMarkup +
      ">" +
      iconMarkup +
      '<span class="' +
      SETTINGS_ROOT_CLASS +
      '__label" data-mpr-settings="label">' +
      escapeHtml(config.label) +
      "</span>" +
      "</button>" +
      "</div>" +
      '<div class="' +
      escapeHtml(config.panelClass) +
      '" data-mpr-settings="panel"' +
      (panelDomId ? ' id="' + escapeHtml(panelDomId) + '"' : "") +
      (config.open ? "" : ' hidden="hidden"') +
      "></div>"
    );
  }

  function resolveSettingsElements(hostElement) {
    if (!hostElement || typeof hostElement.querySelector !== "function") {
      return {};
    }
    return {
      trigger: hostElement.querySelector('[data-mpr-settings="trigger"]'),
      button: hostElement.querySelector('[data-mpr-settings="toggle"]'),
      label: hostElement.querySelector('[data-mpr-settings="label"]'),
      panel: hostElement.querySelector('[data-mpr-settings="panel"]'),
    };
  }

  function applySettingsSlotContent(slotMap, elements) {
    if (!slotMap || !elements) {
      return;
    }
    if (slotMap.trigger && slotMap.trigger.length && elements.trigger) {
      slotMap.trigger.forEach(function appendTrigger(node) {
        if (node && typeof elements.trigger.appendChild === "function") {
          elements.trigger.appendChild(node);
        }
      });
    }
    if (slotMap.panel && slotMap.panel.length && elements.panel) {
      clearNodeContents(elements.panel);
      slotMap.panel.forEach(function appendPanel(node) {
        if (node && typeof elements.panel.appendChild === "function") {
          elements.panel.appendChild(node);
        }
      });
    }
  }

  function createSettingsPanelDomId() {
    settingsPanelCounter += 1;
    return SETTINGS_EMPTY_PANEL_ID_PREFIX + settingsPanelCounter;
  }

  function sanitizeHref(value) {
    if (value === null || value === undefined) {
      return "#";
    }
    var trimmed = String(value).trim();
    if (trimmed === "") {
      return "#";
    }
    if (trimmed[0] === "#" || trimmed[0] === "/") {
      return trimmed;
    }
    if (trimmed.indexOf("//") === 0) {
      return trimmed;
    }
    var protocolMatch = trimmed.match(/^([a-z0-9.+-]+):/i);
    if (!protocolMatch) {
      return trimmed;
    }
    var protocol = protocolMatch[1].toLowerCase();
    var allowedProtocols = ["http", "https", "mailto", "tel"];
    if (allowedProtocols.indexOf(protocol) === -1) {
      return "#";
    }
    return trimmed;
  }

  function normalizeLinkForRendering(link, defaults) {
    if (!link || typeof link !== "object") {
      return null;
    }
    var fallback = defaults && typeof defaults === "object" ? defaults : {};
    var labelRaw =
      link.label || link.Label || (typeof link.text === "string" ? link.text : "");
    var normalizedLabel = typeof labelRaw === "string" ? labelRaw.trim() : "";
    var hrefSource = link.href || link.url || link.URL || "";
    var sanitizedHref = sanitizeHref(hrefSource);
    if (!normalizedLabel || !sanitizedHref) {
      return null;
    }
    var targetSource = link.target || link.Target || fallback.target || "";
    var relSource = link.rel || link.Rel || fallback.rel || "";
    return {
      label: normalizedLabel,
      href: sanitizedHref,
      url: sanitizedHref,
      target: targetSource ? String(targetSource) : "",
      rel: relSource ? String(relSource) : "",
    };
  }

  function normalizeHorizontalLinksAlignment(value, fallback) {
    if (typeof value !== "string") {
      return fallback;
    }
    var normalized = value.trim().toLowerCase();
    if (!normalized) {
      return fallback;
    }
    if (HORIZONTAL_LINKS_ALIGNMENT_VALUES.indexOf(normalized) !== -1) {
      return normalized;
    }
    logError(
      HORIZONTAL_LINKS_ALIGNMENT_ERROR_CODE,
      'Unsupported horizontal-links alignment "' + value + '"',
    );
    return fallback;
  }

  function normalizeHorizontalLinksConfig(candidateConfig, fallbackConfig) {
    var fallback =
      fallbackConfig && typeof fallbackConfig === "object"
        ? fallbackConfig
        : HORIZONTAL_LINKS_DEFAULTS;
    var fallbackAlignment =
      typeof fallback.alignment === "string" && fallback.alignment.trim()
        ? fallback.alignment.trim()
        : HORIZONTAL_LINKS_DEFAULTS.alignment;

    if (Array.isArray(candidateConfig)) {
      logError(
        HORIZONTAL_LINKS_CONFIG_ERROR_CODE,
        "horizontal-links expects an object with { alignment, links }. Received an array; treating it as links list.",
      );
      return {
        alignment: fallbackAlignment,
        links: candidateConfig
          .map(function normalizeSingleLink(link) {
            return normalizeLinkForRendering(link, {});
          })
          .filter(Boolean),
      };
    }

    if (!candidateConfig || typeof candidateConfig !== "object") {
      return { alignment: fallbackAlignment, links: [] };
    }

    var alignmentSource = candidateConfig.alignment || candidateConfig.align || "";
    var alignment = normalizeHorizontalLinksAlignment(
      alignmentSource,
      fallbackAlignment,
    );
    var linksSource = Array.isArray(candidateConfig.links)
      ? candidateConfig.links
      : [];
    var links = linksSource
      .map(function normalizeSingleLink(link) {
        return normalizeLinkForRendering(link, {});
      })
      .filter(Boolean);
    return { alignment: alignment, links: links };
  }

  var FOOTER_LINK_DEFAULT_TARGET = "_blank";
  var FOOTER_LINK_DEFAULT_REL = "noopener noreferrer";
  var FOOTER_STYLE_ID = "mpr-ui-footer-styles";
  var FOOTER_STYLE_MARKUP =
    "mpr-footer{display:block;width:100%;flex-shrink:0;position:relative}" +
    'mpr-footer[data-mpr-sticky="false"]{position:relative}' +
    'mpr-footer [data-mpr-footer="sticky-spacer"]{display:block;width:100%;height:0}' +
    'footer.mpr-footer{position:fixed;left:0;right:0;bottom:0;width:100%;z-index:1200;padding:calc(10px * var(--mpr-footer-scale,1)) 0;background:var(--mpr-color-surface-primary,#0f1114);color:var(--mpr-color-text-primary,#e3e5ec);border-top:1px solid var(--mpr-color-border,#2c2f36);--mpr-footer-scale:1;--mpr-footer-toggle-scale:1}' +
    'footer.mpr-footer[data-mpr-sticky="false"]{position:static;left:auto;right:auto;bottom:auto}' +
    'footer.mpr-footer [data-mpr-footer="inner"]{max-width:var(--mpr-content-width-expanded,1180px);margin:0 auto;padding:0 calc(.75rem * var(--mpr-footer-scale,1));display:flex;flex-wrap:nowrap;align-items:center;justify-content:space-between;gap:calc(.75rem * var(--mpr-footer-scale,1));overflow:visible}' +
    'footer.mpr-footer [data-mpr-footer="layout"]{display:flex;flex-wrap:wrap;align-items:center;gap:calc(.75rem * var(--mpr-footer-scale,1));width:100%;min-width:0;white-space:nowrap}' +
    'footer.mpr-footer .mpr-footer__horizontal-links{display:flex;flex:1 1 auto;min-width:0;flex-wrap:wrap;align-items:center;justify-content:center;gap:calc(.6rem * var(--mpr-footer-scale,1));font-size:max(.72rem,calc(.78rem * var(--mpr-footer-scale,1)));color:var(--mpr-color-text-muted,#c4c7d1);white-space:normal}' +
    'footer.mpr-footer .mpr-footer__horizontal-links[data-mpr-align="left"]{justify-content:flex-start}' +
    'footer.mpr-footer .mpr-footer__horizontal-links[data-mpr-align="right"]{justify-content:flex-end}' +
    "footer.mpr-footer .mpr-footer__horizontal-links a{max-width:100%;overflow-wrap:anywhere;color:inherit;text-decoration:none;font-weight:500}" +
    "footer.mpr-footer .mpr-footer__horizontal-links a:hover{text-decoration:underline}" +
    "footer.mpr-footer .mpr-footer__horizontal-links:empty{display:none}" +
    'footer.mpr-footer [data-mpr-footer="legal"]{flex:1 1 auto;min-width:0;text-align:center;white-space:normal;overflow-wrap:anywhere;font-size:max(.72rem,calc(.78rem * var(--mpr-footer-scale,1)));color:var(--mpr-color-text-muted,#c4c7d1)}' +
    'footer.mpr-footer [data-mpr-footer="legal"]:empty{display:none}' +
    'footer.mpr-footer [data-mpr-footer="legal"]:not(:empty) ~ [data-mpr-footer="spacer"]{display:none}' +
    '.mpr-footer__spacer{display:block;flex:1 1 auto;min-width:1px}' +
    'footer.mpr-footer [data-mpr-footer="brand"]{display:flex;flex-wrap:wrap;min-width:0;max-width:100%;align-items:center;gap:calc(.6rem * var(--mpr-footer-scale,1));font-size:max(.72rem,calc(.78rem * var(--mpr-footer-scale,1)));margin-left:auto;white-space:normal}' +
    '.mpr-footer__prefix{font-weight:600;color:var(--mpr-color-accent,#38bdf8)}' +
    '.mpr-footer__privacy{color:var(--mpr-color-text-muted,#cbd5f5);text-decoration:none;font-size:calc(0.85rem * var(--mpr-footer-scale,1))}' +
    '.mpr-footer__privacy:hover{text-decoration:underline}' +
    'footer.mpr-footer [data-mpr-footer="theme-toggle"]{display:inline-flex;align-items:center;gap:calc(.5rem * var(--mpr-footer-scale,1));background:transparent;border-radius:0;padding:0;color:var(--mpr-color-text-primary,#e3e5ec);font-size:max(.72rem,calc(.78rem * var(--mpr-footer-scale,1)));cursor:pointer;box-shadow:none;border:none}' +
    'footer.mpr-footer input.mpr-footer__theme-checkbox[data-mpr-theme-toggle="control"]{--mpr-theme-toggle-track-width:calc(42px * var(--mpr-footer-toggle-scale,1));--mpr-theme-toggle-track-height:calc(22px * var(--mpr-footer-toggle-scale,1));--mpr-theme-toggle-knob-size:calc(18px * var(--mpr-footer-toggle-scale,1));--mpr-theme-toggle-offset:calc(3px * var(--mpr-footer-toggle-scale,1))}' +
    '[data-mpr-footer="theme-toggle"][data-mpr-theme-toggle-variant="square"]{background:transparent;padding:0;border-radius:0;box-shadow:none;gap:calc(0.75rem * var(--mpr-footer-scale,1))}' +
    '.mpr-footer__theme-checkbox[data-variant="square"]{width:auto;height:auto;display:inline-flex;align-items:center;gap:calc(0.75rem * var(--mpr-footer-scale,1));border-radius:0;background:transparent;border:none;padding:0;box-shadow:none}' +
    "footer.mpr-footer [data-mpr-theme-toggle='control'][data-variant='square']{--mpr-theme-square-size:calc(28px * var(--mpr-footer-scale,1));--mpr-theme-square-dot-size:calc(6px * var(--mpr-footer-scale,1))}" +
    "footer.mpr-footer.mpr-footer--small{--mpr-footer-scale:.82;--mpr-footer-toggle-scale:.82}";

  var FOOTER_LINK_CATALOG = Object.freeze([
    Object.freeze({ label: "Marco Polo Research Lab", url: "https://mprlab.com" }),
    Object.freeze({ label: "Gravity Notes", url: "https://gravity.mprlab.com" }),
    Object.freeze({ label: "LoopAware", url: "https://loopaware.mprlab.com" }),
    Object.freeze({ label: "Allergy Wheel", url: "https://allergy.mprlab.com" }),
    Object.freeze({ label: "Social Threader", url: "https://threader.mprlab.com" }),
    Object.freeze({ label: "RSVP", url: "https://rsvp.mprlab.com" }),
    Object.freeze({ label: "Countdown Calendar", url: "https://countdown.mprlab.com" }),
    Object.freeze({ label: "LLM Crossword", url: "https://llm-crossword.mprlab.com" }),
    Object.freeze({ label: "Prompt Bubbles", url: "https://prompts.mprlab.com" }),
    Object.freeze({ label: "Wallpapers", url: "https://wallpapers.mprlab.com" }),
  ]);

  function getFooterSiteCatalog() {
    return FOOTER_LINK_CATALOG.map(function cloneCatalogEntry(entry) {
      return {
        label: entry.label,
        url: entry.url,
      };
    });
  }

  var LEGAL_DOCUMENT_ROOT_CLASS = "mpr-legal-document";
  var LEGAL_DOCUMENT_STYLE_ID = "mpr-ui-legal-document-styles";
  var LEGAL_DOCUMENT_TYPE_ERROR_CODE = "mpr-ui.legal.invalid_type";
  var LEGAL_DOCUMENT_SECTION_ERROR_CODE = "mpr-ui.legal.invalid_section";
  var LEGAL_DOCUMENT_TYPES = Object.freeze(["terms", "privacy"]);
  var LEGAL_DOCUMENT_DEFAULT_TYPE = "terms";
  var LEGAL_DOCUMENT_SOURCE_OPTIONS =
    typeof WeakMap === "function" ? new WeakMap() : null;
  var LEGAL_DOCUMENT_MONTH_NAMES = Object.freeze([
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
  ]);
  var LEGAL_DOCUMENT_ATTRIBUTE_NAMES = Object.freeze([
    "type",
    "product-name",
    "service-description",
    "service-data-description",
    "effective-date",
    "effective-date-text",
    "last-updated-date",
    "privacy-path",
    "terms-path",
    "pricing-path",
    "company-name",
    "company-short-name",
    "company-form",
    "website-url",
    "support-email",
    "legal-email",
    "phone-display",
    "phone-href",
    "profile",
    "sections",
    "extra-sections",
    "title",
  ]);
  /** @type {LegalProfile} */
  var LEGAL_PROFILE_DEFAULTS = Object.freeze({
    companyName: "Marco Polo Research Lab LLC",
    companyShortName: "MPR Lab",
    companyForm: "California limited liability company",
    websiteUrl: "https://mprlab.com",
    supportEmail: "support@mprlab.com",
    legalNoticesEmail: "legal@mprlab.com",
    phoneDisplay: "(650) 265-1193",
    phoneHref: "+16502651193",
  });
  var LEGAL_DOCUMENT_DEFAULTS = Object.freeze({
    type: LEGAL_DOCUMENT_DEFAULT_TYPE,
    productName: "Service",
    serviceDescription:
      "The service provides software tools and related support services.",
    serviceDataDescription:
      "account records, submitted content, generated results, preferences, and operational history",
    effectiveDate: "2026-03-30",
    effectiveDateText: "March 30, 2026",
    lastUpdatedDate: "2026-04-28",
    privacyPath: "/privacy",
    termsPath: "/tos",
    pricingPath: "/pricing",
    title: "",
    profile: LEGAL_PROFILE_DEFAULTS,
  });
  var LEGAL_DOCUMENT_STYLE_MARKUP =
    "mpr-legal-document{display:block;color:var(--mpr-color-text-primary,#e2e8f0)}" +
    ".mpr-legal-document{display:block}" +
    ".mpr-legal-document__card{max-width:720px;margin:0 auto;padding:1rem;border-radius:var(--mpr-radius-control,6px);border:1px solid var(--mpr-color-border,#2c2f36);background:var(--mpr-color-surface-elevated,#1f2126);box-shadow:none;color:var(--mpr-color-text-primary,#e3e5ec)}" +
    ".mpr-legal-document__title{margin:0 0 .5rem;font-size:1.35rem;line-height:1.2;font-weight:700;letter-spacing:0}" +
    ".mpr-legal-document__meta{margin:0 0 .75rem;color:var(--mpr-color-text-muted,#c4c7d1);font-size:.72rem;line-height:1.45}" +
    ".mpr-legal-document__intro{margin:0 0 .75rem;color:var(--mpr-color-text-muted,#c4c7d1);font-size:.86rem;line-height:1.55}" +
    ".mpr-legal-document__section{margin-block-start:1rem}" +
    ".mpr-legal-document__heading{margin:0 0 .5rem;font-size:.9rem;line-height:1.35;font-weight:700;letter-spacing:0;color:var(--mpr-color-text-primary,#e3e5ec)}" +
    ".mpr-legal-document__paragraph,.mpr-legal-document__list-item{margin:0 0 .65rem;color:var(--mpr-color-text-muted,#c4c7d1);font-size:.86rem;line-height:1.55}" +
    ".mpr-legal-document__list{margin:0;padding-inline-start:1.25rem}" +
    ".mpr-legal-document__link{color:var(--mpr-color-accent,#38bdf8);font-weight:600;text-decoration:none}" +
    ".mpr-legal-document__link:hover{text-decoration:underline}" +
    "@media(max-width:640px){.mpr-legal-document__card{padding:.75rem}.mpr-legal-document__title{font-size:1.15rem}}";

  function ensureLegalDocumentStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(LEGAL_DOCUMENT_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = LEGAL_DOCUMENT_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = LEGAL_DOCUMENT_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(LEGAL_DOCUMENT_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function cloneLegalProfile(profile) {
    var sourceProfile =
      profile && typeof profile === "object" ? profile : LEGAL_PROFILE_DEFAULTS;
    return {
      companyName: sourceProfile.companyName,
      companyShortName: sourceProfile.companyShortName,
      companyForm: sourceProfile.companyForm,
      websiteUrl: sourceProfile.websiteUrl,
      supportEmail: sourceProfile.supportEmail,
      legalNoticesEmail: sourceProfile.legalNoticesEmail,
      phoneDisplay: sourceProfile.phoneDisplay,
      phoneHref: sourceProfile.phoneHref,
    };
  }

  function getLegalProfile() {
    return cloneLegalProfile(LEGAL_PROFILE_DEFAULTS);
  }

  function normalizeLegalText(value, fallbackValue) {
    if (typeof value !== "string") {
      return fallbackValue;
    }
    var trimmed = value.trim();
    return trimmed ? trimmed : fallbackValue;
  }

  function formatLegalDateText(value) {
    if (typeof value !== "string") {
      return "";
    }
    var dateParts = value.split("-");
    if (dateParts.length !== 3) {
      return value;
    }
    var yearText = dateParts[0];
    var monthNumber = Number(dateParts[1]);
    var dayNumber = Number(dateParts[2]);
    var monthName = LEGAL_DOCUMENT_MONTH_NAMES[monthNumber - 1];
    if (!yearText || !monthName || !dayNumber) {
      return value;
    }
    return monthName + " " + String(dayNumber) + ", " + yearText;
  }

  function normalizeLegalTextList(value) {
    if (typeof value === "string") {
      var trimmedValue = value.trim();
      return trimmedValue ? [trimmedValue] : [];
    }
    if (!Array.isArray(value)) {
      return [];
    }
    return value
      .map(function normalizeEntry(entry) {
        return typeof entry === "string" ? entry.trim() : "";
      })
      .filter(Boolean);
  }

  function normalizeLegalSectionId(value, fallbackValue) {
    var source = normalizeLegalText(value, fallbackValue || "");
    if (!source) {
      return "";
    }
    return source
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  function normalizeLegalSection(rawSection, sectionIndex) {
    if (!rawSection || typeof rawSection !== "object") {
      logError(
        LEGAL_DOCUMENT_SECTION_ERROR_CODE,
        "Legal document sections must be objects with heading and content.",
      );
      return null;
    }
    var heading = normalizeLegalText(
      rawSection.heading || rawSection.title,
      "",
    );
    if (!heading) {
      logError(
        LEGAL_DOCUMENT_SECTION_ERROR_CODE,
        "Legal document section heading is required.",
      );
      return null;
    }
    var paragraphs = normalizeLegalTextList(
      rawSection.paragraphs || rawSection.body || rawSection.content,
    );
    var list = normalizeLegalTextList(rawSection.list || rawSection.items);
    if (!paragraphs.length && !list.length) {
      logError(
        LEGAL_DOCUMENT_SECTION_ERROR_CODE,
        "Legal document section content is required.",
      );
      return null;
    }
    return {
      id: normalizeLegalSectionId(rawSection.id, "section-" + String(sectionIndex + 1)),
      heading: heading,
      paragraphs: paragraphs,
      list: list,
    };
  }

  function normalizeLegalSections(rawSections) {
    if (!Array.isArray(rawSections)) {
      return [];
    }
    return rawSections
      .map(function normalizeSection(section, sectionIndex) {
        return normalizeLegalSection(section, sectionIndex);
      })
      .filter(Boolean);
  }

  function cloneLegalSection(section) {
    return {
      id: section.id,
      heading: section.heading,
      paragraphs: section.paragraphs.slice(),
      list: section.list.slice(),
    };
  }

  function createLegalSection(id, heading, paragraphs, list) {
    return {
      id: id,
      heading: heading,
      paragraphs: paragraphs.slice(),
      list: Array.isArray(list) ? list.slice() : [],
    };
  }

  function normalizeLegalDocumentType(value) {
    var normalized = normalizeLegalText(value, LEGAL_DOCUMENT_DEFAULT_TYPE).toLowerCase();
    if (LEGAL_DOCUMENT_TYPES.indexOf(normalized) !== -1) {
      return normalized;
    }
    logError(
      LEGAL_DOCUMENT_TYPE_ERROR_CODE,
      'Unsupported legal document type "' + value + '".',
    );
    return LEGAL_DOCUMENT_DEFAULT_TYPE;
  }

  function normalizeLegalProfile(rawProfile) {
    var profileInput =
      rawProfile && typeof rawProfile === "object" ? rawProfile : {};
    var mergedProfile = deepMergeOptions(
      {},
      LEGAL_PROFILE_DEFAULTS,
      profileInput,
    );
    if (profileInput.legalEmail && !profileInput.legalNoticesEmail) {
      mergedProfile.legalNoticesEmail = profileInput.legalEmail;
    }
    return cloneLegalProfile({
      companyName: normalizeLegalText(
        mergedProfile.companyName,
        LEGAL_PROFILE_DEFAULTS.companyName,
      ),
      companyShortName: normalizeLegalText(
        mergedProfile.companyShortName,
        LEGAL_PROFILE_DEFAULTS.companyShortName,
      ),
      companyForm: normalizeLegalText(
        mergedProfile.companyForm,
        LEGAL_PROFILE_DEFAULTS.companyForm,
      ),
      websiteUrl: normalizeLegalText(
        mergedProfile.websiteUrl,
        LEGAL_PROFILE_DEFAULTS.websiteUrl,
      ),
      supportEmail: normalizeLegalText(
        mergedProfile.supportEmail,
        LEGAL_PROFILE_DEFAULTS.supportEmail,
      ),
      legalNoticesEmail: normalizeLegalText(
        mergedProfile.legalNoticesEmail,
        LEGAL_PROFILE_DEFAULTS.legalNoticesEmail,
      ),
      phoneDisplay: normalizeLegalText(
        mergedProfile.phoneDisplay,
        LEGAL_PROFILE_DEFAULTS.phoneDisplay,
      ),
      phoneHref: normalizeLegalText(
        mergedProfile.phoneHref,
        LEGAL_PROFILE_DEFAULTS.phoneHref,
      ),
    });
  }

  function normalizeLegalDocumentOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var profile = normalizeLegalProfile(options.profile);
    var effectiveDate = normalizeLegalText(
      options.effectiveDate,
      LEGAL_DOCUMENT_DEFAULTS.effectiveDate,
    );
    if (options.companyName) {
      profile.companyName = normalizeLegalText(options.companyName, profile.companyName);
    }
    if (options.companyShortName) {
      profile.companyShortName = normalizeLegalText(
        options.companyShortName,
        profile.companyShortName,
      );
    }
    if (options.companyForm) {
      profile.companyForm = normalizeLegalText(options.companyForm, profile.companyForm);
    }
    if (options.websiteUrl) {
      profile.websiteUrl = normalizeLegalText(options.websiteUrl, profile.websiteUrl);
    }
    if (options.supportEmail) {
      profile.supportEmail = normalizeLegalText(options.supportEmail, profile.supportEmail);
    }
    if (options.legalEmail || options.legalNoticesEmail) {
      profile.legalNoticesEmail = normalizeLegalText(
        options.legalEmail || options.legalNoticesEmail,
        profile.legalNoticesEmail,
      );
    }
    if (options.phoneDisplay) {
      profile.phoneDisplay = normalizeLegalText(options.phoneDisplay, profile.phoneDisplay);
    }
    if (options.phoneHref) {
      profile.phoneHref = normalizeLegalText(options.phoneHref, profile.phoneHref);
    }
    return {
      type: normalizeLegalDocumentType(options.type),
      productName: normalizeLegalText(
        options.productName,
        LEGAL_DOCUMENT_DEFAULTS.productName,
      ),
      serviceDescription: normalizeLegalText(
        options.serviceDescription,
        LEGAL_DOCUMENT_DEFAULTS.serviceDescription,
      ),
      serviceDataDescription: normalizeLegalText(
        options.serviceDataDescription,
        LEGAL_DOCUMENT_DEFAULTS.serviceDataDescription,
      ),
      effectiveDate: effectiveDate,
      effectiveDateText: normalizeLegalText(
        options.effectiveDateText,
        formatLegalDateText(effectiveDate),
      ),
      lastUpdatedDate: normalizeLegalText(
        options.lastUpdatedDate,
        LEGAL_DOCUMENT_DEFAULTS.lastUpdatedDate,
      ),
      privacyPath: normalizeLegalText(
        options.privacyPath,
        LEGAL_DOCUMENT_DEFAULTS.privacyPath,
      ),
      termsPath: normalizeLegalText(
        options.termsPath,
        LEGAL_DOCUMENT_DEFAULTS.termsPath,
      ),
      pricingPath: normalizeLegalText(
        options.pricingPath,
        LEGAL_DOCUMENT_DEFAULTS.pricingPath,
      ),
      title: normalizeLegalText(options.title, ""),
      profile: profile,
      sections: Array.isArray(options.sections)
        ? normalizeLegalSections(options.sections)
        : null,
      extraSections: normalizeLegalSections(options.extraSections),
    };
  }

  function getLegalDocumentSourceOptions(rawOptions) {
    if (
      rawOptions &&
      typeof rawOptions === "object" &&
      LEGAL_DOCUMENT_SOURCE_OPTIONS
    ) {
      var sourceOptions = LEGAL_DOCUMENT_SOURCE_OPTIONS.get(rawOptions);
      if (sourceOptions) {
        return deepMergeOptions({}, sourceOptions);
      }
    }
    return deepMergeOptions({}, rawOptions || {});
  }

  function rememberLegalDocumentSourceOptions(documentConfig, rawOptions) {
    if (
      documentConfig &&
      typeof documentConfig === "object" &&
      LEGAL_DOCUMENT_SOURCE_OPTIONS
    ) {
      LEGAL_DOCUMENT_SOURCE_OPTIONS.set(
        documentConfig,
        getLegalDocumentSourceOptions(rawOptions),
      );
    }
    return documentConfig;
  }

  function buildTermsLegalSections(config) {
    var profile = config.profile;
    return [
      createLegalSection("eligibility", "1. Eligibility and Account Use", [], [
        "You must be legally able to enter into contracts to use the Service.",
        "If you use the Service on behalf of an organization, you confirm you have authority to bind that organization.",
        "You are responsible for maintaining account access and for all activity under your account.",
      ]),
      createLegalSection("service-description", "2. Service Description", [
        config.serviceDescription,
        "Some features, schedules, notifications, pricing options, integrations, or exports may change over time.",
      ]),
      createLegalSection("acceptable-use", "3. Acceptable Use", [], [
        "Use the Service only for lawful business purposes.",
        "Comply with applicable third-party terms, platform rules, and content rights for any data or sites you process through the Service.",
        "Do not interfere with service availability, security, or other users.",
        "Do not upload malicious code, attempt unauthorized access, or abuse APIs, automation, billing, or usage limits.",
      ]),
      createLegalSection("user-content", "4. User Content and Data", [
        "You retain rights to data you upload or generate through the Service. You grant us a limited license to store, process, and display that data as needed to provide, secure, troubleshoot, and improve the Service.",
        "You are responsible for confirming that your use of source websites, uploaded content, and generated outputs is permitted. Privacy and data handling details are in the Privacy Policy at " + config.privacyPath + ".",
      ]),
      createLegalSection("pricing", "5. Pricing, Credits, and Payments", [
        "Pricing may be displayed in-product or at " + config.pricingPath + " and may be updated prospectively.",
        "Usage-based actions may consume credits according to in-product indicators. If paid checkout is enabled, payment processing may be provided by Paddle or another authorized payment provider.",
        "Subscriptions renew automatically until canceled unless the checkout flow says otherwise. Cancellation stops future renewals and takes effect at the end of the then-current billing period.",
      ]),
      createLegalSection("refund-policy", "6. Refund Policy", [
        "For usage-credit operations, the Service may separately restore credits for eligible technical failures according to product behavior.",
        "For any completed checkout charge processed through a website, you may request an unconditional full refund within 14 calendar days of the charge. This policy applies to initial subscription fees, renewals, top-up packs, and other direct purchases, even after you use the Service.",
        "You do not need to provide a reason. To request a refund or get billing support, contact " + profile.supportEmail + ". Purchases processed by the Apple App Store or Google Play use the applicable store's refund process. This policy does not limit rights under applicable law.",
      ]),
      createLegalSection("third-party-services", "7. Third-Party Services", [
        "The Service may depend on third-party services including authentication, hosting, telemetry, support widgets, billing infrastructure, payment processing, and external APIs. We are not responsible for downtime or actions of those third parties beyond our contractual obligations.",
      ]),
      createLegalSection("availability", "8. Availability and Changes", [
        "We may update, suspend, or discontinue features at any time, including to improve security, comply with legal obligations, or maintain platform integrity.",
        "We may revise these Terms by posting an updated version with a new effective date. Continued use after updates means you accept the revised Terms.",
      ]),
      createLegalSection("termination", "9. Suspension and Termination", [
        "We may suspend or terminate access if you violate these Terms, create legal or security risk, or misuse the Service. You may stop using the Service at any time.",
      ]),
      createLegalSection("intellectual-property", "10. Intellectual Property", [
        "The Service software, design, and related materials are proprietary to " + profile.companyName + " and its licensors, and are protected by applicable intellectual property laws.",
      ]),
      createLegalSection("disclaimers", "11. Disclaimers", [
        'The Service is provided "as is" and "as available" without warranties of any kind. Outputs are informational and may be affected by source data, external services, network conditions, or configured rules.',
      ]),
      createLegalSection("limitation-of-liability", "12. Limitation of Liability", [
        "To the maximum extent permitted by law, " + profile.companyName + " is not liable for indirect, incidental, special, consequential, or punitive damages, or for lost profits, revenue, data, or goodwill arising from use of the Service.",
      ]),
      createLegalSection("indemnification", "13. Indemnification", [
        "To the extent permitted by law, you agree to defend, indemnify, and hold harmless " + profile.companyName + " and its officers, employees, contractors, service providers, and licensors from claims, losses, liabilities, damages, costs, and expenses arising from your content, your use of the Service, your violation of these Terms, or your violation of applicable law or third-party rights.",
      ]),
      createLegalSection("governing-law", "14. Governing Law and Venue", [
        "These Terms are governed by the laws of the State of California, without regard to conflict-of-law rules. Except where applicable law requires otherwise, disputes arising from these Terms or the Service will be resolved in state or federal courts located in Los Angeles County, California, and you consent to that venue.",
      ]),
      createLegalSection("contact", "15. Contact and Notices", [
        "For legal notices or Terms questions, contact " + profile.legalNoticesEmail + ". For billing, refund, account, or support questions, contact " + profile.supportEmail + ". You may also call " + profile.phoneDisplay + " or visit " + profile.websiteUrl + ".",
      ]),
    ];
  }

  function buildPrivacyLegalSections(config) {
    var profile = config.profile;
    return [
      createLegalSection("scope", "1. Scope and Controller", [
        "Effective " + config.effectiveDateText + ", " + profile.companyName + " is the data controller for information processed through " + config.productName + ". This policy applies to our website, web application, and related support services.",
      ]),
      createLegalSection("information-we-collect", "2. Information We Collect", [
        "Account and authentication data: we may use Google Identity Services or related authentication providers to sign you in and receive profile fields required to operate the account, including your name, email address, and profile image.",
        "Service data: we collect and store " + config.serviceDataDescription + ".",
        "Preferences and communications: we store account preferences and notification settings, and we process communications such as support requests.",
        "Technical and diagnostics data: we process technical data such as IP address, user agent, timestamps, request metadata, and service logs for security, troubleshooting, abuse prevention, and reliability.",
        "Billing and transaction data: if paid features are enabled, we process credits, subscription, transaction, and reconciliation metadata required to operate billing. Payment providers may process payment details, and we do not receive full payment card numbers.",
      ]),
      createLegalSection("use-of-information", "3. How We Use Information", [], [
        "Authenticate users and secure accounts.",
        "Operate product functionality, exports, settings, notifications, and support workflows.",
        "Operate credits, billing, reconciliation, and fraud prevention workflows.",
        "Monitor, troubleshoot, and improve service reliability and performance.",
        "Comply with legal obligations and enforce our Terms of Service at " + config.termsPath + ".",
      ]),
      createLegalSection("google-oauth", "4. Google OAuth and Google User Data", [
        config.productName + " uses Google OAuth only for sign-in and account identity when Google sign-in is enabled. Google user data is not sold and is not used for advertising. We use Google profile data solely to provide and secure the Service for the authenticated account.",
        "If you disconnect your Google account or request account deletion, we stop further OAuth-based access for that account.",
      ]),
      createLegalSection("sharing", "5. Sharing and Disclosure", [
        "We do not sell personal information. We may share information with service providers strictly as needed to operate the Service, including identity/authentication providers, cloud hosting providers, analytics/support tooling, email delivery providers, billing infrastructure, and payment processors.",
        "We may also disclose information when required by law, to protect rights or safety, or in a corporate transaction.",
      ]),
      createLegalSection("cookies", "6. Cookies, Local Storage, and Analytics", [], [
        "Session cookies may be used for authentication and security.",
        "Browser local storage may store UI preferences such as theme settings.",
        "Analytics tools may be used for aggregate usage analytics.",
        "Support and feedback widgets may collect interaction data needed to provide support.",
      ]),
      createLegalSection("retention", "7. Data Retention", [
        "We retain account and operational data for as long as needed to provide the Service and meet legal, accounting, and security obligations. Retention windows vary by data type and may include active account lifetime, operational backups, and financial recordkeeping periods.",
      ]),
      createLegalSection("security", "8. Security", [
        "We use technical and organizational safeguards designed to protect information, including access controls, transport security, and monitoring. No system is completely secure, and we cannot guarantee absolute security.",
      ]),
      createLegalSection("international-transfers", "9. International Transfers", [
        "We and our providers may process data in multiple countries. When data is transferred across borders, we use appropriate contractual and operational safeguards required by applicable law.",
      ]),
      createLegalSection("rights", "10. Your Rights and Choices", [
        "Depending on your location, you may have rights to access, correct, export, or delete personal information, and to object to or restrict some processing. To submit a request, contact us at " + profile.supportEmail + ".",
      ]),
      createLegalSection("children", "11. Children's Privacy", [
        config.productName + " is not directed to children, and we do not knowingly collect personal information from children.",
      ]),
      createLegalSection("changes", "12. Changes to This Policy", [
        "We may update this Privacy Policy from time to time. Material updates will be reflected by revising the effective date on this page.",
      ]),
      createLegalSection("contact", "13. Contact", [
        "For privacy questions, account deletion requests, or data rights requests, contact " + profile.supportEmail + ". Legal notices may be sent to " + profile.legalNoticesEmail + ". You may also call " + profile.phoneDisplay + " or visit " + profile.websiteUrl + ".",
      ]),
    ];
  }

  function insertLegalExtraSections(baseSections, extraSections) {
    if (!extraSections.length) {
      return baseSections.map(cloneLegalSection);
    }
    var sections = baseSections.map(cloneLegalSection);
    var contactIndex = -1;
    sections.forEach(function findContact(section, sectionIndex) {
      if (section.id === "contact") {
        contactIndex = sectionIndex;
      }
    });
    var additions = extraSections.map(cloneLegalSection);
    if (contactIndex === -1) {
      Array.prototype.push.apply(sections, additions);
      return sections;
    }
    sections.splice.apply(sections, [contactIndex, 0].concat(additions));
    return sections;
  }

  function buildLegalDocument(rawOptions) {
    var config = normalizeLegalDocumentOptions(rawOptions);
    var defaultTitle =
      (config.type === "privacy" ? "Privacy Policy - " : "Terms of Service - ") +
      config.productName;
    var baseSections =
      config.type === "privacy"
        ? buildPrivacyLegalSections(config)
        : buildTermsLegalSections(config);
    var resolvedSections =
      config.sections && config.sections.length
        ? config.sections.map(cloneLegalSection)
        : insertLegalExtraSections(baseSections, config.extraSections);
    return rememberLegalDocumentSourceOptions(
      {
        type: config.type,
        title: config.title || defaultTitle,
        productName: config.productName,
        effectiveDate: config.effectiveDate,
        effectiveDateText: config.effectiveDateText,
        lastUpdatedDate: config.lastUpdatedDate,
        profile: cloneLegalProfile(config.profile),
        introduction:
          config.type === "privacy"
            ? [
                "This Privacy Policy explains how " +
                  config.profile.companyName +
                  ", a " +
                  config.profile.companyForm +
                  ' ("' +
                  config.profile.companyShortName +
                  '", "Company", "we", "our", "us"), collects, uses, discloses, and protects information when you use ' +
                  config.productName +
                  ' (the "Service").',
              ]
            : [
                "These Terms of Service form a binding agreement between you and " +
                  config.profile.companyName +
                  ", a " +
                  config.profile.companyForm +
                  ' ("' +
                  config.profile.companyShortName +
                  '", "Company", "we", "our", "us"), for access to and use of ' +
                  config.productName +
                  ' (the "Service"). By using the Service, you agree to these Terms.',
                "Effective " +
                  config.effectiveDateText +
                  ", " +
                  config.productName +
                  " is operated by " +
                  config.profile.companyName +
                  ". Continued use of the Service on or after that date is governed by these Terms.",
              ],
        sections: resolvedSections,
      },
      rawOptions,
    );
  }

  function renderLegalParagraph(paragraph) {
    return (
      '<p class="' +
      LEGAL_DOCUMENT_ROOT_CLASS +
      '__paragraph">' +
      escapeHtml(paragraph) +
      "</p>"
    );
  }

  function renderLegalListItem(item) {
    return (
      '<li class="' +
      LEGAL_DOCUMENT_ROOT_CLASS +
      '__list-item">' +
      escapeHtml(item) +
      "</li>"
    );
  }

  function buildLegalSectionMarkup(section) {
    var idMarkup = section.id ? ' id="' + escapeHtml(section.id) + '"' : "";
    var paragraphMarkup = section.paragraphs.map(renderLegalParagraph).join("");
    var listMarkup = section.list.length
      ? '<ul class="' +
        LEGAL_DOCUMENT_ROOT_CLASS +
        '__list">' +
        section.list.map(renderLegalListItem).join("") +
        "</ul>"
      : "";
    return (
      '<section class="' +
      LEGAL_DOCUMENT_ROOT_CLASS +
      '__section"' +
      idMarkup +
      ' data-mpr-legal-document="section">' +
      '<h2 class="' +
      LEGAL_DOCUMENT_ROOT_CLASS +
      '__heading">' +
      escapeHtml(section.heading) +
      "</h2>" +
      paragraphMarkup +
      listMarkup +
      "</section>"
    );
  }

  function buildLegalDocumentMarkup(documentConfig) {
    var introductionMarkup = documentConfig.introduction
      .map(function renderIntroduction(paragraph) {
        return (
          '<p class="' +
          LEGAL_DOCUMENT_ROOT_CLASS +
          '__intro">' +
          escapeHtml(paragraph) +
          "</p>"
        );
      })
      .join("");
    return (
      '<article class="' +
      LEGAL_DOCUMENT_ROOT_CLASS +
      '__card" data-mpr-legal-document="card">' +
      '<h1 class="' +
      LEGAL_DOCUMENT_ROOT_CLASS +
      '__title" data-mpr-legal-document="title">' +
      escapeHtml(documentConfig.title) +
      "</h1>" +
      '<p class="' +
      LEGAL_DOCUMENT_ROOT_CLASS +
      '__meta" data-mpr-legal-document="meta">' +
      "<strong>Effective Date:</strong> " +
      '<time datetime="' +
      escapeHtml(documentConfig.effectiveDate) +
      '">' +
      escapeHtml(documentConfig.effectiveDate) +
      "</time> · <strong>Last Updated:</strong> " +
      '<time datetime="' +
      escapeHtml(documentConfig.lastUpdatedDate) +
      '">' +
      escapeHtml(documentConfig.lastUpdatedDate) +
      "</time></p>" +
      introductionMarkup +
      documentConfig.sections.map(buildLegalSectionMarkup).join("") +
      "</article>"
    );
  }

  function createLegalDocumentController(target, options) {
    var host = resolveHost(target);
    if (!host || typeof host !== "object") {
      throw new Error("createLegalDocumentController requires a host element");
    }
    var currentOptions = getLegalDocumentSourceOptions(options);
    function renderCurrentDocument() {
      var documentObject =
        host.ownerDocument ||
        global.document ||
        (global.window && global.window.document) ||
        null;
      ensureLegalDocumentStyles(documentObject);
      var documentConfig = buildLegalDocument(currentOptions);
      if (host.classList && typeof host.classList.add === "function") {
        host.classList.add(LEGAL_DOCUMENT_ROOT_CLASS);
      }
      if (typeof host.setAttribute === "function") {
        host.setAttribute("data-mpr-legal-document-type", documentConfig.type);
        host.setAttribute(
          "data-mpr-legal-document-section-count",
          String(documentConfig.sections.length),
        );
      }
      host.innerHTML = buildLegalDocumentMarkup(documentConfig);
    }
    renderCurrentDocument();
    return {
      update: function update(nextOptions, replaceOptions) {
        var incomingOptions = getLegalDocumentSourceOptions(nextOptions);
        var hasTypeChange =
          !replaceOptions &&
          incomingOptions.type &&
          currentOptions.type &&
          incomingOptions.type !== currentOptions.type;
        var hasSectionOverride =
          Object.prototype.hasOwnProperty.call(incomingOptions, "sections");
        var hasTitleOverride =
          Object.prototype.hasOwnProperty.call(incomingOptions, "title");
        currentOptions = replaceOptions
          ? incomingOptions
          : deepMergeOptions({}, currentOptions, incomingOptions);
        if (hasTypeChange && !hasSectionOverride) {
          delete currentOptions.sections;
        }
        if (hasTypeChange && !hasTitleOverride) {
          delete currentOptions.title;
        }
        renderCurrentDocument();
      },
      destroy: function destroy() {
        if (host && Object.prototype.hasOwnProperty.call(host, "innerHTML")) {
          host.innerHTML = "";
        }
        if (host && typeof host.removeAttribute === "function") {
          host.removeAttribute("data-mpr-legal-document-type");
          host.removeAttribute("data-mpr-legal-document-section-count");
        }
      },
      getDocument: function getDocument() {
        return buildLegalDocument(currentOptions);
      },
    };
  }

  function buildLegalDocumentOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var typeAttr = hostElement.getAttribute("type");
    if (typeAttr) {
      options.type = typeAttr;
    }
    var productNameAttr = hostElement.getAttribute("product-name");
    if (productNameAttr) {
      options.productName = productNameAttr;
    }
    var serviceDescriptionAttr = hostElement.getAttribute("service-description");
    if (serviceDescriptionAttr) {
      options.serviceDescription = serviceDescriptionAttr;
    }
    var serviceDataDescriptionAttr = hostElement.getAttribute(
      "service-data-description",
    );
    if (serviceDataDescriptionAttr) {
      options.serviceDataDescription = serviceDataDescriptionAttr;
    }
    var effectiveDateAttr = hostElement.getAttribute("effective-date");
    if (effectiveDateAttr) {
      options.effectiveDate = effectiveDateAttr;
    }
    var effectiveDateTextAttr = hostElement.getAttribute("effective-date-text");
    if (effectiveDateTextAttr) {
      options.effectiveDateText = effectiveDateTextAttr;
    }
    var lastUpdatedDateAttr = hostElement.getAttribute("last-updated-date");
    if (lastUpdatedDateAttr) {
      options.lastUpdatedDate = lastUpdatedDateAttr;
    }
    var privacyPathAttr = hostElement.getAttribute("privacy-path");
    if (privacyPathAttr) {
      options.privacyPath = privacyPathAttr;
    }
    var termsPathAttr = hostElement.getAttribute("terms-path");
    if (termsPathAttr) {
      options.termsPath = termsPathAttr;
    }
    var pricingPathAttr = hostElement.getAttribute("pricing-path");
    if (pricingPathAttr) {
      options.pricingPath = pricingPathAttr;
    }
    var titleAttr = hostElement.getAttribute("title");
    if (titleAttr) {
      options.title = titleAttr;
    }
    var profile = {};
    var companyNameAttr = hostElement.getAttribute("company-name");
    if (companyNameAttr) {
      profile.companyName = companyNameAttr;
    }
    var companyShortNameAttr = hostElement.getAttribute("company-short-name");
    if (companyShortNameAttr) {
      profile.companyShortName = companyShortNameAttr;
    }
    var companyFormAttr = hostElement.getAttribute("company-form");
    if (companyFormAttr) {
      profile.companyForm = companyFormAttr;
    }
    var websiteUrlAttr = hostElement.getAttribute("website-url");
    if (websiteUrlAttr) {
      profile.websiteUrl = websiteUrlAttr;
    }
    var supportEmailAttr = hostElement.getAttribute("support-email");
    if (supportEmailAttr) {
      profile.supportEmail = supportEmailAttr;
    }
    var legalEmailAttr = hostElement.getAttribute("legal-email");
    if (legalEmailAttr) {
      profile.legalNoticesEmail = legalEmailAttr;
    }
    var phoneDisplayAttr = hostElement.getAttribute("phone-display");
    if (phoneDisplayAttr) {
      profile.phoneDisplay = phoneDisplayAttr;
    }
    var phoneHrefAttr = hostElement.getAttribute("phone-href");
    if (phoneHrefAttr) {
      profile.phoneHref = phoneHrefAttr;
    }
    var profileAttr = hostElement.getAttribute("profile");
    if (profileAttr) {
      options.profile = deepMergeOptions(
        {},
        profile,
        parseJsonValue(profileAttr, {}),
      );
    } else if (Object.keys(profile).length) {
      options.profile = profile;
    }
    var sectionsAttr = hostElement.getAttribute("sections");
    if (sectionsAttr) {
      options.sections = parseJsonValue(sectionsAttr, []);
    }
    var extraSectionsAttr = hostElement.getAttribute("extra-sections");
    if (extraSectionsAttr) {
      options.extraSections = parseJsonValue(extraSectionsAttr, []);
    }
    return options;
  }

  /** @type {readonly BandCatalogEntry[]} */
  var BAND_PROJECT_CATALOG = Object.freeze([
    Object.freeze({
      id: "issues-md",
      name: "ISSUES.md",
      description:
        "Append-only lab worklog that tracks features, improvements, and maintenance activity across Marco Polo Research Lab projects.",
      status: "WIP",
      category: "research",
      url: "https://github.com/MarcoPoloResearchLab/marcopolo.github.io/blob/main/ISSUES.md",
      icon: "assets/projects/issues-md/icon.png",
    }),
    Object.freeze({
      id: "photolab",
      name: "Photolab",
      description:
        "Local photo library classifier and search UI that writes high-confidence labels into EXIF, indexes metadata into SQLite, and serves a minimal browser-based search grid.",
      status: "WIP",
      category: "research",
      url: null,
      icon: "assets/projects/photolab/icon.svg",
    }),
    Object.freeze({
      id: "ctx",
      name: "ctx",
      description:
        "Terminal-first project explorer for browsing trees, reading files with embedded docs, analysing call chains, and fetching upstream docs from GitHub via one CLI.",
      status: "Production",
      category: "tools",
      url: "https://github.com/tyemirov/ctx",
      icon: "assets/projects/ctx/icon.png",
    }),
    Object.freeze({
      id: "gix",
      name: "gix",
      description:
        "Git and GitHub maintenance CLI for keeping large fleets of repositories healthy by normalising folder names, aligning remotes, and automating audit/release workflows.",
      status: "Production",
      category: "tools",
      url: "https://github.com/tyemirov/gix",
      icon: "assets/projects/gix/icon.png",
    }),
    Object.freeze({
      id: "ghttp",
      name: "gHTTP",
      description:
        "Go-powered static file server that mirrors python -m http.server while adding Markdown rendering, structured logging, and easy HTTPS provisioning for local work or containers.",
      status: "Production",
      category: "tools",
      url: "https://github.com/temirov/ghttp",
      icon: "assets/projects/ghttp/icon.png",
    }),
    Object.freeze({
      id: "loopaware",
      name: "LoopAware",
      description:
        "Customer feedback platform with an embeddable widget, Google-authenticated dashboard, and APIs for collecting, triaging, and responding to product messages.",
      status: "Production",
      category: "platform",
      url: "https://loopaware.mprlab.com",
      icon: "assets/projects/loopaware/icon.svg",
      subscribe: Object.freeze({
        script:
          "https://loopaware.mprlab.com/subscribe.js?site_id=c4fa39f7-4690-4bae-93d1-9401bdf98dbf&mode=inline&accent=%23ffd369&cta=Subscribe&success=Thanks%20for%20subscribing&name_field=false",
        title: "Get LoopAware release updates",
        copy:
          "Drop your email to hear when LoopAware ships fresh drops, integrations, and subscriber tooling.",
      }),
    }),
    Object.freeze({
      id: "pinguin",
      name: "Pinguin",
      description:
        "Production-ready notification service that exposes a gRPC API for email and SMS, persists jobs in SQLite, and retries failures with an exponential-backoff scheduler.",
      status: "Production",
      category: "platform",
      url: "https://github.com/temirov/pinguin",
      icon: "assets/projects/pinguin/icon.png",
    }),
    Object.freeze({
      id: "ets",
      name: "Ephemeral Token Service (ETS)",
      description:
        "JWT + DPoP gateway that mints short-lived, browser-bound access tokens and reverse-proxies requests so front-end apps never handle provider secrets directly.",
      status: "Beta",
      category: "platform",
      url: "https://ets.mprlab.com",
      icon: "assets/projects/ets/icon.svg",
    }),
    Object.freeze({
      id: "tauth",
      name: "TAuth",
      description:
        "Google Sign-In and session service that verifies ID tokens, issues short-lived JWT cookies, and ships a tiny auth-client.js helper for same-origin apps.",
      status: "Production",
      category: "platform",
      url: "https://tauth.mprlab.com",
      icon: "assets/projects/tauth/icon.svg",
    }),
    Object.freeze({
      id: "ledger",
      name: "Ledger Service",
      description:
        "Standalone gRPC-based virtual credits ledger that tracks grants, reservations, captures, and releases in an append-only store backed by SQL with full auditability.",
      status: "Beta",
      category: "platform",
      url: "https://github.com/tyemirov/ledger",
      icon: "assets/projects/ledger/icon.png",
      subscribe: Object.freeze({
        script:
          "https://loopaware.mprlab.com/subscribe.js?site_id=9edfc4a2-e5ab-43f8-ada8-72bebf3f56a1&mode=inline&accent=%23ffd369&cta=Subscribe&success=Thanks%20for%20subscribing&name_field=false",
        title: "Get Ledger Service release updates",
        copy:
          "Drop your email to hear when Ledger Service ships new credit controls, integrations, and audit tools.",
      }),
    }),
    Object.freeze({
      id: "product-scanner",
      name: "Poodle Scanner",
      description:
        "AI-assisted storefront auditor nicknamed “Poodle” that sniffs out PDP gaps, evaluates results against configurable rule packs, and reports issues through a CLI and authenticated dashboard.",
      status: "Beta",
      category: "products",
      url: "https://ps.mprlab.com",
      icon: "assets/projects/product-scanner/icon.png",
    }),
    Object.freeze({
      id: "sheet2tube",
      name: "Sheet2Tube",
      description:
        "CSV and web toolkit that round-trips YouTube channel metadata between spreadsheets and your account plus a GPT-powered helper for expanding scripted placeholders.",
      status: "Beta",
      category: "products",
      url: "https://sheet2tube.mprlab.com",
      icon: "assets/projects/sheet2tube/icon.svg",
    }),
    Object.freeze({
      id: "gravity-notes",
      name: "Gravity Notes",
      description:
        "Single-page Markdown notebook with an inline card grid, offline-first storage, and Google-backed sync so ideas flow without modal dialogs or context switches.",
      status: "Production",
      category: "products",
      url: "https://gravity.mprlab.com",
      icon: "assets/projects/gravity-notes/icon.png",
      subscribe: Object.freeze({
        script:
          "https://loopaware.mprlab.com/subscribe.js?site_id=8b4fa15e-52a9-4feb-a466-bb186f42df81&mode=inline&accent=%23ffd369&cta=Subscribe&success=Thanks%20for%20subscribing&name_field=false",
        title: "Get Gravity Notes release updates",
        copy:
          "Drop your email to hear when Gravity Notes ships fresh features, AI integrations, and new plugins.",
        height: 320,
      }),
    }),
    Object.freeze({
      id: "rsvp",
      name: "RSVP",
      description:
        "Event invitation platform that generates QR-code-powered invites, tracks responses, and supports both local and production TLS setups for secure guest flows.",
      status: "Production",
      category: "products",
      url: "https://rsvp.mprlab.com",
      icon: "assets/projects/rsvp/icon.png",
    }),
  ]);

  function getBandProjectCatalog() {
    return BAND_PROJECT_CATALOG.map(function cloneBandProject(entry) {
      return {
        id: entry.id,
        name: entry.name,
        title: entry.name,
        description: entry.description,
        status: entry.status,
        category: entry.category,
        url: entry.url,
        icon: entry.icon,
        subscribe: entry.subscribe
          ? {
              script: entry.subscribe.script,
              title: entry.subscribe.title,
              copy: entry.subscribe.copy,
              height: entry.subscribe.height,
            }
          : null,
      };
    });
  }

  var SITES_ROOT_CLASS = "mpr-sites";
  var SITES_STYLE_ID = "mpr-ui-sites-styles";
  var SITES_STYLE_MARKUP =
    ".mpr-sites{display:flex;flex-direction:column;gap:0.5rem}" +
    ".mpr-sites__heading{margin:0;font-size:0.78rem;font-weight:600;color:var(--mpr-color-text-primary,#e3e5ec)}" +
    ".mpr-sites__list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:0.35rem}" +
    ".mpr-sites__list--grid{display:grid;grid-template-columns:repeat(var(--mpr-sites-columns,2),minmax(0,1fr));gap:0.5rem}" +
    ".mpr-sites__item{margin:0}" +
    ".mpr-sites__link{display:flex;justify-content:space-between;align-items:center;padding:0.45rem 0.55rem;border-radius:var(--mpr-radius-control,6px);border:1px solid var(--mpr-color-border,#2c2f36);color:var(--mpr-color-text-primary,#e3e5ec);font-size:0.78rem;text-decoration:none;font-weight:500;background:var(--mpr-color-surface-elevated,#1f2126)}" +
    ".mpr-sites__link:hover{border-color:var(--mpr-color-accent,#38bdf8);color:var(--mpr-color-accent,#38bdf8)}" +
    ".mpr-sites__empty{padding:0.45rem 0.55rem;border:1px dashed var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);font-size:0.78rem;text-align:center;color:var(--mpr-color-text-muted,#c4c7d1)}" +
    ".mpr-sites--menu ." +
    SITES_ROOT_CLASS +
    "__list{gap:0.35rem}" +
    ".mpr-sites--menu ." +
    SITES_ROOT_CLASS +
    "__link{background:transparent}";
  var SITES_VARIANTS = Object.freeze(["list", "grid", "menu"]);
  var SITES_DEFAULTS = Object.freeze({
    variant: "list",
    columns: 2,
    heading: "",
  });
  var SITES_EMPTY_LABEL = "No sites available";

  function ensureSitesStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(SITES_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = SITES_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = SITES_STYLE_MARKUP;
    } else {
      styleElement.appendChild(documentObject.createTextNode(SITES_STYLE_MARKUP));
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildSitesOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var variantAttr = hostElement.getAttribute("variant");
    if (variantAttr) {
      options.variant = variantAttr;
    }
    var columnsAttr = hostElement.getAttribute("columns");
    if (columnsAttr !== null && columnsAttr !== undefined) {
      var parsedColumns = parseInt(columnsAttr, 10);
      if (!isNaN(parsedColumns)) {
        options.columns = parsedColumns;
      }
    }
    var headingAttr = hostElement.getAttribute("heading");
    if (headingAttr) {
      options.heading = headingAttr;
    }
    var linksAttr = hostElement.getAttribute("links");
    if (linksAttr) {
      options.links = parseJsonValue(linksAttr, []);
    }
    return options;
  }

  function normalizeSitesOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var variantSource =
      typeof options.variant === "string" && options.variant.trim()
        ? options.variant.trim().toLowerCase()
        : SITES_DEFAULTS.variant;
    var variant = SITES_VARIANTS.indexOf(variantSource) === -1
      ? SITES_DEFAULTS.variant
      : variantSource;
    var columns = parseInt(options.columns, 10);
    if (!columns || columns < 1) {
      columns = SITES_DEFAULTS.columns;
    }
    if (columns > 4) {
      columns = 4;
    }
    var heading =
      typeof options.heading === "string" && options.heading.trim()
        ? options.heading.trim()
        : "";
    var links = normalizeSitesLinks(options.links);
    return {
      variant: variant,
      columns: columns,
      heading: heading,
      links: links,
    };
  }

  function normalizeSitesLinks(rawLinks) {
    var source = Array.isArray(rawLinks) ? rawLinks : null;
    var baseList = source && source.length ? source : getFooterSiteCatalog();
    return baseList
      .map(function normalize(entry) {
        return normalizeLinkForRendering(
          {
            label: entry && entry.label,
            href: entry && entry.url,
            target: entry && entry.target,
            rel: entry && entry.rel,
          },
          {
            target: FOOTER_LINK_DEFAULT_TARGET,
            rel: FOOTER_LINK_DEFAULT_REL,
          },
        );
      })
      .filter(Boolean);
  }

  function buildSitesMarkup(config) {
    var listClass = SITES_ROOT_CLASS + "__list";
    if (config.variant === "grid") {
      listClass += " " + SITES_ROOT_CLASS + "__list--grid";
    }
    var itemsMarkup = config.links
      .map(function renderLink(link, index) {
        return (
          '<li class="' +
          SITES_ROOT_CLASS +
          '__item"><a class="' +
          SITES_ROOT_CLASS +
          '__link" data-mpr-sites-index="' +
          String(index) +
          '" href="' +
          escapeHtml(link.href) +
          '" target="' +
          escapeHtml(link.target) +
          '" rel="' +
          escapeHtml(link.rel) +
          '">' +
          escapeHtml(link.label) +
          "</a></li>"
        );
      })
      .join("");
    var headingMarkup = config.heading
      ? '<p class="' + SITES_ROOT_CLASS + '__heading">' + escapeHtml(config.heading) + "</p>"
      : "";
    if (!itemsMarkup) {
      itemsMarkup =
        '<li class="' +
        SITES_ROOT_CLASS +
        '__item"><span class="' +
        SITES_ROOT_CLASS +
        '__empty">' +
        escapeHtml(SITES_EMPTY_LABEL) +
        "</span></li>";
    }
    return (
      '<div class="' +
      SITES_ROOT_CLASS +
      '__container" data-mpr-sites="container">' +
      headingMarkup +
      '<ul class="' +
      listClass +
      '" data-mpr-sites="list" role="list" style="--mpr-sites-columns:' +
      String(config.columns) +
      '">' +
      itemsMarkup +
      "</ul>" +
      "</div>"
    );
  }

  function captureSlotNodesWithDefault(hostElement, slotNames, defaultSlotName) {
    var slots = captureSlotNodes(hostElement, slotNames);
    if (
      !defaultSlotName ||
      !hostElement ||
      typeof hostElement.removeChild !== "function"
    ) {
      return slots;
    }
    var defaultNodes = [];
    while (hostElement.firstChild) {
      var childNode = hostElement.firstChild;
      hostElement.removeChild(childNode);
      var slotName =
        childNode && typeof childNode.getAttribute === "function"
          ? childNode.getAttribute("slot")
          : childNode && typeof childNode.slot === "string"
          ? childNode.slot
          : null;
      if (slotName && Object.prototype.hasOwnProperty.call(slots, slotName)) {
        continue;
      }
      defaultNodes.push(childNode);
    }
    if (!slots[defaultSlotName]) {
      slots[defaultSlotName] = [];
    }
    Array.prototype.push.apply(slots[defaultSlotName], defaultNodes);
    return slots;
  }

  function initializeTrackedSlotMap(slotNames, defaultSlotName) {
    var slots = {};
    if (Array.isArray(slotNames)) {
      slotNames.forEach(function initSlot(name) {
        slots[name] = [];
      });
    }
    if (
      defaultSlotName &&
      !Object.prototype.hasOwnProperty.call(slots, defaultSlotName)
    ) {
      slots[defaultSlotName] = [];
    }
    return slots;
  }

  function trackedSlotMapHasNode(slotMap, node) {
    if (!slotMap || !node) {
      return false;
    }
    return Object.keys(slotMap).some(function hasNode(slotName) {
      return Array.isArray(slotMap[slotName]) && slotMap[slotName].indexOf(node) !== -1;
    });
  }

  function resolveTrackedSlotName(node, slotMap, defaultSlotName) {
    var slotName = null;
    if (node && typeof node.getAttribute === "function") {
      slotName = node.getAttribute("slot");
    }
    if (!slotName && node && typeof node.slot === "string") {
      slotName = node.slot;
    }
    if (slotName && Object.prototype.hasOwnProperty.call(slotMap, slotName)) {
      return slotName;
    }
    return defaultSlotName || null;
  }

  function getDirectHostChildNodes(hostElement) {
    if (!hostElement) {
      return [];
    }
    if (
      hostElement.childNodes &&
      typeof hostElement.childNodes.length === "number"
    ) {
      return Array.prototype.slice.call(hostElement.childNodes);
    }
    if (
      hostElement.children &&
      typeof hostElement.children.length === "number"
    ) {
      return Array.prototype.slice.call(hostElement.children);
    }
    return [];
  }

  function isTrackedNodeAttachedToHost(node, hostElement) {
    if (!node || !hostElement) {
      return false;
    }
    if (typeof hostElement.contains === "function") {
      try {
        return hostElement.contains(node);
      } catch (_error) {}
    }
    var currentNode = node;
    while (currentNode) {
      if (currentNode === hostElement) {
        return true;
      }
      currentNode = currentNode.parentNode || null;
    }
    return node.parentNode !== null;
  }

  function hasTrackedNodeMounted(node) {
    return Boolean(node && node.__mprTrackedSlotMounted);
  }

  function markTrackedNodeAsMounted(node) {
    if (!node || (typeof node !== "object" && typeof node !== "function")) {
      return;
    }
    node.__mprTrackedSlotMounted = true;
  }

  function syncTrackedSlotsWithHost(
    hostElement,
    slotNames,
    defaultSlotName,
    currentSlots,
    preservedRootNodes,
  ) {
    var nextSlots = initializeTrackedSlotMap(slotNames, defaultSlotName);
    Object.keys(nextSlots).forEach(function copySlot(slotName) {
      var nodes =
        currentSlots && Array.isArray(currentSlots[slotName])
          ? currentSlots[slotName]
          : [];
      nodes.forEach(function keepNode(node) {
        if (
          !node ||
          trackedSlotMapHasNode(nextSlots, node) ||
          (hasTrackedNodeMounted(node) &&
            !isTrackedNodeAttachedToHost(node, hostElement))
        ) {
          return;
        }
        nextSlots[slotName].push(node);
      });
    });
    var preservedNodes = Array.isArray(preservedRootNodes)
      ? preservedRootNodes.filter(Boolean)
      : [];
    getDirectHostChildNodes(hostElement).forEach(function captureNode(node) {
      if (!node || preservedNodes.indexOf(node) !== -1) {
        return;
      }
      if (hostElement && typeof hostElement.removeChild === "function") {
        try {
          hostElement.removeChild(node);
        } catch (_error) {}
      }
      if (trackedSlotMapHasNode(nextSlots, node)) {
        return;
      }
      var slotName = resolveTrackedSlotName(node, nextSlots, defaultSlotName);
      if (slotName) {
        nextSlots[slotName].push(node);
      }
    });
    return nextSlots;
  }

  function resolveOwnerWindow(hostElement) {
    if (
      hostElement &&
      hostElement.ownerDocument &&
      hostElement.ownerDocument.defaultView
    ) {
      return hostElement.ownerDocument.defaultView;
    }
    if (global.window) {
      return global.window;
    }
    return null;
  }

  function setHiddenState(element, shouldHide) {
    if (!element || typeof element.setAttribute !== "function") {
      return;
    }
    if (shouldHide) {
      element.setAttribute("hidden", "hidden");
      return;
    }
    if (typeof element.removeAttribute === "function") {
      element.removeAttribute("hidden");
    }
  }

  var DETAIL_DRAWER_ROOT_CLASS = "mpr-detail-drawer";
  var DETAIL_DRAWER_STYLE_ID = "mpr-ui-detail-drawer-styles";
  var DETAIL_DRAWER_STYLE_MARKUP =
    "mpr-detail-drawer{position:fixed;inset:0;display:block;z-index:80;pointer-events:none;overflow:clip}" +
    "mpr-detail-drawer[data-mpr-detail-drawer-open=\"true\"]{pointer-events:auto}" +
    ".mpr-detail-drawer__backdrop{position:absolute;inset:0;background:var(--mpr-color-surface-backdrop,rgba(15,23,42,0.65));opacity:0;transition:opacity 0.22s ease}" +
    ".mpr-detail-drawer__panel{position:absolute;top:0;bottom:0;right:0;display:flex;flex-direction:column;gap:.75rem;inline-size:min(28rem,100vw);padding:.75rem;border-left:1px solid var(--mpr-color-border,#2c2f36);background:var(--mpr-color-surface-elevated,#1f2126);color:var(--mpr-color-text-primary,#e3e5ec);box-shadow:var(--mpr-shadow-flyout,0 8px 24px rgba(0,0,0,.3));transform:translateX(100%);transition:transform .25s ease;box-sizing:border-box;overflow:auto}" +
    "mpr-detail-drawer[data-mpr-detail-drawer-placement=\"left\"] .mpr-detail-drawer__panel{left:0;right:auto;border-left:none;border-right:1px solid var(--mpr-color-border,rgba(148,163,184,0.25));transform:translateX(-100%)}" +
    "mpr-detail-drawer[data-mpr-detail-drawer-open=\"true\"] .mpr-detail-drawer__backdrop{opacity:1}" +
    "mpr-detail-drawer[data-mpr-detail-drawer-open=\"true\"] .mpr-detail-drawer__panel{transform:translateX(0)}" +
    ".mpr-detail-drawer__header{display:flex;align-items:flex-start;justify-content:space-between;gap:0.75rem}" +
    ".mpr-detail-drawer__copy{display:flex;flex-direction:column;gap:0.35rem;min-width:0}" +
    ".mpr-detail-drawer__subheading{margin:0;font-size:0.8rem;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:var(--mpr-color-text-muted,#cbd5f5)}" +
    ".mpr-detail-drawer__heading{margin:0;font-size:1rem;line-height:1.2}" +
    ".mpr-detail-drawer__header-actions{display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap}" +
    ".mpr-detail-drawer__close{appearance:none;border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);padding:.35rem .55rem;background:transparent;color:inherit;cursor:pointer;font-size:.78rem;font-weight:600}" +
    ".mpr-detail-drawer__close:hover{border-color:var(--mpr-color-accent,#38bdf8);color:var(--mpr-color-accent,#38bdf8)}" +
    ".mpr-detail-drawer__busy{padding:0.75rem 0.9rem;border:1px dashed var(--mpr-color-border,rgba(148,163,184,0.3));border-radius:0.9rem;color:var(--mpr-color-text-muted,#cbd5f5);background:var(--mpr-chip-bg,rgba(148,163,184,0.18))}" +
    ".mpr-detail-drawer__busy[hidden]{display:none!important}" +
    ".mpr-detail-drawer__body{display:flex;flex-direction:column;gap:1rem;min-height:0}" +
    ".mpr-detail-drawer__footer{display:flex;align-items:center;justify-content:flex-end;gap:0.75rem;flex-wrap:wrap;padding-top:0.25rem}" +
    ".mpr-detail-drawer__footer[hidden]{display:none!important}" +
    "@media (max-width: 48rem){.mpr-detail-drawer__panel{inline-size:100vw;padding:1rem}}";
  var DETAIL_DRAWER_DEFAULTS = Object.freeze({
    heading: "Details",
    subheading: "",
    placement: "right",
    busy: false,
  });
  var DETAIL_DRAWER_PLACEMENTS = Object.freeze(["left", "right"]);
  var DETAIL_DRAWER_HEADING_ID_PREFIX = "mpr-detail-drawer-heading-";
  var detailDrawerCounter = 0;

  function ensureDetailDrawerStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(DETAIL_DRAWER_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = DETAIL_DRAWER_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = DETAIL_DRAWER_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(DETAIL_DRAWER_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function createDetailDrawerHeadingId() {
    detailDrawerCounter += 1;
    return DETAIL_DRAWER_HEADING_ID_PREFIX + detailDrawerCounter;
  }

  function buildDetailDrawerOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var headingAttr = hostElement.getAttribute("heading");
    if (headingAttr) {
      options.heading = headingAttr;
    }
    var subheadingAttr = hostElement.getAttribute("subheading");
    if (subheadingAttr) {
      options.subheading = subheadingAttr;
    }
    var placementAttr = hostElement.getAttribute("placement");
    if (placementAttr) {
      options.placement = placementAttr;
    }
    var busyAttr = hostElement.getAttribute("busy");
    if (busyAttr !== null) {
      options.busy = normalizeBooleanAttribute(busyAttr, true);
    }
    var openAttr = hostElement.getAttribute("open");
    if (openAttr !== null) {
      options.open = normalizeBooleanAttribute(openAttr, true);
    }
    return options;
  }

  function normalizeDetailDrawerOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var heading =
      typeof options.heading === "string" && options.heading.trim()
        ? options.heading.trim()
        : DETAIL_DRAWER_DEFAULTS.heading;
    var subheading =
      typeof options.subheading === "string" && options.subheading.trim()
        ? options.subheading.trim()
        : DETAIL_DRAWER_DEFAULTS.subheading;
    var placementSource =
      typeof options.placement === "string" && options.placement.trim()
        ? options.placement.trim().toLowerCase()
        : DETAIL_DRAWER_DEFAULTS.placement;
    var placement =
      DETAIL_DRAWER_PLACEMENTS.indexOf(placementSource) === -1
        ? DETAIL_DRAWER_DEFAULTS.placement
        : placementSource;
    return {
      heading: heading,
      subheading: subheading,
      placement: placement,
      busy: Boolean(options.busy),
      open: Boolean(options.open),
    };
  }

  function buildDetailDrawerMarkup(config, headingDomId) {
    return (
      '<div class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__backdrop" data-mpr-detail-drawer="backdrop"' +
      (config.open ? "" : ' hidden="hidden"') +
      "></div>" +
      '<aside class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__panel" data-mpr-detail-drawer="panel" role="dialog" aria-modal="true" aria-hidden="' +
      (config.open ? "false" : "true") +
      '" aria-labelledby="' +
      escapeHtml(headingDomId) +
      '"' +
      (config.open ? "" : ' hidden="hidden"') +
      ">" +
      '<div class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__header">' +
      '<div class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__copy">' +
      '<p class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__subheading" data-mpr-detail-drawer="subheading"' +
      (config.subheading ? "" : ' hidden="hidden"') +
      ">" +
      escapeHtml(config.subheading) +
      "</p>" +
      '<h2 class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__heading" data-mpr-detail-drawer="heading" id="' +
      escapeHtml(headingDomId) +
      '">' +
      escapeHtml(config.heading) +
      "</h2>" +
      "</div>" +
      '<div class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__header-actions" data-mpr-detail-drawer="header-actions"></div>' +
      '<button type="button" class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__close" data-mpr-detail-drawer="close">Close</button>' +
      "</div>" +
      '<div class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__busy" data-mpr-detail-drawer="busy"' +
      (config.busy ? "" : ' hidden="hidden"') +
      '>Loading details…</div>' +
      '<div class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__body" data-mpr-detail-drawer="body"></div>' +
      '<div class="' +
      DETAIL_DRAWER_ROOT_CLASS +
      '__footer" data-mpr-detail-drawer="footer" hidden="hidden"></div>' +
      "</aside>"
    );
  }

  function resolveDetailDrawerElements(hostElement) {
    if (!hostElement || typeof hostElement.querySelector !== "function") {
      return {};
    }
    return {
      backdrop: hostElement.querySelector('[data-mpr-detail-drawer="backdrop"]'),
      panel: hostElement.querySelector('[data-mpr-detail-drawer="panel"]'),
      heading: hostElement.querySelector('[data-mpr-detail-drawer="heading"]'),
      subheading: hostElement.querySelector('[data-mpr-detail-drawer="subheading"]'),
      headerActions: hostElement.querySelector(
        '[data-mpr-detail-drawer="header-actions"]',
      ),
      closeButton: hostElement.querySelector('[data-mpr-detail-drawer="close"]'),
      busy: hostElement.querySelector('[data-mpr-detail-drawer="busy"]'),
      body: hostElement.querySelector('[data-mpr-detail-drawer="body"]'),
      footer: hostElement.querySelector('[data-mpr-detail-drawer="footer"]'),
    };
  }

  function applyDetailDrawerSlotContent(slotMap, elements) {
    if (!slotMap || !elements) {
      return;
    }
    if (
      slotMap["header-actions"] &&
      slotMap["header-actions"].length &&
      elements.headerActions
    ) {
      clearNodeContents(elements.headerActions);
      slotMap["header-actions"].forEach(function appendHeaderAction(node) {
        if (node && typeof elements.headerActions.appendChild === "function") {
          elements.headerActions.appendChild(node);
        }
      });
    }
    if (slotMap.body && elements.body) {
      clearNodeContents(elements.body);
      slotMap.body.forEach(function appendBodyNode(node) {
        if (node && typeof elements.body.appendChild === "function") {
          elements.body.appendChild(node);
        }
      });
    }
    if (elements.footer) {
      clearNodeContents(elements.footer);
      if (slotMap.footer && slotMap.footer.length) {
        slotMap.footer.forEach(function appendFooterNode(node) {
          if (node && typeof elements.footer.appendChild === "function") {
            elements.footer.appendChild(node);
          }
        });
        setHiddenState(elements.footer, false);
      } else {
        setHiddenState(elements.footer, true);
      }
    }
  }

  var WORKSPACE_LAYOUT_ROOT_CLASS = "mpr-workspace-layout";
  var WORKSPACE_LAYOUT_STYLE_ID = "mpr-ui-workspace-layout-styles";
  var WORKSPACE_LAYOUT_STYLE_MARKUP =
    "mpr-workspace-layout{display:block;color:var(--mpr-color-text-primary,#e2e8f0)}" +
    ".mpr-workspace-layout__header{margin-bottom:1rem}" +
    ".mpr-workspace-layout__frame{display:grid;grid-template-columns:minmax(0,var(--mpr-workspace-sidebar-width,18rem)) minmax(0,1fr);gap:1.25rem;align-items:start;min-width:0}" +
    ".mpr-workspace-layout__sidebar{min-width:0}" +
    ".mpr-workspace-layout__content{min-width:0}" +
    "mpr-workspace-layout[data-mpr-workspace-stacked=\"true\"] .mpr-workspace-layout__frame{grid-template-columns:minmax(0,1fr)}" +
    "mpr-workspace-layout[data-mpr-workspace-collapsed=\"true\"] .mpr-workspace-layout__frame{grid-template-columns:minmax(0,1fr)}" +
    "mpr-workspace-layout[data-mpr-workspace-collapsed=\"true\"] .mpr-workspace-layout__sidebar{display:none}" +
    "mpr-workspace-layout[data-mpr-workspace-stacked=\"true\"] .mpr-workspace-layout__sidebar{position:static}" +
    ".mpr-workspace-layout__sidebar>*,.mpr-workspace-layout__content>*{min-width:0}";
  var WORKSPACE_LAYOUT_DEFAULTS = Object.freeze({
    sidebarWidth: "18rem",
    stackedBreakpoint: "64rem",
    collapsed: false,
  });
  var WORKSPACE_LAYOUT_BREAKPOINT_FALLBACK_PX = 1024;

  function ensureWorkspaceLayoutStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(WORKSPACE_LAYOUT_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = WORKSPACE_LAYOUT_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = WORKSPACE_LAYOUT_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(WORKSPACE_LAYOUT_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildWorkspaceLayoutOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var sidebarWidthAttr = hostElement.getAttribute("sidebar-width");
    if (sidebarWidthAttr) {
      options.sidebarWidth = sidebarWidthAttr;
    }
    var breakpointAttr = hostElement.getAttribute("stacked-breakpoint");
    if (breakpointAttr) {
      options.stackedBreakpoint = breakpointAttr;
    }
    var collapsedAttr = hostElement.getAttribute("collapsed");
    if (collapsedAttr !== null) {
      options.collapsed = normalizeBooleanAttribute(collapsedAttr, true);
    }
    return options;
  }

  function normalizeCssLength(value, fallbackValue) {
    if (typeof value !== "string") {
      return fallbackValue;
    }
    var trimmed = value.trim();
    return trimmed ? trimmed : fallbackValue;
  }

  function normalizeWorkspaceLayoutOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    return {
      sidebarWidth: normalizeCssLength(
        options.sidebarWidth,
        WORKSPACE_LAYOUT_DEFAULTS.sidebarWidth,
      ),
      stackedBreakpoint: normalizeCssLength(
        options.stackedBreakpoint,
        WORKSPACE_LAYOUT_DEFAULTS.stackedBreakpoint,
      ),
      collapsed: Boolean(options.collapsed),
    };
  }

  function buildWorkspaceLayoutMarkup() {
    return (
      '<div class="' +
      WORKSPACE_LAYOUT_ROOT_CLASS +
      '__header" data-mpr-workspace-layout="header"></div>' +
      '<div class="' +
      WORKSPACE_LAYOUT_ROOT_CLASS +
      '__frame" data-mpr-workspace-layout="frame">' +
      '<aside class="' +
      WORKSPACE_LAYOUT_ROOT_CLASS +
      '__sidebar" data-mpr-workspace-layout="sidebar"></aside>' +
      '<section class="' +
      WORKSPACE_LAYOUT_ROOT_CLASS +
      '__content" data-mpr-workspace-layout="content"></section>' +
      "</div>"
    );
  }

  function resolveWorkspaceLayoutElements(hostElement) {
    if (!hostElement || typeof hostElement.querySelector !== "function") {
      return {};
    }
    return {
      header: hostElement.querySelector('[data-mpr-workspace-layout="header"]'),
      frame: hostElement.querySelector('[data-mpr-workspace-layout="frame"]'),
      sidebar: hostElement.querySelector('[data-mpr-workspace-layout="sidebar"]'),
      content: hostElement.querySelector('[data-mpr-workspace-layout="content"]'),
    };
  }

  function applyWorkspaceLayoutSlotContent(slotMap, elements) {
    if (!slotMap || !elements) {
      return;
    }
    if (slotMap.header && elements.header) {
      clearNodeContents(elements.header);
      slotMap.header.forEach(function appendHeaderNode(node) {
        if (node && typeof elements.header.appendChild === "function") {
          elements.header.appendChild(node);
        }
      });
    }
    if (slotMap.sidebar && elements.sidebar) {
      clearNodeContents(elements.sidebar);
      slotMap.sidebar.forEach(function appendSidebarNode(node) {
        if (node && typeof elements.sidebar.appendChild === "function") {
          elements.sidebar.appendChild(node);
        }
      });
    }
    if (slotMap.content && elements.content) {
      clearNodeContents(elements.content);
      slotMap.content.forEach(function appendContentNode(node) {
        if (node && typeof elements.content.appendChild === "function") {
          elements.content.appendChild(node);
        }
      });
    }
  }

  function resolveBreakpointPixels(value) {
    var normalized = normalizeCssLength(
      value,
      WORKSPACE_LAYOUT_DEFAULTS.stackedBreakpoint,
    );
    var match = normalized.match(/^([0-9]+(?:\.[0-9]+)?)(px|rem|em)?$/i);
    if (!match) {
      return WORKSPACE_LAYOUT_BREAKPOINT_FALLBACK_PX;
    }
    var amount = parseFloat(match[1]);
    if (!isFinite(amount) || amount <= 0) {
      return WORKSPACE_LAYOUT_BREAKPOINT_FALLBACK_PX;
    }
    var unit = (match[2] || "px").toLowerCase();
    if (unit === "rem" || unit === "em") {
      return Math.round(amount * 16);
    }
    return Math.round(amount);
  }

  function computeWorkspaceLayoutStackedState(hostElement, breakpointValue) {
    var ownerWindow = resolveOwnerWindow(hostElement);
    if (!ownerWindow || typeof ownerWindow.innerWidth !== "number") {
      return false;
    }
    return ownerWindow.innerWidth <= resolveBreakpointPixels(breakpointValue);
  }

  var SIDEBAR_NAV_ROOT_CLASS = "mpr-sidebar-nav";
  var SIDEBAR_NAV_STYLE_ID = "mpr-ui-sidebar-nav-styles";
  var SIDEBAR_NAV_STYLE_MARKUP =
    "mpr-sidebar-nav{display:block;color:var(--mpr-color-text-primary,#e2e8f0)}" +
    ".mpr-sidebar-nav__header,.mpr-sidebar-nav__footer{display:flex;flex-direction:column;gap:0.5rem}" +
    ".mpr-sidebar-nav__header{margin-bottom:0.55rem}" +
    ".mpr-sidebar-nav__footer{margin-top:0.55rem}" +
    ".mpr-sidebar-nav__list{display:flex;flex-direction:column;gap:0.3rem}" +
    ".mpr-sidebar-nav__list>[data-mpr-sidebar-key]{display:flex;align-items:center;gap:0.45rem;padding:0.5rem 0.6rem;border-radius:var(--mpr-radius-control,6px);border:1px solid transparent;color:inherit;font-size:0.78rem;text-decoration:none;background:transparent;cursor:pointer;box-sizing:border-box}" +
    "mpr-sidebar-nav[data-mpr-sidebar-nav-dense=\"true\"] .mpr-sidebar-nav__list>[data-mpr-sidebar-key]{padding:0.4rem 0.5rem;border-radius:4px}" +
    "mpr-sidebar-nav[data-mpr-sidebar-nav-variant=\"surface\"] .mpr-sidebar-nav__list>[data-mpr-sidebar-key]{background:var(--mpr-color-surface-elevated,rgba(15,23,42,0.85));border-color:var(--mpr-color-border,rgba(148,163,184,0.25))}" +
    "mpr-sidebar-nav[data-mpr-sidebar-nav-variant=\"ghost\"] .mpr-sidebar-nav__list>[data-mpr-sidebar-key]:hover{background:var(--mpr-menu-hover-bg,rgba(148,163,184,0.25))}" +
    ".mpr-sidebar-nav__list>[data-mpr-sidebar-key][aria-current=\"page\"],.mpr-sidebar-nav__list>[data-mpr-sidebar-key][data-mpr-sidebar-active=\"true\"]{background:var(--mpr-chip-bg,rgba(148,163,184,0.18));border-color:var(--mpr-color-accent,#38bdf8);color:var(--mpr-color-accent,#38bdf8)}";
  var SIDEBAR_NAV_DEFAULTS = Object.freeze({
    label: "Sections",
    dense: false,
    variant: "surface",
  });
  var SIDEBAR_NAV_VARIANTS = Object.freeze(["surface", "ghost", "list"]);
  var SIDEBAR_NAV_ITEM_SELECTOR = "[data-mpr-sidebar-key]";

  function ensureSidebarNavStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(SIDEBAR_NAV_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = SIDEBAR_NAV_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = SIDEBAR_NAV_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(SIDEBAR_NAV_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildSidebarNavOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var labelAttr = hostElement.getAttribute("label");
    if (labelAttr) {
      options.label = labelAttr;
    }
    var denseAttr = hostElement.getAttribute("dense");
    if (denseAttr !== null) {
      options.dense = normalizeBooleanAttribute(denseAttr, true);
    }
    var variantAttr = hostElement.getAttribute("variant");
    if (variantAttr) {
      options.variant = variantAttr;
    }
    return options;
  }

  function normalizeSidebarNavOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var label =
      typeof options.label === "string" && options.label.trim()
        ? options.label.trim()
        : SIDEBAR_NAV_DEFAULTS.label;
    var variantSource =
      typeof options.variant === "string" && options.variant.trim()
        ? options.variant.trim().toLowerCase()
        : SIDEBAR_NAV_DEFAULTS.variant;
    var variant =
      SIDEBAR_NAV_VARIANTS.indexOf(variantSource) === -1
        ? SIDEBAR_NAV_DEFAULTS.variant
        : variantSource;
    return {
      label: label,
      dense: Boolean(options.dense),
      variant: variant,
    };
  }

  function buildSidebarNavMarkup(config) {
    return (
      '<nav class="' +
      SIDEBAR_NAV_ROOT_CLASS +
      '__root" aria-label="' +
      escapeHtml(config.label) +
      '">' +
      '<div class="' +
      SIDEBAR_NAV_ROOT_CLASS +
      '__header" data-mpr-sidebar-nav="header"></div>' +
      '<div class="' +
      SIDEBAR_NAV_ROOT_CLASS +
      '__list" data-mpr-sidebar-nav="list"></div>' +
      '<div class="' +
      SIDEBAR_NAV_ROOT_CLASS +
      '__footer" data-mpr-sidebar-nav="footer"></div>' +
      "</nav>"
    );
  }

  function resolveSidebarNavElements(hostElement) {
    if (!hostElement || typeof hostElement.querySelector !== "function") {
      return {};
    }
    return {
      header: hostElement.querySelector('[data-mpr-sidebar-nav="header"]'),
      list: hostElement.querySelector('[data-mpr-sidebar-nav="list"]'),
      footer: hostElement.querySelector('[data-mpr-sidebar-nav="footer"]'),
      items: Array.prototype.slice.call(
        hostElement.querySelectorAll(SIDEBAR_NAV_ITEM_SELECTOR),
      ),
    };
  }

  function applySidebarNavSlotContent(slotMap, elements) {
    if (!slotMap || !elements) {
      return;
    }
    if (slotMap.header && elements.header) {
      clearNodeContents(elements.header);
      slotMap.header.forEach(function appendHeaderNode(node) {
        if (node && typeof elements.header.appendChild === "function") {
          elements.header.appendChild(node);
        }
      });
    }
    if (slotMap.default && elements.list) {
      clearNodeContents(elements.list);
      slotMap.default.forEach(function appendListNode(node) {
        if (node && typeof elements.list.appendChild === "function") {
          elements.list.appendChild(node);
        }
      });
    }
    if (slotMap.footer && elements.footer) {
      clearNodeContents(elements.footer);
      slotMap.footer.forEach(function appendFooterNode(node) {
        if (node && typeof elements.footer.appendChild === "function") {
          elements.footer.appendChild(node);
        }
      });
    }
  }

  function parsePositiveInteger(value, fallbackValue) {
    var parsed = parseInt(value, 10);
    if (!isFinite(parsed) || parsed < 1) {
      return fallbackValue;
    }
    return parsed;
  }

  var ENTITY_RAIL_ROOT_CLASS = "mpr-entity-rail";
  var ENTITY_RAIL_STYLE_ID = "mpr-ui-entity-rail-styles";
  var ENTITY_RAIL_STYLE_MARKUP =
    "mpr-entity-rail{display:block;min-width:0;max-width:100%;color:var(--mpr-color-text-primary,#e3e5ec)}" +
    ".mpr-entity-rail__header{display:flex;align-items:center;justify-content:space-between;gap:0.75rem;margin-bottom:0.85rem}" +
    ".mpr-entity-rail__label{margin:0;font-size:1rem;font-weight:700}" +
    ".mpr-entity-rail__edge{display:flex;align-items:center;gap:0.6rem}" +
    ".mpr-entity-rail__nav{display:flex;align-items:center;gap:0.45rem}" +
    ".mpr-entity-rail__nav-button{appearance:none;border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);padding:.3rem .5rem;background:var(--mpr-color-surface-elevated,#1f2126);color:inherit;cursor:pointer}" +
    ".mpr-entity-rail__nav-button[disabled]{opacity:0.45;cursor:not-allowed}" +
    ".mpr-entity-rail__viewport{max-width:100%;overflow-x:auto;overflow-y:hidden;overscroll-behavior-inline:contain;scrollbar-width:thin}" +
    ".mpr-entity-rail__track{display:flex;gap:.5rem;width:max-content;min-width:100%;padding-bottom:.25rem}" +
    ".mpr-entity-rail__empty{padding:1rem;border:1px dashed var(--mpr-color-border,rgba(148,163,184,0.3));border-radius:1rem;color:var(--mpr-color-text-muted,#cbd5f5);text-align:center}" +
    ".mpr-entity-rail__empty[hidden]{display:none!important}";
  var ENTITY_RAIL_DEFAULTS = Object.freeze({
    label: "",
    emptyLabel: "No items available",
    showNav: true,
    navStep: 320,
  });

  function ensureEntityRailStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(ENTITY_RAIL_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = ENTITY_RAIL_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = ENTITY_RAIL_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(ENTITY_RAIL_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildEntityRailOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var labelAttr = hostElement.getAttribute("label");
    if (labelAttr) {
      options.label = labelAttr;
    }
    var emptyLabelAttr = hostElement.getAttribute("empty-label");
    if (emptyLabelAttr) {
      options.emptyLabel = emptyLabelAttr;
    }
    var showNavAttr = hostElement.getAttribute("show-nav");
    if (showNavAttr !== null) {
      options.showNav = normalizeBooleanAttribute(showNavAttr, true);
    }
    var navStepAttr = hostElement.getAttribute("nav-step");
    if (navStepAttr !== null && navStepAttr !== undefined) {
      options.navStep = parsePositiveInteger(
        navStepAttr,
        ENTITY_RAIL_DEFAULTS.navStep,
      );
    }
    return options;
  }

  function normalizeEntityRailOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    return {
      label:
        typeof options.label === "string" && options.label.trim()
          ? options.label.trim()
          : ENTITY_RAIL_DEFAULTS.label,
      emptyLabel:
        typeof options.emptyLabel === "string" && options.emptyLabel.trim()
          ? options.emptyLabel.trim()
          : ENTITY_RAIL_DEFAULTS.emptyLabel,
      showNav:
        options.showNav === undefined
          ? ENTITY_RAIL_DEFAULTS.showNav
          : Boolean(options.showNav),
      navStep: parsePositiveInteger(options.navStep, ENTITY_RAIL_DEFAULTS.navStep),
    };
  }

  function buildEntityRailMarkup(config) {
    var labelMarkup = config.label
      ? '<h2 class="' +
        ENTITY_RAIL_ROOT_CLASS +
        '__label" data-mpr-entity-rail="label">' +
        escapeHtml(config.label) +
        "</h2>"
      : "";
    return (
      '<div class="' +
      ENTITY_RAIL_ROOT_CLASS +
      '__header" data-mpr-entity-rail="header">' +
      '<div class="' +
      ENTITY_RAIL_ROOT_CLASS +
      '__edge" data-mpr-entity-rail="leading"></div>' +
      labelMarkup +
      '<div class="' +
      ENTITY_RAIL_ROOT_CLASS +
      '__edge" data-mpr-entity-rail="trailing">' +
      '<div class="' +
      ENTITY_RAIL_ROOT_CLASS +
      '__nav" data-mpr-entity-rail="nav"' +
      (config.showNav ? "" : ' hidden="hidden"') +
      ">" +
      '<button type="button" class="' +
      ENTITY_RAIL_ROOT_CLASS +
      '__nav-button" data-mpr-entity-rail="prev">Back</button>' +
      '<button type="button" class="' +
      ENTITY_RAIL_ROOT_CLASS +
      '__nav-button" data-mpr-entity-rail="next">Next</button>' +
      "</div>" +
      "</div>" +
      "</div>" +
      '<div class="' +
      ENTITY_RAIL_ROOT_CLASS +
      '__viewport" data-mpr-entity-rail="viewport">' +
      '<div class="' +
      ENTITY_RAIL_ROOT_CLASS +
      '__track" data-mpr-entity-rail="track"></div>' +
      "</div>" +
      '<div class="' +
      ENTITY_RAIL_ROOT_CLASS +
      '__empty" data-mpr-entity-rail="empty"' +
      (config.label ? ' aria-label="' + escapeHtml(config.label) + '"' : "") +
      ' hidden="hidden">' +
      escapeHtml(config.emptyLabel) +
      "</div>"
    );
  }

  function resolveEntityRailElements(hostElement) {
    if (!hostElement || typeof hostElement.querySelector !== "function") {
      return {};
    }
    return {
      header: hostElement.querySelector('[data-mpr-entity-rail="header"]'),
      leading: hostElement.querySelector('[data-mpr-entity-rail="leading"]'),
      trailing: hostElement.querySelector('[data-mpr-entity-rail="trailing"]'),
      nav: hostElement.querySelector('[data-mpr-entity-rail="nav"]'),
      previousButton: hostElement.querySelector('[data-mpr-entity-rail="prev"]'),
      nextButton: hostElement.querySelector('[data-mpr-entity-rail="next"]'),
      viewport: hostElement.querySelector('[data-mpr-entity-rail="viewport"]'),
      track: hostElement.querySelector('[data-mpr-entity-rail="track"]'),
      empty: hostElement.querySelector('[data-mpr-entity-rail="empty"]'),
    };
  }

  function applyEntityRailSlotContent(slotMap, elements) {
    if (!slotMap || !elements) {
      return;
    }
    if (slotMap.leading && elements.leading) {
      clearNodeContents(elements.leading);
      slotMap.leading.forEach(function appendLeadingNode(node) {
        if (node && typeof elements.leading.appendChild === "function") {
          elements.leading.appendChild(node);
          markTrackedNodeAsMounted(node);
        }
      });
    }
    if (slotMap.trailing && elements.trailing) {
      var preservedNav = elements.nav || null;
      clearNodeContents(elements.trailing);
      if (
        preservedNav &&
        typeof elements.trailing.appendChild === "function"
      ) {
        elements.trailing.appendChild(preservedNav);
      }
      slotMap.trailing.forEach(function appendTrailingNode(node) {
        if (node && typeof elements.trailing.appendChild === "function") {
          elements.trailing.appendChild(node);
          markTrackedNodeAsMounted(node);
        }
      });
    }
    if (slotMap.default && elements.track) {
      clearNodeContents(elements.track);
      slotMap.default.forEach(function appendTrackNode(node) {
        if (node && typeof elements.track.appendChild === "function") {
          elements.track.appendChild(node);
          markTrackedNodeAsMounted(node);
        }
      });
    }
  }

  var ENTITY_TILE_ROOT_CLASS = "mpr-entity-tile";
  var ENTITY_TILE_STYLE_ID = "mpr-ui-entity-tile-styles";
  var ENTITY_TILE_STYLE_MARKUP =
    "mpr-entity-tile{display:block;color:var(--mpr-color-text-primary,#e2e8f0)}" +
    ".mpr-entity-tile__surface{display:flex;flex-direction:column;gap:0.5rem;min-height:8rem;padding:0.65rem;border-radius:var(--mpr-radius-control,6px);border:1px solid var(--mpr-color-border,#2c2f36);background:var(--mpr-color-surface-elevated,#1f2126);box-sizing:border-box}" +
    "mpr-entity-tile[data-mpr-entity-tile-interactive=\"true\"] .mpr-entity-tile__surface{cursor:pointer}" +
    "mpr-entity-tile[data-mpr-entity-tile-selected=\"true\"] .mpr-entity-tile__surface{border-color:var(--mpr-color-accent,#38bdf8);box-shadow:0 0 0 1px var(--mpr-color-accent,#38bdf8) inset}" +
    "mpr-entity-tile[data-mpr-entity-tile-disabled=\"true\"] .mpr-entity-tile__surface{opacity:0.55}" +
    ".mpr-entity-tile__top{display:flex;align-items:flex-start;justify-content:space-between;gap:0.5rem}" +
    ".mpr-entity-tile__badge,.mpr-entity-tile__actions{display:flex;align-items:center;gap:0.35rem;flex-wrap:wrap}" +
    ".mpr-entity-tile__title{display:flex;flex-direction:column;gap:0.3rem;font-size:0.86rem;font-weight:700}" +
    ".mpr-entity-tile__meta{display:flex;flex-wrap:wrap;gap:0.35rem;color:var(--mpr-color-text-muted,#c4c7d1)}" +
    ".mpr-entity-tile__empty{margin-top:auto;padding:0.5rem;border:1px dashed var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);color:var(--mpr-color-text-muted,#c4c7d1)}" +
    ".mpr-entity-tile__empty[hidden]{display:none!important}";
  var ENTITY_TILE_DEFAULTS = Object.freeze({
    variant: "default",
    selected: false,
    interactive: false,
    disabled: false,
  });

  function ensureEntityTileStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(ENTITY_TILE_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = ENTITY_TILE_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = ENTITY_TILE_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(ENTITY_TILE_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildEntityTileOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var variantAttr = hostElement.getAttribute("variant");
    if (variantAttr) {
      options.variant = variantAttr;
    }
    var selectedAttr = hostElement.getAttribute("selected");
    if (selectedAttr !== null) {
      options.selected = normalizeBooleanAttribute(selectedAttr, true);
    }
    var interactiveAttr = hostElement.getAttribute("interactive");
    if (interactiveAttr !== null) {
      options.interactive = normalizeBooleanAttribute(interactiveAttr, true);
    }
    var disabledAttr = hostElement.getAttribute("disabled");
    if (disabledAttr !== null) {
      options.disabled = normalizeBooleanAttribute(disabledAttr, true);
    }
    return options;
  }

  function normalizeEntityTileOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    return {
      variant:
        typeof options.variant === "string" && options.variant.trim()
          ? options.variant.trim().toLowerCase()
          : ENTITY_TILE_DEFAULTS.variant,
      selected: Boolean(options.selected),
      interactive: Boolean(options.interactive),
      disabled: Boolean(options.disabled),
    };
  }

  function buildEntityTileMarkup() {
    return (
      '<article class="' +
      ENTITY_TILE_ROOT_CLASS +
      '__surface" data-mpr-entity-tile="surface">' +
      '<div class="' +
      ENTITY_TILE_ROOT_CLASS +
      '__top">' +
      '<div class="' +
      ENTITY_TILE_ROOT_CLASS +
      '__badge" data-mpr-entity-tile="badge"></div>' +
      '<div class="' +
      ENTITY_TILE_ROOT_CLASS +
      '__actions" data-mpr-entity-tile="actions"></div>' +
      "</div>" +
      '<div class="' +
      ENTITY_TILE_ROOT_CLASS +
      '__title" data-mpr-entity-tile="title"></div>' +
      '<div class="' +
      ENTITY_TILE_ROOT_CLASS +
      '__meta" data-mpr-entity-tile="meta"></div>' +
      '<div class="' +
      ENTITY_TILE_ROOT_CLASS +
      '__empty" data-mpr-entity-tile="empty" hidden="hidden"></div>' +
      "</article>"
    );
  }

  function resolveEntityTileElements(hostElement) {
    if (!hostElement || typeof hostElement.querySelector !== "function") {
      return {};
    }
    return {
      surface: hostElement.querySelector('[data-mpr-entity-tile="surface"]'),
      badge: hostElement.querySelector('[data-mpr-entity-tile="badge"]'),
      actions: hostElement.querySelector('[data-mpr-entity-tile="actions"]'),
      title: hostElement.querySelector('[data-mpr-entity-tile="title"]'),
      meta: hostElement.querySelector('[data-mpr-entity-tile="meta"]'),
      empty: hostElement.querySelector('[data-mpr-entity-tile="empty"]'),
    };
  }

  function applyEntityTileSlotContent(slotMap, elements) {
    if (!slotMap || !elements) {
      return;
    }
    if (slotMap.badge && elements.badge) {
      clearNodeContents(elements.badge);
      slotMap.badge.forEach(function appendBadgeNode(node) {
        if (node && typeof elements.badge.appendChild === "function") {
          elements.badge.appendChild(node);
        }
      });
    }
    if (slotMap.actions && elements.actions) {
      clearNodeContents(elements.actions);
      slotMap.actions.forEach(function appendActionNode(node) {
        if (node && typeof elements.actions.appendChild === "function") {
          elements.actions.appendChild(node);
        }
      });
    }
    if (slotMap.title && elements.title) {
      clearNodeContents(elements.title);
      slotMap.title.forEach(function appendTitleNode(node) {
        if (node && typeof elements.title.appendChild === "function") {
          elements.title.appendChild(node);
        }
      });
    }
    if (slotMap.meta && elements.meta) {
      clearNodeContents(elements.meta);
      slotMap.meta.forEach(function appendMetaNode(node) {
        if (node && typeof elements.meta.appendChild === "function") {
          elements.meta.appendChild(node);
        }
      });
    }
    if (elements.empty) {
      clearNodeContents(elements.empty);
      if (slotMap.empty && slotMap.empty.length) {
        slotMap.empty.forEach(function appendEmptyNode(node) {
          if (node && typeof elements.empty.appendChild === "function") {
            elements.empty.appendChild(node);
          }
        });
        setHiddenState(elements.empty, false);
      } else {
        setHiddenState(elements.empty, true);
      }
    }
  }

  var ENTITY_WORKSPACE_ROOT_CLASS = "mpr-entity-workspace";
  var ENTITY_WORKSPACE_STYLE_ID = "mpr-ui-entity-workspace-styles";
  var ENTITY_WORKSPACE_STYLE_MARKUP =
    "mpr-entity-workspace{display:block;color:var(--mpr-color-text-primary,#e2e8f0)}" +
    ".mpr-entity-workspace__heading,.mpr-entity-workspace__toolbar,.mpr-entity-workspace__filters,.mpr-entity-workspace__bulk-actions,.mpr-entity-workspace__list,.mpr-entity-workspace__empty,.mpr-entity-workspace__load-more{display:flex;flex-direction:column;gap:0.5rem}" +
    ".mpr-entity-workspace__surface{display:flex;flex-direction:column;gap:0.5rem;padding:0.75rem;border-radius:var(--mpr-radius-control,6px);border:1px solid var(--mpr-color-border,#2c2f36);background:var(--mpr-color-surface-elevated,#1f2126);box-sizing:border-box}" +
    ".mpr-entity-workspace__busy{padding:0.5rem 0.6rem;border:1px dashed var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);color:var(--mpr-color-text-muted,#c4c7d1)}" +
    ".mpr-entity-workspace__busy[hidden],.mpr-entity-workspace__empty[hidden],.mpr-entity-workspace__load-more[hidden]{display:none!important}" +
    ".mpr-entity-workspace__load-more-button{appearance:none;border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);padding:0.35rem 0.55rem;background:transparent;color:inherit;cursor:pointer;font-size:0.78rem;font-weight:600;align-self:flex-start}" +
    ".mpr-entity-workspace__load-more-button:hover{border-color:var(--mpr-color-accent,#38bdf8);color:var(--mpr-color-accent,#38bdf8)}";
  var ENTITY_WORKSPACE_DEFAULTS = Object.freeze({
    busy: false,
    empty: false,
    selectionCount: 0,
    canLoadMore: false,
  });

  function ensureEntityWorkspaceStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(ENTITY_WORKSPACE_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = ENTITY_WORKSPACE_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = ENTITY_WORKSPACE_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(ENTITY_WORKSPACE_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildEntityWorkspaceOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var busyAttr = hostElement.getAttribute("busy");
    if (busyAttr !== null) {
      options.busy = normalizeBooleanAttribute(busyAttr, true);
    }
    var emptyAttr = hostElement.getAttribute("empty");
    if (emptyAttr !== null) {
      options.empty = normalizeBooleanAttribute(emptyAttr, true);
    }
    var selectionCountAttr = hostElement.getAttribute("selection-count");
    if (selectionCountAttr !== null && selectionCountAttr !== undefined) {
      options.selectionCount = parsePositiveInteger(selectionCountAttr, 0);
    }
    var canLoadMoreAttr = hostElement.getAttribute("can-load-more");
    if (canLoadMoreAttr !== null) {
      options.canLoadMore = normalizeBooleanAttribute(canLoadMoreAttr, true);
    }
    return options;
  }

  function normalizeEntityWorkspaceOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    return {
      busy: Boolean(options.busy),
      empty: Boolean(options.empty),
      selectionCount:
        typeof options.selectionCount === "number" && options.selectionCount >= 0
          ? options.selectionCount
          : parsePositiveInteger(options.selectionCount, 0),
      canLoadMore: Boolean(options.canLoadMore),
    };
  }

  function buildEntityWorkspaceMarkup(config) {
    return (
      '<section class="' +
      ENTITY_WORKSPACE_ROOT_CLASS +
      '__surface" data-mpr-entity-workspace="surface">' +
      '<div class="' +
      ENTITY_WORKSPACE_ROOT_CLASS +
      '__heading" data-mpr-entity-workspace="heading"></div>' +
      '<div class="' +
      ENTITY_WORKSPACE_ROOT_CLASS +
      '__toolbar" data-mpr-entity-workspace="toolbar"></div>' +
      '<div class="' +
      ENTITY_WORKSPACE_ROOT_CLASS +
      '__filters" data-mpr-entity-workspace="filters"></div>' +
      '<div class="' +
      ENTITY_WORKSPACE_ROOT_CLASS +
      '__bulk-actions" data-mpr-entity-workspace="bulk-actions"></div>' +
      '<div class="' +
      ENTITY_WORKSPACE_ROOT_CLASS +
      '__busy" data-mpr-entity-workspace="busy"' +
      (config.busy ? "" : ' hidden="hidden"') +
      '>Loading workspace…</div>' +
      '<div class="' +
      ENTITY_WORKSPACE_ROOT_CLASS +
      '__list" data-mpr-entity-workspace="list"></div>' +
      '<div class="' +
      ENTITY_WORKSPACE_ROOT_CLASS +
      '__empty" data-mpr-entity-workspace="empty"' +
      (config.empty ? "" : ' hidden="hidden"') +
      "></div>" +
      '<div class="' +
      ENTITY_WORKSPACE_ROOT_CLASS +
      '__load-more" data-mpr-entity-workspace="load-more"' +
      (config.canLoadMore ? "" : ' hidden="hidden"') +
      '><button type="button" class="' +
      ENTITY_WORKSPACE_ROOT_CLASS +
      '__load-more-button" data-mpr-entity-workspace="load-more-button">Load more</button></div>' +
      "</section>"
    );
  }

  function resolveEntityWorkspaceElements(hostElement) {
    if (!hostElement || typeof hostElement.querySelector !== "function") {
      return {};
    }
    return {
      surface: hostElement.querySelector('[data-mpr-entity-workspace="surface"]'),
      heading: hostElement.querySelector('[data-mpr-entity-workspace="heading"]'),
      toolbar: hostElement.querySelector('[data-mpr-entity-workspace="toolbar"]'),
      filters: hostElement.querySelector('[data-mpr-entity-workspace="filters"]'),
      bulkActions: hostElement.querySelector(
        '[data-mpr-entity-workspace="bulk-actions"]',
      ),
      busy: hostElement.querySelector('[data-mpr-entity-workspace="busy"]'),
      list: hostElement.querySelector('[data-mpr-entity-workspace="list"]'),
      empty: hostElement.querySelector('[data-mpr-entity-workspace="empty"]'),
      loadMore: hostElement.querySelector('[data-mpr-entity-workspace="load-more"]'),
      loadMoreButton: hostElement.querySelector(
        '[data-mpr-entity-workspace="load-more-button"]',
      ),
    };
  }

  function applyEntityWorkspaceSlotContent(slotMap, elements) {
    if (!slotMap || !elements) {
      return;
    }
    [
      ["heading", "heading"],
      ["toolbar", "toolbar"],
      ["filters", "filters"],
      ["bulk-actions", "bulkActions"],
      ["list", "list"],
    ].forEach(function applyPair(pair) {
      var slotName = pair[0];
      var elementName = pair[1];
      if (!slotMap[slotName] || !elements[elementName]) {
        return;
      }
      clearNodeContents(elements[elementName]);
      slotMap[slotName].forEach(function appendNode(node) {
        if (node && typeof elements[elementName].appendChild === "function") {
          elements[elementName].appendChild(node);
          markTrackedNodeAsMounted(node);
        }
      });
    });
    if (elements.empty) {
      clearNodeContents(elements.empty);
      if (slotMap.empty && slotMap.empty.length) {
        slotMap.empty.forEach(function appendEmptyNode(node) {
          if (node && typeof elements.empty.appendChild === "function") {
            elements.empty.appendChild(node);
            markTrackedNodeAsMounted(node);
          }
        });
      }
    }
    if (elements.loadMore) {
      var preservedButton = elements.loadMoreButton || null;
      clearNodeContents(elements.loadMore);
      if (
        preservedButton &&
        typeof elements.loadMore.appendChild === "function"
      ) {
        elements.loadMore.appendChild(preservedButton);
      }
      if (slotMap["load-more"] && slotMap["load-more"].length) {
        slotMap["load-more"].forEach(function appendLoadMoreNode(node) {
          if (node && typeof elements.loadMore.appendChild === "function") {
            elements.loadMore.appendChild(node);
            markTrackedNodeAsMounted(node);
          }
        });
      }
    }
  }

  var ENTITY_CARD_ROOT_CLASS = "mpr-entity-card";
  var ENTITY_CARD_STYLE_ID = "mpr-ui-entity-card-styles";
  var ENTITY_CARD_STYLE_MARKUP =
    "mpr-entity-card{display:block;color:var(--mpr-color-text-primary,#e2e8f0)}" +
    ".mpr-entity-card__surface{display:grid;grid-template-columns:auto auto minmax(0,1fr) auto;gap:0.5rem;align-items:start;padding:0.65rem;border-radius:var(--mpr-radius-control,6px);border:1px solid var(--mpr-color-border,#2c2f36);background:var(--mpr-color-surface-elevated,#1f2126);box-sizing:border-box}" +
    "mpr-entity-card[data-mpr-entity-card-density=\"compact\"] .mpr-entity-card__surface{padding:0.5rem;gap:0.4rem}" +
    "mpr-entity-card[data-mpr-entity-card-selected=\"true\"] .mpr-entity-card__surface{border-color:var(--mpr-color-accent,#38bdf8);box-shadow:0 0 0 1px var(--mpr-color-accent,#38bdf8) inset}" +
    "mpr-entity-card[data-mpr-entity-card-interactive=\"true\"] .mpr-entity-card__surface{cursor:pointer}" +
    "mpr-entity-card[data-mpr-entity-card-disabled=\"true\"] .mpr-entity-card__surface{opacity:0.55}" +
    ".mpr-entity-card__select,.mpr-entity-card__media,.mpr-entity-card__metric,.mpr-entity-card__actions{display:flex;align-items:center;gap:0.35rem;flex-wrap:wrap}" +
    ".mpr-entity-card__content{display:flex;flex-direction:column;gap:0.4rem;min-width:0}" +
    ".mpr-entity-card__title{font-size:0.86rem;font-weight:700}" +
    ".mpr-entity-card__meta,.mpr-entity-card__summary,.mpr-entity-card__footer{display:flex;flex-wrap:wrap;gap:0.35rem;color:var(--mpr-color-text-muted,#c4c7d1)}" +
    ".mpr-entity-card__busy{display:inline-flex;align-items:center;gap:0.35rem;padding:0.2rem 0.5rem;border-radius:999px;background:var(--mpr-chip-bg,rgba(148,163,184,0.18));color:var(--mpr-color-text-muted,#cbd5f5)}" +
    ".mpr-entity-card__busy[hidden]{display:none!important}" +
    "@media (max-width: 48rem){.mpr-entity-card__surface{grid-template-columns:minmax(0,1fr)}.mpr-entity-card__metric,.mpr-entity-card__actions{justify-content:flex-start}}";
  var ENTITY_CARD_DEFAULTS = Object.freeze({
    selected: false,
    interactive: false,
    disabled: false,
    busy: false,
    density: "comfortable",
  });
  var ENTITY_CARD_DENSITIES = Object.freeze(["comfortable", "compact"]);

  function ensureEntityCardStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(ENTITY_CARD_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = ENTITY_CARD_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = ENTITY_CARD_STYLE_MARKUP;
    } else {
      styleElement.appendChild(
        documentObject.createTextNode(ENTITY_CARD_STYLE_MARKUP),
      );
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildEntityCardOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var selectedAttr = hostElement.getAttribute("selected");
    if (selectedAttr !== null) {
      options.selected = normalizeBooleanAttribute(selectedAttr, true);
    }
    var interactiveAttr = hostElement.getAttribute("interactive");
    if (interactiveAttr !== null) {
      options.interactive = normalizeBooleanAttribute(interactiveAttr, true);
    }
    var disabledAttr = hostElement.getAttribute("disabled");
    if (disabledAttr !== null) {
      options.disabled = normalizeBooleanAttribute(disabledAttr, true);
    }
    var busyAttr = hostElement.getAttribute("busy");
    if (busyAttr !== null) {
      options.busy = normalizeBooleanAttribute(busyAttr, true);
    }
    var densityAttr = hostElement.getAttribute("density");
    if (densityAttr) {
      options.density = densityAttr;
    }
    return options;
  }

  function normalizeEntityCardOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var densitySource =
      typeof options.density === "string" && options.density.trim()
        ? options.density.trim().toLowerCase()
        : ENTITY_CARD_DEFAULTS.density;
    return {
      selected: Boolean(options.selected),
      interactive: Boolean(options.interactive),
      disabled: Boolean(options.disabled),
      busy: Boolean(options.busy),
      density:
        ENTITY_CARD_DENSITIES.indexOf(densitySource) === -1
          ? ENTITY_CARD_DEFAULTS.density
          : densitySource,
    };
  }

  function buildEntityCardMarkup(config) {
    return (
      '<article class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__surface">' +
      '<div class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__select" data-mpr-entity-card="select"></div>' +
      '<div class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__media" data-mpr-entity-card="media"></div>' +
      '<div class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__content">' +
      '<div class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__title" data-mpr-entity-card="title"></div>' +
      '<div class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__meta" data-mpr-entity-card="meta"></div>' +
      '<div class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__summary" data-mpr-entity-card="summary"></div>' +
      '<div class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__footer" data-mpr-entity-card="footer"></div>' +
      "</div>" +
      '<div class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__metric" data-mpr-entity-card="metric">' +
      '<span class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__busy" data-mpr-entity-card="busy"' +
      (config.busy ? "" : ' hidden="hidden"') +
      '>Busy</span>' +
      "</div>" +
      '<div class="' +
      ENTITY_CARD_ROOT_CLASS +
      '__actions" data-mpr-entity-card="actions"></div>' +
      "</article>"
    );
  }

  function resolveEntityCardElements(hostElement) {
    if (!hostElement || typeof hostElement.querySelector !== "function") {
      return {};
    }
    return {
      select: hostElement.querySelector('[data-mpr-entity-card="select"]'),
      media: hostElement.querySelector('[data-mpr-entity-card="media"]'),
      title: hostElement.querySelector('[data-mpr-entity-card="title"]'),
      meta: hostElement.querySelector('[data-mpr-entity-card="meta"]'),
      summary: hostElement.querySelector('[data-mpr-entity-card="summary"]'),
      footer: hostElement.querySelector('[data-mpr-entity-card="footer"]'),
      metric: hostElement.querySelector('[data-mpr-entity-card="metric"]'),
      busy: hostElement.querySelector('[data-mpr-entity-card="busy"]'),
      actions: hostElement.querySelector('[data-mpr-entity-card="actions"]'),
    };
  }

  function applyEntityCardSlotContent(slotMap, elements) {
    if (!slotMap || !elements) {
      return;
    }
    [
      ["select", "select"],
      ["media", "media"],
      ["title", "title"],
      ["meta", "meta"],
      ["summary", "summary"],
      ["footer", "footer"],
      ["actions", "actions"],
    ].forEach(function applyPair(pair) {
      var slotName = pair[0];
      var elementName = pair[1];
      if (!slotMap[slotName] || !elements[elementName]) {
        return;
      }
      clearNodeContents(elements[elementName]);
      slotMap[slotName].forEach(function appendNode(node) {
        if (node && typeof elements[elementName].appendChild === "function") {
          elements[elementName].appendChild(node);
        }
      });
    });
    if (elements.metric) {
      var preservedBusy = elements.busy || null;
      clearNodeContents(elements.metric);
      if (
        preservedBusy &&
        typeof elements.metric.appendChild === "function"
      ) {
        elements.metric.appendChild(preservedBusy);
      }
      if (slotMap.metric && slotMap.metric.length) {
        slotMap.metric.forEach(function appendMetricNode(node) {
          if (node && typeof elements.metric.appendChild === "function") {
            elements.metric.appendChild(node);
          }
        });
      }
    }
  }

  var BAND_ROOT_CLASS = "mpr-band";
  var BAND_STYLE_ID = "mpr-ui-band-styles";
  var BAND_STYLE_MARKUP =
    "mpr-band{display:block;position:relative;width:100%;margin:0;padding:1rem 0.75rem;box-sizing:border-box;background:var(--mpr-band-background,#0f1114);color:var(--mpr-band-text,#e3e5ec)}" +
    "mpr-band::before,mpr-band::after{content:\"\";position:absolute;left:0;right:0;height:1px;background:transparent;pointer-events:none;opacity:1}" +
    "mpr-band::before{top:0;background:var(--mpr-band-line-top,transparent)}" +
    "mpr-band::after{bottom:0;background:var(--mpr-band-line-bottom,transparent)}" +
    "mpr-card{display:block;margin:0;padding:0;box-sizing:border-box;color:inherit}" +
    ".mpr-band__card{background:var(--mpr-band-panel-alt,#1f2126);border-radius:var(--mpr-radius-control,6px);border:1px solid var(--mpr-band-border,#2c2f36);box-shadow:none;position:relative;overflow:hidden;min-height:180px;transition:border-color 0.16s ease;width:360px;max-width:100%;flex:0 0 360px;margin:0 auto}" +
    ".mpr-band__card:hover:not(.mpr-band__card--flipped){border-color:var(--mpr-band-accent,#5d93ff)}" +
    ".mpr-band__card-inner{position:relative;width:100%;height:100%;transform-style:preserve-3d;transition:transform 0.4s ease}" +
    ".mpr-band__card-face{padding:0.75rem;display:flex;flex-direction:column;gap:0.6rem;height:100%;box-sizing:border-box}" +
    ".mpr-band__card--flippable .mpr-band__card-face{position:absolute;inset:0;backface-visibility:hidden}" +
    ".mpr-band__card-face--back{background:var(--mpr-band-panel-background,#1f2126);transform:rotateY(180deg)}" +
    ".mpr-band__card--flipped .mpr-band__card-inner{transform:rotateY(180deg)}" +
    ".mpr-band__card--flippable{cursor:pointer;perspective:2000px}" +
    ".mpr-band__card-header{display:flex;align-items:center;justify-content:space-between;gap:0.5rem}" +
    ".mpr-band__card-title{display:flex;align-items:center;gap:0.5rem}" +
    ".mpr-band__card-title h3{margin:0;font-size:0.86rem;color:var(--mpr-band-text,#e3e5ec)}" +
    ".mpr-band__card-visual{width:36px;height:36px;border-radius:var(--mpr-radius-control,6px);background:rgba(93,147,255,0.12);border:1px solid rgba(93,147,255,0.28);display:flex;align-items:center;justify-content:center;font-size:0.86rem;font-weight:600;color:var(--mpr-band-accent,#5d93ff);overflow:hidden}" +
    ".mpr-band__card-visual img{width:100%;height:100%;object-fit:contain;display:block}" +
    ".mpr-band__status{font-size:0.65rem;text-transform:uppercase;letter-spacing:0.06em;border-radius:999px;padding:0.18rem 0.4rem;border:1px solid var(--mpr-band-border,#2c2f36);color:var(--mpr-band-text,#e3e5ec);background:transparent}" +
    ".mpr-band__status--production{color:#95c23d;background:rgba(149,194,61,0.14);border-color:rgba(149,194,61,0.35)}" +
    ".mpr-band__status--beta{color:#eab465;background:rgba(234,180,101,0.14);border-color:rgba(234,180,101,0.35)}" +
    ".mpr-band__status--wip{color:var(--mpr-band-accent,#5d93ff);border-color:rgba(93,147,255,0.35)}" +
    ".mpr-band__card-body{display:flex;flex-direction:column;gap:0.5rem;flex-grow:1}" +
    ".mpr-band__card-body p{margin:0;color:var(--mpr-band-text,#e3e5ec);font-size:0.78rem;line-height:1.45}" +
    ".mpr-band__action{align-self:flex-start;border-radius:var(--mpr-radius-control,6px);padding:0.35rem 0.55rem;border:1px solid rgba(93,147,255,0.35);font-size:0.72rem;font-weight:600;color:var(--mpr-band-text,#e3e5ec);text-decoration:none;transition:background 0.16s ease,color 0.16s ease}" +
    ".mpr-band__action:hover,.mpr-band__action:focus-visible{background:rgba(93,147,255,0.14);color:var(--mpr-band-accent,#5d93ff)}" +
    ".mpr-band__card-subscribe{position:absolute;inset:0.5rem;display:flex;flex-direction:column;gap:0.5rem;opacity:0;pointer-events:none;transform:rotateY(180deg) translateY(8px);transition:opacity 0.2s ease,transform 0.2s ease;z-index:2;backface-visibility:hidden;border-radius:8px;border:1px solid var(--mpr-band-border,#2c2f36);background:var(--mpr-band-panel-background,#1f2126);box-shadow:0 8px 20px rgba(0,0,0,0.3);padding:0}" +
    ".mpr-band__card--flipped .mpr-band__card-subscribe{opacity:1;pointer-events:auto;transform:rotateY(180deg) translateY(0)}" +
    ".mpr-band__subscribe-body{padding:0.75rem;border-radius:var(--mpr-radius-control,6px);border:1px solid var(--mpr-band-border,#2c2f36);background:var(--mpr-band-panel-background,#1f2126);display:flex;flex-direction:column;gap:0.5rem;box-sizing:border-box;height:100%}" +
    ".mpr-band__subscribe-title{margin:0;font-weight:600;color:var(--mpr-band-text,#e2e8f0)}" +
    ".mpr-band__subscribe-copy{margin:0;color:var(--mpr-band-muted,#c4c7d1);font-size:0.78rem}" +
    ".mpr-band__subscribe-frame{width:100%;border:0;border-radius:var(--mpr-radius-control,6px);background:transparent;min-height:240px;height:240px;box-shadow:inset 0 0 0 1px var(--mpr-band-border,#2c2f36)}" +
    ".mpr-band__card--flippable{outline:none}" +
    ".mpr-band__card--flippable:focus-visible{box-shadow:0 0 0 3px var(--mpr-band-accent,#ffd369)}" +
    ".mpr-band__card--flippable[aria-pressed=\"true\"]{border-color:rgba(255,221,172,0.65)}" +
    ".mpr-band__subscribe-body[data-mpr-band-subscribe-loaded=\"false\"]::after{content:\"Loading…\";font-size:0.85rem;color:var(--mpr-band-muted,#cbd5f5)}" +
    "@media (max-width:520px){mpr-band{padding:0.75rem 0.5rem}}";
  var BAND_LAYOUT_MANUAL = "manual";
  var BAND_THEME_PRESETS = Object.freeze({
    research: Object.freeze({
      background: "#052832",
      panel: "rgba(4, 26, 33, 0.9)",
      panelAlt: "rgba(4, 26, 33, 0.85)",
      text: "#ffe4a9",
      muted: "#eacb73",
      accent: "#ffd369",
      border: "rgba(248, 227, 154, 0.35)",
      shadow: "0 40px 120px rgba(0, 0, 0, 0.45)",
      lineTop: "transparent",
      lineBottom: "transparent",
    }),
    tools: Object.freeze({
      background: "#05333d",
      panel: "rgba(5, 46, 54, 0.92)",
      panelAlt: "rgba(5, 46, 54, 0.85)",
      text: "#ffe4a9",
      muted: "#f3dca3",
      accent: "#ffd369",
      border: "rgba(255, 211, 105, 0.35)",
      shadow: "0 35px 80px rgba(0, 0, 0, 0.55)",
      lineTop: "transparent",
      lineBottom: "transparent",
    }),
    platform: Object.freeze({
      background: "#04222a",
      panel: "rgba(4, 34, 42, 0.92)",
      panelAlt: "rgba(4, 34, 42, 0.85)",
      text: "#fef7e0",
      muted: "#f6e7b7",
      accent: "#ffd369",
      border: "rgba(255, 211, 105, 0.3)",
      shadow: "0 40px 110px rgba(0, 0, 0, 0.5)",
      lineTop: "transparent",
      lineBottom: "transparent",
    }),
    products: Object.freeze({
      background: "#031a21",
      panel: "rgba(3, 26, 33, 0.9)",
      panelAlt: "rgba(3, 26, 33, 0.85)",
      text: "#fbeed0",
      muted: "#e8d196",
      accent: "#ffd369",
      border: "rgba(255, 211, 105, 0.28)",
      shadow: "0 30px 90px rgba(0, 0, 0, 0.5)",
      lineTop: "transparent",
      lineBottom: "transparent",
    }),
    custom: Object.freeze({
      background: "linear-gradient(180deg, rgba(2,10,23,0.95), rgba(3,24,32,0.85))",
      panel: "rgba(3, 27, 32, 0.9)",
      panelAlt: "rgba(3, 27, 32, 0.92)",
      text: "#e2e8f0",
      muted: "#cbd5f5",
      accent: "var(--mpr-color-accent,#38bdf8)",
      border: "rgba(148,163,184,0.25)",
      shadow: "0 25px 60px rgba(0, 0, 0, 0.55)",
      lineTop: "transparent",
      lineBottom: "transparent",
    }),
  });
  var BAND_STATUS_METADATA = Object.freeze({
    production: Object.freeze({
      value: "production",
      label: "Production",
      badgeClass: BAND_ROOT_CLASS + "__status--production",
      actionLabel: "Launch product",
    }),
    beta: Object.freeze({
      value: "beta",
      label: "Beta",
      badgeClass: BAND_ROOT_CLASS + "__status--beta",
      actionLabel: "Explore beta",
    }),
    wip: Object.freeze({
      value: "wip",
      label: "WIP",
      badgeClass: BAND_ROOT_CLASS + "__status--wip",
      actionLabel: "",
    }),
  });
  var BAND_FLIPPABLE_STATUSES = Object.freeze(["beta", "wip"]);
  var BAND_MIN_SUBSCRIBE_HEIGHT = 240;
  var BAND_MAX_SUBSCRIBE_HEIGHT = 420;
  var BAND_DEFAULT_SUBSCRIBE_HEIGHT = 320;

  function ensureBandStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(BAND_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = BAND_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = BAND_STYLE_MARKUP;
    } else {
      styleElement.appendChild(documentObject.createTextNode(BAND_STYLE_MARKUP));
    }
    documentObject.head.appendChild(styleElement);
  }

  function buildBandOptionsFromAttributes(hostElement) {
    var options = {};
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return options;
    }
    var categoryAttr = hostElement.getAttribute("category");
    if (categoryAttr) {
      options.category = categoryAttr;
    }
    var themeAttr = hostElement.getAttribute("theme");
    if (themeAttr) {
      options.theme = parseJsonValue(themeAttr, {});
    }
    var layoutAttr = hostElement.getAttribute("layout");
    if (layoutAttr) {
      options.layout = layoutAttr;
    }
    return options;
  }

  function normalizeBandOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var categorySource =
      typeof options.category === "string" && options.category.trim()
        ? options.category.trim().toLowerCase()
        : "";
    var category = categorySource || "custom";
    var theme = normalizeBandTheme(category, options.theme);
    return {
      category: category,
      theme: theme,
      layout: BAND_LAYOUT_MANUAL,
    };
  }

  function normalizeBandCard(entry, fallbackIndex) {
    if (!entry || typeof entry !== "object") {
      return null;
    }
    var idSource =
      typeof entry.id === "string" && entry.id.trim()
        ? entry.id.trim()
        : "mpr-band-card-" + fallbackIndex;
    var titleSource =
      typeof entry.title === "string" && entry.title.trim()
        ? entry.title.trim()
        : typeof entry.name === "string" && entry.name.trim()
        ? entry.name.trim()
        : idSource;
    var descriptionSource =
      typeof entry.description === "string" && entry.description.trim()
        ? entry.description.trim()
        : "";
    var statusSource =
      typeof entry.status === "string" && entry.status.trim()
        ? entry.status.trim()
        : "production";
    var status = normalizeBandStatus(statusSource);
    var url = sanitizeHref(entry.url || entry.href || "");
    var icon =
      typeof entry.icon === "string" && entry.icon.trim() ? entry.icon.trim() : "";
    var subscribe = normalizeBandSubscribe(entry.subscribe, titleSource);
    var flippable =
      BAND_FLIPPABLE_STATUSES.indexOf(status.value) !== -1 || Boolean(subscribe);
    return {
      id: idSource,
      title: titleSource,
      description: descriptionSource,
      status: status,
      url: url && url !== "#" ? url : "",
      icon: icon,
      monogram: deriveBandMonogram(titleSource),
      subscribe: subscribe,
      flippable: flippable,
    };
  }

  function buildCardOptionsFromAttributes(hostElement) {
    if (!hostElement || typeof hostElement.getAttribute !== "function") {
      return {};
    }
    var cardAttr = hostElement.getAttribute("card");
    var themeAttr = hostElement.getAttribute("theme");
    return {
      card: cardAttr ? parseJsonValue(cardAttr, {}) : {},
      theme: themeAttr ? parseJsonValue(themeAttr, {}) : {},
    };
  }

  function normalizeStandaloneCardOptions(rawOptions) {
    var options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    var sourceCard =
      options.card && typeof options.card === "object" ? options.card : options;
    var normalizedCard = normalizeBandCard(sourceCard, 0);
    if (!normalizedCard) {
      throw new Error("mpr-card requires a valid card configuration");
    }
    var theme = normalizeBandTheme("custom", options.theme);
    return {
      card: normalizedCard,
      theme: theme,
    };
  }

  function normalizeBandStatus(rawValue) {
    var normalized =
      typeof rawValue === "string" && rawValue.trim()
        ? rawValue.trim().toLowerCase()
        : "production";
    if (BAND_STATUS_METADATA[normalized]) {
      return BAND_STATUS_METADATA[normalized];
    }
    return BAND_STATUS_METADATA.production;
  }

  function normalizeBandSubscribe(rawSubscribe, title) {
    if (!rawSubscribe || typeof rawSubscribe !== "object") {
      return null;
    }
    var scriptSource =
      typeof rawSubscribe.script === "string" && rawSubscribe.script.trim()
        ? rawSubscribe.script.trim()
        : "";
    var sanitizedScript = sanitizeHref(scriptSource);
    if (!sanitizedScript || sanitizedScript === "#") {
      return null;
    }
    var copy =
      typeof rawSubscribe.copy === "string" && rawSubscribe.copy.trim()
        ? rawSubscribe.copy.trim()
        : "Drop your email to hear when this project ships new features and announcements.";
    var titleCopy =
      typeof rawSubscribe.title === "string" && rawSubscribe.title.trim()
        ? rawSubscribe.title.trim()
        : "Get " + title + " updates";
    var heightValue = parseInt(rawSubscribe.height, 10);
    var height = BAND_DEFAULT_SUBSCRIBE_HEIGHT;
    if (!isNaN(heightValue)) {
      height = Math.max(
        BAND_MIN_SUBSCRIBE_HEIGHT,
        Math.min(BAND_MAX_SUBSCRIBE_HEIGHT, heightValue),
      );
    }
    return {
      script: sanitizedScript,
      title: titleCopy,
      copy: copy,
      height: height,
    };
  }

  var BAND_THEME_INHERITANCE_MAP = Object.freeze({
    background: "--mpr-color-surface-primary",
    panel: "--mpr-color-surface-elevated",
    panelAlt: "--mpr-color-surface-elevated",
    text: "--mpr-color-text-primary",
    muted: "--mpr-color-text-muted",
    accent: "--mpr-color-accent",
    border: "--mpr-color-border",
    shadow: "--mpr-shadow-elevated",
    lineTop: "--mpr-color-border",
    lineBottom: "--mpr-color-border",
  });

  function wrapWithCssVariable(value, variableName) {
    if (!variableName || typeof value !== "string") {
      return value;
    }
    var trimmed = value.trim();
    if (!trimmed || trimmed.indexOf("var(") === 0) {
      return trimmed;
    }
    return "var(" + variableName + ", " + trimmed + ")";
  }

  function inheritPageTheme(theme) {
    var inherited = {};
    Object.keys(theme).forEach(function inheritKey(key) {
      var variableName = BAND_THEME_INHERITANCE_MAP[key];
      inherited[key] = variableName ? wrapWithCssVariable(theme[key], variableName) : theme[key];
    });
    return inherited;
  }

  function normalizeBandTheme(category, rawTheme) {
    var preset =
      (category && BAND_THEME_PRESETS[category]) || BAND_THEME_PRESETS.custom;
    var themeSource = rawTheme && typeof rawTheme === "object" ? rawTheme : {};
    function pick(key) {
      if (typeof themeSource[key] === "string" && themeSource[key].trim()) {
        return themeSource[key].trim();
      }
      return preset[key];
    }
    return inheritPageTheme({
      background: pick("background"),
      panel: pick("panel"),
      panelAlt: pick("panelAlt"),
      text: pick("text"),
      muted: pick("muted"),
      accent: pick("accent"),
      border: pick("border"),
      shadow: pick("shadow"),
      lineTop: pick("lineTop"),
      lineBottom: pick("lineBottom"),
    });
  }

  function deriveBandMonogram(name) {
    if (!name || typeof name !== "string") {
      return "MP";
    }
    var initials = name
      .split(/\s+/)
      .filter(Boolean)
      .map(function mapPart(part) {
        return part.charAt(0);
      })
      .slice(0, 2)
      .join("");
    if (initials) {
      return initials.toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  }

  function applyBandTheme(hostElement, theme) {
    if (!hostElement || !hostElement.style || typeof hostElement.style.setProperty !== "function") {
      return;
    }
    hostElement.style.setProperty("--mpr-band-background", theme.background);
    hostElement.style.setProperty("--mpr-band-panel-background", theme.panel);
    hostElement.style.setProperty("--mpr-band-panel-alt", theme.panelAlt);
    hostElement.style.setProperty("--mpr-band-text", theme.text);
    hostElement.style.setProperty("--mpr-band-muted", theme.muted);
    hostElement.style.setProperty("--mpr-band-accent", theme.accent);
    hostElement.style.setProperty("--mpr-band-border", theme.border);
    hostElement.style.setProperty("--mpr-band-shadow", theme.shadow);
    hostElement.style.setProperty("--mpr-band-line-top", theme.lineTop || "transparent");
    hostElement.style.setProperty("--mpr-band-line-bottom", theme.lineBottom || "transparent");
  }

  function clearBandTheme(hostElement) {
    if (!hostElement || !hostElement.style || typeof hostElement.style.removeProperty !== "function") {
      return;
    }
    hostElement.style.removeProperty("--mpr-band-background");
    hostElement.style.removeProperty("--mpr-band-panel-background");
    hostElement.style.removeProperty("--mpr-band-panel-alt");
    hostElement.style.removeProperty("--mpr-band-text");
    hostElement.style.removeProperty("--mpr-band-muted");
    hostElement.style.removeProperty("--mpr-band-accent");
    hostElement.style.removeProperty("--mpr-band-border");
    hostElement.style.removeProperty("--mpr-band-shadow");
    hostElement.style.removeProperty("--mpr-band-line-top");
    hostElement.style.removeProperty("--mpr-band-line-bottom");
  }

  function createBandCardElement(documentObject, cardConfig, hostElement, cardOptions) {
    var renderIntoHost =
      Boolean(
        cardOptions &&
          cardOptions.renderIntoHost &&
          hostElement &&
          typeof hostElement === "object" &&
          typeof hostElement.nodeType === "number",
      );
    var card = renderIntoHost ? hostElement : documentObject.createElement("article");
    if (renderIntoHost) {
      clearNodeContents(card);
    } else {
      card.className = BAND_ROOT_CLASS + "__card";
    }
    card.classList.add(BAND_ROOT_CLASS + "__card");
    card.setAttribute("data-mpr-band-card", cardConfig.id);
    card.setAttribute("data-mpr-band-status", cardConfig.status.value);
    if (cardConfig.flippable) {
      card.classList.add(BAND_ROOT_CLASS + "__card--flippable");
      card.setAttribute("role", "button");
      card.setAttribute("aria-pressed", "false");
      card.tabIndex = 0;
    }
    var inner = documentObject.createElement("div");
    inner.className = BAND_ROOT_CLASS + "__card-inner";
    function createFace(variant) {
      var face = documentObject.createElement("div");
      face.className =
        BAND_ROOT_CLASS +
        "__card-face " +
        BAND_ROOT_CLASS +
        "__card-face--" +
        variant;
      return face;
    }
    var frontFace = createFace("front");
    var backFace = null;
    if (cardConfig.flippable) {
      backFace = createFace("back");
    }

    function buildCardHeader(targetFace) {
      var header = documentObject.createElement("div");
      header.className = BAND_ROOT_CLASS + "__card-header";
      var titleWrapper = documentObject.createElement("div");
      titleWrapper.className = BAND_ROOT_CLASS + "__card-title";
      var visual = documentObject.createElement("div");
      visual.className = BAND_ROOT_CLASS + "__card-visual";
      if (cardConfig.icon) {
        var iconImage = documentObject.createElement("img");
        iconImage.src = cardConfig.icon;
        iconImage.alt = cardConfig.title + " icon";
        iconImage.loading = "lazy";
        visual.appendChild(iconImage);
      } else {
        visual.textContent = cardConfig.monogram;
      }
      var title = documentObject.createElement("h3");
      title.textContent = cardConfig.title;
      titleWrapper.appendChild(visual);
      titleWrapper.appendChild(title);
      var statusBadge = documentObject.createElement("span");
      statusBadge.className =
        BAND_ROOT_CLASS + "__status " + cardConfig.status.badgeClass;
      statusBadge.textContent = cardConfig.status.label;
      header.appendChild(titleWrapper);
      header.appendChild(statusBadge);
      targetFace.appendChild(header);
    }

    function buildCardBody(targetFace) {
      var body = documentObject.createElement("div");
      body.className = BAND_ROOT_CLASS + "__card-body";
      if (cardConfig.description) {
        var description = documentObject.createElement("p");
        description.textContent = cardConfig.description;
        body.appendChild(description);
      }
      if (cardConfig.url && cardConfig.status.value !== "wip") {
        var action = documentObject.createElement("a");
        action.className = BAND_ROOT_CLASS + "__action";
        action.href = cardConfig.url;
        action.target = "_blank";
        action.rel = "noreferrer noopener";
        action.textContent =
          cardConfig.status.actionLabel || "Explore";
        body.appendChild(action);
      }
      targetFace.appendChild(body);
    }

    buildCardHeader(frontFace);
    buildCardBody(frontFace);
    if (backFace) {
      buildCardHeader(backFace);
      buildCardBody(backFace);
    }

    var options =
      cardOptions && typeof cardOptions === "object"
        ? cardOptions
        : null;
    var eventNamespace =
      options && typeof options.eventNamespace === "string" && options.eventNamespace.trim()
        ? options.eventNamespace.trim()
        : "mpr-band";
    var subscribeLoader = null;
    if (cardConfig.subscribe && backFace) {
      var overlay = documentObject.createElement("div");
      overlay.className = BAND_ROOT_CLASS + "__card-subscribe";
      var subscribeBody = documentObject.createElement("div");
      subscribeBody.className = BAND_ROOT_CLASS + "__subscribe-body";
      subscribeBody.setAttribute("data-mpr-band-subscribe-loaded", "false");
      var subscribeTitle = documentObject.createElement("p");
      subscribeTitle.className = BAND_ROOT_CLASS + "__subscribe-title";
      subscribeTitle.textContent = cardConfig.subscribe.title;
      var subscribeCopy = documentObject.createElement("p");
      subscribeCopy.className = BAND_ROOT_CLASS + "__subscribe-copy";
      subscribeCopy.textContent = cardConfig.subscribe.copy;
      var subscribeFrame = documentObject.createElement("iframe");
      subscribeFrame.className = BAND_ROOT_CLASS + "__subscribe-frame";
      subscribeFrame.loading = "lazy";
      subscribeFrame.title = cardConfig.subscribe.title;
      subscribeFrame.setAttribute("aria-label", cardConfig.subscribe.title);
      subscribeFrame.setAttribute("tabindex", "-1");
      subscribeFrame.style.minHeight = cardConfig.subscribe.height + "px";
      subscribeFrame.style.height = cardConfig.subscribe.height + "px";
      subscribeBody.appendChild(subscribeTitle);
      subscribeBody.appendChild(subscribeCopy);
      subscribeBody.appendChild(subscribeFrame);
      overlay.appendChild(subscribeBody);
      backFace.appendChild(overlay);
      subscribeLoader = function loadSubscribeFrame() {
        if (subscribeBody.getAttribute("data-mpr-band-subscribe-loaded") === "true") {
          return;
        }
        subscribeFrame.addEventListener(
          "load",
          function handleSubscribeLoad() {
            subscribeBody.setAttribute("data-mpr-band-subscribe-loaded", "true");
            dispatchEvent(hostElement, eventNamespace + ":subscribe-ready", {
              cardId: cardConfig.id,
            });
          },
          { once: true },
        );
        subscribeFrame.srcdoc = buildSubscribeFrameDocument(cardConfig.subscribe.script);
      };
    }

    inner.appendChild(frontFace);
    if (backFace) {
      inner.appendChild(backFace);
    }
    card.appendChild(inner);

    var isFlipped = false;

    function setFlipped(nextValue, source) {
      if (!cardConfig.flippable || isFlipped === nextValue) {
        return;
      }
      isFlipped = nextValue;
      if (isFlipped) {
        card.classList.add(BAND_ROOT_CLASS + "__card--flipped");
        card.setAttribute("aria-pressed", "true");
        if (typeof subscribeLoader === "function") {
          subscribeLoader();
        }
      } else {
        card.classList.remove(BAND_ROOT_CLASS + "__card--flipped");
        card.setAttribute("aria-pressed", "false");
      }
      dispatchEvent(hostElement, eventNamespace + ":card-toggle", {
        cardId: cardConfig.id,
        flipped: isFlipped,
        source: source || "user",
        status: cardConfig.status.value,
      });
    }

    function handleClick(event) {
      if (
        event &&
        event.target &&
        typeof event.target.closest === "function" &&
        event.target.closest("a")
      ) {
        return;
      }
      if (event && typeof event.preventDefault === "function") {
        event.preventDefault();
      }
      setFlipped(!isFlipped, "click");
    }

    function handleKeydown(event) {
      if (!event) {
        return;
      }
      var key = event.key || "";
      if (key === "Enter" || key === " " || key === "Spacebar") {
        if (
          event.target &&
          typeof event.target.closest === "function" &&
          event.target.closest("a")
        ) {
          return;
        }
        event.preventDefault();
        setFlipped(!isFlipped, "keyboard");
      }
    }

    if (cardConfig.flippable) {
      card.addEventListener("click", handleClick);
      card.addEventListener("keydown", handleKeydown);
    }

    function resetCardRoot() {
      card.classList.remove(
        BAND_ROOT_CLASS + "__card",
        BAND_ROOT_CLASS + "__card--flippable",
        BAND_ROOT_CLASS + "__card--flipped",
      );
      card.removeAttribute("role");
      card.removeAttribute("tabindex");
      card.removeAttribute("aria-pressed");
      card.removeAttribute("data-mpr-band-card");
      card.removeAttribute("data-mpr-band-status");
    }

    return {
      node: card,
      destroy: function destroyCard() {
        if (cardConfig.flippable) {
          card.removeEventListener("click", handleClick);
          card.removeEventListener("keydown", handleKeydown);
        }
        if (renderIntoHost) {
          resetCardRoot();
        }
      },
    };
  }

  function buildSubscribeFrameDocument(scriptUrl) {
    var safeUrl = String(scriptUrl).replace(/"/g, "&quot;");
    return (
      "<!DOCTYPE html>" +
      '<html lang="en">' +
      "<head>" +
      '<meta charset="utf-8" />' +
      "<style>:root{color-scheme:dark}body{margin:0;background:transparent;font-family:'Space Grotesk','Roboto',sans-serif;}</style>" +
      "</head>" +
      "<body>" +
      '<script defer src="' +
      safeUrl +
      '"></script>' +
      "</body>" +
      "</html>"
    );
  }

  function createCardController(target, options) {
    var hostElement = resolveHost(target);
    if (!hostElement || typeof hostElement !== "object") {
      throw new Error("createCardController requires a host element");
    }
    var documentObject =
      hostElement.ownerDocument ||
      global.document ||
      (global.window && global.window.document) ||
      null;
    if (!documentObject) {
      throw new Error("createCardController requires a document context");
    }
    ensureBandStyles(documentObject);
    var latestOptions = deepMergeOptions({}, options || {});
    var cardState = null;

    function teardownCard() {
      if (cardState && typeof cardState.destroy === "function") {
        cardState.destroy();
      }
      cardState = null;
    }

    function render(config) {
      var normalized = normalizeStandaloneCardOptions(config);
      hostElement.classList.add("mpr-card");
      hostElement.setAttribute("data-mpr-card-id", normalized.card.id);
      hostElement.setAttribute("data-mpr-card-status", normalized.card.status.value);
      applyBandTheme(hostElement, normalized.theme);
      teardownCard();
      clearNodeContents(hostElement);
      var card = createBandCardElement(documentObject, normalized.card, hostElement, {
        eventNamespace: "mpr-card",
        renderIntoHost: true,
      });
      cardState = card;
      if (card.node !== hostElement) {
        hostElement.appendChild(card.node);
      }
    }

    render(latestOptions);

    return {
      update: function update(nextOptions) {
        latestOptions = deepMergeOptions({}, latestOptions, nextOptions || {});
        render(latestOptions);
      },
      destroy: function destroy() {
        teardownCard();
        clearBandTheme(hostElement);
        hostElement.removeAttribute("data-mpr-card-id");
        hostElement.removeAttribute("data-mpr-card-status");
        if (hostElement.classList && typeof hostElement.classList.remove === "function") {
          hostElement.classList.remove("mpr-card");
        }
        clearNodeContents(hostElement);
      },
    };
  }

  function createBandController(target, options) {
    var hostElement = resolveHost(target);
    if (!hostElement || typeof hostElement !== "object") {
      throw new Error("createBandController requires a host element");
    }
    var documentObject =
      hostElement.ownerDocument ||
      global.document ||
      (global.window && global.window.document) ||
      null;
    if (!documentObject) {
      throw new Error("createBandController requires a document context");
    }
    ensureBandStyles(documentObject);
    var latestOptions = deepMergeOptions({}, options || {});
    var currentConfig = normalizeBandOptions(latestOptions);

    function render(config) {
      hostElement.classList.add(BAND_ROOT_CLASS);
      hostElement.setAttribute("data-mpr-band-layout", BAND_LAYOUT_MANUAL);
      hostElement.setAttribute("data-mpr-band-category", config.category);
      hostElement.setAttribute("data-mpr-band-count", "0");
      var hasContent = hostElement.children && hostElement.children.length > 0;
      hostElement.setAttribute("data-mpr-band-empty", hasContent ? "false" : "true");
      applyBandTheme(hostElement, config.theme);
    }

    render(currentConfig);

    return {
      update: function update(nextOptions) {
        latestOptions = deepMergeOptions({}, latestOptions, nextOptions || {});
        currentConfig = normalizeBandOptions(latestOptions);
        render(currentConfig);
      },
      destroy: function destroy() {
        clearBandTheme(hostElement);
        hostElement.classList.remove(BAND_ROOT_CLASS);
        hostElement.removeAttribute("data-mpr-band-category");
        hostElement.removeAttribute("data-mpr-band-count");
        hostElement.removeAttribute("data-mpr-band-empty");
        hostElement.removeAttribute("data-mpr-band-layout");
      },
      getConfig: function getConfig() {
        return currentConfig;
      },
    };
  }

  var DROPDOWN_ROOT_CLASS = "mpr-dropdown";
  var DROPDOWN_STYLE_ID = "mpr-ui-dropdown-styles";
  var DROPDOWN_ERROR_CODES = Object.freeze({
    REQUIRED: "mpr-ui.dropdown.menu_required",
    INVALID_JSON: "mpr-ui.dropdown.menu_invalid_json",
    UNKNOWN_KEY: "mpr-ui.dropdown.menu_unknown_key",
    VALUE_REQUIRED: "mpr-ui.dropdown.menu_value_required",
    VALUE_INVALID: "mpr-ui.dropdown.menu_value_invalid",
    DUPLICATE_SECTION_ID: "mpr-ui.dropdown.section_id_duplicate",
  });
  var DROPDOWN_MENU_KEYS = Object.freeze(["label", "placement", "sections"]);
  var DROPDOWN_SECTION_KEYS = Object.freeze(["id", "label", "mode", "links"]);
  var DROPDOWN_LINK_KEYS = Object.freeze(["label", "href", "target", "rel"]);
  var DROPDOWN_PLACEMENTS = Object.freeze(["top", "bottom"]);
  var DROPDOWN_SECTION_MODES = Object.freeze(["static", "expanded", "collapsed"]);
  var DROPDOWN_SECTION_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_-]*$/;
  var DROPDOWN_LINK_DEFAULT_REL = "noopener noreferrer";
  var DROPDOWN_VIEWPORT_OFFSET_PROPERTY = "--mpr-dropdown-viewport-offset-x";
  var DROPDOWN_STYLE_MARKUP =
    "mpr-dropdown{position:relative;display:inline-block;white-space:normal}" +
    ".mpr-dropdown__trigger{display:inline-flex;align-items:center;justify-content:center;gap:0.35rem;background:var(--mpr-chip-bg,rgba(93,147,255,0.12));color:var(--mpr-color-text-primary,#e3e5ec);border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);padding:calc(0.3rem * var(--mpr-footer-scale,1)) calc(0.55rem * var(--mpr-footer-scale,1));font:inherit;font-weight:600;font-size:calc(0.78rem * var(--mpr-footer-scale,1));cursor:pointer}" +
    ".mpr-dropdown__trigger:hover,.mpr-dropdown__trigger:focus-visible{background:var(--mpr-chip-hover-bg,rgba(148,163,184,0.32));outline:2px solid transparent}" +
    ".mpr-dropdown__indicator{font-size:0.75em;line-height:1;transition:transform 0.16s ease}" +
    'mpr-dropdown[data-mpr-dropdown-open="true"] .mpr-dropdown__indicator{transform:rotate(180deg)}' +
    ".mpr-dropdown__panel{position:absolute;inset-inline-end:0;z-index:20;display:flex;flex-direction:column;gap:0.3rem;box-sizing:border-box;inline-size:max-content;min-inline-size:min(16rem,calc(100vw - 2rem));max-inline-size:min(22rem,calc(100vw - 2rem));max-block-size:min(70vh,32rem);overflow:auto;padding:0.5rem;transform:translateX(var(--mpr-dropdown-viewport-offset-x,0));background:var(--mpr-color-surface-elevated,#1f2126);color:var(--mpr-color-text-primary,#e3e5ec);border:1px solid var(--mpr-color-border,#2c2f36);border-radius:10px;box-shadow:var(--mpr-shadow-flyout,0 8px 20px rgba(0,0,0,0.35))}" +
    'mpr-dropdown[data-mpr-dropdown-placement="top"] .mpr-dropdown__panel{bottom:calc(100% + 0.5rem)}' +
    'mpr-dropdown[data-mpr-dropdown-placement="bottom"] .mpr-dropdown__panel{top:calc(100% + 0.5rem)}' +
    ".mpr-dropdown__panel[hidden],.mpr-dropdown__links[hidden]{display:none}" +
    ".mpr-dropdown__section{display:flex;flex-direction:column;gap:0.2rem}" +
    ".mpr-dropdown__section+.mpr-dropdown__section{border-top:1px solid var(--mpr-color-border,rgba(148,163,184,0.2));padding-top:0.35rem}" +
    ".mpr-dropdown__heading,.mpr-dropdown__section-button{margin:0;padding:0.35rem 0.45rem;color:var(--mpr-color-text-muted,#c4c7d1);font:inherit;font-size:0.68rem;font-weight:700;letter-spacing:0.06em;text-align:start;text-transform:uppercase}" +
    ".mpr-dropdown__section-button{display:flex;inline-size:100%;align-items:center;justify-content:space-between;border:0;border-radius:4px;background:transparent;cursor:pointer}" +
    ".mpr-dropdown__section-button:hover,.mpr-dropdown__section-button:focus-visible{background:var(--mpr-menu-hover-bg,rgba(148,163,184,0.18));color:var(--mpr-color-text-primary,#e2e8f0);outline:2px solid transparent}" +
    ".mpr-dropdown__section-indicator{font-size:0.8rem;transition:transform 0.16s ease}" +
    '.mpr-dropdown__section-button[aria-expanded="true"] .mpr-dropdown__section-indicator{transform:rotate(180deg)}' +
    ".mpr-dropdown__links{display:flex;flex-direction:column;gap:0.1rem;list-style:none;margin:0;padding:0}" +
    ".mpr-dropdown__link{display:block;padding:0.4rem 0.5rem;border-radius:4px;color:var(--mpr-color-text-primary,#e3e5ec);font-weight:500;font-size:calc(0.78rem * var(--mpr-footer-scale,1));text-decoration:none}" +
    ".mpr-dropdown__link:hover,.mpr-dropdown__link:focus-visible{background:var(--mpr-menu-hover-bg,rgba(148,163,184,0.25));outline:2px solid transparent}" +
    "@media (max-width:32rem){.mpr-dropdown__panel{min-inline-size:min(18rem,calc(100vw - 1rem));max-inline-size:calc(100vw - 1rem);max-block-size:60vh}}";
  var dropdownInstanceCounter = 0;

  /**
   * @param {string} code
   * @param {string} message
   * @returns {MprUiError}
   */
  function createDropdownError(code, message) {
    /** @type {MprUiError} */
    var error = new Error(message);
    error.code = code;
    return error;
  }

  function assertDropdownKeys(candidate, allowedKeys, subject) {
    Object.keys(candidate).forEach(function validateDropdownKey(key) {
      if (allowedKeys.indexOf(key) === -1) {
        throw createDropdownError(
          DROPDOWN_ERROR_CODES.UNKNOWN_KEY,
          subject + ' contains the unknown field "' + key + '"',
        );
      }
    });
  }

  function requireDropdownString(value, subject) {
    if (typeof value !== "string" || !value.trim()) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_REQUIRED,
        subject + " is required",
      );
    }
    return value.trim();
  }

  function normalizeDropdownLink(candidateLink, sectionId, linkIndex) {
    var subject = 'Dropdown link "' + sectionId + '"[' + String(linkIndex) + "]";
    if (!candidateLink || typeof candidateLink !== "object" || Array.isArray(candidateLink)) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        subject + " must be an object",
      );
    }
    assertDropdownKeys(candidateLink, DROPDOWN_LINK_KEYS, subject);
    var label = requireDropdownString(candidateLink.label, subject + ".label");
    var rawHref = requireDropdownString(candidateLink.href, subject + ".href");
    var href = sanitizeHref(rawHref);
    if (href === "#" && rawHref !== "#") {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        subject + ".href uses an unsupported protocol",
      );
    }
    if (
      candidateLink.target !== undefined &&
      typeof candidateLink.target !== "string"
    ) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        subject + ".target must be a string",
      );
    }
    if (candidateLink.rel !== undefined && typeof candidateLink.rel !== "string") {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        subject + ".rel must be a string",
      );
    }
    var target = typeof candidateLink.target === "string"
      ? candidateLink.target.trim()
      : "";
    var rel = typeof candidateLink.rel === "string" ? candidateLink.rel.trim() : "";
    if (target === "_blank" && !rel) {
      rel = DROPDOWN_LINK_DEFAULT_REL;
    }
    return Object.freeze({
      label: label,
      href: href,
      target: target,
      rel: rel,
    });
  }

  function normalizeDropdownSection(candidateSection, sectionIndex, sectionIds) {
    var subject = "Dropdown section[" + String(sectionIndex) + "]";
    if (
      !candidateSection ||
      typeof candidateSection !== "object" ||
      Array.isArray(candidateSection)
    ) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        subject + " must be an object",
      );
    }
    assertDropdownKeys(candidateSection, DROPDOWN_SECTION_KEYS, subject);
    var sectionId = requireDropdownString(candidateSection.id, subject + ".id");
    if (!DROPDOWN_SECTION_ID_PATTERN.test(sectionId)) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        subject + ".id is invalid",
      );
    }
    if (sectionIds[sectionId]) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.DUPLICATE_SECTION_ID,
        'Dropdown section ID "' + sectionId + '" is not unique',
      );
    }
    sectionIds[sectionId] = true;
    var label = requireDropdownString(candidateSection.label, subject + ".label");
    var mode = requireDropdownString(candidateSection.mode, subject + ".mode").toLowerCase();
    if (DROPDOWN_SECTION_MODES.indexOf(mode) === -1) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        subject + ".mode is invalid",
      );
    }
    if (!Array.isArray(candidateSection.links) || candidateSection.links.length === 0) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_REQUIRED,
        subject + ".links must contain one or more links",
      );
    }
    var links = candidateSection.links.map(function normalizeSectionLink(link, linkIndex) {
      return normalizeDropdownLink(link, sectionId, linkIndex);
    });
    return Object.freeze({
      id: sectionId,
      label: label,
      mode: /** @type {DropdownSectionMode} */ (mode),
      links: Object.freeze(links),
    });
  }

  /**
   * @param {unknown} candidateMenu
   * @returns {DropdownMenu}
   */
  function normalizeDropdownMenu(candidateMenu) {
    if (!candidateMenu || typeof candidateMenu !== "object" || Array.isArray(candidateMenu)) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        "Dropdown menu must be an object",
      );
    }
    var menuObject = /** @type {{ label?: unknown, placement?: unknown, sections?: unknown }} */ (
      candidateMenu
    );
    assertDropdownKeys(menuObject, DROPDOWN_MENU_KEYS, "Dropdown menu");
    var label = requireDropdownString(menuObject.label, "Dropdown menu.label");
    var placement = requireDropdownString(
      menuObject.placement,
      "Dropdown menu.placement",
    ).toLowerCase();
    if (DROPDOWN_PLACEMENTS.indexOf(placement) === -1) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        "Dropdown menu.placement is invalid",
      );
    }
    if (!Array.isArray(menuObject.sections) || menuObject.sections.length === 0) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_REQUIRED,
        "Dropdown menu.sections must contain one or more sections",
      );
    }
    var sectionIds = Object.create(null);
    var sections = menuObject.sections.map(function normalizeMenuSection(
      section,
      sectionIndex,
    ) {
      return normalizeDropdownSection(section, sectionIndex, sectionIds);
    });
    return Object.freeze({
      label: label,
      placement: /** @type {DropdownPlacement} */ (placement),
      sections: Object.freeze(sections),
    });
  }

  function parseDropdownMenuValue(rawValue) {
    if (rawValue === null || rawValue === undefined || rawValue === "") {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.REQUIRED,
        "The dropdown menu is required",
      );
    }
    if (rawValue && typeof rawValue === "object") {
      return normalizeDropdownMenu(rawValue);
    }
    if (typeof rawValue !== "string") {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        "The dropdown menu must be JSON",
      );
    }
    var parsedMenu;
    try {
      parsedMenu = JSON.parse(rawValue);
    } catch (_error) {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.INVALID_JSON,
        "The dropdown menu contains invalid JSON",
      );
    }
    return normalizeDropdownMenu(parsedMenu);
  }

  function ensureDropdownStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(DROPDOWN_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = DROPDOWN_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = DROPDOWN_STYLE_MARKUP;
    } else {
      styleElement.appendChild(documentObject.createTextNode(DROPDOWN_STYLE_MARKUP));
    }
    documentObject.head.appendChild(styleElement);
  }

  function createDropdownDomId() {
    dropdownInstanceCounter += 1;
    return "mpr-dropdown-" + String(dropdownInstanceCounter);
  }

  function buildDropdownLinkAttributes(link) {
    var attributes = ' href="' + escapeHtml(link.href) + '"';
    if (link.target) {
      attributes += ' target="' + escapeHtml(link.target) + '"';
    }
    if (link.rel) {
      attributes += ' rel="' + escapeHtml(link.rel) + '"';
    }
    return attributes;
  }

  function buildDropdownSectionMarkup(section, dropdownId) {
    var sectionLabelId = dropdownId + "-section-" + section.id + "-label";
    var sectionContentId = dropdownId + "-section-" + section.id + "-links";
    var linksMarkup = section.links
      .map(function renderDropdownLink(link, linkIndex) {
        return (
          '<li><a class="mpr-dropdown__link" data-mpr-dropdown="link" data-mpr-dropdown-section-id="' +
          escapeHtml(section.id) +
          '" data-mpr-dropdown-link-index="' +
          String(linkIndex) +
          '"' +
          buildDropdownLinkAttributes(link) +
          ">" +
          escapeHtml(link.label) +
          "</a></li>"
        );
      })
      .join("");
    var labelMarkup = section.mode === "static"
      ? '<div class="mpr-dropdown__heading" id="' +
        sectionLabelId +
        '" role="heading" aria-level="2">' +
        escapeHtml(section.label) +
        "</div>"
      : '<button class="mpr-dropdown__section-button" type="button" data-mpr-dropdown="section-trigger" data-mpr-dropdown-section-id="' +
        escapeHtml(section.id) +
        '" id="' +
        sectionLabelId +
        '" aria-controls="' +
        sectionContentId +
        '" aria-expanded="' +
        (section.mode === "expanded" ? "true" : "false") +
        '"><span>' +
        escapeHtml(section.label) +
        '</span><span class="mpr-dropdown__section-indicator" aria-hidden="true">⌃</span></button>';
    return (
      '<div class="mpr-dropdown__section" data-mpr-dropdown="section" data-mpr-dropdown-section-id="' +
      escapeHtml(section.id) +
      '" role="group" aria-labelledby="' +
      sectionLabelId +
      '">' +
      labelMarkup +
      '<ul class="mpr-dropdown__links" data-mpr-dropdown="section-links" data-mpr-dropdown-section-id="' +
      escapeHtml(section.id) +
      '" id="' +
      sectionContentId +
      '"' +
      (section.mode === "collapsed" ? ' hidden="hidden"' : "") +
      ">" +
      linksMarkup +
      "</ul></div>"
    );
  }

  function buildDropdownMarkup(menu, dropdownId) {
    var panelId = dropdownId + "-panel";
    return (
      '<button class="mpr-dropdown__trigger" type="button" data-mpr-dropdown="trigger" aria-haspopup="true" aria-controls="' +
      panelId +
      '" aria-expanded="false"><span>' +
      escapeHtml(menu.label) +
      '</span><span class="mpr-dropdown__indicator" aria-hidden="true">⌃</span></button>' +
      '<nav class="mpr-dropdown__panel" data-mpr-dropdown="panel" id="' +
      panelId +
      '" aria-label="' +
      escapeHtml(menu.label) +
      '" hidden="hidden">' +
      menu.sections
        .map(function renderDropdownSection(section) {
          return buildDropdownSectionMarkup(section, dropdownId);
        })
        .join("") +
      "</nav>"
    );
  }

  /**
   * Registers the reusable sectioned link menu custom element.
   * @param {object} registry
   * @returns {void}
   */
  function defineDropdownElement(registry) {
    registry.define("mpr-dropdown", function setupDropdownElement(Base) {
      return class MprDropdownElement extends Base {
        constructor() {
          super();
          this.__dropdownId = createDropdownDomId();
          this.__dropdownMenu = null;
          this.__dropdownOpen = false;
          this.__dropdownSectionState = Object.create(null);
          this.__dropdownListeners = [];
          this.__dropdownDocument = null;
          this.__dropdownWindow = null;
          this.__boundDropdownTrigger = this.__handleDropdownTrigger.bind(this);
          this.__boundDropdownOutsidePointer = this.__handleDropdownOutsidePointer.bind(this);
          this.__boundDropdownEscape = this.__handleDropdownEscape.bind(this);
          this.__boundDropdownViewportResize = this.__handleDropdownViewportResize.bind(this);
        }
        static get observedAttributes() {
          return DROPDOWN_ATTRIBUTE_NAMES;
        }
        render() {
          this.__renderDropdown();
        }
        update() {
          this.__renderDropdown();
        }
        destroy() {
          this.__detachDropdownListeners();
          this.__dropdownMenu = null;
          this.__dropdownSectionState = Object.create(null);
          this.__dropdownOpen = false;
          this.innerHTML = "";
        }
        __renderDropdown() {
          if (!this.__mprConnected) {
            return;
          }
          this.__detachDropdownListeners();
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureDropdownStyles(documentObject);
          var menu;
          try {
            menu = parseDropdownMenuValue(this.getAttribute("menu"));
          } catch (error) {
            var errorObject = /** @type {MprUiError} */ (error);
            var errorCode = errorObject && errorObject.code
              ? errorObject.code
              : DROPDOWN_ERROR_CODES.VALUE_INVALID;
            this.__dropdownMenu = null;
            this.__dropdownOpen = false;
            this.__dropdownSectionState = Object.create(null);
            this.setAttribute("data-mpr-dropdown-error", errorCode);
            this.removeAttribute("data-mpr-dropdown-placement");
            this.setAttribute("data-mpr-dropdown-open", "false");
            this.innerHTML = "";
            logError(errorCode, errorObject && errorObject.message ? errorObject.message : String(error));
            dispatchEvent(this, "mpr-dropdown:error", {
              code: errorCode,
              message: errorObject && errorObject.message ? errorObject.message : String(error),
            });
            return;
          }
          this.removeAttribute("data-mpr-dropdown-error");
          this.classList.add(DROPDOWN_ROOT_CLASS);
          this.__dropdownMenu = menu;
          this.__dropdownOpen = false;
          this.__dropdownSectionState = Object.create(null);
          menu.sections.forEach(
            function initializeDropdownSectionState(section) {
              this.__dropdownSectionState[section.id] = section.mode !== "collapsed";
            }.bind(this),
          );
          this.setAttribute("data-mpr-dropdown-placement", menu.placement);
          this.setAttribute("data-mpr-dropdown-open", "false");
          this.setAttribute("data-mpr-dropdown-section-count", String(menu.sections.length));
          this.innerHTML = buildDropdownMarkup(menu, this.__dropdownId);
          this.__attachDropdownListeners(documentObject);
        }
        __listenDropdown(element, eventName, handler) {
          if (!element || typeof element.addEventListener !== "function") {
            return;
          }
          element.addEventListener(eventName, handler);
          this.__dropdownListeners.push({
            element: element,
            eventName: eventName,
            handler: handler,
          });
        }
        __attachDropdownListeners(documentObject) {
          var trigger = this.querySelector('[data-mpr-dropdown="trigger"]');
          this.__listenDropdown(trigger, "click", this.__boundDropdownTrigger);
          var sectionTriggers = this.querySelectorAll(
            '[data-mpr-dropdown="section-trigger"]',
          );
          for (
            var sectionTriggerIndex = 0;
            sectionTriggerIndex < sectionTriggers.length;
            sectionTriggerIndex += 1
          ) {
            this.__listenDropdown(
              sectionTriggers[sectionTriggerIndex],
              "click",
              this.__handleDropdownSectionToggle.bind(this),
            );
          }
          var links = this.querySelectorAll('[data-mpr-dropdown="link"]');
          for (var linkIndex = 0; linkIndex < links.length; linkIndex += 1) {
            this.__listenDropdown(
              links[linkIndex],
              "click",
              this.__handleDropdownLinkClick.bind(this),
            );
          }
          if (documentObject && typeof documentObject.addEventListener === "function") {
            this.__dropdownDocument = documentObject;
            documentObject.addEventListener("pointerdown", this.__boundDropdownOutsidePointer);
            documentObject.addEventListener("keydown", this.__boundDropdownEscape);
          }
          this.__dropdownWindow = resolveOwnerWindow(this);
          if (
            this.__dropdownWindow &&
            typeof this.__dropdownWindow.addEventListener === "function"
          ) {
            this.__dropdownWindow.addEventListener(
              "resize",
              this.__boundDropdownViewportResize,
            );
          }
        }
        __detachDropdownListeners() {
          this.__dropdownListeners.forEach(function detachDropdownListener(listener) {
            if (
              listener.element &&
              typeof listener.element.removeEventListener === "function"
            ) {
              listener.element.removeEventListener(
                listener.eventName,
                listener.handler,
              );
            }
          });
          this.__dropdownListeners = [];
          if (
            this.__dropdownDocument &&
            typeof this.__dropdownDocument.removeEventListener === "function"
          ) {
            this.__dropdownDocument.removeEventListener(
              "pointerdown",
              this.__boundDropdownOutsidePointer,
            );
            this.__dropdownDocument.removeEventListener(
              "keydown",
              this.__boundDropdownEscape,
            );
          }
          this.__dropdownDocument = null;
          if (
            this.__dropdownWindow &&
            typeof this.__dropdownWindow.removeEventListener === "function"
          ) {
            this.__dropdownWindow.removeEventListener(
              "resize",
              this.__boundDropdownViewportResize,
            );
          }
          this.__dropdownWindow = null;
        }
        __handleDropdownTrigger(eventObject) {
          if (eventObject && typeof eventObject.preventDefault === "function") {
            eventObject.preventDefault();
          }
          this.__setDropdownOpen(!this.__dropdownOpen, "trigger", false);
        }
        __handleDropdownOutsidePointer(eventObject) {
          if (!this.__dropdownOpen || !eventObject) {
            return;
          }
          var target = eventObject.target || null;
          if (target && typeof this.contains === "function" && this.contains(target)) {
            return;
          }
          this.__setDropdownOpen(false, "outside", false);
        }
        __handleDropdownEscape(eventObject) {
          if (!this.__dropdownOpen || !eventObject) {
            return;
          }
          var key = eventObject.key || eventObject.keyCode || "";
          if (key === "Escape" || key === "Esc" || key === 27) {
            if (typeof eventObject.preventDefault === "function") {
              eventObject.preventDefault();
            }
            this.__setDropdownOpen(false, "escape", true);
          }
        }
        __handleDropdownViewportResize() {
          if (this.__dropdownOpen) {
            this.__positionDropdownPanel();
          }
        }
        __handleDropdownSectionToggle(eventObject) {
          var sectionTrigger =
            eventObject && eventObject.currentTarget ? eventObject.currentTarget : null;
          if (!sectionTrigger || typeof sectionTrigger.getAttribute !== "function") {
            return;
          }
          var sectionId = sectionTrigger.getAttribute("data-mpr-dropdown-section-id");
          if (!sectionId) {
            return;
          }
          this.__setDropdownSectionOpen(
            sectionId,
            !this.__dropdownSectionState[sectionId],
          );
        }
        __handleDropdownLinkClick(eventObject) {
          if (!this.__dropdownMenu) {
            return;
          }
          var linkElement =
            eventObject && eventObject.currentTarget ? eventObject.currentTarget : null;
          if (!linkElement || typeof linkElement.getAttribute !== "function") {
            return;
          }
          var sectionId = linkElement.getAttribute("data-mpr-dropdown-section-id");
          var linkIndex = Number(
            linkElement.getAttribute("data-mpr-dropdown-link-index"),
          );
          var sectionIndex = this.__dropdownMenu.sections.findIndex(
            function findDropdownSection(section) {
              return section.id === sectionId;
            },
          );
          if (
            sectionIndex < 0 ||
            !Number.isInteger(linkIndex) ||
            linkIndex < 0 ||
            linkIndex >= this.__dropdownMenu.sections[sectionIndex].links.length
          ) {
            return;
          }
          var link = this.__dropdownMenu.sections[sectionIndex].links[linkIndex];
          dispatchEvent(this, "mpr-dropdown:link-click", {
            sectionId: sectionId,
            sectionIndex: sectionIndex,
            linkIndex: linkIndex,
            link: {
              label: link.label,
              href: link.href,
              target: link.target,
              rel: link.rel,
            },
          });
          this.__setDropdownOpen(false, "link", false);
        }
        __setDropdownOpen(nextOpen, source, returnFocus) {
          var nextState = Boolean(nextOpen);
          if (nextState === this.__dropdownOpen) {
            return;
          }
          this.__dropdownOpen = nextState;
          var trigger = this.querySelector('[data-mpr-dropdown="trigger"]');
          var panel = this.querySelector('[data-mpr-dropdown="panel"]');
          if (trigger && typeof trigger.setAttribute === "function") {
            trigger.setAttribute("aria-expanded", nextState ? "true" : "false");
          }
          setHiddenState(panel, !nextState);
          this.setAttribute("data-mpr-dropdown-open", nextState ? "true" : "false");
          if (nextState) {
            this.__positionDropdownPanel();
          }
          if (
            !nextState &&
            returnFocus &&
            trigger &&
            typeof trigger.focus === "function"
          ) {
            trigger.focus();
          }
          dispatchEvent(this, "mpr-dropdown:toggle", {
            open: nextState,
            source: source,
          });
        }
        __positionDropdownPanel() {
          var panel = this.querySelector('[data-mpr-dropdown="panel"]');
          var ownerWindow = this.__dropdownWindow || resolveOwnerWindow(this);
          positionPanelInViewport(panel, ownerWindow, DROPDOWN_VIEWPORT_OFFSET_PROPERTY);
        }
        __setDropdownSectionOpen(sectionId, nextOpen) {
          if (!this.__dropdownMenu) {
            return;
          }
          var section = this.__dropdownMenu.sections.find(
            function findDropdownSection(candidateSection) {
              return candidateSection.id === sectionId;
            },
          );
          if (!section || section.mode === "static") {
            return;
          }
          var nextState = Boolean(nextOpen);
          var sectionTrigger = this.querySelector(
            '[data-mpr-dropdown="section-trigger"][data-mpr-dropdown-section-id="' +
              sectionId +
              '"]',
          );
          var sectionLinks = this.querySelector(
            '[data-mpr-dropdown="section-links"][data-mpr-dropdown-section-id="' +
              sectionId +
              '"]',
          );
          var documentObject = this.ownerDocument || this.__dropdownDocument;
          var activeElement = documentObject ? documentObject.activeElement : null;
          var focusInsideSection = Boolean(
            !nextState &&
              sectionLinks &&
              activeElement &&
              typeof sectionLinks.contains === "function" &&
              sectionLinks.contains(activeElement),
          );
          this.__dropdownSectionState[sectionId] = nextState;
          if (sectionTrigger && typeof sectionTrigger.setAttribute === "function") {
            sectionTrigger.setAttribute("aria-expanded", nextState ? "true" : "false");
          }
          setHiddenState(sectionLinks, !nextState);
          if (
            focusInsideSection &&
            sectionTrigger &&
            typeof sectionTrigger.focus === "function"
          ) {
            sectionTrigger.focus();
          }
          dispatchEvent(this, "mpr-dropdown:section-toggle", {
            sectionId: sectionId,
            expanded: nextState,
          });
        }
      };
    });
  }

  var FOOTER_THEME_SWITCHER_ERROR_CODE = "mpr-ui.footer.theme-switcher";
  var FOOTER_ROOT_CLASS = "mpr-footer";
  var FOOTER_SMALL_CLASS = FOOTER_ROOT_CLASS + "--small";

  var FOOTER_DEFAULTS = Object.freeze({
    elementId: "",
    baseClass: FOOTER_ROOT_CLASS,
    innerElementId: "",
    innerClass: "mpr-footer__inner",
    wrapperClass: "mpr-footer__layout",
    brandWrapperClass: "mpr-footer__brand",
    spacerClass: "mpr-footer__spacer",
    prefixClass: "mpr-footer__prefix",
    prefixText: "Built by Marco Polo Research Lab",
    menu: null,
    horizontalLinks: HORIZONTAL_LINKS_DEFAULTS,
    privacyLinkClass: "mpr-footer__privacy",
    privacyLinkHref: "#",
    privacyLinkLabel: "Privacy • Terms",
    privacyLinkHidden: false,
    privacyModalContent: "",
    themeToggle: Object.freeze({
      enabled: false,
      variant: "",
      label: "Build by Marco Polo Research Lab",
      wrapperClass: "mpr-footer__theme-toggle",
      inputClass: "mpr-footer__theme-checkbox",
      dataTheme: "light",
      inputId: "mpr-footer-theme-toggle",
      ariaLabel: "Toggle theme",
    }),
    sticky: true,
  });

  function ensureFooterStyles(documentObject) {
    if (
      !documentObject ||
      typeof documentObject.createElement !== "function" ||
      !documentObject.head
    ) {
      return;
    }
    ensureThemeTokenStyles(documentObject);
    if (documentObject.getElementById(FOOTER_STYLE_ID)) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.type = "text/css";
    styleElement.id = FOOTER_STYLE_ID;
    if (styleElement.styleSheet) {
      styleElement.styleSheet.cssText = FOOTER_STYLE_MARKUP;
    } else {
      styleElement.appendChild(documentObject.createTextNode(FOOTER_STYLE_MARKUP));
    }
    documentObject.head.appendChild(styleElement);
  }

  function mergeFooterObjects(targetObject) {
    var args = [targetObject];
    for (var index = 1; index < arguments.length; index += 1) {
      args.push(arguments[index]);
    }
    return deepMergeOptions.apply(null, args);
  }

  function escapeFooterHtml(inputValue) {
    var value = inputValue === undefined || inputValue === null ? "" : String(inputValue);
    return value
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function sanitizeFooterAttribute(inputValue) {
    var raw = escapeFooterHtml(inputValue);
    if (/^\s*javascript:/i.test(String(inputValue || ""))) {
      return "#";
    }
    return raw;
  }

  function sanitizeFooterHref(inputValue) {
    return sanitizeHref(inputValue);
  }

  function normalizeFooterThemeToggle(themeToggleInput) {
    if (
      themeToggleInput &&
      typeof themeToggleInput === "object" &&
      Object.prototype.hasOwnProperty.call(themeToggleInput, "themeSwitcher")
    ) {
      logLegacyConfig(
        "<mpr-footer>",
        "themeToggle.themeSwitcher",
        LEGACY_DSL_THEME_VARIANT_REPLACEMENT,
      );
    }
    var hasExplicitEnabled =
      themeToggleInput &&
      typeof themeToggleInput === "object" &&
      Object.prototype.hasOwnProperty.call(themeToggleInput, "enabled");
    var mergedToggle = mergeFooterObjects(
      {},
      FOOTER_DEFAULTS.themeToggle,
      themeToggleInput || {},
    );
    var variantSource = "";
    if (
      typeof mergedToggle.variant === "string" &&
      mergedToggle.variant.trim()
    ) {
      variantSource = mergedToggle.variant.trim();
    }
    var normalizedVariant = "";
    var invalidVariant = false;
    if (variantSource) {
      var variantValue = variantSource.toLowerCase();
      if (variantValue === "toggle" || variantValue === "switch") {
        normalizedVariant = "switch";
      } else if (variantValue === "button") {
        normalizedVariant = "button";
      } else if (variantValue === "square") {
        normalizedVariant = "square";
      } else {
        logError(
          FOOTER_THEME_SWITCHER_ERROR_CODE,
          'Unsupported theme-switcher value "' + variantSource + '"',
        );
        invalidVariant = true;
      }
    }
    var enabledValue = hasExplicitEnabled
      ? Boolean(mergedToggle.enabled)
      : Boolean(normalizedVariant);
    if (invalidVariant) {
      normalizedVariant = "";
      enabledValue = false;
    } else if (!normalizedVariant && enabledValue) {
      normalizedVariant = "switch";
    }
    if (invalidVariant) {
      enabledValue = false;
    }
    if (variantSource && !normalizedVariant) {
      enabledValue = false;
    }
    mergedToggle.enabled = enabledValue;
    mergedToggle.variant = normalizedVariant;
    var core = normalizeThemeToggleCore(mergedToggle, {
      enabled: FOOTER_DEFAULTS.themeToggle.enabled,
      ariaLabel: FOOTER_DEFAULTS.themeToggle.ariaLabel,
    });
    var labelValue =
      typeof mergedToggle.label === "string" && mergedToggle.label.trim()
        ? mergedToggle.label.trim()
        : FOOTER_DEFAULTS.themeToggle.label;
    return {
      enabled: core.enabled,
      label: labelValue,
      wrapperClass:
        mergedToggle.wrapperClass || FOOTER_DEFAULTS.themeToggle.wrapperClass,
      inputClass:
        mergedToggle.inputClass || FOOTER_DEFAULTS.themeToggle.inputClass,
      dataTheme:
        typeof mergedToggle.dataTheme === "string"
          ? mergedToggle.dataTheme
          : FOOTER_DEFAULTS.themeToggle.dataTheme,
      inputId:
        typeof mergedToggle.inputId === "string"
          ? mergedToggle.inputId
          : FOOTER_DEFAULTS.themeToggle.inputId,
      ariaLabel: core.ariaLabel,
      variant: normalizedVariant,
      attribute: core.attribute,
      targets: core.targets,
      modes: core.modes,
      initialMode: core.initialMode,
    };
  }

  function normalizeFooterConfig() {
    var providedConfigs = Array.prototype.slice.call(arguments);
    var mergedConfig = mergeFooterObjects({}, FOOTER_DEFAULTS);
    providedConfigs.forEach(function apply(config) {
      if (!config || typeof config !== "object") {
        return;
      }
      mergeFooterObjects(mergedConfig, config);
    });
    mergedConfig.themeToggle = normalizeFooterThemeToggle(
      providedConfigs.reduce(function reduceToggle(current, candidate) {
        if (candidate && typeof candidate === "object" && candidate.themeToggle) {
          return candidate.themeToggle;
        }
        return current;
      }, mergedConfig.themeToggle),
    );
    var resolvedMenu = providedConfigs.reduce(function reduceFooterMenu(current, candidate) {
      if (
        candidate &&
        typeof candidate === "object" &&
        Object.prototype.hasOwnProperty.call(candidate, "menu")
      ) {
        return candidate.menu;
      }
      return current;
    }, mergedConfig.menu);
    mergedConfig.menu = resolvedMenu !== null && resolvedMenu !== undefined
      ? parseDropdownMenuValue(resolvedMenu)
      : null;
    if (mergedConfig.menu && mergedConfig.menu.placement !== "top") {
      throw createDropdownError(
        DROPDOWN_ERROR_CODES.VALUE_INVALID,
        "The footer menu placement must be top",
      );
    }
    mergedConfig.privacyModalContent =
      typeof mergedConfig.privacyModalContent === "string" &&
      mergedConfig.privacyModalContent.trim()
        ? mergedConfig.privacyModalContent.trim()
        : "";
    mergedConfig.privacyLinkHidden = normalizeBooleanAttribute(
      mergedConfig.privacyLinkHidden,
      FOOTER_DEFAULTS.privacyLinkHidden,
    );
    mergedConfig.horizontalLinks = normalizeHorizontalLinksConfig(
      mergedConfig.horizontalLinks,
      FOOTER_DEFAULTS.horizontalLinks,
    );
    mergedConfig.prefixText =
      typeof mergedConfig.prefixText === "string"
        ? mergedConfig.prefixText.trim()
        : FOOTER_DEFAULTS.prefixText;
    mergedConfig.sticky = normalizeBooleanAttribute(
      mergedConfig.sticky,
      FOOTER_DEFAULTS.sticky,
    );
    
    var sizeValue = "normal";
    if (
      typeof mergedConfig.size === "string" &&
      mergedConfig.size.trim().toLowerCase() === "small"
    ) {
      sizeValue = "small";
    }
    mergedConfig.size = sizeValue;

    return mergedConfig;
  }

  function buildFooterThemeToggleConfig(config) {
    return normalizeThemeToggleDisplayOptions(
      {
        enabled: config.themeToggle.enabled,
        variant: config.themeToggle.variant || "switch",
        label: config.themeToggle.label || "Theme",
        showLabel: false,
        wrapperClass: config.themeToggle.wrapperClass,
        controlClass: config.themeToggle.inputClass,
        ariaLabel: config.themeToggle.ariaLabel,
        inputId: config.themeToggle.inputId,
        dataTheme: config.themeToggle.dataTheme,
        icons: {
          light: THEME_TOGGLE_DEFAULT_ICONS.light,
          dark: THEME_TOGGLE_DEFAULT_ICONS.dark,
          unknown: THEME_TOGGLE_DEFAULT_ICONS.unknown,
        },
        modes: config.themeToggle.modes,
        source: "footer",
      },
    );
  }

  function footerQuery(rootElement, selector) {
    if (!rootElement || !selector) {
      return null;
    }
    return rootElement.querySelector(selector);
  }

  function resolveFooterSlotElements(hostElement) {
    if (!hostElement || typeof hostElement.querySelector !== "function") {
      return {};
    }
    var root = hostElement.querySelector('footer[role="contentinfo"]');
    if (!root) {
      return {};
    }
    return {
      root: root,
      brand: footerQuery(root, '[data-mpr-footer="brand"]'),
      legal: footerQuery(root, '[data-mpr-footer="legal"]'),
    };
  }

  function applyFooterSlotContent(slotMap, hostElement) {
    if (!slotMap || !hostElement) {
      return;
    }
    var elements = resolveFooterSlotElements(hostElement);
    if (
      elements.brand &&
      slotMap["menu-prefix"] &&
      slotMap["menu-prefix"].length
    ) {
      slotMap["menu-prefix"].forEach(function appendBrandSlot(node) {
        if (node && typeof elements.brand.appendChild === "function") {
          elements.brand.appendChild(node);
        }
      });
    }
    if (elements.legal && slotMap.legal && slotMap.legal.length) {
      slotMap.legal.forEach(function appendLegalSlot(node) {
        if (node && typeof elements.legal.appendChild === "function") {
          elements.legal.appendChild(node);
        }
      });
    }
  }

  function resolveFooterThemeModes(themeToggleConfig) {
    var config = themeToggleConfig && typeof themeToggleConfig === "object"
      ? themeToggleConfig
      : {};
    var candidateModes = Array.isArray(config.modes) && config.modes.length
      ? config.modes
      : DEFAULT_THEME_MODES;
    var modes = normalizeThemeModes(candidateModes);
    var attribute =
      typeof config.attribute === "string" && config.attribute.trim()
        ? config.attribute.trim()
        : DEFAULT_THEME_ATTRIBUTE;
    var candidateTargets =
      Array.isArray(config.targets) && config.targets.length
        ? config.targets
        : DEFAULT_THEME_TARGETS;
    var targets = normalizeThemeTargets(candidateTargets);
    var initialMode = null;
    if (typeof config.mode === "string" && config.mode.trim()) {
      initialMode = config.mode.trim();
    } else if (typeof config.initialMode === "string" && config.initialMode.trim()) {
      initialMode = config.initialMode.trim();
    }
    return {
      modes: modes,
      attribute: attribute,
      targets: targets,
      initialMode: initialMode,
    };
  }

  function setFooterClass(targetElement, className) {
    if (!targetElement || !className) {
      return;
    }
    targetElement.className = className;
  }

  function normalizeClassTokens(className) {
    if (typeof className !== "string" || !className.trim()) {
      return [];
    }
    return className
      .split(/\s+/)
      .map(function trimClassToken(token) {
        return token.trim();
      })
      .filter(Boolean);
  }

  function dedupeClassTokens(tokens) {
    var seen = Object.create(null);
    var deduped = [];
    (tokens || []).forEach(function addClassToken(token) {
      if (!token || seen[token]) {
        return;
      }
      seen[token] = true;
      deduped.push(token);
    });
    return deduped;
  }

  function readElementClassName(element) {
    if (!element) {
      return "";
    }
    if (typeof element.className === "string") {
      return element.className;
    }
    if (typeof element.getAttribute === "function") {
      return element.getAttribute("class") || "";
    }
    return "";
  }

  function writeElementClassName(element, className) {
    if (!element) {
      return;
    }
    if (typeof element.className === "string" || typeof element.className === "undefined") {
      element.className = className;
    }
    if (typeof element.setAttribute === "function") {
      if (className) {
        element.setAttribute("class", className);
      } else if (typeof element.removeAttribute === "function") {
        element.removeAttribute("class");
      }
    }
  }

  function elementHasClassToken(element, token) {
    if (!element || !token) {
      return false;
    }
    if (
      element.classList &&
      typeof element.classList.contains === "function"
    ) {
      return element.classList.contains(token);
    }
    return normalizeClassTokens(readElementClassName(element)).indexOf(token) !== -1;
  }

  function updateManagedClassTokens(element, nextTokens, previousTokens) {
    var previous = dedupeClassTokens(Array.isArray(previousTokens) ? previousTokens : []);
    var next = dedupeClassTokens(Array.isArray(nextTokens) ? nextTokens : []);
    if (!element) {
      return next;
    }
    if (
      element.classList &&
      typeof element.classList.add === "function" &&
      typeof element.classList.remove === "function"
    ) {
      previous.forEach(function removeClassToken(token) {
        if (next.indexOf(token) === -1) {
          element.classList.remove(token);
        }
      });
      var managedTokens = [];
      next.forEach(function addClassToken(token) {
        if (previous.indexOf(token) !== -1) {
          if (!elementHasClassToken(element, token)) {
            element.classList.add(token);
          }
          managedTokens.push(token);
          return;
        }
        if (elementHasClassToken(element, token)) {
          return;
        }
        element.classList.add(token);
        managedTokens.push(token);
      });
      return managedTokens;
    }
    var retainedTokens = normalizeClassTokens(readElementClassName(element)).filter(
      function keepExistingClass(token) {
        return previous.indexOf(token) === -1;
      },
    );
    var managedTokens = next.filter(function keepManagedToken(token) {
      return retainedTokens.indexOf(token) === -1;
    });
    writeElementClassName(
      element,
      dedupeClassTokens(retainedTokens.concat(next)).join(" "),
    );
    return dedupeClassTokens(managedTokens);
  }

  function buildFooterClassNames(config) {
    var baseTokens = normalizeClassTokens(
      config && typeof config.baseClass === "string" ? config.baseClass : "",
    );
    var sharedTokens = [];
    baseTokens.forEach(function collectSharedToken(token) {
      if (token === FOOTER_ROOT_CLASS || token === FOOTER_SMALL_CLASS) {
        return;
      }
      sharedTokens.push(token);
    });
    var rootTokens = [FOOTER_ROOT_CLASS].concat(sharedTokens);
    if (config && config.size === "small") {
      rootTokens.push(FOOTER_SMALL_CLASS);
    }
    return {
      hostTokens: config && config.sticky === false ? dedupeClassTokens(sharedTokens) : [],
      rootClassName: dedupeClassTokens(rootTokens).join(" "),
    };
  }

  function buildFooterMarkup(config) {
    var themeToggleMarkup = config.themeToggle && config.themeToggle.enabled
      ? '<div data-mpr-footer="theme-toggle"></div>'
      : "";
    var spacerMarkup = themeToggleMarkup
      ? '<span data-mpr-footer="spacer"' +
        (config.spacerClass
          ? ' class="' + escapeFooterHtml(config.spacerClass) + '"'
          : "") +
        ' aria-hidden="true"></span>'
      : "";

    var dropdownMarkup = config.menu
      ? '<mpr-dropdown data-mpr-footer="dropdown" menu="' +
        escapeFooterHtml(JSON.stringify(config.menu)) +
        '"></mpr-dropdown>'
      : "";

    var privacyHeading = escapeFooterHtml(
      config.privacyModalTitle || config.privacyLinkLabel || "Privacy & Terms",
    );
    var modalMarkup = config.privacyModalContent && !config.privacyLinkHidden
      ? '<div data-mpr-footer="privacy-modal" data-mpr-modal="container" aria-hidden="true" data-mpr-modal-open="false">' +
        '<div data-mpr-modal="backdrop" data-mpr-footer="privacy-modal-backdrop"></div>' +
        '<div data-mpr-modal="dialog" data-mpr-footer="privacy-modal-dialog" role="dialog" aria-modal="true" tabindex="-1">' +
        '<header data-mpr-modal="header" data-mpr-footer="privacy-modal-header">' +
        '<h1 data-mpr-modal="title" data-mpr-footer="privacy-modal-title">' +
        privacyHeading +
        "</h1>" +
        '<button type="button" data-mpr-modal="close" data-mpr-footer="privacy-modal-close" aria-label="Close">&times;</button>' +
        "</header>" +
        '<div data-mpr-modal="body" data-mpr-footer="privacy-modal-content">' +
        config.privacyModalContent +
        "</div>" +
        "</div>" +
        "</div>"
      : "";

    var prefixMarkup = config.prefixText
      ? '<span data-mpr-footer="prefix"></span>'
      : "";

    var privacyLinkMarkup = config.privacyLinkHidden
      ? ""
      : '<a data-mpr-footer="privacy-link" href="' +
        escapeFooterHtml(sanitizeFooterHref(config.privacyLinkHref)) +
        '"></a>';

    var horizontalLinksMarkup =
      '<nav data-mpr-footer="horizontal-links" class="mpr-footer__horizontal-links" aria-label="Utility links" data-mpr-align="' +
      escapeFooterHtml(config.horizontalLinks && config.horizontalLinks.alignment
        ? config.horizontalLinks.alignment
        : FOOTER_DEFAULTS.horizontalLinks.alignment) +
      '"></nav>';

    var layoutMarkup =
      '<div data-mpr-footer="layout">' +
      privacyLinkMarkup +
      horizontalLinksMarkup +
      '<div data-mpr-footer="legal"></div>' +
      spacerMarkup +
      themeToggleMarkup +
      '<div data-mpr-footer="brand">' +
      prefixMarkup +
      dropdownMarkup +
      "</div>" +
      "</div>";

    var stickySpacerMarkup =
      '<div data-mpr-footer="sticky-spacer" aria-hidden="true"></div>';

    return (
      stickySpacerMarkup +
      '<footer role="contentinfo" data-mpr-footer="root">' +
      '<div data-mpr-footer="inner">' +
      layoutMarkup +
      modalMarkup +
      "</div>" +
      "</footer>"
    );
  }

  function mountFooterDom(hostElement, config) {
    if (!hostElement || typeof hostElement !== "object") {
      throw new Error("mountFooterDom requires a host element");
    }
    hostElement.innerHTML = buildFooterMarkup(config);
    var footerRoot = hostElement.querySelector('footer[role="contentinfo"]');
    if (!footerRoot) {
      throw new Error("mountFooterDom failed to locate the footer root");
    }
    footerRoot.setAttribute("data-mpr-footer-root", "true");
    applyFooterStickyState(footerRoot, config && config.sticky, hostElement);
    var stickySpacer = null;
    if (typeof hostElement.querySelector === "function") {
      stickySpacer = hostElement.querySelector('[data-mpr-footer="sticky-spacer"]');
    }
    updateFooterStickySpacer(stickySpacer, footerRoot, config && config.sticky);
    return footerRoot;
  }

  function applyFooterStickyState(footerRootElement, sticky, hostElement) {
    if (!footerRootElement) {
      return;
    }
    if (sticky === false) {
      if (typeof footerRootElement.setAttribute === "function") {
        footerRootElement.setAttribute("data-mpr-sticky", "false");
      }
      if (hostElement && typeof hostElement.setAttribute === "function") {
        hostElement.setAttribute("data-mpr-sticky", "false");
      }
    } else if (typeof footerRootElement.removeAttribute === "function") {
      footerRootElement.removeAttribute("data-mpr-sticky");
      if (hostElement && typeof hostElement.removeAttribute === "function") {
        hostElement.removeAttribute("data-mpr-sticky");
      }
    }
  }

  function updateFooterStickySpacer(spacerElement, footerRootElement, sticky) {
    if (!spacerElement || !footerRootElement) {
      return;
    }
    if (!spacerElement.style) {
      spacerElement.style = {};
    }
    if (sticky === false) {
      spacerElement.style.height = "0px";
      return;
    }
    var height = 0;
    if (typeof footerRootElement.getBoundingClientRect === "function") {
      var rect = footerRootElement.getBoundingClientRect();
      height = rect && rect.height ? rect.height : 0;
    }
    if (!height && typeof footerRootElement.offsetHeight === "number") {
      height = footerRootElement.offsetHeight;
    }
    spacerElement.style.height = height > 0 ? height + "px" : "0px";
  }

  function initializeFooterStickyState(hostElement, footerRootElement, spacerElement, sticky) {
    applyFooterStickyState(footerRootElement, sticky, hostElement);
    if (!spacerElement) {
      return null;
    }
    function updateSpacerHeight() {
      updateFooterStickySpacer(spacerElement, footerRootElement, sticky);
    }
    if (sticky === false) {
      spacerElement.style.height = "0px";
      return null;
    }
    updateSpacerHeight();
    var resizeObserver = null;
    var resizeHandler = null;
    if (typeof global.ResizeObserver === "function") {
      resizeObserver = new global.ResizeObserver(function handleFooterResize() {
        updateSpacerHeight();
      });
      resizeObserver.observe(footerRootElement);
      return function cleanupStickyState() {
        if (resizeObserver && typeof resizeObserver.disconnect === "function") {
          resizeObserver.disconnect();
        }
        resizeObserver = null;
        spacerElement.style.height = "0px";
      };
    }
    if (global.window && typeof global.window.addEventListener === "function") {
      resizeHandler = function handleWindowResize() {
        updateSpacerHeight();
      };
      global.window.addEventListener("resize", resizeHandler);
      return function cleanupStickyState() {
        if (
          global.window &&
          typeof global.window.removeEventListener === "function" &&
          resizeHandler
        ) {
          global.window.removeEventListener("resize", resizeHandler);
        }
        resizeHandler = null;
        spacerElement.style.height = "0px";
      };
    }
    return function cleanupStickyState() {
      spacerElement.style.height = "0px";
    };
  }

  var FOOTER_PRIVACY_INTERACTIVE_ROLE = "button";
  var FOOTER_PRIVACY_TABINDEX_ATTRIBUTE = "tabindex";
  var FOOTER_PRIVACY_TAB_INDEX_VALUE = "0";

  function toggleFooterPrivacyInteractivity(anchorElement, enabled) {
    if (!anchorElement) {
      return;
    }
    if (enabled) {
      anchorElement.setAttribute("role", FOOTER_PRIVACY_INTERACTIVE_ROLE);
      anchorElement.setAttribute(
        FOOTER_PRIVACY_TABINDEX_ATTRIBUTE,
        FOOTER_PRIVACY_TAB_INDEX_VALUE,
      );
      return;
    }
    anchorElement.removeAttribute("role");
    anchorElement.removeAttribute(FOOTER_PRIVACY_TABINDEX_ATTRIBUTE);
  }

  function updateFooterPrivacy(containerElement, config, modalControls) {
    var privacyAnchor = footerQuery(containerElement, '[data-mpr-footer="privacy-link"]');
    if (!privacyAnchor) {
      return;
    }
    if (config.privacyLinkClass) {
      privacyAnchor.className = config.privacyLinkClass;
    }
    if (config.privacyLinkHref) {
      privacyAnchor.setAttribute("href", sanitizeFooterHref(config.privacyLinkHref));
    }
    var modalEnabled = Boolean(config.privacyModalContent);
    if (config.privacyLinkLabel) {
      privacyAnchor.textContent = config.privacyLinkLabel;
      if (modalEnabled && modalControls && typeof modalControls.updateLabel === "function") {
        modalControls.updateLabel(config.privacyLinkLabel);
      }
    }
    toggleFooterPrivacyInteractivity(privacyAnchor, modalEnabled);
  }

  function updateFooterPrefix(containerElement, config) {
    var prefixElement = footerQuery(containerElement, '[data-mpr-footer="prefix"]');
    if (!prefixElement) {
      return;
    }
    if (config.prefixClass) {
      prefixElement.className = config.prefixClass;
    }
    prefixElement.textContent = config.prefixText || "";
  }

  function updateFooterHorizontalLinks(containerElement, config) {
    var horizontalLinksContainer = footerQuery(
      containerElement,
      '[data-mpr-footer="horizontal-links"]',
    );
    if (!horizontalLinksContainer) {
      return;
    }
    var horizontalLinksConfig =
      config.horizontalLinks && typeof config.horizontalLinks === "object"
        ? config.horizontalLinks
        : FOOTER_DEFAULTS.horizontalLinks;
    var alignment =
      typeof horizontalLinksConfig.alignment === "string" &&
      horizontalLinksConfig.alignment.trim()
        ? horizontalLinksConfig.alignment.trim()
        : FOOTER_DEFAULTS.horizontalLinks.alignment;
    if (typeof horizontalLinksContainer.setAttribute === "function") {
      horizontalLinksContainer.setAttribute("data-mpr-align", alignment);
    }
    var items = Array.isArray(horizontalLinksConfig.links)
      ? horizontalLinksConfig.links
      : [];
    horizontalLinksContainer.innerHTML = items
      .map(function renderSingle(link) {
        var normalizedLink = normalizeLinkForRendering(link, {});
        if (!normalizedLink) {
          return "";
        }
        var hrefValue = escapeFooterHtml(normalizedLink.href);
        var labelValue = escapeFooterHtml(normalizedLink.label);
        var targetValue = normalizedLink.target ? normalizedLink.target : "";
        var relValue = normalizedLink.rel ? normalizedLink.rel : "";
        if (targetValue === "_blank" && !relValue) {
          relValue = FOOTER_LINK_DEFAULT_REL;
        }
        var extraAttributes = "";
        if (targetValue) {
          extraAttributes += ' target="' + escapeFooterHtml(targetValue) + '"';
        }
        if (relValue) {
          extraAttributes += ' rel="' + escapeFooterHtml(relValue) + '"';
        }
        return (
          '<a href="' +
          hrefValue +
          '"' +
          extraAttributes +
          ">" +
          labelValue +
          "</a>"
        );
      })
      .filter(Boolean)
      .join("");
  }

  function applyFooterStructure(containerElement, config) {
    if (!containerElement) {
      return;
    }
    var innerElement = config.innerElementId
      ? containerElement.querySelector('#' + sanitizeFooterAttribute(config.innerElementId))
      : footerQuery(containerElement, '[data-mpr-footer="inner"]');
    if (innerElement && config.innerClass) {
      setFooterClass(innerElement, config.innerClass);
    }
    var layoutElement = footerQuery(containerElement, '[data-mpr-footer="layout"]');
    if (layoutElement && config.wrapperClass) {
      setFooterClass(layoutElement, config.wrapperClass);
    }
    var brandElement = footerQuery(containerElement, '[data-mpr-footer="brand"]');
    if (brandElement && config.brandWrapperClass) {
      setFooterClass(brandElement, config.brandWrapperClass);
    }
  }

  function readFooterOptionsFromDataset(rootElement) {
    if (!rootElement || !rootElement.dataset) {
      return {};
    }
    var dataset = rootElement.dataset;
    var options = {};
    if (dataset.elementId) {
      options.elementId = dataset.elementId;
    }
    if (dataset.baseClass) {
      options.baseClass = dataset.baseClass;
    }
    if (dataset.innerElementId) {
      options.innerElementId = dataset.innerElementId;
    }
    if (dataset.innerClass) {
      options.innerClass = dataset.innerClass;
    }
    if (dataset.wrapperClass) {
      options.wrapperClass = dataset.wrapperClass;
    }
    if (dataset.brandWrapperClass) {
      options.brandWrapperClass = dataset.brandWrapperClass;
    }
    if (dataset.prefixClass) {
      options.prefixClass = dataset.prefixClass;
    }
    if (dataset.prefixText) {
      options.prefixText = dataset.prefixText;
    }
    if (dataset.horizontalLinks) {
      options.horizontalLinks = parseJsonValue(dataset.horizontalLinks, {});
    }
    if (dataset.privacyLinkClass) {
      options.privacyLinkClass = dataset.privacyLinkClass;
    }
    if (dataset.privacyLinkHref) {
      options.privacyLinkHref = dataset.privacyLinkHref;
    }
    if (dataset.privacyLinkLabel) {
      options.privacyLinkLabel = dataset.privacyLinkLabel;
    }
    if (dataset.privacyLinkHidden !== undefined) {
      options.privacyLinkHidden = normalizeBooleanAttribute(
        dataset.privacyLinkHidden,
        FOOTER_DEFAULTS.privacyLinkHidden,
      );
    }
    if (dataset.privacyModalContent) {
      options.privacyModalContent = dataset.privacyModalContent;
    }
    if (dataset.themeToggle) {
      options.themeToggle = parseJsonValue(dataset.themeToggle, {});
    }
    var themeSwitcherValue = dataset.themeSwitcher;
    if (
      !themeSwitcherValue &&
      rootElement &&
      typeof rootElement.getAttribute === "function"
    ) {
      var attributeValue = rootElement.getAttribute("theme-switcher");
      if (attributeValue) {
        themeSwitcherValue = attributeValue;
      }
    }
    if (themeSwitcherValue) {
      options.themeToggle = options.themeToggle || {};
      options.themeToggle.variant = themeSwitcherValue;
    }
    if (dataset.menu !== undefined) {
      options.menu = parseDropdownMenuValue(dataset.menu);
    }
    if (dataset.sticky !== undefined) {
      options.sticky = normalizeBooleanAttribute(dataset.sticky, true);
    }
    if (dataset.size) {
      options.size = dataset.size;
    }
    return options;
  }

  function initializeFooterPrivacyModal(containerElement, config) {
    if (
      !config ||
      !config.privacyModalContent ||
      typeof config.privacyModalContent !== "string"
    ) {
      return null;
    }
    var modalElement = footerQuery(containerElement, '[data-mpr-footer="privacy-modal"]');
    var dialogElement = footerQuery(modalElement, '[data-mpr-footer="privacy-modal-dialog"]');
    var closeButton = footerQuery(modalElement, '[data-mpr-footer="privacy-modal-close"]');
    var backdropElement = footerQuery(modalElement, '[data-mpr-footer="privacy-modal-backdrop"]');
    var privacyLink = footerQuery(containerElement, '[data-mpr-footer="privacy-link"]');
    if (
      !modalElement ||
      !dialogElement ||
      !privacyLink ||
      typeof privacyLink.addEventListener !== "function"
    ) {
      return null;
    }
    if (!dialogElement.hasAttribute("tabindex")) {
      dialogElement.setAttribute("tabindex", "-1");
    }
    var ownerDocument = modalElement.ownerDocument || (global.document || null);
    if (
      ownerDocument &&
      ownerDocument.body &&
      modalElement.parentNode &&
      modalElement.parentNode !== ownerDocument.body &&
      typeof ownerDocument.body.appendChild === "function"
    ) {
      ownerDocument.body.appendChild(modalElement);
    }
    var modalController = createViewportModalController({
      modalElement: modalElement,
      dialogElement: dialogElement,
      closeButton: closeButton,
      backdropElement: backdropElement,
      labelElement: footerQuery(modalElement, '[data-mpr-footer="privacy-modal-title"]'),
      labelText: config.privacyLinkLabel || "Privacy & Terms",
      defaultLabel: "Privacy & Terms",
      ownerDocument: ownerDocument,
      getHeaderOffset: function getHeaderOffset() {
        if (!ownerDocument) {
          return 0;
        }
        var headerElement =
          ownerDocument.querySelector('header.mpr-header') ||
          ownerDocument.querySelector('[data-mpr-header="root"]');
        if (!headerElement) {
          return 0;
        }
        if (typeof headerElement.getBoundingClientRect === "function") {
          var headerRect = headerElement.getBoundingClientRect();
          return Math.max(0, Math.round(headerRect.bottom));
        }
        if (typeof headerElement.offsetHeight === "number") {
          return Math.max(0, headerElement.offsetHeight);
        }
        return 0;
      },
      getFooterOffset: function getFooterOffset() {
        var footerRoot =
          footerQuery(containerElement, '[data-mpr-footer="root"]') ||
          containerElement;
        if (!footerRoot) {
          return 0;
        }
        if (typeof footerRoot.getBoundingClientRect === "function") {
          var footerRect = footerRoot.getBoundingClientRect();
          var viewportHeight =
            (ownerDocument && ownerDocument.documentElement
              ? ownerDocument.documentElement.clientHeight
              : 0) ||
            (global.window && typeof global.window.innerHeight === "number"
              ? global.window.innerHeight
              : 0);
          if (viewportHeight) {
            return Math.max(0, Math.round(viewportHeight - footerRect.top));
          }
          return Math.max(0, Math.round(footerRect.height));
        }
        if (typeof footerRoot.offsetHeight === "number") {
          return Math.max(0, footerRoot.offsetHeight);
        }
        return 0;
      },
    });
    if (!modalController) {
      return null;
    }

    function notifyModalOpen(source) {
      dispatchEvent(
        containerElement || modalElement,
        "mpr-footer:privacy-modal-open",
        {
          source: source || "privacy-link",
          modal: "privacy",
        },
      );
    }

    function openPrivacyModal(source) {
      if (!modalController || typeof modalController.open !== "function") {
        return;
      }
      modalController.open();
      notifyModalOpen(source || "privacy-link");
    }

    function handleLinkKeydown(event) {
      if (!event) {
        return;
      }
      var key = event.key || event.keyCode;
      if (
        key === "Enter" ||
        key === " " ||
        key === "Spacebar" ||
        key === 13 ||
        key === 32
      ) {
        event.preventDefault();
        openPrivacyModal("keyboard");
      }
    }

    function handleLinkClick(event) {
      if (event && typeof event.preventDefault === "function") {
        event.preventDefault();
      }
      openPrivacyModal("mouse");
    }

    privacyLink.addEventListener("click", handleLinkClick);
    privacyLink.addEventListener("keydown", handleLinkKeydown);

    return {
      controller: modalController,
      cleanup: function cleanupPrivacyModal() {
        privacyLink.removeEventListener("click", handleLinkClick);
        privacyLink.removeEventListener("keydown", handleLinkKeydown);
        if (modalController && typeof modalController.destroy === "function") {
          modalController.destroy();
        }
        if (
          modalElement &&
          modalElement.parentNode &&
          typeof modalElement.parentNode.removeChild === "function"
        ) {
          modalElement.parentNode.removeChild(modalElement);
        }
      },
    };
  }


  function createFooterComponent(initialOptions) {
    var startingOptions = initialOptions && typeof initialOptions === "object" ? initialOptions : {};
    var component = {
      config: normalizeFooterConfig(startingOptions),
      $el: null,
      cleanupHandlers: [],
      hostBaseClassTokens: [],
      $dispatch: null,
      init: function init(userOptions) {
        var datasetOptions = this.$el ? readFooterOptionsFromDataset(this.$el) : {};
        this.config = normalizeFooterConfig(startingOptions, datasetOptions, userOptions);

        ensureFooterStyles(global.document || (global.window && global.window.document));

        this.cleanupHandlers.forEach(function callCleanup(callback) {
          if (typeof callback === "function") {
            callback();
          }
        });
        this.cleanupHandlers = [];

        var footerTheme = this.config.themeToggle;
        themeManager.configure({
          attribute: footerTheme.attribute,
          targets: footerTheme.targets,
          modes: footerTheme.modes,
        });
        if (
          footerTheme.initialMode &&
          footerTheme.initialMode !== themeManager.getMode()
        ) {
          themeManager.setMode(footerTheme.initialMode, "footer:init");
        }

        if (!this.$el) {
          return;
        }
        var footerRoot;
        try {
          footerRoot = mountFooterDom(this.$el, this.config);
        } catch (_error) {
          return;
        }
        if (this.config.elementId) {
          footerRoot.id = this.config.elementId;
        }
        var footerClassNames = buildFooterClassNames(this.config);
        setFooterClass(footerRoot, footerClassNames.rootClassName);
        if (this.$el) {
          this.hostBaseClassTokens = updateManagedClassTokens(
            this.$el,
            footerClassNames.hostTokens,
            this.hostBaseClassTokens,
          );
        }

        var self = this;
        var footerThemeUnsubscribe = themeManager.on(function handleFooterTheme(detail) {
          var payload = { theme: detail.mode, source: detail.source || null };
          if (typeof self.$dispatch === "function") {
            self.$dispatch("mpr-footer:theme-change", payload);
          }
          if (self.$el) {
            dispatchEvent(self.$el, "mpr-footer:theme-change", payload);
          } else {
            dispatchEvent(footerRoot, "mpr-footer:theme-change", payload);
          }
        });
        this.cleanupHandlers.push(footerThemeUnsubscribe);

        applyFooterStructure(footerRoot, this.config);
        var privacyModalLifecycle = this.config.privacyModalContent && !this.config.privacyLinkHidden
          ? initializeFooterPrivacyModal(footerRoot, this.config)
          : null;
        updateFooterPrivacy(
          footerRoot,
          this.config,
          privacyModalLifecycle && privacyModalLifecycle.controller,
        );
        updateFooterPrefix(footerRoot, this.config);
        updateFooterHorizontalLinks(footerRoot, this.config);

        if (
          privacyModalLifecycle &&
          typeof privacyModalLifecycle.cleanup === "function"
        ) {
          this.cleanupHandlers.push(privacyModalLifecycle.cleanup);
        }

        var toggleHost = footerQuery(footerRoot, '[data-mpr-footer="theme-toggle"]');
        if (toggleHost) {
          var footerToggleConfig = buildFooterThemeToggleConfig(this.config);
          var themeCleanup = initializeThemeToggle(toggleHost, footerToggleConfig);
          if (typeof themeCleanup === "function") {
            this.cleanupHandlers.push(themeCleanup);
          }
        }

        var stickySpacerElement =
          this.$el.querySelector &&
          this.$el.querySelector('[data-mpr-footer="sticky-spacer"]');
        var stickyCleanup = initializeFooterStickyState(
          this.$el,
          footerRoot,
          stickySpacerElement,
          this.config.sticky,
        );
        if (typeof stickyCleanup === "function") {
          this.cleanupHandlers.push(stickyCleanup);
        }
      },
      destroy: function destroy() {
        this.cleanupHandlers.forEach(function callCleanup(callback) {
          if (typeof callback === "function") {
            callback();
          }
        });
        this.cleanupHandlers = [];
        this.hostBaseClassTokens = updateManagedClassTokens(
          this.$el,
          [],
          this.hostBaseClassTokens,
        );
        if (this.$el) {
          this.$el.innerHTML = "";
        }
      },
    };
    return component;
  }

  function createFooterController(target, options) {
    var host = resolveHost(target);
    if (!host || typeof host !== "object") {
      throw new Error("createFooterController requires a host element");
    }
    var component = createFooterComponent(options);
    component.$el = host;
    component.init(options);
    return {
      update: function update(nextOptions) {
        component.init(nextOptions);
      },
      destroy: function destroy() {
        component.destroy();
      },
      getConfig: function getConfig() {
        return component.config;
      },
    };
  }

  function createThemeToggleController(target, options) {
    var host = resolveHost(target);
    if (!host || typeof host !== "object") {
      throw new Error("createThemeToggleController requires a root element");
    }
    var latestOptions = deepMergeOptions({}, options || {});
    var normalized = normalizeStandaloneThemeToggleOptions(latestOptions);
    var controller = mountThemeToggleComponent(
      host,
      normalized,
      true,
      "theme-toggle:init",
    );
    return {
      update: function update(nextOptions) {
        latestOptions = deepMergeOptions({}, latestOptions, nextOptions || {});
        var normalizedNext = normalizeStandaloneThemeToggleOptions(latestOptions);
        controller.update(normalizedNext, "theme-toggle:update");
      },
      destroy: function destroy() {
        controller.destroy();
        if (host && Object.prototype.hasOwnProperty.call(host, "innerHTML")) {
          host.innerHTML = "";
        }
        if (host && typeof host.removeAttribute === "function") {
          host.removeAttribute("data-mpr-theme-mode");
          host.removeAttribute("data-mpr-theme-toggle-variant");
        }
      },
    };
  }

  function authDiagnosticsStatusLabel(status) {
    return AUTH_DIAGNOSTICS_LABELS[status] || AUTH_DIAGNOSTICS_LABELS.error;
  }

  function authDiagnosticsUserLabel(profile) {
    if (!profile) {
      return AUTH_DIAGNOSTICS_LABELS.noUser;
    }
    var candidateFields = [
      "display",
      "full_name",
      "name",
      "user_email",
      "user_id",
    ];
    for (var index = 0; index < candidateFields.length; index += 1) {
      var value = profile[candidateFields[index]];
      if (typeof value === "string" && value.trim()) {
        return value.trim();
      }
    }
    return AUTH_DIAGNOSTICS_LABELS.noUser;
  }

  function buildAuthDiagnosticsMarkup(status, profile) {
    return (
      '<section class="mpr-auth-diagnostics" data-mpr-auth-diagnostics="root" aria-label="' +
      escapeHtml(AUTH_DIAGNOSTICS_LABELS.heading) +
      '">' +
      '<h2 class="mpr-auth-diagnostics__heading">' +
      escapeHtml(AUTH_DIAGNOSTICS_LABELS.heading) +
      "</h2>" +
      '<dl class="mpr-auth-diagnostics__list">' +
      '<div><dt>' +
      escapeHtml(AUTH_DIAGNOSTICS_LABELS.status) +
      "</dt><dd data-mpr-auth-diagnostics=\"status\">" +
      escapeHtml(authDiagnosticsStatusLabel(status)) +
      "</dd></div>" +
      '<div><dt>' +
      escapeHtml(AUTH_DIAGNOSTICS_LABELS.user) +
      "</dt><dd data-mpr-auth-diagnostics=\"user\">" +
      escapeHtml(authDiagnosticsUserLabel(profile)) +
      "</dd></div>" +
      "</dl>" +
      "</section>"
    );
  }

  function defineAuthDiagnosticsElement(registry) {
    registry.define(
      "mpr-auth-diagnostics",
      function setupAuthDiagnosticsElement(Base) {
        return class MprAuthDiagnosticsElement extends Base {
          constructor() {
            super();
            this.__authDiagnosticsTarget = null;
            this.__authDiagnosticsEventHandler =
              this.__handleAuthDiagnosticsEvent.bind(this);
          }
          static get observedAttributes() {
            return [AUTH_DIAGNOSTICS_TARGET_ATTRIBUTE];
          }
          render() {
            this.__bindAuthDiagnosticsTarget();
          }
          update() {
            this.__bindAuthDiagnosticsTarget();
          }
          destroy() {
            this.__detachAuthDiagnosticsTarget();
            clearNodeContents(this);
            this.removeAttribute("data-mpr-auth-diagnostics-status");
            this.removeAttribute("data-mpr-auth-diagnostics-last-event");
            this.removeAttribute("data-mpr-auth-diagnostics-provider");
            this.removeAttribute("data-mpr-auth-diagnostics-error");
          }
          __detachAuthDiagnosticsTarget() {
            if (
              this.__authDiagnosticsTarget &&
              typeof this.__authDiagnosticsTarget.removeEventListener === "function"
            ) {
              [
                "mpr-ui:auth:authenticated",
                "mpr-ui:auth:unauthenticated",
                "mpr-ui:auth:status-change",
                "mpr-ui:auth:error",
              ].forEach((eventName) => {
                this.__authDiagnosticsTarget.removeEventListener(
                  eventName,
                  this.__authDiagnosticsEventHandler,
                );
              });
            }
            this.__authDiagnosticsTarget = null;
          }
          __bindAuthDiagnosticsTarget() {
            if (!this.__mprConnected) {
              return;
            }
            this.__detachAuthDiagnosticsTarget();
            var targetSelector = this.getAttribute(
              AUTH_DIAGNOSTICS_TARGET_ATTRIBUTE,
            );
            if (typeof targetSelector !== "string" || !targetSelector.trim()) {
              this.__renderAuthDiagnosticsError(
                AUTH_DIAGNOSTICS_TARGET_REQUIRED_ERROR_CODE,
                "auth-target is required",
              );
              return;
            }
            var documentObject =
              this.ownerDocument ||
              global.document ||
              (global.window && global.window.document) ||
              null;
            var targetElement = null;
            if (
              documentObject &&
              typeof documentObject.querySelector === "function"
            ) {
              try {
                targetElement = documentObject.querySelector(
                  targetSelector.trim(),
                );
              } catch (_error) {
                this.__renderAuthDiagnosticsError(
                  AUTH_DIAGNOSTICS_TARGET_INVALID_ERROR_CODE,
                  "auth-target must be a valid selector",
                );
                return;
              }
            }
            if (!targetElement) {
              this.__renderAuthDiagnosticsError(
                AUTH_DIAGNOSTICS_TARGET_MISSING_ERROR_CODE,
                "auth-target does not match an auth surface",
              );
              return;
            }
            this.removeAttribute("data-mpr-auth-diagnostics-error");
            this.__authDiagnosticsTarget = targetElement;
            [
              "mpr-ui:auth:authenticated",
              "mpr-ui:auth:unauthenticated",
              "mpr-ui:auth:status-change",
              "mpr-ui:auth:error",
            ].forEach((eventName) => {
              targetElement.addEventListener(
                eventName,
                this.__authDiagnosticsEventHandler,
              );
            });
            resolveAuthProfileSnapshot(targetElement).then((snapshot) => {
              if (this.__authDiagnosticsTarget !== targetElement) {
                return;
              }
              this.__renderAuthDiagnostics(snapshot.status, snapshot.profile);
            }).catch((error) => {
              if (this.__authDiagnosticsTarget !== targetElement) {
                return;
              }
              this.__renderAuthDiagnosticsError(
                error && error.code
                  ? error.code
                  : AUTH_DIAGNOSTICS_TARGET_MISSING_ERROR_CODE,
                error && error.message ? error.message : String(error),
              );
            });
          }
          __handleAuthDiagnosticsEvent(eventObject) {
            if (!this.__authDiagnosticsTarget) {
              return;
            }
            this.setAttribute(
              "data-mpr-auth-diagnostics-last-event",
              eventObject.type,
            );
            var provider =
              eventObject &&
              eventObject.detail &&
              typeof eventObject.detail.provider === "string"
                ? eventObject.detail.provider
                : "";
            if (provider) {
              this.setAttribute("data-mpr-auth-diagnostics-provider", provider);
            }
            if (eventObject.type === "mpr-ui:auth:error") {
              this.__renderAuthDiagnostics("error", null);
              return;
            }
            var targetElement = this.__authDiagnosticsTarget;
            resolveAuthProfileSnapshot(targetElement).then((snapshot) => {
              if (this.__authDiagnosticsTarget !== targetElement) {
                return;
              }
              this.__renderAuthDiagnostics(snapshot.status, snapshot.profile);
            }).catch((error) => {
              if (this.__authDiagnosticsTarget !== targetElement) {
                return;
              }
              this.__renderAuthDiagnosticsError(
                error && error.code
                  ? error.code
                  : AUTH_DIAGNOSTICS_TARGET_MISSING_ERROR_CODE,
                error && error.message ? error.message : String(error),
              );
            });
          }
          __renderAuthDiagnostics(status, profile) {
            this.setAttribute("data-mpr-auth-diagnostics-status", status);
            this.innerHTML = buildAuthDiagnosticsMarkup(status, profile);
          }
          __renderAuthDiagnosticsError(code, message) {
            this.setAttribute("data-mpr-auth-diagnostics-error", code);
            this.setAttribute("data-mpr-auth-diagnostics-status", "error");
            this.innerHTML = buildAuthDiagnosticsMarkup("error", null);
            dispatchEvent(this, "mpr-auth-diagnostics:error", {
              code: code,
              message: message,
            });
          }
        };
      },
    );
  }

  function defineHeaderElement(registry) {
    registry.define("mpr-header", function setupHeaderElement(Base) {
      return class MprHeaderElement extends Base {
        constructor() {
          super();
          this.__headerController = null;
          this.__headerSlots = null;
          this.__headerSlotsCaptured = false;
          this.__headerUserMenuElement = null;
        }
        static get observedAttributes() {
          return HEADER_ATTRIBUTE_OBSERVERS;
        }
        render() {
          this.__captureHeaderSlots();
          syncDatasetFromAttributes(this, HEADER_ATTRIBUTE_DATASET_MAP);
          this.__renderHeader();
        }
        update(name, _oldValue, newValue) {
          reflectAttributeToDataset(
            this,
            name,
            normalizeAttributeReflectionValue(name, newValue),
            HEADER_ATTRIBUTE_DATASET_MAP,
          );
          this.__renderHeader();
        }
        destroy() {
          if (this.__headerController && typeof this.__headerController.destroy === "function") {
            this.__headerController.destroy();
          }
          this.__headerController = null;
        }
        __captureHeaderSlots() {
          if (this.__headerSlotsCaptured) {
            return;
          }
          this.__headerSlots = captureSlotNodes(this, HEADER_SLOT_NAMES);
          this.__headerUserMenuElement = resolveHeaderUserMenuSlot(
            this.__headerSlots,
          );
          if (this.__headerUserMenuElement) {
            prepareHeaderUserMenuSlotElement(this.__headerUserMenuElement);
          }
          this.__headerSlotsCaptured = true;
        }
        __renderHeader() {
          if (!this.__mprConnected) {
            return;
          }
          var options;
          try {
            options = buildHeaderOptionsFromAttributes(this);
          } catch (error) {
            if (
              this.__headerController &&
              typeof this.__headerController.destroy === "function"
            ) {
              this.__headerController.destroy();
            }
            this.__headerController = null;
            this.setAttribute(
              "data-mpr-auth-error",
              error && error.code
                ? error.code
                : "mpr-ui.auth.config_invalid",
            );
            this.setAttribute("data-mpr-auth-status", "error");
            this.innerHTML = "";
            dispatchEvent(this, "mpr-ui:header:error", {
              code:
                error && error.code
                  ? error.code
                  : "mpr-ui.auth.config_invalid",
              message: error && error.message ? error.message : String(error),
            });
            return;
          }
          this.removeAttribute("data-mpr-auth-error");
          var userMenuElement = this.__headerUserMenuElement;
          if (this.__headerController) {
            this.__headerController.update(options);
          } else {
            this.__headerController = createSiteHeaderController(this, options, {
              userMenuElement: userMenuElement,
            });
          }
          if (this.__headerSlots) {
            var elements = resolveHeaderElements(this);
            applyHeaderSlotContent(this.__headerSlots, elements);
          }
        }
      };
    });
  }

  function defineFooterElement(registry) {
    registry.define("mpr-footer", function setupFooterElement(Base) {
      return class MprFooterElement extends Base {
        constructor() {
          super();
          this.__footerController = null;
          this.__footerSlots = null;
          this.__footerSlotsCaptured = false;
        }
        static get observedAttributes() {
          return FOOTER_ATTRIBUTE_OBSERVERS;
        }
        render() {
          this.__captureFooterSlots();
          syncDatasetFromAttributes(this, FOOTER_ATTRIBUTE_DATASET_MAP);
          this.__applyFooter();
        }
        update(name, _oldValue, newValue) {
          reflectAttributeToDataset(
            this,
            name,
            normalizeAttributeReflectionValue(name, newValue),
            FOOTER_ATTRIBUTE_DATASET_MAP,
          );
          this.__applyFooter();
        }
        destroy() {
          if (this.__footerController && typeof this.__footerController.destroy === "function") {
            this.__footerController.destroy();
          }
          this.__footerController = null;
        }
        __captureFooterSlots() {
          if (this.__footerSlotsCaptured) {
            return;
          }
          this.__footerSlots = captureSlotNodes(this, FOOTER_SLOT_NAMES);
          this.__footerSlotsCaptured = true;
        }
        __applyFooter() {
          if (!this.__mprConnected) {
            return;
          }
          var options;
          try {
            options = buildFooterOptionsFromAttributes(this);
          } catch (error) {
            var errorObject = /** @type {MprUiError} */ (error);
            var errorCode = errorObject && errorObject.code
              ? errorObject.code
              : DROPDOWN_ERROR_CODES.VALUE_INVALID;
            if (
              this.__footerController &&
              typeof this.__footerController.destroy === "function"
            ) {
              this.__footerController.destroy();
            }
            this.__footerController = null;
            this.setAttribute("data-mpr-footer-error", errorCode);
            this.innerHTML = "";
            logError(
              errorCode,
              errorObject && errorObject.message
                ? errorObject.message
                : String(error),
            );
            dispatchEvent(this, "mpr-footer:error", {
              code: errorCode,
              message:
                errorObject && errorObject.message
                  ? errorObject.message
                  : String(error),
            });
            return;
          }
          this.removeAttribute("data-mpr-footer-error");
          if (this.__footerController) {
            this.__footerController.update(options);
          } else {
            this.__footerController = createFooterController(this, options);
          }
          if (this.__footerSlots) {
            applyFooterSlotContent(this.__footerSlots, this);
          }
        }
      };
    });
  }

  function defineThemeToggleElement(registry) {
    registry.define("mpr-theme-toggle", function setupThemeToggleElement(Base) {
      return class MprThemeToggleElement extends Base {
        constructor() {
          super();
          this.__themeToggleController = null;
        }
        static get observedAttributes() {
          return THEME_TOGGLE_ATTRIBUTE_NAMES;
        }
        render() {
          this.__applyThemeToggle();
        }
        update() {
          this.__applyThemeToggle();
        }
        destroy() {
          if (
            this.__themeToggleController &&
            typeof this.__themeToggleController.destroy === "function"
          ) {
            this.__themeToggleController.destroy();
          }
          this.__themeToggleController = null;
        }
        __applyThemeToggle() {
          if (!this.__mprConnected) {
            return;
          }
          var options = buildThemeToggleOptionsFromAttributes(this);
          if (this.__themeToggleController) {
            this.__themeToggleController.update(options);
          } else {
            this.__themeToggleController =
              createThemeToggleController(this, options);
          }
        }
      };
    });
  }

  var PASSWORD_AUTH_FORM_DEFINITIONS = Object.freeze({
    login: Object.freeze({
      title: AUTH_FORM_LABELS.loginTitle,
      submit: AUTH_FORM_LABELS.loginSubmit,
      fields: Object.freeze([
        Object.freeze({ key: "email", label: AUTH_FORM_LABELS.email, type: "email", autocomplete: "email" }),
        Object.freeze({ key: "password", label: AUTH_FORM_LABELS.password, type: "password", autocomplete: "current-password", secret: true }),
      ]),
    }),
    signup: Object.freeze({
      title: AUTH_FORM_LABELS.signupTitle,
      submit: AUTH_FORM_LABELS.signupSubmit,
      fields: Object.freeze([
        Object.freeze({ key: "email", label: AUTH_FORM_LABELS.email, type: "email", autocomplete: "email" }),
        Object.freeze({ key: "password", label: AUTH_FORM_LABELS.password, type: "password", autocomplete: "new-password", secret: true }),
      ]),
    }),
    "verify-email": Object.freeze({
      title: AUTH_FORM_LABELS.verifyEmailTitle,
      submit: AUTH_FORM_LABELS.verifyEmailSubmit,
      fields: Object.freeze([
        Object.freeze({ key: "token", label: AUTH_FORM_LABELS.token, type: "text", autocomplete: "one-time-code", secret: true }),
      ]),
    }),
    "reset-start": Object.freeze({
      title: AUTH_FORM_LABELS.resetStartTitle,
      submit: AUTH_FORM_LABELS.resetStartSubmit,
      fields: Object.freeze([
        Object.freeze({ key: "email", label: AUTH_FORM_LABELS.email, type: "email", autocomplete: "email" }),
      ]),
    }),
    "reset-complete": Object.freeze({
      title: AUTH_FORM_LABELS.resetCompleteTitle,
      submit: AUTH_FORM_LABELS.resetCompleteSubmit,
      fields: Object.freeze([
        Object.freeze({ key: "token", label: AUTH_FORM_LABELS.token, type: "text", autocomplete: "one-time-code", secret: true }),
        Object.freeze({ key: "password", label: AUTH_FORM_LABELS.newPassword, type: "password", autocomplete: "new-password", secret: true }),
      ]),
    }),
  });

  var ACCOUNT_PANEL_FORM_DEFINITIONS = Object.freeze({
    "password-change": Object.freeze({
      title: AUTH_FORM_LABELS.passwordChangeTitle,
      submit: AUTH_FORM_LABELS.passwordChangeSubmit,
      fields: Object.freeze([
        Object.freeze({ key: "currentPassword", label: AUTH_FORM_LABELS.currentPassword, type: "password", autocomplete: "current-password", secret: true }),
        Object.freeze({ key: "newPassword", label: AUTH_FORM_LABELS.newPassword, type: "password", autocomplete: "new-password", secret: true }),
      ]),
    }),
    "password-link-start": Object.freeze({
      title: AUTH_FORM_LABELS.passwordLinkStartTitle,
      submit: AUTH_FORM_LABELS.passwordLinkStartSubmit,
      fields: Object.freeze([
        Object.freeze({ key: "email", label: AUTH_FORM_LABELS.email, type: "email", autocomplete: "email" }),
        Object.freeze({ key: "password", label: AUTH_FORM_LABELS.password, type: "password", autocomplete: "new-password", secret: true }),
      ]),
    }),
    "password-link-verify": Object.freeze({
      title: AUTH_FORM_LABELS.passwordLinkVerifyTitle,
      submit: AUTH_FORM_LABELS.passwordLinkVerifySubmit,
      fields: Object.freeze([
        Object.freeze({ key: "token", label: AUTH_FORM_LABELS.token, type: "text", autocomplete: "one-time-code", secret: true }),
      ]),
    }),
    "google-link": Object.freeze({
      title: AUTH_FORM_LABELS.googleLinkTitle,
      fields: Object.freeze([]),
    }),
    unlink: Object.freeze({
      title: AUTH_FORM_LABELS.unlinkTitle,
      submit: AUTH_FORM_LABELS.unlinkSubmit,
      fields: Object.freeze([
        Object.freeze({ key: "identity", label: AUTH_FORM_LABELS.identity, type: "select", autocomplete: "off", options: Object.freeze([]) }),
      ]),
    }),
    disable: Object.freeze({
      title: AUTH_FORM_LABELS.disableTitle,
      submit: AUTH_FORM_LABELS.disableSubmit,
      fields: Object.freeze([]),
    }),
  });

  var AUTH_FORM_STYLE_MARKUP =
    ".mpr-auth-form__navigation{justify-self:start;border:0;padding:.25rem 0;background:transparent;color:var(--mpr-color-accent,#5d93ff);font:inherit;font-size:.85rem;text-decoration:underline;cursor:pointer}.mpr-auth-form__navigation:focus-visible{outline:2px solid currentColor;outline-offset:3px}" +
    "mpr-password-auth,mpr-account-panel{display:block;box-sizing:border-box;inline-size:100%;min-inline-size:0;max-inline-size:20rem}" +
    ".mpr-auth-form{display:grid;white-space:normal;overflow-wrap:anywhere;box-sizing:border-box;inline-size:100%;min-inline-size:0;gap:.5rem;padding:.75rem;border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);background:var(--mpr-color-surface-elevated,#1f2126);color:var(--mpr-color-text-primary,#e3e5ec);font-size:.78rem}" +
    ".mpr-auth-form__title{margin:0;font-size:.86rem}" +
    ".mpr-auth-form__field{display:grid;gap:.25rem;font-weight:600}" +
    ".mpr-auth-form__input{box-sizing:border-box;inline-size:100%;min-inline-size:0;min-block-size:2.125rem;padding:.35rem .5rem;border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px);background:var(--mpr-color-surface-primary,#0f1114);color:var(--mpr-color-text-primary,#e3e5ec);font:inherit}" +
    ".mpr-auth-form__submit{box-sizing:border-box;inline-size:100%;min-inline-size:0;min-block-size:2.125rem;padding:.35rem .55rem;border:1px solid var(--mpr-color-accent,#5d93ff);border-radius:var(--mpr-radius-control,6px);background:rgba(93,147,255,.14);color:var(--mpr-color-text-primary,#e3e5ec);font:inherit;font-weight:700;cursor:pointer}" +
    ".mpr-auth-form__submit:disabled,.mpr-auth-form__input:disabled{cursor:not-allowed;opacity:.65}" +
    ".mpr-auth-form__google-action{display:flex;align-items:center;min-block-size:2.5rem;max-inline-size:100%;overflow:hidden}" +
    ".mpr-auth-form__google-action[aria-disabled='true']{opacity:.65}" +
    ".mpr-auth-form__status{min-block-size:1.25rem;margin:0}" +
    ".mpr-auth-form[data-status='error'] .mpr-auth-form__status{color:var(--mpr-color-error,#ef4444)}" +
    ".mpr-auth-form__unauthenticated{margin:0;padding:.75rem;border:1px solid var(--mpr-color-border,#2c2f36);border-radius:var(--mpr-radius-control,6px)}";

  function ensureAuthFormStyles(documentObject) {
    if (
      !documentObject ||
      !documentObject.head ||
      typeof documentObject.createElement !== "function" ||
      documentObject.getElementById(AUTH_FORM_STYLE_ID)
    ) {
      return;
    }
    var styleElement = documentObject.createElement("style");
    styleElement.id = AUTH_FORM_STYLE_ID;
    styleElement.type = "text/css";
    styleElement.appendChild(documentObject.createTextNode(AUTH_FORM_STYLE_MARKUP));
    documentObject.head.appendChild(styleElement);
  }

  function createAuthComponentError(code, message) {
    /** @type {MprUiError} */
    var componentError = new Error(message);
    componentError.code = code;
    return componentError;
  }

  /**
   * @param {Element} hostElement
   * @returns {readonly AccountIdentityOption[]}
   */
  function parseAccountIdentityOptions(hostElement) {
    var rawValue = hostElement.getAttribute(ACCOUNT_PANEL_IDENTITIES_ATTRIBUTE);
    if (typeof rawValue !== "string" || rawValue.trim() === "") {
      throw createAuthComponentError(
        "mpr-ui.account_panel.identities_required",
        "unlink requires at least one linked identity",
      );
    }
    var parsedValue;
    try {
      parsedValue = JSON.parse(rawValue);
    } catch (_error) {
      throw createAuthComponentError(
        "mpr-ui.account_panel.identities_invalid",
        "identities must be valid JSON",
      );
    }
    if (!Array.isArray(parsedValue) || parsedValue.length === 0) {
      throw createAuthComponentError(
        "mpr-ui.account_panel.identities_required",
        "unlink requires at least one linked identity",
      );
    }
    var seenIdentityKeys = Object.create(null);
    return Object.freeze(
      parsedValue.map(function normalizeAccountIdentity(identity) {
        if (!identity || typeof identity !== "object" || Array.isArray(identity)) {
          throw createAuthComponentError(
            "mpr-ui.account_panel.identity_invalid",
            "each linked identity must be an object",
          );
        }
        var identityKeys = Object.keys(identity).sort();
        if (identityKeys.join(",") !== "label,provider,providerId") {
          throw createAuthComponentError(
            "mpr-ui.account_panel.identity_invalid",
            "each linked identity requires provider, providerId, and label",
          );
        }
        var provider = typeof identity.provider === "string" ? identity.provider.trim() : "";
        var providerId =
          typeof identity.providerId === "string" ? identity.providerId.trim() : "";
        var label = typeof identity.label === "string" ? identity.label.trim() : "";
        if (
          ACCOUNT_IDENTITY_PROVIDERS.indexOf(provider) === -1 ||
          !providerId ||
          !label
        ) {
          throw createAuthComponentError(
            "mpr-ui.account_panel.identity_invalid",
            "linked identities require a supported provider, providerId, and label",
          );
        }
        var identityKey = provider + "\u0000" + providerId;
        if (seenIdentityKeys[identityKey]) {
          throw createAuthComponentError(
            "mpr-ui.account_panel.identity_duplicate",
            "linked identities must be unique",
          );
        }
        seenIdentityKeys[identityKey] = true;
        return Object.freeze({
          provider: provider,
          providerId: providerId,
          label: label,
        });
      }),
    );
  }

  function accountPanelFormDefinition(action, identityOptions) {
    var definition = ACCOUNT_PANEL_FORM_DEFINITIONS[action];
    if (action !== "unlink") {
      return definition;
    }
    return Object.freeze({
      title: definition.title,
      submit: definition.submit,
      fields: Object.freeze([
        Object.freeze({
          key: "identity",
          label: AUTH_FORM_LABELS.identity,
          type: "select",
          autocomplete: "off",
          options: Object.freeze(
            identityOptions.map(function createIdentitySelectOption(identity, index) {
              return Object.freeze({ value: String(index), label: identity.label });
            }),
          ),
        }),
      ]),
    });
  }

  function readAccountPanelRequest(action, definition, inputs, identityOptions) {
    if (action !== "unlink") {
      return readAuthFormRequest(definition, inputs);
    }
    var selectedIdentityValue = inputs.identity.value;
    var selectedIdentityIndex = Number(selectedIdentityValue);
    var selectedIdentity = identityOptions[selectedIdentityIndex];
    if (
      typeof selectedIdentityValue !== "string" ||
      String(selectedIdentityIndex) !== selectedIdentityValue ||
      !Number.isInteger(selectedIdentityIndex) ||
      !selectedIdentity
    ) {
      throw createAuthComponentError(
        "mpr-ui.account_panel.identity_selection_invalid",
        "a configured linked identity must be selected",
      );
    }
    return {
      provider: selectedIdentity.provider,
      providerId: selectedIdentity.providerId,
    };
  }

  function resolveControllerFromAuthSurface(authSurface) {
    if (!authSurface || typeof authSurface !== "object") {
      return null;
    }
    if (
      typeof authSurface.performPasswordAction === "function" &&
      typeof authSurface.performAccountAction === "function"
    ) {
      return authSurface;
    }
    if (
      authSurface.__headerController &&
      typeof authSurface.__headerController.getAuthController === "function"
    ) {
      return authSurface.__headerController.getAuthController();
    }
    return authSurface.__authController || null;
  }

  function resolveAuthComponentController(hostElement) {
    if (hostElement.__authControllerOverride) {
      return hostElement.__authControllerOverride;
    }
    var targetSelector = hostElement.getAttribute(AUTH_COMPONENT_TARGET_ATTRIBUTE);
    if (typeof targetSelector === "string" && targetSelector.trim()) {
      var documentObject =
        hostElement.ownerDocument || global.document || null;
      var targetElement;
      try {
        targetElement = documentObject.querySelector(targetSelector.trim());
      } catch (_error) {
        throw createAuthComponentError(
          "mpr-ui.auth_component.target_invalid",
          "auth-target must be a valid selector",
        );
      }
      var selectedController = resolveControllerFromAuthSurface(targetElement);
      if (!selectedController) {
        throw createAuthComponentError(
          "mpr-ui.auth_component.controller_missing",
          "auth-target does not own an auth controller",
        );
      }
      return selectedController;
    }
    var ancestor = hostElement.parentNode;
    while (ancestor) {
      var ancestorController = resolveControllerFromAuthSurface(ancestor);
      if (ancestorController) {
        return ancestorController;
      }
      ancestor = ancestor.parentNode;
    }
    throw createAuthComponentError(
      "mpr-ui.auth_component.target_required",
      "auth-target or an owning auth surface is required",
    );
  }

  function requireAuthComponentOptions(hostElement, requiredSection) {
    var componentOptions = parseAuthConfigAttribute(hostElement);
    if (!componentOptions[requiredSection]) {
      throw createAuthComponentError(
        "mpr-ui.auth_component.config_required",
        "auth." + requiredSection + " configuration is required",
      );
    }
    var authController = resolveAuthComponentController(hostElement);
    if (
      !authController ||
      !authController.state ||
      JSON.stringify(authController.state.options) !== JSON.stringify(componentOptions)
    ) {
      throw createAuthComponentError(
        "mpr-ui.auth_component.config_mismatch",
        "The component auth configuration must match its owning controller",
      );
    }
    return { options: componentOptions, controller: authController };
  }

  function createAuthFormField(documentObject, fieldDefinition, disabled) {
    var fieldElement = documentObject.createElement("label");
    var labelElement = documentObject.createElement("span");
    var inputElement = documentObject.createElement(
      fieldDefinition.type === "select" ? "select" : "input",
    );
    fieldElement.className = "mpr-auth-form__field";
    labelElement.textContent = fieldDefinition.label;
    inputElement.className = "mpr-auth-form__input";
    inputElement.name = fieldDefinition.key;
    inputElement.autocomplete = fieldDefinition.autocomplete;
    inputElement.required = true;
    inputElement.disabled = disabled;
    if (fieldDefinition.type === "select") {
      fieldDefinition.options.forEach(function appendAuthFieldOption(optionDefinition) {
        var optionElement = documentObject.createElement("option");
        optionElement.value = optionDefinition.value;
        optionElement.textContent = optionDefinition.label;
        inputElement.appendChild(optionElement);
      });
      inputElement.value = fieldDefinition.options[0].value;
    } else {
      inputElement.type = fieldDefinition.type;
    }
    fieldElement.appendChild(labelElement);
    fieldElement.appendChild(inputElement);
    return { element: fieldElement, input: inputElement };
  }

  function createAuthForm(documentObject, definition, disabled, includeSubmitButton) {
    var formElement = documentObject.createElement("form");
    var titleElement = documentObject.createElement("h2");
    var submitButton = null;
    var statusElement = documentObject.createElement("p");
    var inputs = {};
    formElement.className = "mpr-auth-form";
    formElement.setAttribute("data-status", "ready");
    titleElement.className = "mpr-auth-form__title";
    titleElement.textContent = definition.title;
    formElement.appendChild(titleElement);
    definition.fields.forEach(function appendAuthField(fieldDefinition) {
      var field = createAuthFormField(documentObject, fieldDefinition, disabled);
      inputs[fieldDefinition.key] = field.input;
      formElement.appendChild(field.element);
    });
    if (includeSubmitButton !== false) {
      submitButton = documentObject.createElement("button");
      submitButton.className = "mpr-auth-form__submit";
      submitButton.type = "submit";
      submitButton.disabled = disabled;
      submitButton.textContent = definition.submit;
      formElement.appendChild(submitButton);
    }
    statusElement.className = "mpr-auth-form__status";
    statusElement.setAttribute("role", "status");
    statusElement.setAttribute("aria-live", "polite");
    statusElement.textContent = AUTH_FORM_LABELS.ready;
    formElement.appendChild(statusElement);
    return {
      form: formElement,
      inputs: inputs,
      submitButton: submitButton,
      statusElement: statusElement,
    };
  }

  var challengeTokenForms = new WeakMap();

  function applyChallengeTokenFragment(hostElement, inputs) {
    var parameterName = hostElement.getAttribute(
      CHALLENGE_TOKEN_FRAGMENT_PARAMETER_ATTRIBUTE,
    );
    var context = JSON.stringify([
      hostElement.getAttribute(PASSWORD_AUTH_MODE_ATTRIBUTE),
      hostElement.getAttribute(ACCOUNT_PANEL_ACTION_ATTRIBUTE),
      hostElement.getAttribute(AUTH_COMPONENT_TARGET_ATTRIBUTE),
      hostElement.getAttribute(AUTH_CONFIG_ATTRIBUTE),
      parameterName,
    ]);
    var previousForm = challengeTokenForms.get(hostElement);
    challengeTokenForms.delete(hostElement);
    if (parameterName === null) {
      return;
    }
    if (!inputs.token || !/^[A-Za-z][A-Za-z0-9_-]*$/.test(parameterName)) {
      throw createAuthComponentError(
        "mpr-ui.auth_component.token_fragment_parameter_invalid",
        "A token form and valid fragment parameter are required",
      );
    }
    var documentObject = hostElement.ownerDocument || global.document;
    var windowObject = documentObject && documentObject.defaultView;
    if (!windowObject || !windowObject.location) {
      return;
    }
    var fragmentValues = new URLSearchParams(
      String(windowObject.location.hash || "").replace(/^#/, ""),
    );
    var challengeToken = fragmentValues.get(parameterName);
    if (!challengeToken) {
      if (previousForm && previousForm.context === context) {
        inputs.token.value = previousForm.input.value;
        challengeTokenForms.set(hostElement, { context: context, input: inputs.token });
      }
      return;
    }
    inputs.token.value = challengeToken;
    challengeTokenForms.set(hostElement, { context: context, input: inputs.token });
    fragmentValues.delete(parameterName);
    var nextURL = new URL(windowObject.location.href);
    nextURL.hash = fragmentValues.toString();
    windowObject.history.replaceState(
      windowObject.history.state,
      "",
      nextURL.href,
    );
  }

  function readAuthFormRequest(definition, inputs) {
    var request = {};
    definition.fields.forEach(function readAuthField(fieldDefinition) {
      request[fieldDefinition.key] = inputs[fieldDefinition.key].value;
    });
    return request;
  }

  function clearAuthFormSecrets(definition, inputs) {
    definition.fields.forEach(function clearSecretField(fieldDefinition) {
      if (fieldDefinition.secret) {
        inputs[fieldDefinition.key].value = "";
      }
    });
  }

  function setAuthFormStatus(formElements, status, message, disabled) {
    formElements.form.setAttribute("data-status", status);
    formElements.statusElement.textContent = message;
    if (formElements.submitButton) {
      formElements.submitButton.disabled = disabled;
    }
    Object.keys(formElements.inputs).forEach(function updateAuthInput(key) {
      formElements.inputs[key].disabled = disabled;
    });
  }

  function renderAuthComponentError(hostElement, attributeName, error) {
    clearNodeContents(hostElement);
    var documentObject = hostElement.ownerDocument || global.document;
    var errorElement = documentObject.createElement("p");
    var errorCode =
      error && error.code ? error.code : "mpr-ui.auth_component.config_invalid";
    errorElement.className = "mpr-auth-form__unauthenticated";
    errorElement.setAttribute("role", "alert");
    errorElement.textContent = AUTH_FORM_LABELS.failure;
    hostElement.setAttribute(attributeName, errorCode);
    hostElement.appendChild(errorElement);
    dispatchEvent(hostElement, "mpr-ui:auth:error", { code: errorCode });
  }

  function definePasswordAuthElement(registry) {
    registry.define("mpr-password-auth", function setupPasswordAuthElement(Base) {
      return class MprPasswordAuthElement extends Base {
        constructor() {
          super();
          this.__passwordSubmitHandler = null;
          this.__passwordForm = null;
          this.__passwordAttempt = 0;
          this.__passwordNavigationCleanup = null;
        }
        static get observedAttributes() {
          return [
            AUTH_CONFIG_ATTRIBUTE,
            PASSWORD_AUTH_MODE_ATTRIBUTE,
            AUTH_COMPONENT_TARGET_ATTRIBUTE,
            CHALLENGE_TOKEN_FRAGMENT_PARAMETER_ATTRIBUTE,
            "disabled",
          ];
        }
        render() {
          this.__renderPasswordAuth();
        }
        update() {
          this.__renderPasswordAuth();
        }
        destroy() {
          this.__passwordAttempt += 1;
          challengeTokenForms.delete(this);
          if (this.__passwordNavigationCleanup) {
            this.__passwordNavigationCleanup();
            this.__passwordNavigationCleanup = null;
          }
          if (this.__passwordForm && this.__passwordSubmitHandler) {
            this.__passwordForm.removeEventListener(
              "submit",
              this.__passwordSubmitHandler,
            );
          }
          this.__passwordForm = null;
          this.__passwordSubmitHandler = null;
          clearNodeContents(this);
        }
        __navigatePasswordAuth(mode) {
          var emailInput = this.__passwordForm.elements.namedItem("email");
          var email = emailInput ? emailInput.value : "";
          if (this.hasAttribute(CHALLENGE_TOKEN_FRAGMENT_PARAMETER_ATTRIBUTE)) {
            this.removeAttribute(CHALLENGE_TOKEN_FRAGMENT_PARAMETER_ATTRIBUTE);
          }
          this.setAttribute(PASSWORD_AUTH_MODE_ATTRIBUTE, mode);
          var nextEmailInput = this.__passwordForm.elements.namedItem("email");
          nextEmailInput.value = email;
          nextEmailInput.focus();
          dispatchEvent(this, PASSWORD_AUTH_MODE_EVENT, { mode: mode });
        }
        __renderPasswordAuth() {
          if (!this.__mprConnected) {
            return;
          }
          this.__passwordAttempt += 1;
          if (this.__passwordNavigationCleanup) {
            this.__passwordNavigationCleanup();
            this.__passwordNavigationCleanup = null;
          }
          if (this.__passwordForm && this.__passwordSubmitHandler) {
            this.__passwordForm.removeEventListener(
              "submit",
              this.__passwordSubmitHandler,
            );
          }
          clearNodeContents(this);
          var mode = this.getAttribute(PASSWORD_AUTH_MODE_ATTRIBUTE);
          if (PASSWORD_AUTH_MODES.indexOf(mode) === -1) {
            renderAuthComponentError(
              this,
              "data-mpr-password-auth-error",
              createAuthComponentError(
                "mpr-ui.password_auth.mode_invalid",
                "A supported password auth mode is required",
              ),
            );
            return;
          }
          var authContext;
          try {
            authContext = requireAuthComponentOptions(this, "password");
          } catch (error) {
            renderAuthComponentError(this, "data-mpr-password-auth-error", error);
            return;
          }
          var documentObject = this.ownerDocument || global.document;
          ensureAuthFormStyles(documentObject);
          var definition = PASSWORD_AUTH_FORM_DEFINITIONS[mode];
          var hostDisabled = this.hasAttribute("disabled");
          var formElements = createAuthForm(documentObject, definition, hostDisabled);
          try {
            applyChallengeTokenFragment(this, formElements.inputs);
          } catch (error) {
            renderAuthComponentError(this, "data-mpr-password-auth-error", error);
            return;
          }
          var passwordElement = this;
          var navigationDefinition = {
            login: { mode: "reset-start", label: AUTH_FORM_LABELS.forgotPassword },
            "reset-start": { mode: "login", label: AUTH_FORM_LABELS.backToSignIn },
            "reset-complete": { mode: "reset-start", label: AUTH_FORM_LABELS.newResetLink },
          }[mode];
          var navigationButton = null;
          if (navigationDefinition) {
            navigationButton = documentObject.createElement("button");
            navigationButton.type = "button";
            navigationButton.className = "mpr-auth-form__navigation";
            navigationButton.textContent = navigationDefinition.label;
            navigationButton.disabled = hostDisabled;
            navigationButton.hidden = mode === "reset-complete";
            function handlePasswordNavigation() {
              passwordElement.__navigatePasswordAuth(navigationDefinition.mode);
            }
            navigationButton.addEventListener("click", handlePasswordNavigation);
            this.__passwordNavigationCleanup = function cleanupPasswordNavigation() {
              navigationButton.removeEventListener("click", handlePasswordNavigation);
            };
            formElements.form.appendChild(navigationButton);
          }
          var currentAttempt = this.__passwordAttempt;
          this.__passwordSubmitHandler = function handlePasswordSubmit(event) {
            event.preventDefault();
            if (hostDisabled) {
              return;
            }
            if (navigationButton) {
              navigationButton.disabled = true;
            }
            var request = readAuthFormRequest(definition, formElements.inputs);
            clearAuthFormSecrets(definition, formElements.inputs);
            setAuthFormStatus(
              formElements,
              "loading",
              AUTH_FORM_LABELS.loading,
              true,
            );
            passwordElement.setAttribute("data-mpr-password-auth-status", "loading");
            dispatchEvent(passwordElement, "mpr-ui:password-auth:submit", { mode: mode });
            dispatchEvent(passwordElement, "mpr-ui:password-auth:status", {
              mode: mode,
              status: "loading",
            });
            Promise.resolve(
              authContext.controller.performPasswordAction(mode, request),
            ).then(
              function handlePasswordSuccess(result) {
                if (currentAttempt !== passwordElement.__passwordAttempt) {
                  return;
                }
                setAuthFormStatus(
                  formElements,
                  "success",
                  mode === "reset-start" ? AUTH_FORM_LABELS.resetStartSuccess :
                    mode === "reset-complete" ? AUTH_FORM_LABELS.resetCompleteSuccess : AUTH_FORM_LABELS.success,
                  hostDisabled || mode === "reset-start" || mode === "reset-complete",
                );
                if (navigationButton) {
                  navigationButton.disabled = hostDisabled;
                }
                passwordElement.removeAttribute("data-mpr-password-auth-error");
                passwordElement.setAttribute("data-mpr-password-auth-status", "success");
                dispatchEvent(passwordElement, "mpr-ui:password-auth:status", {
                  mode: mode,
                  status: "success",
                });
              },
              function handlePasswordFailure(error) {
                if (currentAttempt !== passwordElement.__passwordAttempt) {
                  return;
                }
                var errorCode =
                  error && error.code
                    ? error.code
                    : "mpr-ui.password_auth.action_failed";
                setAuthFormStatus(
                  formElements,
                  "error",
                  AUTH_FORM_LABELS.failure,
                  hostDisabled,
                );
                if (navigationButton) {
                  navigationButton.disabled = hostDisabled;
                  navigationButton.hidden = false;
                }
                passwordElement.setAttribute("data-mpr-password-auth-error", errorCode);
                passwordElement.setAttribute("data-mpr-password-auth-status", "error");
                dispatchEvent(passwordElement, "mpr-ui:password-auth:status", {
                  mode: mode,
                  status: "error",
                  code: errorCode,
                });
              },
            );
          };
          formElements.form.addEventListener("submit", this.__passwordSubmitHandler);
          this.__passwordForm = formElements.form;
          this.removeAttribute("data-mpr-password-auth-error");
          this.setAttribute("data-mpr-password-auth-status", "ready");
          this.appendChild(formElements.form);
        }
      };
    });
  }

  function defineAccountPanelElement(registry) {
    registry.define("mpr-account-panel", function setupAccountPanelElement(Base) {
      return class MprAccountPanelElement extends Base {
        constructor() {
          super();
          this.__accountSubmitHandler = null;
          this.__accountForm = null;
          this.__accountProviderActionCleanup = null;
          this.__accountAuthTarget = null;
          this.__accountAttempt = 0;
          this.__accountAuthEventHandler = this.__handleAccountAuthEvent.bind(this);
        }
        static get observedAttributes() {
          return [
            AUTH_CONFIG_ATTRIBUTE,
            ACCOUNT_PANEL_ACTION_ATTRIBUTE,
            AUTH_COMPONENT_TARGET_ATTRIBUTE,
            ACCOUNT_PANEL_IDENTITIES_ATTRIBUTE,
            CHALLENGE_TOKEN_FRAGMENT_PARAMETER_ATTRIBUTE,
            "disabled",
          ];
        }
        render() {
          this.__renderAccountPanel();
        }
        update() {
          this.__renderAccountPanel();
        }
        destroy() {
          this.__accountAttempt += 1;
          challengeTokenForms.delete(this);
          this.__detachAccountAuthEvents();
          if (this.__accountForm && this.__accountSubmitHandler) {
            this.__accountForm.removeEventListener("submit", this.__accountSubmitHandler);
          }
          if (this.__accountProviderActionCleanup) {
            this.__accountProviderActionCleanup();
          }
          this.__accountForm = null;
          this.__accountSubmitHandler = null;
          this.__accountProviderActionCleanup = null;
          clearNodeContents(this);
        }
        __handleAccountAuthEvent() {
          this.__renderAccountPanel();
        }
        __detachAccountAuthEvents() {
          if (!this.__accountAuthTarget) {
            return;
          }
          ["mpr-ui:auth:authenticated", "mpr-ui:auth:unauthenticated"].forEach(
            (eventName) => {
              this.__accountAuthTarget.removeEventListener(
                eventName,
                this.__accountAuthEventHandler,
              );
            },
          );
          this.__accountAuthTarget = null;
        }
        __attachAccountAuthEvents(authController) {
          this.__detachAccountAuthEvents();
          var authTarget = authController.host;
          if (!authTarget || typeof authTarget.addEventListener !== "function") {
            return;
          }
          this.__accountAuthTarget = authTarget;
          ["mpr-ui:auth:authenticated", "mpr-ui:auth:unauthenticated"].forEach(
            (eventName) => {
              authTarget.addEventListener(eventName, this.__accountAuthEventHandler);
            },
          );
        }
        __renderAccountPanel() {
          if (!this.__mprConnected) {
            return;
          }
          this.__accountAttempt += 1;
          if (this.__accountForm && this.__accountSubmitHandler) {
            this.__accountForm.removeEventListener("submit", this.__accountSubmitHandler);
          }
          if (this.__accountProviderActionCleanup) {
            this.__accountProviderActionCleanup();
            this.__accountProviderActionCleanup = null;
          }
          this.__accountForm = null;
          this.__accountSubmitHandler = null;
          clearNodeContents(this);
          var action = this.getAttribute(ACCOUNT_PANEL_ACTION_ATTRIBUTE);
          if (ACCOUNT_PANEL_ACTIONS.indexOf(action) === -1) {
            renderAuthComponentError(
              this,
              "data-mpr-account-panel-error",
              createAuthComponentError(
                "mpr-ui.account_panel.action_invalid",
                "A supported account action is required",
              ),
            );
            return;
          }
          var authContext;
          var identityOptions = Object.freeze([]);
          try {
            authContext = requireAuthComponentOptions(this, "account");
          } catch (error) {
            renderAuthComponentError(this, "data-mpr-account-panel-error", error);
            return;
          }
          this.__attachAccountAuthEvents(authContext.controller);
          var documentObject = this.ownerDocument || global.document;
          ensureAuthFormStyles(documentObject);
          if (
            authContext.controller.state.status !== AUTH_CONTROLLER_STATUS.AUTHENTICATED ||
            !authContext.controller.state.profile
          ) {
            var unauthenticatedElement = documentObject.createElement("p");
            unauthenticatedElement.className = "mpr-auth-form__unauthenticated";
            unauthenticatedElement.textContent = AUTH_FORM_LABELS.unauthenticated;
            this.setAttribute("data-mpr-account-panel-status", "unauthenticated");
            this.appendChild(unauthenticatedElement);
            return;
          }
          if (action === "unlink") {
            try {
              identityOptions = parseAccountIdentityOptions(this);
            } catch (error) {
              renderAuthComponentError(this, "data-mpr-account-panel-error", error);
              return;
            }
          }
          var definition = accountPanelFormDefinition(action, identityOptions);
          var hostDisabled = this.hasAttribute("disabled");
          var formElements = createAuthForm(
            documentObject,
            definition,
            hostDisabled,
            action !== "google-link",
          );
          try {
            applyChallengeTokenFragment(this, formElements.inputs);
          } catch (error) {
            renderAuthComponentError(this, "data-mpr-account-panel-error", error);
            return;
          }
          var accountElement = this;
          var currentAttempt = this.__accountAttempt;
          function handleAccountSuccess(result) {
            if (currentAttempt !== accountElement.__accountAttempt) {
              return;
            }
            setAuthFormStatus(
              formElements,
              "success",
              AUTH_FORM_LABELS.success,
              hostDisabled,
            );
            accountElement.removeAttribute("data-mpr-account-panel-error");
            accountElement.setAttribute("data-mpr-account-panel-status", "success");
            dispatchEvent(accountElement, "mpr-ui:account-panel:status", {
              action: action,
              status: "success",
            });
          }

          function handleAccountFailure(error) {
            if (currentAttempt !== accountElement.__accountAttempt) {
              return;
            }
            var errorCode =
              error && error.code
                ? error.code
                : "mpr-ui.account_panel.action_failed";
            setAuthFormStatus(
              formElements,
              "error",
              AUTH_FORM_LABELS.failure,
              hostDisabled,
            );
            accountElement.setAttribute("data-mpr-account-panel-error", errorCode);
            accountElement.setAttribute("data-mpr-account-panel-status", "error");
            dispatchEvent(accountElement, "mpr-ui:account-panel:status", {
              action: action,
              status: "error",
              code: errorCode,
            });
          }

          if (action === "google-link") {
            var googleActionElement = documentObject.createElement("div");
            googleActionElement.className = "mpr-auth-form__google-action";
            googleActionElement.setAttribute(
              "aria-disabled",
              hostDisabled ? "true" : "false",
            );
            if (hostDisabled) {
              googleActionElement.setAttribute("inert", "");
            }
            formElements.form.insertBefore(
              googleActionElement,
              formElements.statusElement,
            );
            var googleProviderAction = mountGoogleProviderAction(
              accountElement,
              googleActionElement,
              {
                prepareGoogleNonce: authContext.controller.prepareGoogleNonce,
                handleCredential: function handleGoogleLinkCredential(
                  credentialResponse,
                  nonceToken,
                ) {
                  return authContext.controller.startGoogleLink(
                    credentialResponse,
                    nonceToken,
                  );
                },
              },
              {
                googleButtonOptions: {
                  theme: LOGIN_BUTTON_THEME.OUTLINE,
                  size: LOGIN_BUTTON_SIZE.MEDIUM,
                  text: GOOGLE_SIGNIN_TEXT_OPTION.CONTINUE_WITH,
                  shape: LOGIN_BUTTON_SHAPE.RECTANGULAR,
                },
                handleStart: function handleGoogleLinkStart() {
                  if (currentAttempt !== accountElement.__accountAttempt) {
                    return;
                  }
                  setAuthFormStatus(
                    formElements,
                    "loading",
                    AUTH_FORM_LABELS.loading,
                    true,
                  );
                  accountElement.setAttribute(
                    "data-mpr-account-panel-status",
                    "loading",
                  );
                  dispatchEvent(accountElement, "mpr-ui:account-panel:submit", {
                    action: action,
                  });
                },
                handleSuccess: function handleGoogleLinkSuccess(
                  _providerId,
                  result,
                ) {
                  handleAccountSuccess(result);
                },
                handleError: function handleGoogleLinkFailure(
                  _providerId,
                  error,
                ) {
                  handleAccountFailure(error);
                },
              },
              function preserveAccountPanelStatus() {
                return null;
              },
            );
            this.__accountProviderActionCleanup = googleProviderAction.cleanup;
            this.__accountForm = formElements.form;
            this.removeAttribute("data-mpr-account-panel-error");
            this.setAttribute("data-mpr-account-panel-status", "ready");
            this.appendChild(formElements.form);
            return;
          }
          this.__accountSubmitHandler = function handleAccountSubmit(event) {
            event.preventDefault();
            if (hostDisabled) {
              return;
            }
            var request;
            try {
              request = readAccountPanelRequest(
                action,
                definition,
                formElements.inputs,
                identityOptions,
              );
            } catch (error) {
              var selectionErrorCode =
                error && error.code
                  ? error.code
                  : "mpr-ui.account_panel.identity_selection_invalid";
              setAuthFormStatus(
                formElements,
                "error",
                AUTH_FORM_LABELS.failure,
                hostDisabled,
              );
              accountElement.setAttribute(
                "data-mpr-account-panel-error",
                selectionErrorCode,
              );
              accountElement.setAttribute("data-mpr-account-panel-status", "error");
              dispatchEvent(accountElement, "mpr-ui:account-panel:status", {
                action: action,
                status: "error",
                code: selectionErrorCode,
              });
              return;
            }
            clearAuthFormSecrets(definition, formElements.inputs);
            setAuthFormStatus(
              formElements,
              "loading",
              AUTH_FORM_LABELS.loading,
              true,
            );
            accountElement.setAttribute("data-mpr-account-panel-status", "loading");
            dispatchEvent(accountElement, "mpr-ui:account-panel:submit", {
              action: action,
            });
            Promise.resolve(
              authContext.controller.performAccountAction(action, request),
            ).then(handleAccountSuccess, handleAccountFailure);
          };
          formElements.form.addEventListener("submit", this.__accountSubmitHandler);
          this.__accountForm = formElements.form;
          this.removeAttribute("data-mpr-account-panel-error");
          this.setAttribute("data-mpr-account-panel-status", "ready");
          this.appendChild(formElements.form);
        }
      };
    });
  }

  function defineLoginButtonElement(registry) {
    registry.define("mpr-login-button", function setupLoginElement(Base) {
      return class MprLoginButtonElement extends Base {
        constructor() {
          super();
          this.__authController = null;
          this.__providerActionsCleanup = null;
          this.__providerActionsHost = null;
        }
        static get observedAttributes() {
          return LOGIN_BUTTON_ATTRIBUTE_NAMES;
        }
        render() {
          this.__renderLoginButton();
        }
        update() {
          this.__renderLoginButton();
        }
        destroy() {
          if (this.__providerActionsCleanup) {
            this.__providerActionsCleanup();
            this.__providerActionsCleanup = null;
          }
          if (this.__authController && typeof this.__authController.destroy === "function") {
            this.__authController.destroy();
          }
          this.__authController = null;
          this.__providerActionsHost = null;
        }
        __renderLoginButton() {
          if (!this.__mprConnected) {
            return;
          }
          prepareLoginButtonHost(this);
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureLoginButtonStyles(documentObject);
          var container = ensureLoginButtonContainer(this);
          if (!container) {
            return;
          }
          this.__providerActionsHost = container;
          var authOptions;
          try {
            authOptions = buildLoginAuthOptionsFromAttributes(this);
          } catch (error) {
            if (this.__providerActionsCleanup) {
              this.__providerActionsCleanup();
              this.__providerActionsCleanup = null;
            }
            if (
              this.__authController &&
              typeof this.__authController.destroy === "function"
            ) {
              this.__authController.destroy();
            }
            this.__authController = null;
            clearNodeContents(container);
            this.setAttribute(
              "data-mpr-auth-error",
              error && error.code
                ? error.code
                : "mpr-ui.auth.config_invalid",
            );
            dispatchEvent(this, "mpr-login:error", {
              code:
                error && error.code
                  ? error.code
                  : "mpr-ui.auth.config_invalid",
              message: error && error.message ? error.message : String(error),
            });
            return;
          }
          var tenantId = normalizeTenantId(authOptions.tenantId);
          var currentTenantId =
            this.__authController &&
            this.__authController.state &&
            this.__authController.state.options
              ? normalizeTenantId(this.__authController.state.options.tenantId)
              : null;
          if (currentTenantId && currentTenantId !== tenantId) {
            throw createAuthTenantIdChangeError(currentTenantId, tenantId);
          }
          if (this.__authController && typeof this.__authController.updateOptions === "function") {
            this.__authController.updateOptions(authOptions);
          } else if (!this.__authController) {
            this.__authController = createAuthHeader(this, authOptions);
          }
          if (this.__providerActionsCleanup) {
            this.__providerActionsCleanup();
            this.__providerActionsCleanup = null;
          }
          var loginElement = this;
          var buttonOptions = buildLoginButtonDisplayOptions(loginElement);
          var buttonLabel = normalizeGoogleSignInButtonLabel(
            buttonOptions.text,
            AUTH_ACTION_LABELS.google,
          );
          applyLoginButtonPresentation(container, buttonOptions);
          var providerActions = mountAuthProviderActions(
            loginElement,
            container,
            authOptions,
            this.__authController,
            {
              googleLabel: buttonLabel,
              googleButtonOptions: buttonOptions,
              handleError: function handleLoginProviderError(providerId, error) {
                loginElement.setAttribute(
                  "data-mpr-auth-error",
                  error && error.code
                    ? error.code
                    : "mpr-ui.auth.provider_attempt_failed",
                );
                dispatchEvent(loginElement, "mpr-login:error", {
                  code:
                    error && error.code
                      ? error.code
                      : "mpr-ui.auth.provider_attempt_failed",
                  provider: providerId,
                  message: error && error.message ? error.message : String(error),
                });
              },
            },
          );
          this.removeAttribute("data-mpr-auth-error");
          this.setAttribute(
            "data-mpr-auth-providers",
            enabledAuthProviderIds(authOptions).join(","),
          );
          this.__providerActionsCleanup = function cleanupLoginProviderActions() {
            providerActions.cleanup();
          };
        }
      };
    });
  }

  function defineAuthProviderChooserElement(registry) {
    registry.define(
      "mpr-auth-provider-chooser",
      function setupAuthProviderChooserElement(Base) {
        return class MprAuthProviderChooserElement extends Base {
          constructor() {
            super();
            this.__authProviderCleanupHandlers = [];
            this.__emailExpanded = false;
            this.__emailPanelId = createAuthProviderEmailPanelId();
          }
          static get observedAttributes() {
            return AUTH_PROVIDER_CHOOSER_ATTRIBUTE_NAMES;
          }
          render() {
            this.__renderAuthProviderChooser();
          }
          update() {
            this.__renderAuthProviderChooser();
          }
          destroy() {
            this.__cleanupAuthProviderChooser();
            clearNodeContents(this);
            clearAuthProviderChooserError(this);
            this.removeAttribute(AUTH_PROVIDER_CHOOSER_SELECTED_ATTRIBUTE);
            this.removeAttribute(AUTH_PROVIDER_CHOOSER_EMAIL_EXPANDED_ATTRIBUTE);
          }
          __cleanupAuthProviderChooser() {
            this.__authProviderCleanupHandlers.forEach(function runCleanup(cleanup) {
              cleanup();
            });
            this.__authProviderCleanupHandlers = [];
          }
          __renderAuthProviderChooser() {
            if (!this.__mprConnected) {
              return;
            }
            this.__cleanupAuthProviderChooser();
            clearNodeContents(this);
            try {
              var options = buildAuthProviderChooserOptionsFromAttributes(
                /** @type {{ getAttribute: (attributeName: string) => (string|null) }} */ (
                  /** @type {unknown} */ (this)
                ),
              );
              var selectedProvider = this.getAttribute(
                AUTH_PROVIDER_CHOOSER_SELECTED_ATTRIBUTE,
              );
              if (
                selectedProvider &&
                options.providers.indexOf(selectedProvider) === -1
              ) {
                this.removeAttribute(AUTH_PROVIDER_CHOOSER_SELECTED_ATTRIBUTE);
                selectedProvider = "";
              }
              if (this.__emailExpanded && selectedProvider !== AUTH_PROVIDER_IDS.EMAIL) {
                this.__emailExpanded = false;
              }
              clearAuthProviderChooserError(this);
              this.setAttribute(
                "data-mpr-auth-provider-variant",
                options.variant,
              );
              this.setAttribute(
                "data-mpr-auth-provider-layout",
                options.providers.length === 1 ? "direct" : "chooser",
              );
              this.setAttribute(
                AUTH_PROVIDER_CHOOSER_EMAIL_EXPANDED_ATTRIBUTE,
                this.__emailExpanded ? "true" : "false",
              );
              this.__mountAuthProviderChooser(options);
            } catch (error) {
              this.__emailExpanded = false;
              this.removeAttribute("data-mpr-auth-provider-variant");
              this.removeAttribute("data-mpr-auth-provider-layout");
              this.removeAttribute(AUTH_PROVIDER_CHOOSER_SELECTED_ATTRIBUTE);
              this.removeAttribute(AUTH_PROVIDER_CHOOSER_EMAIL_EXPANDED_ATTRIBUTE);
              setAuthProviderChooserError(this, error);
            }
          }
          __mountAuthProviderChooser(options) {
            var documentObject =
              this.ownerDocument ||
              global.document ||
              (global.window && global.window.document) ||
              null;
            ensureAuthProviderChooserStyles(documentObject);
            var rootElement = createAuthProviderElement(this, "div");
            var actionsElement = createAuthProviderElement(this, "div");
            var chooserElement = this;
            setAuthProviderElementClass(rootElement, AUTH_PROVIDER_CHOOSER_ROOT_CLASS);
            setAuthProviderElementClass(
              actionsElement,
              AUTH_PROVIDER_CHOOSER_ROOT_CLASS + "__actions",
            );
            if (typeof rootElement.setAttribute === "function") {
              rootElement.setAttribute("data-mpr-auth-provider-chooser", "root");
              rootElement.setAttribute(
                "data-mpr-auth-provider-variant",
                options.variant,
              );
              rootElement.setAttribute("role", "group");
              rootElement.setAttribute(
                "aria-label",
                AUTH_PROVIDER_CHOOSER_LABELS.group,
              );
            }
            if (typeof actionsElement.setAttribute === "function") {
              actionsElement.setAttribute(
                "data-mpr-auth-provider-chooser",
                "actions",
              );
            }
            options.providers.forEach(function mountProvider(providerId) {
              function handleProviderClick(event) {
                chooserElement.__handleAuthProviderSelection(providerId, event);
              }
              var actionButton = createAuthProviderActionButton(
                chooserElement,
                providerId,
                chooserElement.__emailPanelId,
                chooserElement.__emailExpanded,
                handleProviderClick,
              );
              chooserElement.__authProviderCleanupHandlers.push(
                function cleanupProviderAction() {
                  actionButton.removeEventListener("click", handleProviderClick);
                },
              );
              appendAuthProviderElement(actionsElement, actionButton);
            });
            appendAuthProviderElement(rootElement, actionsElement);
            if (this.__emailExpanded) {
              function handleEmailSubmit(event) {
                if (event && typeof event.preventDefault === "function") {
                  event.preventDefault();
                }
                dispatchEvent(chooserElement, AUTH_PROVIDER_EMAIL_SUBMIT_EVENT, {
                  provider: AUTH_PROVIDER_IDS.EMAIL,
                  action: "login",
                });
              }
              function handleForgotPasswordClick(event) {
                if (event && typeof event.preventDefault === "function") {
                  event.preventDefault();
                }
                dispatchAuthProviderModeEvent(
                  chooserElement,
                  AUTH_PROVIDER_EMAIL_MODE.RESET_START,
                );
              }
              function handleCreateAccountClick(event) {
                if (event && typeof event.preventDefault === "function") {
                  event.preventDefault();
                }
                dispatchAuthProviderModeEvent(
                  chooserElement,
                  AUTH_PROVIDER_EMAIL_MODE.SIGNUP,
                );
              }
              var emailPanel = createAuthProviderEmailPanel(
                this,
                this.__emailPanelId,
                handleEmailSubmit,
                handleForgotPasswordClick,
                handleCreateAccountClick,
              );
              this.__authProviderCleanupHandlers.push(emailPanel.cleanup);
              appendAuthProviderElement(rootElement, emailPanel.panel);
            }
            appendAuthProviderElement(this, rootElement);
          }
          __handleAuthProviderSelection(providerId, event) {
            if (event && typeof event.preventDefault === "function") {
              event.preventDefault();
            }
            this.setAttribute(AUTH_PROVIDER_CHOOSER_SELECTED_ATTRIBUTE, providerId);
            this.__emailExpanded = providerId === AUTH_PROVIDER_IDS.EMAIL;
            this.__renderAuthProviderChooser();
            dispatchEvent(this, AUTH_PROVIDER_SELECT_EVENT, { provider: providerId });
          }
        };
      },
    );
  }

  function defineUserMenuElement(registry) {
    registry.define("mpr-user", function setupUserElement(Base) {
      return class MprUserElement extends Base {
        constructor() {
          super();
          this.__userMenuConfig = null;
          this.__userMenuElements = null;
          this.__menuDomId = "";
          this.__profile = null;
          this.__isOpen = false;
          this.__authEventTarget = null;
          this.__dismissTarget = null;
          this.__dismissWindow = null;
          this.__boundUserViewportResizeHandler = this.__handleUserViewportResize.bind(this);
          this.__boundTriggerHandler = this.__handleTriggerClick.bind(this);
          this.__boundLogoutHandler = this.__handleLogoutClick.bind(this);
          this.__boundMenuItemHandler = this.__handleMenuItemClick.bind(this);
          this.__boundOutsideClickHandler = this.__handleOutsideClick.bind(this);
          this.__boundEscapeHandler = this.__handleEscape.bind(this);
          this.__boundAuthHandler = this.__handleAuthEvent.bind(this);
        }
        static get observedAttributes() {
          return USER_MENU_ATTRIBUTE_NAMES;
        }
        render() {
          this.__applyUserMenu();
        }
        update() {
          this.__applyUserMenu();
        }
        destroy() {
          this.__detachMenuEvents();
          this.__detachDismissEvents();
          this.__detachAuthEvents();
          this.__userMenuElements = null;
          this.__userMenuConfig = null;
          this.__profile = null;
          this.__isOpen = false;
          clearUserMenuError(this);
          this.removeAttribute("data-mpr-user-status");
          this.removeAttribute("data-mpr-user-mode");
          this.removeAttribute("data-mpr-user-open");
          applyUserProfileDataset(this, null);
        }
        __applyUserMenu() {
          if (!this.__mprConnected) {
            return;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureUserMenuStyles(documentObject);
          var config = null;
          try {
            var rawOptions = buildUserMenuOptionsFromAttributes(this);
            config = normalizeUserMenuOptions(rawOptions);
            config.authHost = resolveUserMenuScopedAuthHost(this);
          } catch (error) {
            this.__applyUserMenuError(error);
            return;
          }
          clearUserMenuError(this);
          this.__userMenuConfig = config;
          this.classList.add(USER_MENU_ROOT_CLASS);
          if (!this.__menuDomId) {
            this.__menuDomId = createUserMenuDomId();
          }
          this.__detachMenuEvents();
          this.__detachDismissEvents();
          this.innerHTML = buildUserMenuMarkup(config, this.__menuDomId);
          this.__userMenuElements = resolveUserMenuElements(this);
          applyUserMenuOpenState(this, this.__userMenuElements, this.__isOpen);
          try {
            applyUserMenuProfile(this, this.__userMenuElements, config, this.__profile);
          } catch (error) {
            reportUserMenuError(this, error);
            return;
          }
          this.__attachMenuEvents();
          this.__attachAuthEvents();
          if (!this.__syncProfileFromAuthHost("auth-host")) {
            this.__refreshProfile();
          }
        }
        __applyUserMenuError(error) {
          this.__userMenuConfig = null;
          this.__profile = null;
          this.__isOpen = false;
          this.__detachMenuEvents();
          this.__detachDismissEvents();
          this.__detachAuthEvents();
          if (Object.prototype.hasOwnProperty.call(this, "innerHTML")) {
            this.innerHTML = "";
          }
          reportUserMenuError(this, error);
        }
        __attachMenuEvents() {
          if (!this.__userMenuElements) {
            return;
          }
          if (
            this.__userMenuElements.trigger &&
            typeof this.__userMenuElements.trigger.addEventListener === "function"
          ) {
            this.__userMenuElements.trigger.addEventListener(
              "click",
              this.__boundTriggerHandler,
            );
          }
          if (
            this.__userMenuElements.menuItems &&
            this.__userMenuElements.menuItems.length
          ) {
            for (
              var menuItemIndex = 0;
              menuItemIndex < this.__userMenuElements.menuItems.length;
              menuItemIndex += 1
            ) {
              var menuItem = this.__userMenuElements.menuItems[menuItemIndex];
              if (menuItem && typeof menuItem.addEventListener === "function") {
                menuItem.addEventListener("click", this.__boundMenuItemHandler);
              }
            }
          }
          if (
            this.__userMenuElements.logoutButton &&
            typeof this.__userMenuElements.logoutButton.addEventListener === "function"
          ) {
            this.__userMenuElements.logoutButton.addEventListener(
              "click",
              this.__boundLogoutHandler,
            );
          }
        }
        __detachMenuEvents() {
          if (!this.__userMenuElements) {
            return;
          }
          if (
            this.__userMenuElements.trigger &&
            typeof this.__userMenuElements.trigger.removeEventListener === "function"
          ) {
            this.__userMenuElements.trigger.removeEventListener(
              "click",
              this.__boundTriggerHandler,
            );
          }
          if (
            this.__userMenuElements.menuItems &&
            this.__userMenuElements.menuItems.length
          ) {
            for (
              var menuItemIndex = 0;
              menuItemIndex < this.__userMenuElements.menuItems.length;
              menuItemIndex += 1
            ) {
              var menuItem = this.__userMenuElements.menuItems[menuItemIndex];
              if (menuItem && typeof menuItem.removeEventListener === "function") {
                menuItem.removeEventListener("click", this.__boundMenuItemHandler);
              }
            }
          }
          if (
            this.__userMenuElements.logoutButton &&
            typeof this.__userMenuElements.logoutButton.removeEventListener === "function"
          ) {
            this.__userMenuElements.logoutButton.removeEventListener(
              "click",
              this.__boundLogoutHandler,
            );
          }
        }
        __attachAuthEvents() {
          var target = resolveUserMenuEventTarget(this);
          if (target === this.__authEventTarget) {
            return;
          }
          this.__detachAuthEvents();
          this.__authEventTarget = target;
          if (!target) {
            return;
          }
          target.addEventListener("mpr-ui:auth:authenticated", this.__boundAuthHandler);
          target.addEventListener("mpr-ui:auth:unauthenticated", this.__boundAuthHandler);
        }
        __detachAuthEvents() {
          if (!this.__authEventTarget) {
            return;
          }
          this.__authEventTarget.removeEventListener(
            "mpr-ui:auth:authenticated",
            this.__boundAuthHandler,
          );
          this.__authEventTarget.removeEventListener(
            "mpr-ui:auth:unauthenticated",
            this.__boundAuthHandler,
          );
          this.__authEventTarget = null;
        }
        __syncProfileFromAuthHost(source) {
          var authHost = this.__userMenuConfig.authHost;
          if (!authHost) {
            return false;
          }
          this.__setProfile(readUserMenuProfileFromAuthHost(authHost), source);
          return true;
        }
        __attachDismissEvents() {
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          if (
            !documentObject ||
            typeof documentObject.addEventListener !== "function"
          ) {
            return;
          }
          if (documentObject === this.__dismissTarget) {
            return;
          }
          this.__detachDismissEvents();
          this.__dismissTarget = documentObject;
          documentObject.addEventListener("click", this.__boundOutsideClickHandler);
          documentObject.addEventListener("keydown", this.__boundEscapeHandler);
          this.__dismissWindow = resolveOwnerWindow(this);
          if (this.__dismissWindow && typeof this.__dismissWindow.addEventListener === "function") {
            this.__dismissWindow.addEventListener("resize", this.__boundUserViewportResizeHandler);
          }
        }
        __detachDismissEvents() {
          if (!this.__dismissTarget) {
            return;
          }
          if (typeof this.__dismissTarget.removeEventListener === "function") {
            this.__dismissTarget.removeEventListener(
              "click",
              this.__boundOutsideClickHandler,
            );
            this.__dismissTarget.removeEventListener(
              "keydown",
              this.__boundEscapeHandler,
            );
          }
          if (this.__dismissWindow && typeof this.__dismissWindow.removeEventListener === "function") {
            this.__dismissWindow.removeEventListener("resize", this.__boundUserViewportResizeHandler);
          }
          this.__dismissWindow = null;
          this.__dismissTarget = null;
        }
        __handleUserViewportResize() {
          if (this.__isOpen && this.__userMenuElements) {
            positionPanelInViewport(
              this.__userMenuElements.menu,
              this.__dismissWindow,
              USER_MENU_VIEWPORT_OFFSET_PROPERTY,
            );
          }
        }
        __refreshProfile() {
          if (!this.__userMenuConfig) {
            return;
          }
          var currentConfig = this.__userMenuConfig;
          configureAuthTenant(currentConfig.tenantId);
          var profileResult;
          try {
            profileResult = requestTauthProfile(currentConfig);
          } catch (error) {
            reportUserMenuError(this, error);
            return;
          }
          if (profileResult && typeof profileResult.then === "function") {
            profileResult
              .then(
                function handleProfile(profile) {
                  if (this.__userMenuConfig !== currentConfig) {
                    return;
                  }
                  this.__setProfile(profile, "tauth");
                }.bind(this),
              )
              .catch(
                function handleProfileError(error) {
                  reportUserMenuError(this, error);
                }.bind(this),
              );
            return;
          }
          this.__setProfile(profileResult, "tauth");
        }
        __handleAuthEvent(eventObject) {
          if (!this.__userMenuConfig) {
            return;
          }
          var eventType = eventObject ? eventObject.type : "";
          if (eventType === "mpr-ui:auth:authenticated") {
            var profile =
              eventObject && eventObject.detail ? eventObject.detail.profile : null;
            this.__setProfile(profile, "event");
            return;
          }
          if (eventType === "mpr-ui:auth:unauthenticated") {
            this.__setProfile(null, "event");
          }
        }
        __setProfile(profile, source) {
          var resolvedProfile = null;
          if (profile !== null && profile !== undefined) {
            if (!profile || typeof profile !== "object") {
              reportUserMenuError(
                this,
                createUserMenuError(
                  USER_MENU_PROFILE_ERROR_CODE,
                  "Profile payload is invalid",
                ),
              );
              return;
            }
            resolvedProfile = profile;
          }
          this.__profile = resolvedProfile;
          if (!this.__userMenuElements || !this.__userMenuConfig) {
            return;
          }
          try {
            applyUserMenuProfile(
              this,
              this.__userMenuElements,
              this.__userMenuConfig,
              resolvedProfile,
            );
            clearUserMenuError(this);
          } catch (error) {
            reportUserMenuError(this, error);
            return;
          }
          if (!resolvedProfile) {
            this.__setMenuOpen(false, source || "profile");
          }
        }
        __handleTriggerClick(eventObject) {
          if (eventObject && typeof eventObject.preventDefault === "function") {
            eventObject.preventDefault();
          }
          this.__setMenuOpen(!this.__isOpen, "user");
        }
        __handleOutsideClick(eventObject) {
          if (!this.__isOpen || !eventObject) {
            return;
          }
          var target = eventObject.target || null;
          if (isUserMenuEventTarget(this, this.__userMenuElements, target)) {
            return;
          }
          this.__setMenuOpen(false, "outside");
        }
        __handleEscape(eventObject) {
          if (!this.__isOpen || !eventObject) {
            return;
          }
          var key = eventObject.key || eventObject.keyCode || "";
          if (key === "Escape" || key === "Esc" || key === 27) {
            this.__setMenuOpen(false, "escape");
          }
        }
        __handleMenuItemClick(eventObject) {
          var config = this.__userMenuConfig;
          if (!config || !config.menuItems || !config.menuItems.length) {
            return;
          }
          var menuItemElement =
            eventObject && eventObject.currentTarget ? eventObject.currentTarget : null;
          if (!menuItemElement || typeof menuItemElement.getAttribute !== "function") {
            return;
          }
          var menuItemIndexValue = menuItemElement.getAttribute(
            USER_MENU_ITEM_INDEX_ATTRIBUTE,
          );
          if (menuItemIndexValue === null) {
            reportUserMenuError(
              this,
              createUserMenuError(
                USER_MENU_ITEMS_ERROR_CODE,
                "User menu item index is required",
              ),
            );
            return;
          }
          var menuItemIndex = Number(menuItemIndexValue);
          if (!Number.isFinite(menuItemIndex) || menuItemIndex < 0) {
            reportUserMenuError(
              this,
              createUserMenuError(
                USER_MENU_ITEMS_ERROR_CODE,
                "User menu item index is invalid",
              ),
            );
            return;
          }
          var menuItem = config.menuItems[menuItemIndex];
          if (!menuItem) {
            reportUserMenuError(
              this,
              createUserMenuError(
                USER_MENU_ITEMS_ERROR_CODE,
                "User menu item is missing",
              ),
            );
            return;
          }
          if (!menuItem.action) {
            return;
          }
          if (eventObject && typeof eventObject.preventDefault === "function") {
            eventObject.preventDefault();
          }
          this.__setMenuOpen(false, "menu-item");
          dispatchEvent(this, USER_MENU_ITEM_EVENT, {
            action: menuItem.action,
            label: menuItem.label,
            index: menuItemIndex,
          });
        }
        __handleLogoutClick(eventObject) {
          if (eventObject && typeof eventObject.preventDefault === "function") {
            eventObject.preventDefault();
          }
          var config = this.__userMenuConfig;
          if (!config) {
            return;
          }
          configureAuthTenant(config.tenantId);
          this.__setMenuOpen(false, "logout");
          var logoutResult;
          try {
            logoutResult = requestTauthLogout(config);
          } catch (error) {
            this.__reportLogoutFailure(error);
            return;
          }
          var handleLogoutSuccess = function handleLogoutSuccess() {
            this.__setProfile(null, "logout");
            dispatchEvent(this, "mpr-user:logout", {
              redirectUrl: config.logoutUrl,
            });
            var locationTarget = resolveLocationTarget(this);
            if (locationTarget && typeof locationTarget.assign === "function") {
              locationTarget.assign(config.logoutUrl);
            } else if (locationTarget) {
              locationTarget.href = config.logoutUrl;
            }
          }.bind(this);
          var handleLogoutFailure = function handleLogoutFailure(error) {
            /** @type {MprUiError | null} */
            var errorObject = error instanceof Error ? error : null;
            if (!errorObject || !errorObject.code) {
              errorObject = createUserMenuError(
                USER_MENU_LOGOUT_FAILED_ERROR_CODE,
                errorObject && errorObject.message
                  ? errorObject.message
                  : "Logout failed",
              );
            }
            this.__reportLogoutFailure(errorObject);
          }.bind(this);
          if (logoutResult && typeof logoutResult.then === "function") {
            logoutResult.then(handleLogoutSuccess).catch(handleLogoutFailure);
            return;
          }
          handleLogoutSuccess();
        }
        __reportLogoutFailure(error) {
          reportUserMenuError(this, error);
          applyUserMenuProfile(
            this,
            this.__userMenuElements,
            this.__userMenuConfig,
            this.__profile,
          );
        }
        __setMenuOpen(nextValue, source) {
          var nextState = Boolean(nextValue);
          var changed = nextState !== this.__isOpen;
          this.__isOpen = nextState;
          if (this.__userMenuElements) {
            applyUserMenuOpenState(this, this.__userMenuElements, nextState);
          }
          if (nextState) {
            this.__attachDismissEvents();
          } else {
            this.__detachDismissEvents();
          }
          if (changed && source && source !== "render") {
            dispatchEvent(this, "mpr-user:toggle", {
              open: nextState,
              source: source,
            });
          }
        }
      };
    });
  }

  function defineSettingsElement(registry) {
    registry.define("mpr-settings", function setupSettingsElement(Base) {
      return class MprSettingsElement extends Base {
        constructor() {
          super();
          this.__settingsSlots = null;
          this.__settingsSlotsCaptured = false;
          this.__elements = null;
          this.__panelDomId = "";
          this.__isOpen = false;
          this.__boundToggleHandler = this.__handleToggle.bind(this);
        }
        static get observedAttributes() {
          return SETTINGS_ATTRIBUTE_NAMES;
        }
        get open() {
          return this.__isOpen;
        }
        set open(value) {
          this.__setOpenState(Boolean(value), "property");
        }
        toggle(force) {
          if (typeof force === "boolean") {
            this.__setOpenState(force, "api");
            return;
          }
          this.__setOpenState(!this.__isOpen, "api");
        }
        render() {
          this.__captureSettingsSlots();
          this.__renderSettings();
        }
        update(name) {
          if (name === "open") {
            this.__setOpenState(this.__computeOpenState(), "attribute");
            return;
          }
          this.__renderSettings();
        }
        destroy() {
          this.__detachSettingsEvents();
          this.__settingsSlots = null;
          this.__settingsSlotsCaptured = false;
          this.__elements = null;
          this.__isOpen = false;
        }
        __captureSettingsSlots() {
          if (this.__settingsSlotsCaptured) {
            return;
          }
          var slots = captureSlotNodes(this, SETTINGS_SLOT_NAMES);
          var defaultNodes = [];
          while (this.firstChild) {
            var childNode = this.firstChild;
            this.removeChild(childNode);
            var slotName =
              childNode && typeof childNode.getAttribute === "function"
                ? childNode.getAttribute("slot")
                : childNode && typeof childNode.slot === "string"
                ? childNode.slot
                : null;
            if (slotName && Object.prototype.hasOwnProperty.call(slots, slotName)) {
              continue;
            }
            defaultNodes.push(childNode);
          }
          if (!slots.panel) {
            slots.panel = [];
          }
          Array.prototype.push.apply(slots.panel, defaultNodes);
          this.__settingsSlots = slots;
          this.__settingsSlotsCaptured = true;
        }
        __renderSettings() {
          if (!this.__mprConnected) {
            return;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureSettingsStyles(documentObject);
          this.classList.add(SETTINGS_ROOT_CLASS);
          if (!this.__panelDomId) {
            this.__panelDomId = createSettingsPanelDomId();
          }
          var attributeOptions = buildSettingsOptionsFromAttributes(this);
          if (typeof attributeOptions.open !== "boolean") {
            attributeOptions.open = this.__isOpen;
          }
          var config = normalizeSettingsOptions(attributeOptions);
          var ariaControls = config.panelId || this.__panelDomId;
          this.__detachSettingsEvents();
          this.innerHTML = buildSettingsMarkup(config, this.__panelDomId, ariaControls);
          this.__elements = resolveSettingsElements(this);
          if (this.__elements && this.__elements.label) {
            this.__elements.label.textContent = config.label;
          }
          if (this.__settingsSlots) {
            applySettingsSlotContent(this.__settingsSlots, this.__elements);
          }
          this.__attachSettingsEvents();
          this.__setOpenState(config.open, "render");
        }
        __attachSettingsEvents() {
          if (
            this.__elements &&
            this.__elements.button &&
            typeof this.__elements.button.addEventListener === "function"
          ) {
            this.__elements.button.addEventListener("click", this.__boundToggleHandler);
          }
        }
        __detachSettingsEvents() {
          if (
            this.__elements &&
            this.__elements.button &&
            typeof this.__elements.button.removeEventListener === "function"
          ) {
            this.__elements.button.removeEventListener("click", this.__boundToggleHandler);
          }
        }
        __computeOpenState() {
          var openAttr = this.getAttribute("open");
          if (openAttr === null || openAttr === undefined) {
            return false;
          }
          return normalizeBooleanAttribute(openAttr, false);
        }
        __setOpenState(nextValue, source) {
          var next = Boolean(nextValue);
          var changed = next !== this.__isOpen;
          this.__isOpen = next;
          this.__applyOpenState(next);
          if (source && source !== "render" && changed) {
            dispatchEvent(this, "mpr-settings:toggle", {
              panelId: this.getAttribute("panel-id") || null,
              open: next,
              source: source,
            });
          }
        }
        __applyOpenState(isOpen) {
          if (!this.__elements) {
            return;
          }
          this.setAttribute("data-mpr-settings-open", isOpen ? "true" : "false");
          if (this.__elements.button && typeof this.__elements.button.setAttribute === "function") {
            this.__elements.button.setAttribute("aria-expanded", isOpen ? "true" : "false");
          }
          if (this.__elements.panel) {
            if (isOpen) {
              this.__elements.panel.removeAttribute("hidden");
            } else {
              this.__elements.panel.setAttribute("hidden", "hidden");
            }
          }
          var panelTarget = this.__resolvePanelTarget();
          if (panelTarget) {
            if (isOpen) {
              panelTarget.removeAttribute("hidden");
            } else {
              panelTarget.setAttribute("hidden", "hidden");
            }
          }
        }
        __resolvePanelTarget() {
          var targetId = this.getAttribute("panel-id");
          if (!targetId) {
            return null;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          if (!documentObject || typeof documentObject.getElementById !== "function") {
            return null;
          }
          return documentObject.getElementById(targetId);
        }
        __handleToggle(event) {
          if (event && typeof event.preventDefault === "function") {
            event.preventDefault();
          }
          this.__setOpenState(!this.__isOpen, "user");
        }
      };
    });
  }

  function defineDetailDrawerElement(registry) {
    registry.define("mpr-detail-drawer", function setupDetailDrawerElement(Base) {
      return class MprDetailDrawerElement extends Base {
        constructor() {
          super();
          this.__detailDrawerSlots = null;
          this.__detailDrawerSlotsCaptured = false;
          this.__detailDrawerElements = null;
          this.__detailDrawerHeadingId = "";
          this.__detailDrawerOpen = false;
          this.__detailDrawerSyncingOpenAttribute = false;
          this.__detailDrawerOwnerDocument = null;
          this.__boundDetailDrawerCloseHandler = this.__handleClose.bind(this);
          this.__boundDetailDrawerBackdropHandler = this.__handleBackdropClick.bind(this);
          this.__boundDetailDrawerKeydownHandler = this.__handleDocumentKeydown.bind(this);
        }
        static get observedAttributes() {
          return DETAIL_DRAWER_ATTRIBUTE_NAMES;
        }
        get open() {
          return this.__detailDrawerOpen;
        }
        set open(value) {
          this.__setOpenState(Boolean(value), "property");
        }
        show() {
          this.__setOpenState(true, "api");
        }
        hide() {
          this.__setOpenState(false, "api");
        }
        toggle(force) {
          if (typeof force === "boolean") {
            this.__setOpenState(force, "api");
            return;
          }
          this.__setOpenState(!this.__detailDrawerOpen, "api");
        }
        render() {
          this.__captureDetailDrawerSlots();
          this.__renderDetailDrawer();
        }
        update(name) {
          if (name === "open") {
            if (this.__detailDrawerSyncingOpenAttribute) {
              return;
            }
            this.__setOpenState(this.__computeOpenState(), "attribute");
            return;
          }
          this.__renderDetailDrawer();
        }
        destroy() {
          this.__detachDetailDrawerEvents();
          this.__detailDrawerSlots = null;
          this.__detailDrawerSlotsCaptured = false;
          this.__detailDrawerElements = null;
          this.__detailDrawerOpen = false;
        }
        __captureDetailDrawerSlots() {
          if (this.__detailDrawerSlotsCaptured) {
            return;
          }
          this.__detailDrawerSlots = captureSlotNodesWithDefault(
            this,
            DETAIL_DRAWER_SLOT_NAMES,
            "body",
          );
          this.__detailDrawerSlotsCaptured = true;
        }
        __renderDetailDrawer() {
          if (!this.__mprConnected) {
            return;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureDetailDrawerStyles(documentObject);
          this.classList.add(DETAIL_DRAWER_ROOT_CLASS);
          if (!this.__detailDrawerHeadingId) {
            this.__detailDrawerHeadingId = createDetailDrawerHeadingId();
          }
          var attributeOptions = buildDetailDrawerOptionsFromAttributes(this);
          if (typeof attributeOptions.open !== "boolean") {
            attributeOptions.open = this.__detailDrawerOpen;
          }
          var config = normalizeDetailDrawerOptions(attributeOptions);
          this.__detachDetailDrawerEvents();
          this.innerHTML = buildDetailDrawerMarkup(
            config,
            this.__detailDrawerHeadingId,
          );
          this.__detailDrawerElements = resolveDetailDrawerElements(this);
          this.__applyDetailDrawerConfig(config);
          if (this.__detailDrawerSlots) {
            applyDetailDrawerSlotContent(
              this.__detailDrawerSlots,
              this.__detailDrawerElements,
            );
          }
          this.__attachDetailDrawerEvents();
          this.__setOpenState(config.open, "render");
        }
        __attachDetailDrawerEvents() {
          this.__detailDrawerOwnerDocument =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          if (
            this.__detailDrawerElements &&
            this.__detailDrawerElements.closeButton &&
            typeof this.__detailDrawerElements.closeButton.addEventListener === "function"
          ) {
            this.__detailDrawerElements.closeButton.addEventListener(
              "click",
              this.__boundDetailDrawerCloseHandler,
            );
          }
          if (
            this.__detailDrawerElements &&
            this.__detailDrawerElements.backdrop &&
            typeof this.__detailDrawerElements.backdrop.addEventListener === "function"
          ) {
            this.__detailDrawerElements.backdrop.addEventListener(
              "click",
              this.__boundDetailDrawerBackdropHandler,
            );
          }
          if (
            this.__detailDrawerOwnerDocument &&
            typeof this.__detailDrawerOwnerDocument.addEventListener === "function"
          ) {
            this.__detailDrawerOwnerDocument.addEventListener(
              "keydown",
              this.__boundDetailDrawerKeydownHandler,
            );
          }
        }
        __detachDetailDrawerEvents() {
          if (
            this.__detailDrawerElements &&
            this.__detailDrawerElements.closeButton &&
            typeof this.__detailDrawerElements.closeButton.removeEventListener === "function"
          ) {
            this.__detailDrawerElements.closeButton.removeEventListener(
              "click",
              this.__boundDetailDrawerCloseHandler,
            );
          }
          if (
            this.__detailDrawerElements &&
            this.__detailDrawerElements.backdrop &&
            typeof this.__detailDrawerElements.backdrop.removeEventListener === "function"
          ) {
            this.__detailDrawerElements.backdrop.removeEventListener(
              "click",
              this.__boundDetailDrawerBackdropHandler,
            );
          }
          if (
            this.__detailDrawerOwnerDocument &&
            typeof this.__detailDrawerOwnerDocument.removeEventListener === "function"
          ) {
            this.__detailDrawerOwnerDocument.removeEventListener(
              "keydown",
              this.__boundDetailDrawerKeydownHandler,
            );
          }
          this.__detailDrawerOwnerDocument = null;
        }
        __computeOpenState() {
          var openAttr = this.getAttribute("open");
          if (openAttr === null || openAttr === undefined) {
            return false;
          }
          return normalizeBooleanAttribute(openAttr, false);
        }
        __syncOpenAttribute(nextValue) {
          if (this.__detailDrawerSyncingOpenAttribute) {
            return;
          }
          this.__detailDrawerSyncingOpenAttribute = true;
          if (nextValue) {
            if (this.getAttribute("open") === null) {
              this.setAttribute("open", "");
            }
          } else if (this.getAttribute("open") !== null) {
            this.removeAttribute("open");
          }
          this.__detailDrawerSyncingOpenAttribute = false;
        }
        __applyDetailDrawerConfig(config) {
          this.setAttribute("data-mpr-detail-drawer-placement", config.placement);
          this.setAttribute(
            "data-mpr-detail-drawer-busy",
            config.busy ? "true" : "false",
          );
          if (
            this.__detailDrawerElements &&
            this.__detailDrawerElements.heading
          ) {
            this.__detailDrawerElements.heading.textContent = config.heading;
          }
          if (
            this.__detailDrawerElements &&
            this.__detailDrawerElements.subheading
          ) {
            this.__detailDrawerElements.subheading.textContent = config.subheading;
            setHiddenState(
              this.__detailDrawerElements.subheading,
              !config.subheading,
            );
          }
          if (
            this.__detailDrawerElements &&
            this.__detailDrawerElements.busy
          ) {
            setHiddenState(this.__detailDrawerElements.busy, !config.busy);
          }
        }
        __applyOpenState(isOpen) {
          this.setAttribute(
            "data-mpr-detail-drawer-open",
            isOpen ? "true" : "false",
          );
          if (
            this.__detailDrawerElements &&
            this.__detailDrawerElements.backdrop
          ) {
            setHiddenState(this.__detailDrawerElements.backdrop, !isOpen);
          }
          if (this.__detailDrawerElements && this.__detailDrawerElements.panel) {
            setHiddenState(this.__detailDrawerElements.panel, !isOpen);
            this.__detailDrawerElements.panel.setAttribute(
              "aria-hidden",
              isOpen ? "false" : "true",
            );
          }
        }
        __setOpenState(nextValue, source) {
          var next = Boolean(nextValue);
          var changed = next !== this.__detailDrawerOpen;
          this.__detailDrawerOpen = next;
          if (source !== "attribute") {
            this.__syncOpenAttribute(next);
          }
          this.__applyOpenState(next);
          if (changed && source && source !== "render") {
            dispatchEvent(
              this,
              next ? "mpr-detail-drawer:open" : "mpr-detail-drawer:close",
              {
                open: next,
                source: source,
                placement:
                  this.getAttribute("data-mpr-detail-drawer-placement") ||
                  DETAIL_DRAWER_DEFAULTS.placement,
              },
            );
          }
        }
        __handleClose(event) {
          if (event && typeof event.preventDefault === "function") {
            event.preventDefault();
          }
          this.__setOpenState(false, "user");
        }
        __handleBackdropClick(event) {
          if (event && typeof event.preventDefault === "function") {
            event.preventDefault();
          }
          this.__setOpenState(false, "backdrop");
        }
        __handleDocumentKeydown(event) {
          if (!this.__detailDrawerOpen || !event) {
            return;
          }
          var key = event.key || event.keyCode || "";
          if (key === "Escape" || key === "Esc" || key === 27) {
            this.__setOpenState(false, "keyboard");
          }
        }
      };
    });
  }

  function defineWorkspaceLayoutElement(registry) {
    registry.define("mpr-workspace-layout", function setupWorkspaceLayoutElement(Base) {
      return class MprWorkspaceLayoutElement extends Base {
        constructor() {
          super();
          this.__workspaceLayoutSlots = null;
          this.__workspaceLayoutSlotsCaptured = false;
          this.__workspaceLayoutElements = null;
          this.__workspaceLayoutCollapsed = false;
          this.__workspaceLayoutStacked = false;
          this.__workspaceLayoutSyncingCollapsedAttribute = false;
          this.__workspaceLayoutWindow = null;
          this.__workspaceLayoutBreakpoint = WORKSPACE_LAYOUT_DEFAULTS.stackedBreakpoint;
          this.__boundWorkspaceLayoutResizeHandler = this.__handleResize.bind(this);
        }
        static get observedAttributes() {
          return WORKSPACE_LAYOUT_ATTRIBUTE_NAMES;
        }
        get collapsed() {
          return this.__workspaceLayoutCollapsed;
        }
        set collapsed(value) {
          this.__setCollapsedState(Boolean(value), "property");
        }
        toggleSidebar(force) {
          if (typeof force === "boolean") {
            this.__setCollapsedState(force, "api");
            return;
          }
          this.__setCollapsedState(!this.__workspaceLayoutCollapsed, "api");
        }
        render() {
          this.__captureWorkspaceLayoutSlots();
          this.__renderWorkspaceLayout();
        }
        update(name) {
          if (name === "collapsed") {
            if (this.__workspaceLayoutSyncingCollapsedAttribute) {
              return;
            }
            this.__setCollapsedState(this.__computeCollapsedState(), "attribute");
            return;
          }
          this.__renderWorkspaceLayout();
        }
        destroy() {
          this.__detachResizeHandler();
          this.__workspaceLayoutSlots = null;
          this.__workspaceLayoutSlotsCaptured = false;
          this.__workspaceLayoutElements = null;
          this.__workspaceLayoutCollapsed = false;
          this.__workspaceLayoutStacked = false;
        }
        __captureWorkspaceLayoutSlots() {
          if (this.__workspaceLayoutSlotsCaptured) {
            return;
          }
          this.__workspaceLayoutSlots = captureSlotNodesWithDefault(
            this,
            WORKSPACE_LAYOUT_SLOT_NAMES,
            "content",
          );
          this.__workspaceLayoutSlotsCaptured = true;
        }
        __renderWorkspaceLayout() {
          if (!this.__mprConnected) {
            return;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureWorkspaceLayoutStyles(documentObject);
          this.classList.add(WORKSPACE_LAYOUT_ROOT_CLASS);
          var attributeOptions = buildWorkspaceLayoutOptionsFromAttributes(this);
          if (typeof attributeOptions.collapsed !== "boolean") {
            attributeOptions.collapsed = this.__workspaceLayoutCollapsed;
          }
          var config = normalizeWorkspaceLayoutOptions(attributeOptions);
          this.__workspaceLayoutBreakpoint = config.stackedBreakpoint;
          this.__detachResizeHandler();
          this.innerHTML = buildWorkspaceLayoutMarkup();
          this.__workspaceLayoutElements = resolveWorkspaceLayoutElements(this);
          if (this.__workspaceLayoutSlots) {
            applyWorkspaceLayoutSlotContent(
              this.__workspaceLayoutSlots,
              this.__workspaceLayoutElements,
            );
          }
          if (
            this.style &&
            typeof this.style.setProperty === "function"
          ) {
            this.style.setProperty(
              "--mpr-workspace-sidebar-width",
              config.sidebarWidth,
            );
          }
          this.__attachResizeHandler();
          this.__setStackedState(
            computeWorkspaceLayoutStackedState(this, config.stackedBreakpoint),
          );
          this.__setCollapsedState(config.collapsed, "render");
        }
        __attachResizeHandler() {
          this.__workspaceLayoutWindow = resolveOwnerWindow(this);
          if (
            this.__workspaceLayoutWindow &&
            typeof this.__workspaceLayoutWindow.addEventListener === "function"
          ) {
            this.__workspaceLayoutWindow.addEventListener(
              "resize",
              this.__boundWorkspaceLayoutResizeHandler,
            );
          }
        }
        __detachResizeHandler() {
          if (
            this.__workspaceLayoutWindow &&
            typeof this.__workspaceLayoutWindow.removeEventListener === "function"
          ) {
            this.__workspaceLayoutWindow.removeEventListener(
              "resize",
              this.__boundWorkspaceLayoutResizeHandler,
            );
          }
          this.__workspaceLayoutWindow = null;
        }
        __computeCollapsedState() {
          var collapsedAttr = this.getAttribute("collapsed");
          if (collapsedAttr === null || collapsedAttr === undefined) {
            return false;
          }
          return normalizeBooleanAttribute(collapsedAttr, false);
        }
        __syncCollapsedAttribute(nextValue) {
          if (this.__workspaceLayoutSyncingCollapsedAttribute) {
            return;
          }
          this.__workspaceLayoutSyncingCollapsedAttribute = true;
          if (nextValue) {
            if (this.getAttribute("collapsed") === null) {
              this.setAttribute("collapsed", "");
            }
          } else if (this.getAttribute("collapsed") !== null) {
            this.removeAttribute("collapsed");
          }
          this.__workspaceLayoutSyncingCollapsedAttribute = false;
        }
        __applyWorkspaceLayoutState() {
          this.setAttribute(
            "data-mpr-workspace-collapsed",
            this.__workspaceLayoutCollapsed ? "true" : "false",
          );
          this.setAttribute(
            "data-mpr-workspace-stacked",
            this.__workspaceLayoutStacked ? "true" : "false",
          );
          if (
            this.__workspaceLayoutElements &&
            this.__workspaceLayoutElements.sidebar
          ) {
            setHiddenState(
              this.__workspaceLayoutElements.sidebar,
              this.__workspaceLayoutCollapsed,
            );
          }
        }
        __setCollapsedState(nextValue, source) {
          var next = Boolean(nextValue);
          var changed = next !== this.__workspaceLayoutCollapsed;
          this.__workspaceLayoutCollapsed = next;
          if (source !== "attribute") {
            this.__syncCollapsedAttribute(next);
          }
          this.__applyWorkspaceLayoutState();
          if (changed && source && source !== "render") {
            dispatchEvent(this, "mpr-workspace-layout:sidebar-toggle", {
              collapsed: next,
              stacked: this.__workspaceLayoutStacked,
              source: source,
            });
          }
        }
        __setStackedState(nextValue) {
          this.__workspaceLayoutStacked = Boolean(nextValue);
          this.__applyWorkspaceLayoutState();
        }
        __handleResize() {
          this.__setStackedState(
            computeWorkspaceLayoutStackedState(
              this,
              this.__workspaceLayoutBreakpoint,
            ),
          );
        }
      };
    });
  }

  function defineSidebarNavElement(registry) {
    registry.define("mpr-sidebar-nav", function setupSidebarNavElement(Base) {
      return class MprSidebarNavElement extends Base {
        constructor() {
          super();
          this.__sidebarNavSlots = null;
          this.__sidebarNavSlotsCaptured = false;
          this.__sidebarNavElements = null;
          this.__sidebarNavItems = [];
          this.__boundSidebarNavItemHandler = this.__handleItemClick.bind(this);
        }
        static get observedAttributes() {
          return SIDEBAR_NAV_ATTRIBUTE_NAMES;
        }
        render() {
          this.__captureSidebarNavSlots();
          this.__renderSidebarNav();
        }
        update() {
          this.__renderSidebarNav();
        }
        destroy() {
          this.__detachSidebarNavEvents();
          this.__sidebarNavSlots = null;
          this.__sidebarNavSlotsCaptured = false;
          this.__sidebarNavElements = null;
        }
        __captureSidebarNavSlots() {
          if (this.__sidebarNavSlotsCaptured) {
            return;
          }
          this.__sidebarNavSlots = captureSlotNodesWithDefault(
            this,
            SIDEBAR_NAV_SLOT_NAMES,
            "default",
          );
          this.__sidebarNavSlotsCaptured = true;
        }
        __renderSidebarNav() {
          if (!this.__mprConnected) {
            return;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureSidebarNavStyles(documentObject);
          this.classList.add(SIDEBAR_NAV_ROOT_CLASS);
          var config = normalizeSidebarNavOptions(
            buildSidebarNavOptionsFromAttributes(this),
          );
          this.__detachSidebarNavEvents();
          this.innerHTML = buildSidebarNavMarkup(config);
          this.__sidebarNavElements = resolveSidebarNavElements(this);
          if (this.__sidebarNavSlots) {
            applySidebarNavSlotContent(
              this.__sidebarNavSlots,
              this.__sidebarNavElements,
            );
          }
          this.__sidebarNavElements = resolveSidebarNavElements(this);
          this.setAttribute("data-mpr-sidebar-nav-variant", config.variant);
          this.setAttribute(
            "data-mpr-sidebar-nav-dense",
            config.dense ? "true" : "false",
          );
          this.__attachSidebarNavEvents();
        }
        __attachSidebarNavEvents() {
          this.__sidebarNavItems = [];
          if (
            !this.__sidebarNavElements ||
            !Array.isArray(this.__sidebarNavElements.items)
          ) {
            return;
          }
          this.__sidebarNavElements.items.forEach(
            function attach(item) {
              if (
                !item ||
                typeof item.addEventListener !== "function"
              ) {
                return;
              }
              item.addEventListener("click", this.__boundSidebarNavItemHandler);
              this.__sidebarNavItems.push(item);
            }.bind(this),
          );
        }
        __detachSidebarNavEvents() {
          this.__sidebarNavItems.forEach(
            function detach(item) {
              if (item && typeof item.removeEventListener === "function") {
                item.removeEventListener(
                  "click",
                  this.__boundSidebarNavItemHandler,
                );
              }
            }.bind(this),
          );
          this.__sidebarNavItems = [];
        }
        __handleItemClick(event) {
          var item = event && event.currentTarget ? event.currentTarget : null;
          if (!item || typeof item.getAttribute !== "function") {
            return;
          }
          var key = item.getAttribute("data-mpr-sidebar-key");
          if (!key) {
            return;
          }
          var label = "";
          if (typeof item.getAttribute === "function") {
            label = item.getAttribute("data-mpr-sidebar-label") || "";
          }
          if (
            !label &&
            item.textContent &&
            typeof item.textContent === "string"
          ) {
            label = item.textContent.trim();
          }
          dispatchEvent(this, "mpr-sidebar-nav:change", {
            key: key,
            label: label,
            source: "user",
          });
        }
      };
    });
  }

  function defineEntityRailElement(registry) {
    registry.define("mpr-entity-rail", function setupEntityRailElement(Base) {
      return class MprEntityRailElement extends Base {
        constructor() {
          super();
          this.__entityRailSlots = null;
          this.__entityRailSlotsCaptured = false;
          this.__entityRailElements = null;
          this.__entityRailMutationObserver = null;
          this.__entityRailNavStep = ENTITY_RAIL_DEFAULTS.navStep;
          this.__boundEntityRailPreviousHandler = this.__handlePreviousClick.bind(this);
          this.__boundEntityRailNextHandler = this.__handleNextClick.bind(this);
          this.__boundEntityRailScrollHandler = this.__handleViewportScroll.bind(this);
          this.__boundEntityRailMutationHandler = this.__handleEntityRailMutations.bind(this);
        }
        static get observedAttributes() {
          return ENTITY_RAIL_ATTRIBUTE_NAMES;
        }
        render() {
          this.__captureEntityRailSlots();
          this.__renderEntityRail();
        }
        update() {
          this.__renderEntityRail();
        }
        destroy() {
          this.__detachEntityRailEvents();
          this.__detachEntityRailObserver();
          this.__entityRailSlots = null;
          this.__entityRailSlotsCaptured = false;
          this.__entityRailElements = null;
        }
        scrollPrevious() {
          this.__scrollByAmount(-1, "api");
        }
        scrollNext() {
          this.__scrollByAmount(1, "api");
        }
        __captureEntityRailSlots() {
          if (this.__entityRailSlotsCaptured) {
            return;
          }
          this.__entityRailSlots = captureSlotNodesWithDefault(
            this,
            ENTITY_RAIL_SLOT_NAMES,
            "default",
          );
          this.__entityRailSlotsCaptured = true;
        }
        __syncEntityRailSlots() {
          this.__entityRailSlots = syncTrackedSlotsWithHost(
            this,
            ENTITY_RAIL_SLOT_NAMES,
            "default",
            this.__entityRailSlots,
            [
              this.__entityRailElements && this.__entityRailElements.header,
              this.__entityRailElements && this.__entityRailElements.viewport,
              this.__entityRailElements && this.__entityRailElements.empty,
            ],
          );
        }
        __renderEntityRail() {
          if (!this.__mprConnected) {
            return;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureEntityRailStyles(documentObject);
          this.classList.add(ENTITY_RAIL_ROOT_CLASS);
          this.__detachEntityRailObserver();
          this.__captureEntityRailSlots();
          this.__syncEntityRailSlots();
          var config = normalizeEntityRailOptions(
            buildEntityRailOptionsFromAttributes(this),
          );
          this.__entityRailNavStep = config.navStep;
          this.__detachEntityRailEvents();
          this.innerHTML = buildEntityRailMarkup(config);
          this.__entityRailElements = resolveEntityRailElements(this);
          if (this.__entityRailSlots) {
            applyEntityRailSlotContent(
              this.__entityRailSlots,
              this.__entityRailElements,
            );
          }
          this.__applyEntityRailState(config);
          this.__attachEntityRailEvents();
          this.__attachEntityRailObserver();
          this.__updateEntityRailBoundaryState("render");
        }
        __attachEntityRailObserver() {
          var ownerWindow = resolveOwnerWindow(this);
          var MutationObserverCtor =
            (ownerWindow && ownerWindow.MutationObserver) ||
            global.MutationObserver ||
            null;
          if (!MutationObserverCtor) {
            return;
          }
          if (!this.__entityRailMutationObserver) {
            this.__entityRailMutationObserver = new MutationObserverCtor(
              this.__boundEntityRailMutationHandler,
            );
          }
          this.__entityRailMutationObserver.observe(this, {
            childList: true,
          });
        }
        __detachEntityRailObserver() {
          if (
            this.__entityRailMutationObserver &&
            typeof this.__entityRailMutationObserver.disconnect === "function"
          ) {
            this.__entityRailMutationObserver.disconnect();
          }
        }
        __attachEntityRailEvents() {
          if (
            this.__entityRailElements &&
            this.__entityRailElements.previousButton &&
            typeof this.__entityRailElements.previousButton.addEventListener === "function"
          ) {
            this.__entityRailElements.previousButton.addEventListener(
              "click",
              this.__boundEntityRailPreviousHandler,
            );
          }
          if (
            this.__entityRailElements &&
            this.__entityRailElements.nextButton &&
            typeof this.__entityRailElements.nextButton.addEventListener === "function"
          ) {
            this.__entityRailElements.nextButton.addEventListener(
              "click",
              this.__boundEntityRailNextHandler,
            );
          }
          if (
            this.__entityRailElements &&
            this.__entityRailElements.viewport &&
            typeof this.__entityRailElements.viewport.addEventListener === "function"
          ) {
            this.__entityRailElements.viewport.addEventListener(
              "scroll",
              this.__boundEntityRailScrollHandler,
            );
          }
        }
        __detachEntityRailEvents() {
          if (
            this.__entityRailElements &&
            this.__entityRailElements.previousButton &&
            typeof this.__entityRailElements.previousButton.removeEventListener === "function"
          ) {
            this.__entityRailElements.previousButton.removeEventListener(
              "click",
              this.__boundEntityRailPreviousHandler,
            );
          }
          if (
            this.__entityRailElements &&
            this.__entityRailElements.nextButton &&
            typeof this.__entityRailElements.nextButton.removeEventListener === "function"
          ) {
            this.__entityRailElements.nextButton.removeEventListener(
              "click",
              this.__boundEntityRailNextHandler,
            );
          }
          if (
            this.__entityRailElements &&
            this.__entityRailElements.viewport &&
            typeof this.__entityRailElements.viewport.removeEventListener === "function"
          ) {
            this.__entityRailElements.viewport.removeEventListener(
              "scroll",
              this.__boundEntityRailScrollHandler,
            );
          }
        }
        __hasEntityRailItems() {
          return Boolean(
            this.__entityRailSlots &&
              this.__entityRailSlots.default &&
              this.__entityRailSlots.default.length,
          );
        }
        __applyEntityRailState(config) {
          var hasItems = this.__hasEntityRailItems();
          this.setAttribute("data-mpr-entity-rail-empty", hasItems ? "false" : "true");
          this.setAttribute(
            "data-mpr-entity-rail-show-nav",
            config.showNav ? "true" : "false",
          );
          if (
            this.__entityRailElements &&
            this.__entityRailElements.empty
          ) {
            this.__entityRailElements.empty.textContent = config.emptyLabel;
            setHiddenState(this.__entityRailElements.empty, hasItems);
          }
          if (
            this.__entityRailElements &&
            this.__entityRailElements.nav
          ) {
            setHiddenState(
              this.__entityRailElements.nav,
              !config.showNav || !hasItems,
            );
          }
        }
        __scrollByAmount(direction, source) {
          if (
            !this.__entityRailElements ||
            !this.__entityRailElements.viewport
          ) {
            return;
          }
          var viewport = this.__entityRailElements.viewport;
          var offset = this.__entityRailNavStep * direction;
          if (typeof viewport.scrollBy === "function") {
            viewport.scrollBy({ left: offset, behavior: "smooth" });
          } else if (typeof viewport.scrollLeft === "number") {
            viewport.scrollLeft += offset;
          }
          this.__updateEntityRailBoundaryState(source || "api");
        }
        __updateEntityRailBoundaryState(source) {
          if (
            !this.__entityRailElements ||
            !this.__entityRailElements.viewport
          ) {
            return;
          }
          var viewport = this.__entityRailElements.viewport;
          var scrollLeft =
            typeof viewport.scrollLeft === "number" ? viewport.scrollLeft : 0;
          var clientWidth =
            typeof viewport.clientWidth === "number" ? viewport.clientWidth : 0;
          var scrollWidth =
            typeof viewport.scrollWidth === "number" ? viewport.scrollWidth : clientWidth;
          var hasOverflow = scrollWidth > clientWidth + 1;
          var isAtStart = !hasOverflow || scrollLeft <= 0;
          var isAtEnd = !hasOverflow || scrollLeft + clientWidth >= scrollWidth - 1;
          if (
            this.__entityRailElements.previousButton &&
            typeof this.__entityRailElements.previousButton.setAttribute === "function"
          ) {
            if (isAtStart) {
              this.__entityRailElements.previousButton.setAttribute(
                "disabled",
                "disabled",
              );
            } else {
              this.__entityRailElements.previousButton.removeAttribute("disabled");
            }
          }
          if (
            this.__entityRailElements.nextButton &&
            typeof this.__entityRailElements.nextButton.setAttribute === "function"
          ) {
            if (isAtEnd) {
              this.__entityRailElements.nextButton.setAttribute(
                "disabled",
                "disabled",
              );
            } else {
              this.__entityRailElements.nextButton.removeAttribute("disabled");
            }
          }
          if (source && source !== "render") {
            if (isAtStart) {
              dispatchEvent(this, "mpr-entity-rail:scroll-start", {
                source: source,
                position: scrollLeft,
              });
            }
            if (isAtEnd) {
              dispatchEvent(this, "mpr-entity-rail:scroll-end", {
                source: source,
                position: scrollLeft,
              });
            }
          }
        }
        __handlePreviousClick(event) {
          if (event && typeof event.preventDefault === "function") {
            event.preventDefault();
          }
          this.__scrollByAmount(-1, "user");
        }
        __handleNextClick(event) {
          if (event && typeof event.preventDefault === "function") {
            event.preventDefault();
          }
          this.__scrollByAmount(1, "user");
        }
        __handleViewportScroll() {
          this.__updateEntityRailBoundaryState("scroll");
        }
        __handleEntityRailMutations() {
          if (!this.__mprConnected) {
            return;
          }
          this.__renderEntityRail();
        }
      };
    });
  }

  function defineEntityTileElement(registry) {
    registry.define("mpr-entity-tile", function setupEntityTileElement(Base) {
      return class MprEntityTileElement extends Base {
        constructor() {
          super();
          this.__entityTileSlots = null;
          this.__entityTileSlotsCaptured = false;
          this.__entityTileElements = null;
        }
        static get observedAttributes() {
          return ENTITY_TILE_ATTRIBUTE_NAMES;
        }
        render() {
          this.__captureEntityTileSlots();
          this.__renderEntityTile();
        }
        update() {
          this.__renderEntityTile();
        }
        destroy() {
          this.__entityTileSlots = null;
          this.__entityTileSlotsCaptured = false;
          this.__entityTileElements = null;
        }
        __captureEntityTileSlots() {
          if (this.__entityTileSlotsCaptured) {
            return;
          }
          this.__entityTileSlots = captureSlotNodesWithDefault(
            this,
            ENTITY_TILE_SLOT_NAMES,
            "title",
          );
          this.__entityTileSlotsCaptured = true;
        }
        __renderEntityTile() {
          if (!this.__mprConnected) {
            return;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureEntityTileStyles(documentObject);
          this.classList.add(ENTITY_TILE_ROOT_CLASS);
          var config = normalizeEntityTileOptions(
            buildEntityTileOptionsFromAttributes(this),
          );
          this.innerHTML = buildEntityTileMarkup();
          this.__entityTileElements = resolveEntityTileElements(this);
          if (this.__entityTileSlots) {
            applyEntityTileSlotContent(
              this.__entityTileSlots,
              this.__entityTileElements,
            );
          }
          this.setAttribute(
            "data-mpr-entity-tile-selected",
            config.selected ? "true" : "false",
          );
          this.setAttribute(
            "data-mpr-entity-tile-interactive",
            config.interactive ? "true" : "false",
          );
          this.setAttribute(
            "data-mpr-entity-tile-disabled",
            config.disabled ? "true" : "false",
          );
          this.setAttribute("data-mpr-entity-tile-variant", config.variant);
        }
      };
    });
  }

  function defineEntityWorkspaceElement(registry) {
    registry.define("mpr-entity-workspace", function setupEntityWorkspaceElement(Base) {
      return class MprEntityWorkspaceElement extends Base {
        constructor() {
          super();
          this.__entityWorkspaceSlots = null;
          this.__entityWorkspaceSlotsCaptured = false;
          this.__entityWorkspaceElements = null;
          this.__entityWorkspaceMutationObserver = null;
          this.__boundEntityWorkspaceLoadMoreHandler =
            this.__handleLoadMoreClick.bind(this);
          this.__boundEntityWorkspaceMutationHandler =
            this.__handleEntityWorkspaceMutations.bind(this);
        }
        static get observedAttributes() {
          return ENTITY_WORKSPACE_ATTRIBUTE_NAMES;
        }
        render() {
          this.__captureEntityWorkspaceSlots();
          this.__renderEntityWorkspace();
        }
        update() {
          this.__renderEntityWorkspace();
        }
        destroy() {
          this.__detachEntityWorkspaceEvents();
          this.__detachEntityWorkspaceObserver();
          this.__entityWorkspaceSlots = null;
          this.__entityWorkspaceSlotsCaptured = false;
          this.__entityWorkspaceElements = null;
        }
        requestLoadMore() {
          dispatchEvent(this, "mpr-entity-workspace:load-more", {
            source: "api",
            selectionCount:
              parsePositiveInteger(this.getAttribute("selection-count"), 0),
          });
        }
        __captureEntityWorkspaceSlots() {
          if (this.__entityWorkspaceSlotsCaptured) {
            return;
          }
          this.__entityWorkspaceSlots = captureSlotNodesWithDefault(
            this,
            ENTITY_WORKSPACE_SLOT_NAMES,
            "list",
          );
          this.__entityWorkspaceSlotsCaptured = true;
        }
        __syncEntityWorkspaceSlots() {
          this.__entityWorkspaceSlots = syncTrackedSlotsWithHost(
            this,
            ENTITY_WORKSPACE_SLOT_NAMES,
            "list",
            this.__entityWorkspaceSlots,
            [
              this.__entityWorkspaceElements && this.__entityWorkspaceElements.surface,
            ],
          );
        }
        __renderEntityWorkspace() {
          if (!this.__mprConnected) {
            return;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureEntityWorkspaceStyles(documentObject);
          this.classList.add(ENTITY_WORKSPACE_ROOT_CLASS);
          this.__detachEntityWorkspaceObserver();
          this.__captureEntityWorkspaceSlots();
          this.__syncEntityWorkspaceSlots();
          var config = normalizeEntityWorkspaceOptions(
            buildEntityWorkspaceOptionsFromAttributes(this),
          );
          this.__detachEntityWorkspaceEvents();
          this.innerHTML = buildEntityWorkspaceMarkup(config);
          this.__entityWorkspaceElements = resolveEntityWorkspaceElements(this);
          if (this.__entityWorkspaceSlots) {
            applyEntityWorkspaceSlotContent(
              this.__entityWorkspaceSlots,
              this.__entityWorkspaceElements,
            );
          }
          this.__entityWorkspaceElements = resolveEntityWorkspaceElements(this);
          this.__applyEntityWorkspaceState(config);
          this.__attachEntityWorkspaceEvents();
          this.__attachEntityWorkspaceObserver();
        }
        __attachEntityWorkspaceObserver() {
          var ownerWindow = resolveOwnerWindow(this);
          var MutationObserverCtor =
            (ownerWindow && ownerWindow.MutationObserver) ||
            global.MutationObserver ||
            null;
          if (!MutationObserverCtor) {
            return;
          }
          if (!this.__entityWorkspaceMutationObserver) {
            this.__entityWorkspaceMutationObserver = new MutationObserverCtor(
              this.__boundEntityWorkspaceMutationHandler,
            );
          }
          this.__entityWorkspaceMutationObserver.observe(this, {
            childList: true,
          });
        }
        __detachEntityWorkspaceObserver() {
          if (
            this.__entityWorkspaceMutationObserver &&
            typeof this.__entityWorkspaceMutationObserver.disconnect === "function"
          ) {
            this.__entityWorkspaceMutationObserver.disconnect();
          }
        }
        __attachEntityWorkspaceEvents() {
          if (
            this.__entityWorkspaceElements &&
            this.__entityWorkspaceElements.loadMoreButton &&
            typeof this.__entityWorkspaceElements.loadMoreButton.addEventListener === "function"
          ) {
            this.__entityWorkspaceElements.loadMoreButton.addEventListener(
              "click",
              this.__boundEntityWorkspaceLoadMoreHandler,
            );
          }
        }
        __detachEntityWorkspaceEvents() {
          if (
            this.__entityWorkspaceElements &&
            this.__entityWorkspaceElements.loadMoreButton &&
            typeof this.__entityWorkspaceElements.loadMoreButton.removeEventListener === "function"
          ) {
            this.__entityWorkspaceElements.loadMoreButton.removeEventListener(
              "click",
              this.__boundEntityWorkspaceLoadMoreHandler,
            );
          }
        }
        __applyEntityWorkspaceState(config) {
          this.setAttribute(
            "data-mpr-entity-workspace-busy",
            config.busy ? "true" : "false",
          );
          this.setAttribute(
            "data-mpr-entity-workspace-empty",
            config.empty ? "true" : "false",
          );
          this.setAttribute(
            "data-mpr-entity-workspace-selection-count",
            String(config.selectionCount),
          );
          this.setAttribute(
            "data-mpr-entity-workspace-can-load-more",
            config.canLoadMore ? "true" : "false",
          );
          if (
            this.__entityWorkspaceElements &&
            this.__entityWorkspaceElements.busy
          ) {
            setHiddenState(this.__entityWorkspaceElements.busy, !config.busy);
          }
          if (
            this.__entityWorkspaceElements &&
            this.__entityWorkspaceElements.empty
          ) {
            setHiddenState(this.__entityWorkspaceElements.empty, !config.empty);
          }
          if (
            this.__entityWorkspaceElements &&
            this.__entityWorkspaceElements.list
          ) {
            setHiddenState(this.__entityWorkspaceElements.list, config.empty);
          }
          if (
            this.__entityWorkspaceElements &&
            this.__entityWorkspaceElements.loadMore
          ) {
            setHiddenState(
              this.__entityWorkspaceElements.loadMore,
              !config.canLoadMore,
            );
          }
        }
        __handleLoadMoreClick(event) {
          if (event && typeof event.preventDefault === "function") {
            event.preventDefault();
          }
          dispatchEvent(this, "mpr-entity-workspace:load-more", {
            source: "user",
            selectionCount:
              parsePositiveInteger(this.getAttribute("selection-count"), 0),
          });
        }
        __handleEntityWorkspaceMutations() {
          if (!this.__mprConnected) {
            return;
          }
          this.__renderEntityWorkspace();
        }
      };
    });
  }

  function defineEntityCardElement(registry) {
    registry.define("mpr-entity-card", function setupEntityCardElement(Base) {
      return class MprEntityCardElement extends Base {
        constructor() {
          super();
          this.__entityCardSlots = null;
          this.__entityCardSlotsCaptured = false;
          this.__entityCardElements = null;
        }
        static get observedAttributes() {
          return ENTITY_CARD_ATTRIBUTE_NAMES;
        }
        render() {
          this.__captureEntityCardSlots();
          this.__renderEntityCard();
        }
        update() {
          this.__renderEntityCard();
        }
        destroy() {
          this.__entityCardSlots = null;
          this.__entityCardSlotsCaptured = false;
          this.__entityCardElements = null;
        }
        __captureEntityCardSlots() {
          if (this.__entityCardSlotsCaptured) {
            return;
          }
          this.__entityCardSlots = captureSlotNodesWithDefault(
            this,
            ENTITY_CARD_SLOT_NAMES,
            "summary",
          );
          this.__entityCardSlotsCaptured = true;
        }
        __renderEntityCard() {
          if (!this.__mprConnected) {
            return;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureEntityCardStyles(documentObject);
          this.classList.add(ENTITY_CARD_ROOT_CLASS);
          var config = normalizeEntityCardOptions(
            buildEntityCardOptionsFromAttributes(this),
          );
          this.innerHTML = buildEntityCardMarkup(config);
          this.__entityCardElements = resolveEntityCardElements(this);
          if (this.__entityCardSlots) {
            applyEntityCardSlotContent(
              this.__entityCardSlots,
              this.__entityCardElements,
            );
          }
          this.setAttribute(
            "data-mpr-entity-card-selected",
            config.selected ? "true" : "false",
          );
          this.setAttribute(
            "data-mpr-entity-card-interactive",
            config.interactive ? "true" : "false",
          );
          this.setAttribute(
            "data-mpr-entity-card-disabled",
            config.disabled ? "true" : "false",
          );
          this.setAttribute(
            "data-mpr-entity-card-busy",
            config.busy ? "true" : "false",
          );
          this.setAttribute("data-mpr-entity-card-density", config.density);
          if (
            this.__entityCardElements &&
            this.__entityCardElements.busy
          ) {
            setHiddenState(this.__entityCardElements.busy, !config.busy);
          }
        }
      };
    });
  }

  function defineSitesElement(registry) {
    registry.define("mpr-sites", function setupSitesElement(Base) {
      return class MprSitesElement extends Base {
        constructor() {
          super();
          this.__linksConfig = [];
          this.__linkNodes = [];
          this.__boundLinkHandler = this.__handleLinkClick.bind(this);
        }
        static get observedAttributes() {
          return SITES_ATTRIBUTE_NAMES;
        }
        render() {
          this.__renderSites();
        }
        update() {
          this.__renderSites();
        }
        destroy() {
          this.__detachLinkHandlers();
          this.__linksConfig = [];
          this.__linkNodes = [];
        }
        __renderSites() {
          if (!this.__mprConnected) {
            return;
          }
          var documentObject =
            this.ownerDocument ||
            global.document ||
            (global.window && global.window.document) ||
            null;
          ensureSitesStyles(documentObject);
          var attributeOptions = buildSitesOptionsFromAttributes(this);
          var config = normalizeSitesOptions(attributeOptions);
          this.__linksConfig = config.links;
          this.classList.add(SITES_ROOT_CLASS);
          this.classList.toggle(SITES_ROOT_CLASS + "--grid", config.variant === "grid");
          this.classList.toggle(SITES_ROOT_CLASS + "--list", config.variant === "list");
          this.classList.toggle(SITES_ROOT_CLASS + "--menu", config.variant === "menu");
          this.setAttribute("data-mpr-sites-variant", config.variant);
          this.setAttribute("data-mpr-sites-columns", String(config.columns));
          this.setAttribute("data-mpr-sites-count", String(config.links.length));
          this.setAttribute(
            "data-mpr-sites-empty",
            config.links.length ? "false" : "true",
          );
          this.__detachLinkHandlers();
          this.innerHTML = buildSitesMarkup(config);
          this.__attachLinkHandlers();
        }
        __attachLinkHandlers() {
          var nodes = [];
          if (typeof this.querySelectorAll === "function") {
            var nodeList = this.querySelectorAll('[data-mpr-sites-index]');
            if (nodeList && typeof nodeList.length === "number") {
              for (var index = 0; index < nodeList.length; index += 1) {
                nodes.push(nodeList[index]);
              }
            }
          }
          this.__linkNodes = [];
          nodes.forEach(
            function attach(node) {
              if (
                node &&
                typeof node.addEventListener === "function" &&
                typeof node.getAttribute === "function"
              ) {
                node.addEventListener("click", this.__boundLinkHandler);
                this.__linkNodes.push(node);
              }
            }.bind(this),
          );
        }
        __detachLinkHandlers() {
          this.__linkNodes.forEach(
            function detach(node) {
              if (node && typeof node.removeEventListener === "function") {
                node.removeEventListener("click", this.__boundLinkHandler);
              }
            }.bind(this),
          );
          this.__linkNodes = [];
        }
        __handleLinkClick(event) {
          var anchor = event && event.currentTarget ? event.currentTarget : null;
          if (!anchor || typeof anchor.getAttribute !== "function") {
            return;
          }
          var indexValue = anchor.getAttribute("data-mpr-sites-index");
          var parsedIndex = parseInt(indexValue, 10);
          if (
            isNaN(parsedIndex) ||
            parsedIndex < 0 ||
            parsedIndex >= this.__linksConfig.length
          ) {
            return;
          }
          var link = this.__linksConfig[parsedIndex];
          dispatchEvent(this, "mpr-sites:link-click", {
            label: link.label,
            url: link.href,
            target: link.target,
            rel: link.rel,
            index: parsedIndex,
          });
        }
      };
    });
  }

  function defineLegalDocumentElement(registry) {
    registry.define("mpr-legal-document", function setupLegalDocumentElement(Base) {
      return class MprLegalDocumentElement extends Base {
        constructor() {
          super();
          this.__legalDocumentController = null;
        }
        static get observedAttributes() {
          return LEGAL_DOCUMENT_ATTRIBUTE_NAMES;
        }
        render() {
          this.__applyLegalDocument();
        }
        update() {
          this.__applyLegalDocument();
        }
        destroy() {
          if (
            this.__legalDocumentController &&
            typeof this.__legalDocumentController.destroy === "function"
          ) {
            this.__legalDocumentController.destroy();
          }
          this.__legalDocumentController = null;
        }
        __applyLegalDocument() {
          if (!this.__mprConnected) {
            return;
          }
          var options = buildLegalDocumentOptionsFromAttributes(this);
          if (this.__legalDocumentController) {
            this.__legalDocumentController.update(options, true);
          } else {
            this.__legalDocumentController = createLegalDocumentController(
              this,
              options,
            );
          }
        }
      };
    });
  }

  function defineBandElement(registry) {
    registry.define("mpr-band", function setupBandElement(Base) {
      return class MprBandElement extends Base {
        constructor() {
          super();
          this.__bandController = null;
        }
        static get observedAttributes() {
          return BAND_ATTRIBUTE_NAMES;
        }
        render() {
          this.__applyBand();
        }
        update() {
          this.__applyBand();
        }
        destroy() {
          if (this.__bandController && typeof this.__bandController.destroy === "function") {
            this.__bandController.destroy();
          }
          this.__bandController = null;
        }
        __applyBand() {
          if (!this.__mprConnected) {
            return;
          }
          var options = buildBandOptionsFromAttributes(this);
          if (this.__bandController) {
            this.__bandController.update(options);
          } else {
            this.__bandController = createBandController(this, options);
          }
        }
      };
    });
  }

  function defineCardElement(registry) {
    registry.define("mpr-card", function setupCardElement(Base) {
      return class MprCardElement extends Base {
        constructor() {
          super();
          this.__cardController = null;
        }
        static get observedAttributes() {
          return CARD_ATTRIBUTE_NAMES;
        }
        render() {
          this.__applyCard();
        }
        update() {
          this.__applyCard();
        }
        destroy() {
          if (this.__cardController && typeof this.__cardController.destroy === "function") {
            this.__cardController.destroy();
          }
          this.__cardController = null;
        }
        __applyCard() {
          if (!this.__mprConnected) {
            return;
          }
          var options = buildCardOptionsFromAttributes(this);
          if (this.__cardController) {
            this.__cardController.update(options);
          } else {
            this.__cardController = createCardController(this, options);
          }
        }
      };
    });
  }

  function registerCustomElements(namespace) {
    if (
      !namespace ||
      typeof namespace.createCustomElementRegistry !== "function"
    ) {
      return;
    }
    var registry = namespace.createCustomElementRegistry();
    if (!registry || (typeof registry.supports === "function" && !registry.supports())) {
      return;
    }
    defineHeaderElement(registry);
    defineDropdownElement(registry);
    defineFooterElement(registry);
    defineThemeToggleElement(registry);
    defineLoginButtonElement(registry);
    defineAuthProviderChooserElement(registry);
    definePasswordAuthElement(registry);
    defineAccountPanelElement(registry);
    defineAuthDiagnosticsElement(registry);
    defineUserMenuElement(registry);
    defineSettingsElement(registry);
    defineDetailDrawerElement(registry);
    defineWorkspaceLayoutElement(registry);
    defineSidebarNavElement(registry);
    defineEntityRailElement(registry);
    defineEntityTileElement(registry);
    defineEntityWorkspaceElement(registry);
    defineEntityCardElement(registry);
    defineSitesElement(registry);
    defineLegalDocumentElement(registry);
    defineBandElement(registry);
    defineCardElement(registry);
  }

  var HTMLElementBridge =
    typeof global.HTMLElement === "function"
      ? global.HTMLElement
      : class HTMLElementShim {};

  var MprElement = (function () {
    function createElementClass() {
      return /** @class */ (function (_super) {
        function MprElementClass() {
          var self = Reflect.construct(_super, [], new.target || MprElementClass);
          var elementInstance = /** @type {MprElementLifecycle} */ (self);
          elementInstance.__mprConnected = false;
          return self;
        }
        MprElementClass.prototype = Object.create(_super.prototype);
        MprElementClass.prototype.constructor = MprElementClass;
        MprElementClass.prototype.connectedCallback = function connectedCallback() {
          var elementInstance = /** @type {MprElementLifecycle} */ (this);
          elementInstance.__mprConnected = true;
          if (typeof elementInstance.render === "function") {
            elementInstance.render();
          }
        };
        MprElementClass.prototype.disconnectedCallback = function disconnectedCallback() {
          var elementInstance = /** @type {MprElementLifecycle} */ (this);
          elementInstance.__mprConnected = false;
          if (typeof elementInstance.destroy === "function") {
            elementInstance.destroy();
          }
        };
        MprElementClass.prototype.attributeChangedCallback =
          function attributeChangedCallback(name, oldValue, newValue) {
            var elementInstance = /** @type {MprElementLifecycle} */ (this);
            if (!elementInstance.__mprConnected) {
              return;
            }
            if (typeof elementInstance.update === "function") {
              elementInstance.update(name, oldValue, newValue);
            }
          };
        return MprElementClass;
      })(HTMLElementBridge);
    }
    try {
      return createElementClass();
    } catch (_error) {
      return (function () {
        function FallbackElement() {
          HTMLElementBridge.call(this);
          var elementInstance = /** @type {MprElementLifecycle} */ (this);
          elementInstance.__mprConnected = false;
        }
        FallbackElement.prototype = Object.create(
          (HTMLElementBridge && HTMLElementBridge.prototype) || Object.prototype,
        );
        FallbackElement.prototype.constructor = FallbackElement;
        FallbackElement.prototype.connectedCallback = function connectedCallback() {
          var elementInstance = /** @type {MprElementLifecycle} */ (this);
          elementInstance.__mprConnected = true;
          if (typeof elementInstance.render === "function") {
            elementInstance.render();
          }
        };
        FallbackElement.prototype.disconnectedCallback = function disconnectedCallback() {
          var elementInstance = /** @type {MprElementLifecycle} */ (this);
          elementInstance.__mprConnected = false;
          if (typeof elementInstance.destroy === "function") {
            elementInstance.destroy();
          }
        };
        FallbackElement.prototype.attributeChangedCallback =
          function attributeChangedCallback(name, oldValue, newValue) {
            var elementInstance = /** @type {MprElementLifecycle} */ (this);
            if (!elementInstance.__mprConnected) {
              return;
            }
            if (typeof elementInstance.update === "function") {
              elementInstance.update(name, oldValue, newValue);
            }
          };
        return FallbackElement;
      })();
    }
  })();

  function createCustomElementRegistry(target) {
    var rootObject = target || global;
    var customElementsApi =
      (rootObject && rootObject.customElements) ||
      (rootObject && rootObject.window && rootObject.window.customElements) ||
      null;
    var cache = Object.create(null);
    function supportsCustomElements() {
      return (
        customElementsApi &&
        typeof customElementsApi.define === "function" &&
        typeof customElementsApi.get === "function"
      );
    }
    return {
      define: function define(tagName, setupCallback) {
        var normalizedName = String(tagName);
        if (cache[normalizedName]) {
          return cache[normalizedName];
        }
        if (!supportsCustomElements()) {
          cache[normalizedName] = null;
          return null;
        }
        if (typeof setupCallback !== "function") {
          throw new Error(
            "createCustomElementRegistry.define requires a setup callback",
          );
        }
        var definition = setupCallback(MprElement);
        if (!definition) {
          throw new Error(
            "createCustomElementRegistry.define requires the setup callback to return a class",
          );
        }
        customElementsApi.define(normalizedName, definition);
        cache[normalizedName] = definition;
        return definition;
      },
      get: function get(tagName) {
        if (cache[tagName]) {
          return cache[tagName];
        }
        if (!supportsCustomElements()) {
          return null;
        }
        return customElementsApi.get(tagName);
      },
      supports: supportsCustomElements,
    };
  }

  var namespace = ensureNamespace(global);
  namespace.createAuthHeader = createAuthHeader;
  namespace.createAuthOptions = createAuthOptions;
  namespace.authenticatedFetch = authenticatedFetch;
  namespace.resolveAuthProfileSnapshot = resolveAuthProfileSnapshot;
  namespace.renderAuthHeader = renderAuthHeader;
  namespace.getFooterSiteCatalog = getFooterSiteCatalog;
  namespace.getLegalProfile = getLegalProfile;
  namespace.getLegalDocument = buildLegalDocument;
  namespace.renderLegalDocument = createLegalDocumentController;
  namespace.getBandProjectCatalog = getBandProjectCatalog;
  namespace.configureTheme = function configureTheme(config) {
    return themeManager.configure(config || {});
  };
  namespace.setThemeMode = function setThemeMode(mode) {
    return themeManager.setMode(mode, "external");
  };
  namespace.getThemeMode = themeManager.getMode;
  namespace.onThemeChange = themeManager.on;
  namespace.createSelectionState = createSelectionState;
  namespace.createCustomElementRegistry = createCustomElementRegistry;
  namespace.MprElement = MprElement;
  if (!namespace.testing || typeof namespace.testing !== "object") {
    namespace.testing = {};
  }
  namespace.testing.authenticate = authenticateForTesting;
  namespace.testing.unauthenticate = unauthenticateForTesting;
  namespace.testing.prepareRedirectProvider = prepareRedirectProviderForTesting;
  namespace.testing.navigateRedirectProvider = navigateRedirectProviderForTesting;
  namespace.testing.googleIdentity = {
    isDriverAvailable: isGoogleIdentityTestingDriverAvailable,
    isInitialized: isGoogleIdentityTestingInitialized,
    getInitializedNonce: getGoogleIdentityTestingInitializedNonce,
    getInitializeCallCount: getGoogleIdentityTestingInitializeCallCount,
    enableAutoCredentialOnClick: enableGoogleIdentityTestingAutoCredentialOnClick,
  };
  if (!namespace.__dom) {
    namespace.__dom = {};
  }
  namespace.__dom.mountHeaderDom = mountHeaderDom;
  namespace.__dom.mountFooterDom = mountFooterDom;
  if (!namespace.__utils) {
    namespace.__utils = {};
  }
  namespace.__utils.normalizeLinkForRendering = normalizeLinkForRendering;
  registerCustomElements(namespace);
})(typeof window !== "undefined" ? window : globalThis);
