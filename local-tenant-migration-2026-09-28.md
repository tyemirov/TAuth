# Local tenant migration: 2026-09-28

I215 selects complete local definitions for the existing owner account.
The migration runs outside the service through the separate GORM executable.
It introduces no personal account behavior.

## Selection

The scan found 22 complete tenant definitions after duplicate selection.
The selection prefers each application's local configuration over its Gateway copy.
The dedicated Pinguin configuration takes precedence over the copy in LoopAware.
Tenant IDs and configuration values remain unchanged.

| Tenant ID | Selected repository |
| --- | --- |
| `download-your-data-local` | `download_your_data/configs/tauth.local.yml` |
| `gravity` | `gravity/configs/config.tauth.yml` |
| `hecate` | `Hecate/tauth.config.local.yaml` |
| `iroom-local` | `interview_room/iRoom/local/tauth.yaml` |
| `kamu` | `mprlab-gateway/configs/config.tauth.yml` |
| `kamu-local` | `Kamu/configs/local/tauth.yaml` |
| `ledger-local` | `ledger/demo/configs/tauth.config.yaml` |
| `llm-proxy` | `llm-proxy/configs/tauth.local.yml` |
| `loopaware` | `loopaware/configs/config.tauth.yml` |
| `mediaops` | `mprlab-gateway/configs/config.tauth.yml` |
| `mpr-ui-delivery-admin` | `mpr-ui/demo/tauth-config.yaml` |
| `mprlab-investors-local` | `marcopolo.github.io/config/investor-local/tauth.yml` |
| `namesignal` | `NameSignal/configs/tauth-config.yaml` |
| `pb-dev` | `mprlab-gateway/configs/config.tauth.yml` |
| `pinguin` | `pinguin/configs/config.tauth.yml` |
| `prompt-bubbles` | `mprlab-gateway/configs/config.tauth.yml` |
| `prompt-bubbles-dev` | `prompts/tauth-config.yaml` |
| `ps` | `mprlab-gateway/configs/config.tauth.yml` |
| `social-threader` | `social_threader/configs/tauth.local.yml` |
| `summercan` | `SummerCan/configs/tauth-config.yaml` |
| `tyemirov-gallery-development` | `tyemirov.github.io/local/tauth.yaml` |
| `writers-block` | `WriterBlock/ops/tauth/config.yaml` |

The incomplete `mpr-sites` definition has no configured email-delivery API key.
The PoodleScanner local template has unresolved environment inputs.
Neither incomplete source is imported.
The complete `mpr-ui-delivery-admin` sibling is included.
The complete Gateway `ps` definition is included.

## Initial result and correction

The initial I215 import stored 22 inactive definitions.
That result did not satisfy the requirement for active tenants.
B098 replaced the inactive result through a separate GORM data migration.
The application has no account-specific migration behavior.

Hecate and NameSignal both used `app_session` and `app_refresh` on localhost.
The corrected snapshot assigns `tauth_hecate_session` and `tauth_hecate_refresh` to Hecate.
It assigns `tauth_namesignal_session` and `tauth_namesignal_refresh` to NameSignal.
The other 20 tenants retain their cookie names.
Fifteen tenants require an explicit tenant ID because their application origins overlap.
The repair preserves all keys, providers, origins, lifetimes, and ownership.

One imported tenant requires the OAuth authorization server.
The local service now supplies its issuer configuration with a persistent local signing key.
The local issuer is `http://localhost:8082`.

## Current destination state

The destination is the retained local `tauth-local_tauth_data` volume.
All 28 tenants belong to 19 Apps under owner `J6NfFX3MVfAMfplROmxJdg`.
The original 22 tenants are active at revision 2. Six additional manifest tenants are active at revision 1.
Revision 1 remains unchanged as the original import record.
The service accepts authentication requests for all 28 tenants.

## Repair evidence

The original receipt ID is `local-development-20260928`.
The repair receipt ID is `local-import-activation-b098`.
Private snapshots, backups, receipts, comparisons, and HTTP results remain under `.cache/tauth-local/repair-b098/`.
These files contain credentials or operational data and remain outside version control.

The rehearsal and actual repair both activated all 22 definitions.
The repeated actual invocation returned the identical receipt without additional revisions.
The comparison verified the permitted cookie and header changes.
It also verified unchanged original revisions and 29 unrelated tables.
Those tables include accounts, identities, sessions, owner bindings, and console configuration.
The stopped database backup passed its integrity check before the repair.

`make test-deployment-migration`, `make test-console`, and `make ci` passed.
The HTTP integration test verified Google login, refresh, profile isolation, and independent logout for tenants with a shared origin.
That test injects Google token validation and uses the real service and database.
The migration tests verified rollback, repeated execution, ownership, unchanged keys, and rejection of edited imports.
The local lifecycle test verified issuer metadata and signing-key persistence across restarts.

`make up` restarted the retained local stack after the repair.
Both local services report healthy.
Live local requests returned 200 for nonce creation for every imported tenant.
Unauthenticated profile requests returned 401 for every imported tenant.
A request with a shared origin and no tenant header returned 404.
An unregistered origin returned 403.
The console retained the selected Google client ID.
Live Google credential qualification and production deployment remain separate operations.

## App hierarchy result

F017 added App membership through the separate deployment migration.
The explicit map is `deployment/migrations/local-apps-20260928.json`.
Kamu contains `kamu` and `kamu-local`.
Prompt Bubbles contains `pb-dev`, `prompt-bubbles`, and `prompt-bubbles-dev`.
Each other tenant has its own named App.

The rehearsal and actual migration both produced 19 Apps with 22 active tenants.
The comparison found no changes to existing data across 33 tables.
Tenant IDs, keys, configurations, revisions, users, identities, and sessions stayed unchanged.
All database integrity and foreign-key checks passed.
Private backups and results remain under `.cache/tauth-local/apps-f017/`.
The local database had no provisioning credentials to assign.

`make ci` and the actual Gateway client tests passed.
The automated browser verified App creation, tenant selection, automatic persistence, and account isolation.
`make up` started both local services successfully.
The console serves the App selector. All 22 live tenant nonce requests returned 200.
The console Google client ID stayed unchanged.
Production migration and deployment were not performed.

## Deployment manifest correction

B103 corrected an incomplete source inventory. The earlier scan omitted deployment manifests.
The recursive scan found eight additional tenant IDs, including the nested iRoom repository.
Six definitions passed canonical contribution validation and were imported into their existing Apps.

| Tenant ID | App | Source repository |
| --- | --- | --- |
| `download-your-data` | Download Your Data | `download_your_data` |
| `ledger` | Ledger | `ledger` |
| `mpr-ui-demo` | MPR UI | `mpr-ui` |
| `mprlab-investors` | MPR Lab Investors | `marcopolo.github.io` |
| `tyemirov-gallery` | Gallery | `tyemirov.github.io` |
| `iroom` | iRoom | `interview_room/iRoom` |

Each source uses `.mprlab/deploy/resources.yml` and its declared private environment inputs.
The separate migration command uses the canonical contribution resolver to produce private snapshots.
The import keeps each source ID, provider configuration, key, cookie name, and origin.
No existing tenant definition was replaced.

The MailGoblin declaration contains only its ID and name. It has no complete authentication configuration.
The ISSUES.md environment lacks `TAUTH_GITHUB_CREDENTIAL_KEY` and `ISSUES_MD_MCP_GITHUB_CREDENTIALS_KEY`.
These two definitions remain excluded under the complete-definitions-only requirement.

The rehearsal and actual import both produced 28 active tenants in 19 Apps.
Repeated imports returned the same receipts. Existing rows across 36 tables stayed unchanged.
All database integrity and foreign-key checks passed.
Private snapshots and comparisons remain under `.cache/tauth-local/manifest-b103/`.
The receipt identifiers use the `manifest-b103-` prefix and the imported tenant ID.

`make test-deployment-migration` and `make ci` passed.
All 28 live nonce requests returned 200 after `make up`.
The console Google client ID stayed unchanged. Production services were not changed.

I217 replaced the App dropdown with compact App rows and tenant counts.
The selected App expands into its tenant list. The desktop and mobile interfaces use the same navigation.
Browser tests verified navigation, automatic persistence, account isolation, and compact control dimensions.
The layout uses the Smith MPR styling tokens. Dialogs support Escape and backdrop dismissal.
