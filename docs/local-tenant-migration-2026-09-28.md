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
All 22 tenants belong to owner `J6NfFX3MVfAMfplROmxJdg`.
Each tenant is active at revision 2.
Revision 1 remains unchanged as the original import record.
The service accepts authentication requests for all 22 tenants.

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
