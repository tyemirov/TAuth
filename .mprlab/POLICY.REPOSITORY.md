# Repository Policy Sections

## Application Deployment Contract

- Expose only `make deploy` as the production application command.
- Call the installed `mprlab-gateway deploy --app-root` coordinator from that command.
- Let Gateway complete missing preparation, publication, deployment, and verification for one selected version.
- Keep `app-release`, `app-publish`, and `app-deploy` as internal manifest policy identifiers.
- Give the terminal deployment policy a completion budget for the full pipeline.
- Seal release artifacts and publish them without a rebuild.
- Call the installed Gateway directly from `make deploy`.
- Use the selected `resources.yml` as the only deployment specification.
- Preserve existing database records, client credentials, tenant session keys, and the server encryption key.
- Keep the retained database volume across application versions and restarts.
- Capture private inputs once through the selected manifest.
- Let the service apply its current database schema migrations at startup.
- Remove completed deployment cutover plans, executables, and readers.
- Do not require a separate migration, ownership, credential-generation, or key-generation command.
- Keep server encryption keys private and outside application clients.

## Selected Manifest Contract

The application uses the current Gateway v9 selected-manifest contract.
The current contract preserves existing provider data and permanent state-v1 fields.

- Keep the selected application manifest versionless.
- Keep `owner`, `release`, and `lifecycle` as the required baseline fields.
- Use the fixed `artifacts`, `publications`, and `targets` catalogs.
- Use explicit identity lists and ordered command lists.
- Declare CI and execution policy in the selected manifest's `lifecycle` field.
- Declare the CI command and its enabled state in the selected manifest.
- Declare positive startup, completion, readiness, request, and shutdown timeouts.
- Declare finite polling for provider observations without a reliable event source.
- Keep execution policy outside separate files, CLI options, and environment overrides.
- Preserve each accepted field name, type, requirement, and function after this cutover.
- Give each new optional field one canonical default or manifest inheritance rule.
- Normalize defaults and inheritance before manifest identity calculation.
- Add a declaration kind only with one closed shape.
- Reject obsolete root collection shapes, unknown fields, and `schema_version`.
