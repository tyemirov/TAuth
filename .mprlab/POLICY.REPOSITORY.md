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

## Static Website Hosting

Apply this section to deployment or publication work for a browser frontend.

- Use GitHub Pages as the production host for each deployable browser frontend.
- Declare the browser frontend with a `targets.github_pages.sites[]` declaration in `.mprlab/deploy/resources.yml`.
- Use `gh-pages` as the publication branch.
- The GitHub Pages repository can differ from the application repository.
- Keep API and service routes on hostnames that differ from the website hostname.
- Reserve the GitHub Pages domain and its `www` hostname for GitHub Pages.
- Treat a container as an artifact source only when its static output goes to GitHub Pages.
- Verify publication through the public website and `/.mprlab-release.json`.
- Run the Governor check after each selected manifest change and before each release, publish, or deploy operation.

## Credential Discovery

Apply this gate when the selected task requires credentials.

- Identify each required environment variable from the active command and repository contract.
- Treat tracked example and sample environment files as documentation only.
- Search only for exact variable names. Do not print, copy, or record secret values.

For selected-manifest lifecycle commands:

- Use the selected manifest as the sole lifecycle input authority.
- Keep `environment.source` optional. Declare each selected file explicitly in the manifest.
- Use process values before file values for declared environment references.
- Resolve declared inputs once at the selected manifest boundary.
- Pass captured inputs to child operations.
- Use captured values downstream without reading private environment files again.
- Diagnose missing credentials only through declared process references and the explicitly selected file.

For other commands:

- Use the active command's documented credential sources and standard environment lookup.
- Diagnose missing credentials only through those declared sources.
- Do not add a credential parser or another input channel.

For each command:

- Inspect its declared sources before you request a login or report a credential blocker.
- When available, use a non-mutating authentication command to verify the discovered value.
- Request new credentials only after each authorized existing input fails verification.
- Report a credential blocker only after you complete this gate.
