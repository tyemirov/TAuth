# Confident Programming

This policy controls all agent work in this repository.

## Operator Rules

- Validate only at edges: I/O, HTTP, CLI, DB adapters, browser bootstrap, imported files, and other external boundaries.
- Design HTTP APIs as resource-oriented REST APIs. Use standard HTTP methods, status codes, and semantics.
- For gRPC APIs, obey protobuf service and RPC conventions. REST constraints do not apply.
- Make illegal states unrepresentable with domain types, smart constructors, dataclasses, enums, or closed action objects.
- Fail fast on impossible states.
- Wrap boundary errors with operation and subject context.
- After boundary validation, do not repeat validation in core modules.
- Keep interfaces narrow. Prefer domain types instead of loose strings, maps, booleans, or `any` values.
- Centralize reusable literals: paths, operation names, event names, config keys, status values, and shared messages.
- Tests target public contracts and invariants, not defensive branches.
- Prefer black-box integration and end-to-end tests through real entry points.

## Automatic Data Updates And Persistence

This is a binding product principle for every user interface.

- Load current data automatically when a view opens and when its relevant data changes.
- Update stale data automatically after reconnection and when the user returns to the view.
- Never require or expose refresh or reload controls for data synchronization.
- Persist valid user edits automatically. Never require or expose save controls for data persistence.
- Show pending, saved, validation, conflict, and failure states without requiring a manual refresh or save.
- Preserve unsaved edits during background updates, request failures, and concurrent changes.
- Serialize writes and retain newer edits when an earlier write completes.
- Keep explicit controls for user intent, such as creation, deletion, activation, and confirmation of consequential actions.
- Do not use an explicit action as a substitute for automatic data persistence.
- Verify automatic updates, persistence, error recovery, and account isolation through public interface tests.

## Test-Driven Development

- Use test-driven development with an inverted test pyramid.
- Integration tests are the primary test layer.
- Use focused unit tests for complex algorithms, calculations, and isolated logic when useful.
- Require integration coverage of public behavior for product acceptance.
- An integration test must use a real public entry point.
- For a behavior change, start with the integration test that represents the required public behavior.
- Run the new or changed integration test before you change production code.
- Confirm that the integration test fails because the required behavior is absent or incorrect.
- After this failure, use focused unit tests to guide complex internal implementation when useful.
- Change the minimum production code necessary to make the integration test pass.
- Refactor only while the applicable integration tests pass.
- For a refactor with no behavior change, run the applicable integration tests before you change production code.
- If focused coverage is absent, add a characterization test before the refactor.
- Use deterministic local infrastructure for repository-owned databases, filesystems, queues, servers, and browsers.
- At an external provider boundary, use a provider sandbox or a local protocol implementation for routine integration tests.
- Keep live-provider acceptance as a separate qualification step.

## Dependency Injection In Integration Tests

- Use dependency injection for integration scenarios that are difficult to reproduce.
- Inject the dependency that creates the test condition.
- Use controlled clocks, dependency failures, or unusual responses when the scenario requires them.
- Keep the product logic under test and its related internal interactions real.
- Assert observable results through the public contract.
- Keep integration coverage with real dependency implementations.
- Injected scenarios prove behavior under the specified conditions. They do not prove actual provider connectivity.
- Qualify actual provider connectivity separately from injected scenarios.

## Prohibited Patterns

- Silent fallbacks, best-effort behavior, legacy aliases, and compatibility reads unless an explicit product requirement says the behavior is current.
- Duplicated validation inside core modules.
- Exporting invalid zero-values as usable domain objects.
- Swallowing errors.
- Increasing waits or timeouts as the primary fix for flakiness.
- Boolean parameters that switch unrelated behaviors.
- Hardcoded workflow, path, event, or message literals when a canonical constant or backend payload exists.

## Device Validation

- Never require a physical device or physical-device access for any task or gate, under any circumstances.
- Apply this prohibition to development, tests, validation, acceptance, issue closure, release, publication, and deployment.
- Never ask the user to provide, obtain, connect, or arrange access to physical devices or physical-device test services.
- Use simulators, emulators, and automated browsers for device validation.
- Accept these environments as sufficient for device validation and acceptance.
- Remove physical-device requirements and blockers from the selected task and its current acceptance records.
- Never replace a removed physical-device gate with another hardware prerequisite.
- Report the actual test environment and observed results without claiming physical-device execution.

## File Permission Boundary

- File permission modes are outside agent scope.
- Never examine, validate, compare, require, change, or record a file permission mode.
- Never use a file permission mode in acceptance, security, credential, execution, publication, deployment, or failure analysis.
- The values `0600` and `7777` have no governance meaning.
- This rule does not change service authorization or operation authority.

## Application Deployment Contract

- Keep `make release && make publish && make deploy` as the complete production application procedure.
- Make `make release` validate source, package migrations, and seal all release artifacts.
- Make `make publish` publish the sealed artifacts without a rebuild.
- Make `make deploy` prepare private inputs and run pending timestamped migrations automatically.
- Keep application migration policy in this repository and resource convergence in the installed Gateway runtime.
- Give each migration one fixed timestamp identifier and a durable completion receipt.
- Back up the database and stop its writers before a data cutover.
- Commit migration data and its completion receipt together.
- Skip a completed migration during every subsequent deployment.
- Resume incomplete deployment work through `make deploy` without reversing committed data.
- Never require a separate production migration, bootstrap, credential-generation, or key-generation command.
- Generate a missing server encryption key automatically before the first encrypted database initialization.
- Keep that key across releases, deployments, restarts, and database recovery.
- Keep server encryption keys private. Never supply them to application clients.
- Keep existing client credentials and tenant session keys during a migration.
- Use “one-off migration” to mean a timestamped migration that runs automatically once within deployment.

## Selected Manifest Contract

Apply this section when the task changes or validates a selected application manifest.

- Keep the selected application manifest versionless.
- Keep `owner`, `release`, and `resources` as the current baseline fields.
- Apply the B607 execution policy contract before the general extension rules below.
- Declare CI and execution policy in `.mprlab/deploy/resources.yml`.
- Enable CI with the `make ci` command.
- Declare positive startup, completion, readiness, request, and shutdown timeouts.
- Declare finite polling for provider observations without a reliable event source.
- Keep execution policy outside Gateway defaults, separate files, CLI options, and environment overrides.
- After this cutover, each later gateway must accept every manifest that an earlier versionless gateway accepted.
- Keep each accepted field name, type, requirement, and function.
- A field added to an existing shape must be optional.
- A field added to an existing shape must have one canonical default.
- Normalize that default before manifest identity calculation.
- Add a resource kind only with one closed shape.
- Reject unknown fields and `schema_version`.

## Static Website Hosting

Apply this section to deployment or publication work for a browser frontend.

- Use GitHub Pages as the production host for each deployable browser frontend.
- Declare the browser frontend with a `github_pages` resource in `.mprlab/deploy/resources.yml`.
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
- Inspect the process environment before you request a login.
- Inspect repository private environment files before you report a credential blocker.
- Include ignored `.env`, `.env.*`, and `*.env` files in the authorized repository roots.
- Treat tracked example and sample environment files as documentation only.
- Search only for exact variable names. Do not print, copy, or record secret values.
- When a command declares one repository environment file as its input, clear
  its owned process variables and source only that file.
- Use the command's standard environment lookup. Do not add a credential parser
  or another input channel.
- When available, use a non-mutating authentication command to verify the discovered value.
- Request new credentials only after each authorized existing input fails verification.
- Report a credential blocker only after you complete this gate.

## Validation

- Use repository-native `make` targets.
- Do not run a pre-edit or per-issue `make ci` baseline.
- Preserve the expected failing integration-test result as implementation evidence.
- During the change, run the smallest public-entrypoint target that validates the changed contract.
- After the last stack change, run `make ci` once at the documented stack completion checkpoint.
- If this run reports an error, run the target that reports the error during the correction.
- After the last correction, run `make ci` once.
- Run `make verify` only when the operator explicitly selects the complete qualification lane.
- When `make ci` includes `make fmt`, `make lint`, and `make test`, use its result for those targets.
- During the change or error diagnosis, run the necessary component target.
- Run a component target when `make ci` does not include the necessary check.
- For documentation-only work, run the applicable document and repository checks.
- For `.mprlab/`-only work, run the Governor check and `git diff --check`.
- These are the repository checks for `.mprlab/`-only work. Changed prose also requires the documentation-language review.
- For read-only work, use source facts and run only the necessary checks.
- For frontend behavior, verify through a browser test when the behavior is user-visible.
- For services and CLIs, verify through HTTP, CLI, or public API entry points.

## Documentation Language

- Write new or changed English technical prose in ASD-STE100 Simplified Technical English, Issue 9.
- Read `.mprlab/AGENTS.DOCS.md` and `.mprlab/TERMINOLOGY.md` before you write technical prose.
- Apply this rule to PRDs, architecture documents, issues, plans, policies, ADRs, READMEs, runbooks, and API documents.
- Do not change technical meaning to make the language simpler.
- Run the skill `prepare-ste-reference` script to retrieve and verify the official Issue 9 PDF.
- Run the skill `check-ste` script on each technical document that you change.
- The producing agent must review Part 1 writing rules and the Part 2 dictionary.
- Do not assign the reference retrieval or language review to the end user.
- If the official reference is not available, report a blocker and do not claim compliance.

## Language Rules

### Go

- Use smart constructors returning `(Type, error)` when a type has invariants.
- Do not export invalid zero-values.
- Wrap errors with `%w`.
- Prefer integration tests through real HTTP, CLI, or package entry points.
- `make lint` must include `go vet`, `staticcheck`, and `ineffassign` when those tools are part of the repo contract.

### Python

- Use `@dataclass(frozen=True)` or Pydantic when already in use.
- Validate in constructors or edge adapters.
- Use type hints throughout.
- Use pytest for integration, end-to-end, and focused unit tests under the shared test-driven development rules.

### JavaScript And Frontend

- Put `// @ts-check` at the top of new or edited JavaScript modules when the repo uses checked JS.
- Use JSDoc typedefs for domain objects and payload contracts.
- Components render validated state and emit intent.
- Backend clients own request construction and response validation.
- User-visible behavior belongs in browser or integration coverage.

## Self-Check

Before claiming completion:

- External inputs are validated once at the edge.
- Core modules consume validated domain values.
- Error paths include operation and subject context.
- Reusable literals are centralized.
- Public behavior is covered through public entry points.
- Repo-native validation was run or a concrete blocker is documented.
