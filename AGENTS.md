# AGENTS.md

## Forward-Only Contract Discipline

This repository follows a forward-only, confident programming paradigm. This is a binding agent contract: no fallbacks, no backward compatibility, no legacy support, and no compatibility shims. Do not spend design or implementation effort on backward compatibility considerations except for explicit one-off data migrations into the current canonical contract.

Repeat for emphasis because this rule is binding: no fallbacks, no backward compatibility, no legacy compatibility. Delete or reject obsolete code paths, stale schemas, deprecated config, and old persisted shapes instead of preserving them through compatibility layers, dual reads/writes, aliases, or best-effort recovery.

One-off data migrations are allowed only when they move existing persisted data into the current schema in a bounded operation. After migration, remove the bridge and keep only the current contract.

## TAuth

Single-origin authentication service for Goole Identy Service designed for stand-alone front-end apps. See README.md for details

## Document Roles

- AGENTS.md: Read-only workflow + behavior playbook maintained by leads. Agents never edit it during implementation cycles.
- ISSUES.md: Log of newly discovered requests and changes. Each entry records what changed or what was discovered. Located at `.mprlab/ISSUES.md`.
- `.mprlab/<PLAN-ID>-PLAN.md`: Temporary execution plan. Use `.mprlab/PLANNING.md` for the plan ID.

### Document Precedence

- `POLICY.md` (`.mprlab/POLICY.md`) defines binding validation, error-handling, and "confident programming" rules.
- `AGENTS.md` (this file) defines repo-wide workflow, testing philosophy, and agent behavior; stack-specific AGENTS.* guides refine these rules for each technology.
- `AGENTS.*.md` files (in `.mprlab/`) never contradict `AGENTS.md` or `POLICY.md`; if guidance appears inconsistent, defer to `POLICY.md` first, then `AGENTS.md`, and treat the stack guide as a refinement.

### Issue Status Terms

- Resolved: Completed and verified; no further action (`[x]`).
- Unresolved: Needs decision and/or implementation (`[ ]`).
- Blocked: Requires an external dependency or policy decision (`[!]`); must include a `Blocked:` explanation in the issue body.

### Validation & Confidence Policy

All rules for validation, error handling, invariants, and "confident programming" (no defensive checks, edge-only validation, smart constructors, CI gates) are defined in `.mprlab/POLICY.md`. Treat that document as binding; this file does not restate them.

### Build & Test Commands

- Use the repository `Makefile` for local automation. Invoke `make test`, `make lint`, `make ci`, or other documented targets instead of running ad-hoc tool commands.
- `make test` runs the canonical test suite for the active stack.
- `make lint` enforces linting rules before code review.
- `make ci` mirrors the CI workflow and should pass locally before opening a PR.

## Workflow

Operational playbook for working in this repository. Use it to coordinate planning, execution, and delivery. Code style, stack-specific rules, and tooling details remain in the `.mprlab/AGENTS.*` documents; this section focuses purely on day-to-day process.

### Authoritative References

- `AGENTS.md` + per-stack guides (`.mprlab/AGENTS.*.md`) for coding standards.
- `.mprlab/POLICY.md` for validation/confident-programming rules.
- `.mprlab/AGENTS.GIT.md` for Git/GitHub workflow.
- `.mprlab/AGENTS.DOCKER.md` for container expectations.
- `.mprlab/ISSUES.FORMAT.md` for the canonical ISSUES.md entry format specification.
- `README.md` for product context.

### Workflow Overview

1. Run `make ci` before any code changes to establish a clean baseline. Fix any pre-existing failures before proceeding.
2. Read `AGENTS.md` (plus relevant stack guides in `.mprlab/`) before touching code.
3. For backlog selection, review the backlog in `.mprlab/ISSUES.md`. Work sequentially through BugFixes, Improvements, Maintenance, then Features. Planning is reserved for future work. Do not implement Planning items.
4. For the active issue, read `.mprlab/PLANNING.md`. Make the execution plan that this contract specifies.
5. Implement the requested change, keeping to stack-specific standards. Limit edits to necessary files plus issue-document updates when required.
6. Run `make ci` to verify all tests, linting, and formatting pass.
7. Report what changed and any blockers.

### Completion Gate (Non-negotiable)

1. Requested file/documentation changes are implemented.
2. Any required issue status/notes updates are made in `.mprlab/ISSUES.md`.
3. Blockers are reported clearly when present.
4. `make ci` passes.

### Testing & Tooling

- Use `Makefile` targets (`make test`, `make lint`, `make ci`) for local verification.
- Run stack-specific formatters only when the issue requires local validation output or explicit formatting changes.

### Git & Release Flow

- `master` is production. Work branches use taxonomy prefixes (`feature/`, `improvement/`, `bugfix/`, `maintenance/`, `blocked/`) outlined in `.mprlab/AGENTS.GIT.md`.
- Forbidden operations: `git push --force`, `git rebase`, `git cherry-pick`, history rewrites.

### Output Requirements

- Always follow AGENTS* rules; do not restate them in PRs.
- Begin every implementation with the execution plan that `.mprlab/PLANNING.md` specifies.
- Do not touch `AGENTS.md` during normal work; treat it as read-only guidance.
- `.mprlab/ISSUES.md` tracks issue status; mark items `[x]` with a concise resolution note once tests pass.
- Keep each execution plan untracked. If Git tracks a plan, remove it with `git filter-repo --path-glob '.mprlab/*-PLAN.md' --invert-paths`.
- Summaries at the end of each issue should list changed files.

### Pre-Finish Checklist

1. The execution plan for the active issue shows the final execution state.
2. `.mprlab/ISSUES.md` entry is marked `[x]` with the resolution note.
3. Requested implementation and documentation updates are complete.
4. Any blockers are documented with concrete failure context.
5. Provide a short summary plus next steps before moving to the next issue.

If any checklist item is incomplete, do not claim completion. Complete the missing step(s) first.

### Action Items Reminder

- Before planning, use the task-specific reading conditions in the MPR Lab Governance section.
- For product or integration changes, read the relevant product documents and runbooks.
  References: `README.md`.
- Keep working sequentially through the backlog — never parallelize issues.
- Add missing issues to `.mprlab/ISSUES.md` if you discover new work while investigating; plan and resolve them in order.

### Testing Philosophy

- Testing follows an **inverted test pyramid**: heavy bias to high-value black-box integration and end-to-end tests that exercise external public APIs.
- We **strive for (approximately) 100% test coverage**, with CI enforcing an agreed threshold. If coverage drops, add scenarios at the public entry points; do not chase coverage with isolated unit tests.
- For the Go backend, tests run the real HTTP server and call real endpoints, capturing responses and asserting observable results — not internal functions.
- For the frontend, tests run the app and backing web server, drive flows through the browser or JSDOM, and assert against the rendered page, DOM state, events, and other user-visible behavior.
- Use focused unit tests for complex algorithms, calculations, and isolated logic when useful.
- Require integration coverage of public behavior for product acceptance.

## Tech Stack Guides

Stack-specific instructions live in `.mprlab/`. Apply the relevant guide alongside the shared policies above.

- Front-End (Browser ES Modules, vanilla JS): `.mprlab/AGENTS.FRONTEND.md`
- Backend (Go): `.mprlab/AGENTS.GO.md`
- Docker and containerization: `.mprlab/AGENTS.DOCKER.md`
- Git and version control workflow: `.mprlab/AGENTS.GIT.md`

<!-- BEGIN MPRLAB-GOVERNANCE -->
## MPR Lab Governance

Root `AGENTS.md` is the agent entrypoint. Shared rules live under `.mprlab/`.

Read `.mprlab/POLICY.md` for every task.
Read the following files only when their condition applies.
Read each selected guide in full before its first applicable action.

- Before edits: `.mprlab/PLANNING.md`.
- For technical prose: `.mprlab/AGENTS.DOCS.md` and `.mprlab/TERMINOLOGY.md`.
- For issue work: the selected issue and its dependencies in `.mprlab/ISSUES.md`.
- For tracker edits: `.mprlab/issues-md-format.md`.
- For Git operations: `.mprlab/AGENTS.GIT.md`.
- For HTTP or gRPC API changes: `.mprlab/AGENTS.API.md`.
- For Go changes: `.mprlab/AGENTS.GO.md`.
- For browser changes: `.mprlab/AGENTS.FRONTEND.md`.
- For container changes: `.mprlab/AGENTS.DOCKER.md`.

File permission modes are outside agent scope.
Never examine, validate, compare, require, change, or record a file permission mode.
Never use a file permission mode in acceptance, security, credential, execution, publication, deployment, or failure analysis.
The values `0600` and `7777` have no governance meaning.
This rule does not change service authorization or operation authority.

Do not create `.mprlab/AGENTS.md`. Scoped guidance belongs in `.mprlab/AGENTS.*.md` files.
If guidance conflicts, obey `.mprlab/POLICY.md` first, then root `AGENTS.md`, then the applicable scoped guide.
<!-- END MPRLAB-GOVERNANCE -->
