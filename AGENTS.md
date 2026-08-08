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
- PLAN.md: Working plan for one concrete change/issue; ephemeral and replaced per change.

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
3. Review the backlog in `.mprlab/ISSUES.md`; work sequentially through BugFixes, Improvements, Maintenance, then Features. Planning is reserved for future work; do not implement Planning items.
4. For the active issue, create `PLAN.md` (ignored by git) with bullet steps. Keep it updated and delete/rewrite it for the next issue.
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
- Begin every implementation with an up-to-date `PLAN.md`.
- Do not touch `AGENTS.md` during normal work; treat it as read-only guidance.
- `.mprlab/ISSUES.md` tracks issue status; mark items `[x]` with a concise resolution note once tests pass.
- `PLAN.md` must remain untracked. If it enters git history, remove it via `git filter-repo --path PLAN.md --invert-paths` before continuing.
- Summaries at the end of each issue should list changed files.

### Pre-Finish Checklist

1. `PLAN.md` reflects the final state for the active issue.
2. `.mprlab/ISSUES.md` entry is marked `[x]` with the resolution note.
3. Requested implementation and documentation updates are complete.
4. Any blockers are documented with concrete failure context.
5. Provide a short summary plus next steps before moving to the next issue.

If any checklist item is incomplete, do not claim completion. Complete the missing step(s) first.

### Action Items Reminder

- Read guiding docs (`README.md`, `AGENTS*`, `.mprlab/POLICY.md`) before planning.
- Keep working sequentially through the backlog — never parallelize issues.
- Add missing issues to `.mprlab/ISSUES.md` if you discover new work while investigating; plan and resolve them in order.

### Testing Philosophy

- Testing follows an **inverted test pyramid**: heavy bias to high-value black-box integration and end-to-end tests that exercise external public APIs.
- We **strive for (approximately) 100% test coverage**, with CI enforcing an agreed threshold. If coverage drops, add scenarios at the public entry points; do not chase coverage with isolated unit tests.
- For the Go backend, tests run the real HTTP server and call real endpoints, capturing responses and asserting observable results — not internal functions.
- For the frontend, tests run the app and backing web server, drive flows through the browser or JSDOM, and assert against the rendered page, DOM state, events, and other user-visible behavior.
- Unit tests are generally discouraged and may be prohibited by your stack guide. Only use unit tests when the relevant stack guide explicitly allows them, and never use them as a substitute for black-box coverage.

## Tech Stack Guides

Stack-specific instructions live in `.mprlab/`. Apply the relevant guide alongside the shared policies above.

- Front-End (Browser ES Modules, vanilla JS): `.mprlab/AGENTS.FRONTEND.md`
- Backend (Go): `.mprlab/AGENTS.GO.md`
- Docker and containerization: `.mprlab/AGENTS.DOCKER.md`
- Git and version control workflow: `.mprlab/AGENTS.GIT.md`

<!-- BEGIN MPRLAB-GOVERNANCE -->
## MPR Lab Governance

Most workflow context files live under `.mprlab/`. The root `AGENTS.md` remains the repository entrypoint for agents.

Read these files before editing:

- `.mprlab/POLICY.md`: binding validation and confident-programming rules.
- `.mprlab/PLANNING.md`: durable planning contract.
- `.mprlab/AGENTS.DOCS.md`: ASD-STE100 documentation rules.
- `.mprlab/TERMINOLOGY.md`: approved repository technical terms.
- `.mprlab/issues-md-format.md`: issue tracker format and recurring identifier rules.
- `.mprlab/ISSUES.md`: active issue tracker.
- `.mprlab/AGENTS.GIT.md`: Git and pull request workflow.
- `.mprlab/AGENTS.API.md`: RESTful HTTP and gRPC API guidance.
- `.mprlab/AGENTS.GO.md`: Go guidance.
- `.mprlab/AGENTS.FRONTEND.md`: browser frontend guidance.
- `.mprlab/AGENTS.DOCKER.md`: Docker and container guidance.

Do not create `.mprlab/AGENTS.md`. Scoped guidance belongs in `.mprlab/AGENTS.*.md` files.
If guidance conflicts, follow `.mprlab/POLICY.md` first, then root `AGENTS.md`, then the relevant scoped guide.
<!-- END MPRLAB-GOVERNANCE -->
