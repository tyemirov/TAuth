# ISSUES (Append-only Log)

Entries record newly discovered requests or changes, with their outcomes. No instructive content lives here. Read @NOTES.md for the process to follow when fixing issues.

## Features (100–199)

## Improvements (200–299)

- [x] [TA-200] Use GORM and abstract away the flavor of the DB through GORM. If the DB url sent through an envionment variable specifies postgres protocol, then use postgres, if sqlite, then use sqlite, etc — Resolved with `NewDatabaseRefreshTokenStore` (GORM, Postgres/SQLite), mandatory `--database_url` / `APP_DATABASE_URL`, legacy Postgres-only store removed, docs + tests added

## BugFixes (300–399)

## Maintenance (400–499)

- [x] [TA-400] Update the documentation @README.md and focus on the usefullness to the user. Move the technical details to ARCHITECTURE.md. — Delivered user-centric README and migrated deep technical content into the new ARCHITECTURE.md reference.
- [x] [TA-401] Ensure architrecture matches the reality of code. Update @ARCHITECTURE.md when needed. Review the code and prepare a comprehensive ARCHITECTURE.md file with the overview of the app architecture, sufficient for understanding of a mid to senior software engineer. — Expanded ARCHITECTURE.md with accurate flow descriptions, interfaces, dependency notes, and security guidance reflecting current code.
- [ ] [TA-402] Review @POLICY.md and verify what code areas need improvements and refactoring. Prepare a detailed plan of refactoring. Check for bugs, missing tests, poor coding practices, uplication and slop. Ensure strong encapsulation and following the principles og @AGENTS.md and policies of @POLICY.md
- [ ] [TA-403] preparea comprehensive code coverage. Use external tests (so no direct testing of internal functions) and strive to achive 95% code coverage using exposed API.

## Planning
