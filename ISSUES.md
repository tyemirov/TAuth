# ISSUES (Append-only Log)

Entries record newly discovered requests or changes, with their outcomes. No instructive content lives here. Read @NOTES.md for the process to follow when fixing issues.

Read AGENTS.md , ARCHITECTURE.md , POLICY.md , NOTES.md ,  README.md and ISSUES.md . Start working on open issues. Work autonomously and stack up PRs

## Features (100–199)

- [ ] [TA-100] Make TAuth multitenant. Deliver implementation plan and document it as open issues in @ISSUES.md

## Improvements (212–299)

- None.

## BugFixes (330–399)

- [x] [TA-332] Ensure the cancellat context is propagated. Currently Ctrl-C in the docker container leaves the app in non-exited state and requires a second ctrl-C — Server now shares a signal-aware context across validator and database initialization, runs shutdown with a single 10s timeout path, and exits cleanly on first context cancellation (covered by `TestRunServerHonorsContextCancellation`).
```
tauth-1 exited with code 1 (restarting)
Gracefully Stopping... press Ctrl+C again to force
 Container docker-compose-tauth-1  Stopping
 Container docker-compose-tauth-1  Stopped
^C
12:37:23 tyemirov@Vadyms-MacBook-Pro:~/Development/tyemirov/TAuth/examples/docker-compose - [improvement/TA-333-compose-build] $ 
```

## Maintenance (410–499)

- [x] [TA-400] Update the documentation @README.md and focus on the usefullness to the user. Move the technical details to ARCHITECTURE.md. — README now surfaces the hosted + local deployments, points custom flows at ARCHITECTURE.md, and the detailed GIS/nonce handshake (with sample code) was moved under `ARCHITECTURE.md#google-sign-in-exchange`.

## Planning
So not work on these, not ready

