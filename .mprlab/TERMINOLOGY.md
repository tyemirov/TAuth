# Repository Terminology

This file contains the approved technical nouns and technical verbs for repository documentation.

Use this file with `.mprlab/AGENTS.DOCS.md` and ASD-STE100 Simplified Technical English, Issue 9.

Do not add a general dictionary word to this file. Use the ASD-STE100 dictionary for general words.

Give each term one meaning. Use the same term for the same concept in all documents.

## MPR Lab Technical Nouns

- `emulator`: Software that reproduces a device runtime for application tests.
- `physical device`: Hardware used to run an application or do a device test.
- `simulator`: Software that models a device environment for application tests.

- `acceptance criteria`: Conditions that show that a change has the necessary behavior.
- `active issue tracker`: The canonical file that contains current work.
- `ADR`: An architecture decision record.
- `adapter`: A code unit that connects a core module to an external system.
- `agent guide`: A file that gives binding instructions to an agent.
- `API`: A repository-owned application programming interface.
- `API contract`: The canonical schema and behavior of an API.
- `ASD-STE100`: The Simplified Technical English standard for technical documentation.
- `architecture`: The structure, boundaries, and ownership of a software system.
- `App Store Connect`: The Apple service that receives and manages iOS store artifacts.
- `artifact`: A file or image that a build, release, or generator creates.
- `backlog`: The set of unresolved issues in the active issue tracker.
- `backend client`: A code unit that sends requests to a backend.
- `browser frontend`: A user interface that operates in a web browser.
- `build`: A process or output that converts source code into an artifact.
- `changelog`: A file that records completed changes for releases.
- `CI`: The repository continuous-integration system.
- `CLI`: A command-line interface.
- `code path`: A sequence of operations in source code.
- `config`: Source-controlled configuration data.
- `container`: An isolated runtime package with an application and its dependencies.
- `contract`: A binding definition of behavior, data, or ownership.
- `documentation`: Technical information in repository documents.
- `coverage`: Evidence that tests exercise specified behavior.
- `dependency`: An external or internal component that a system requires.
- `deployment`: An operation that changes a runtime environment.
- `domain type`: A type that represents validated domain data.
- `EAS`: Expo Application Services for hosted build, submission, and update operations.
- `endpoint`: One HTTP API address and its operation.
- `end user`: The person who requests or receives the agent work.
- `Expo`: A framework and source config system for React Native mobile clients.
- `Expo CLI`: The Expo command-line tool for local development and native project generation.
- `Google Play`: The Google service that receives and manages Android store artifacts.
- `issue`: One tracked unit of work.
- `issue tracker`: A file or system that contains issues.
- `language checker`: A tool that finds specified language errors.
- `language review`: An agent-owned examination of text against language rules and terminology.
- `manifest`: A source-controlled file that declares resources or configuration.
- `mobile client`: An application for a mobile platform.
- `mobile store artifact`: A signed `.ipa` or `.aab` file for store publication.
- `native toolchain`: The platform tools that build and sign a mobile store artifact.
- `payload`: Structured data that crosses a system boundary.
- `Pinguin`: The MPR Lab notification service that queues email and SMS delivery.
- `PDF`: A file that uses the Portable Document Format.
- `PRD`: A product requirement document.
- `producing agent`: The agent that creates or changes technical prose.
- `pull request`: A proposed Git change for review and merge.
- `repository`: A source-controlled project and its files.
- `reference cache`: A private local directory that stores a verified official reference.
- `route`: An API or user-interface address and its handler.
- `runbook`: A technical procedure for an operator or agent.
- `runtime`: An operating instance of a service or application.
- `schema`: A machine-readable definition of structured data.
- `SHA-256`: A cryptographic digest that identifies the verified official reference.
- `source code`: Human-readable instructions that define software behavior.
- `source blocker`: A failure that prevents access to a necessary official source.
- `stack guide`: An agent guide for one language, framework, or runtime.
- `STE reference`: The verified official ASD-STE100 PDF that controls a language review.
- `store publisher`: A repository-owned tool that submits a mobile store artifact directly to its store.
- `technical document`: A repository document that contains technical information or instructions.
- `technical noun`: A subject-field noun that the repository approves.
- `technical prose`: English technical text outside code and source-controlled literals.
- `technical verb`: A subject-field verb that the repository approves.
- `validation`: Evidence that a change obeys its current contract.
- `worktree`: A Git checkout that has its own working directory.

- `characterization test`: An integration test that records current public behavior before a refactor.
- `file permission mode`: A number or symbol that gives filesystem access bits.
- `GitHub Pages`: The GitHub service that hosts a static website from a repository branch.
- `integration test`: A test of real product logic and component interactions through a public entry point, with controlled dependencies when necessary.
- `inverted test pyramid`: The MPR Lab test strategy with integration tests as the primary layer and focused unit tests where useful.
- `production code`: Source code that implements repository behavior outside the test suite.
- `public entry point`: An interface through which a user or caller uses repository behavior.
- `static website`: A browser frontend that uses generated files without a website server runtime.
- `test-driven development`: A coding sequence that uses a failing integration test before a production code change.
- `unit test`: A test that isolates one code unit from its collaborators.
- `website hostname`: The hostname that identifies a public static website.

- `dependency injection`: A design that supplies a component's dependencies from outside that component.

- `automatic persistence`: Storage of valid user edits without a manual save action.
- `data synchronization`: An update that brings a view into agreement with current stored data.
- `modal`: A dialog that holds input focus until the user closes it.
- `migration snapshot`: A fixed collection of effective configuration values for a bounded data migration.

## Repository Technical Nouns

- `public user ID`: The fixed tenant-scoped account identifier that TAuth supplies to applications and uses in session claims.
- `internal account ID`: The opaque identifier that TAuth uses for its account resources.
- `application subject`: The public user ID in a signed TAuth session or OAuth credential.

- `timestamped migration`: A fixed deployment data change with a timestamp identifier and a durable completion receipt.
- `one-off migration`: A timestamped migration that runs automatically once within `make deploy`.
- `server encryption key`: The private TAuth key that protects stored tenant and console configuration.
- `cutover`: The bounded transfer from the previous persisted configuration to the current database contract.

- `Web Locks`: The browser API that serializes operations across pages with the same origin.
- `request budget`: The maximum number of requests permitted within one time window.
- `cooldown`: The time that must pass before another request is permitted.
- `bcrypt`: The password hash algorithm used by TAuth.

- `App`: An account-owned resource that contains related application tenants.

- `tenant console`: The TAuth browser frontend through which an owner configures application tenants.
- `owner account`: A console account that owns Apps through a verified TAuth subject.
- `application tenant`: An isolated TAuth configuration and its application users, credentials, and sessions.
- `console tenant`: The reserved TAuth tenant that authenticates tenant console owners.
- `control plane`: The API and storage that manage tenant ownership and configuration.
- `runtime snapshot`: One immutable set of active tenant settings used for a request.
- `activation revision`: The persisted configuration revision that the runtime currently uses.
- `origin proof`: Evidence that an owner controls a specified production hostname.
- `setup check`: A recorded integration test result for one tenant configuration revision.
- `reauthentication`: A fresh identity verification for one protected owner operation.
- `cookie site`: The scheme and registrable domain used by browser SameSite cookie rules.
- `address pinning`: Use of one resolved network address for a bounded destination check.
- `DNS rebinding`: A change in DNS answers that redirects a later connection to another network address.
- `base64`: A text encoding for byte values.
- `session key`: The tenant-specific HS256 secret used to sign and validate session cookies.
- `secret export`: An authorized response that contains a secret for backend installation.
- `ETag`: An HTTP representation identifier used to detect concurrent changes.
- `idempotency key`: A request identifier that prevents duplicate resource creation during retries.
- `DNS TXT record`: A DNS text record used to prove hostname control.
- `reverse proxy`: A server that forwards a request to another server and returns its response.
- `CORS`: The browser protocol that controls access to responses from another origin.
- `HS256`: The HMAC SHA-256 algorithm used for TAuth session signatures.

- `customer value`: The measurable benefit that a product change gives its users.
- `platform account`: One account that a person can use across participating MPR Lab applications.
- `shared identity`: A stable person identifier and approved profile data available to participating applications.
- `single sign-on`: Authentication in another participating application through an existing central login session.
- `GitHub identity`: The provider identity whose subject is the immutable numeric GitHub user ID.
- `provider identity`: A verified provider name and subject associated with one tenant account.
- `identity claim`: A signed OAuth claim that discloses a verified provider identity to an authorized resource.
- `login transaction`: A single-use record that binds browser authentication to its tenant, provider, and approved destination.
- `MCP`: Model Context Protocol, through which an agent discovers and calls application tools.
- `popup`: A separate browser window that completes an authentication transaction for its initiating page.
- `CSRF`: Cross-site request forgery, an attack that induces an unauthorized request through another user's browser.
- `access token`: A short-lived signed token that permits an exact client grant at one protected resource.
- `authorization code`: A short-lived one-time value that a client exchanges for tokens with PKCE.
- `authorization server`: The TAuth component that gets user consent and issues resource-bound tokens.
- `deployment config renderer`: The TAuth CLI command that converts normalized
  resource contributions into one validated native config.
- `Client ID Metadata Document`: An HTTPS JSON document that describes one public OAuth client.
- `consent grant`: A time-bounded user approval for one client, resource, scope set, and disclosure policy.
- `disclosure policy`: The mapping from requested resource scopes to identity providers presented for user consent.
- `disclosure policy digest`: The SHA-256 digest that identifies one disclosure policy.
- `JWKS`: A JSON Web Key Set that contains the public OAuth verification keys.
- `OAuth`: The authorization protocol that TAuth uses to issue first-party resource tokens.
- `PKCE`: The Proof Key for Code Exchange binding between an authorization request and a token request.
- `protected resource`: A service that accepts a resource-bound TAuth access token.
- `render request`: The schema-v1 JSON document that contains normalized TAuth
  resource contributions and resolved output envelopes.
- `refresh-token family`: The sequence of opaque rotating refresh tokens for one application session or OAuth consent grant.
- `resource indicator`: The exact protected-resource identifier that becomes the access-token audience.

## MPR Lab Technical Verbs

- `archive`: Move completed history from the active issue tracker to durable storage.
- `authenticate`: Confirm the identity of a client or user.
- `authorize`: Confirm that an identity can do an operation on a resource.
- `build`: Convert source code into an executable or generated artifact.
- `cache`: Store a verified reference outside a target repository for repeated use.
- `commit`: Record a Git change in repository history.
- `configure`: Set source-controlled values that control system behavior.
- `deploy`: Change a runtime environment to use a specified artifact and configuration.
- `file`: Add an issue to the active issue tracker.
- `generate`: Create an artifact from its canonical source.
- `lint`: Use static rules to find source or document errors.
- `merge`: Add the changes from a pull request to its target branch.
- `normalize`: Change a file to obey one canonical format or contract.
- `parse`: Convert input data into a typed internal value.
- `publish`: Make an artifact available outside the source repository.
- `refactor`: Change code structure without a change to public behavior.
- `regenerate`: Create a generated artifact again from its canonical source.
- `redistribute`: Provide a third-party reference outside its approved distribution method.
- `render`: Convert source data into a visible or machine-readable output.
- `retrieve`: Get an official reference from its approved source.
- `review`: Examine an artifact against its requirements and record the result.
- `scan`: Use an automated process to find specified source patterns.
- `serialize`: Convert a typed value into a transport or storage representation.
- `validate`: Confirm that an input or artifact obeys its contract.
- `verify`: Confirm a result at its public or runtime boundary.

- `persist`: Store application data durably.
- `refresh`: Retrieve current application data for a view.
- `save`: Write edited application data to its durable store.
- `synchronize`: Bring displayed application data into agreement with its current source.

Use the simple present, simple past, simple future, imperative, or infinitive form of these verbs.

## Repository Technical Verbs

Add repository-specific technical verbs below this line.

```text
- `term`: Definition with one meaning and the approved verb forms.
```
