# Isolated test fixtures

F020 supplies a separate executable for consumer integration tests.
The executable creates an isolated encrypted store through TAuth-owned APIs.
It creates a synthetic owner, App, and active application tenant.
It also creates a separate reserved console tenant.
The production service and image do not contain this executable or a fixture command.

## Build and delivery

Use the repository toolchain and lockfiles.

```sh
CI=1 make build-test-fixture </dev/null
```

The output is `.cache/tauth-test-fixture`.
The package is `github.com/tyemirov/tauth/cmd/testfixture`.
The required build tag is `tauth_testfixture`.
Use `TEST_FIXTURE_OUTPUT` to select an explicit output file.

Supply the reviewed executable through the consumer's declared `TAUTH_TEST_FIXTURE_BIN` input.
Use an absolute path to an immutable candidate artifact.
Record its SHA-256 and build identity before consumer validation.
Do not infer a sibling checkout or search `PATH` for another executable.

A hosted pipeline must acquire a declared fixture artifact before it starts consumer CI.
This task does not publish the executable.
A currently published module or `@latest` image must not be assumed to contain F020.
After F020 publication, use the declared `@latest` acquisition input:

```sh
fixture_tools="$(pwd)/.cache/test-tools"
mkdir -p "$fixture_tools"
CI=1 GOBIN="$fixture_tools" go install -tags=tauth_testfixture \
  github.com/tyemirov/tauth/cmd/testfixture@latest </dev/null
export TAUTH_TEST_FIXTURE_BIN="$fixture_tools/testfixture"
```

Go installation names this executable `testfixture`.
The local Make target names its artifact `tauth-test-fixture`.
The explicit absolute path is the consumer interface.
Until `@latest` contains F020, this acquisition command cannot supply the tool.
Do not invoke publication as part of fixture preparation.

## Fixture declaration

Put generated declarations and secret-bearing outputs in the project's ignored test directory.
Supply all fields from the declared smoke profile.
The following JSON shows the complete closed schema.
Its signing key is synthetic test data.

```json
{
  "schema": "tauth.test-fixture.v1",
  "test_only": true,
  "app_id": "prompt-bubbles-smoke",
  "server": { "listen_addr": ":8081" },
  "tenant": {
    "id": "prompt-bubbles-smoke",
    "display_name": "Prompt Bubbles Smoke",
    "origin": "http://localhost:32123",
    "google_web_client_id": "fixture-web.apps.googleusercontent.com",
    "google_native_client_id": "fixture-native.apps.googleusercontent.com",
    "jwt_signing_key": "synthetic-test-signing-key",
    "session_cookie_name": "prompts_session",
    "refresh_cookie_name": "prompts_refresh",
    "session_ttl": "30m",
    "refresh_ttl": "720h",
    "nonce_ttl": "10m"
  }
}
```

All displayed fields are required.
Unknown fields, multiple JSON documents, empty values, and outer whitespace cause an error.
The application and tenant IDs must differ from `tauth-console`.
The origin must use HTTP or HTTPS with `localhost` or a literal loopback IP address.
Paths, credentials, query strings, and fragments are prohibited in the origin.
The listener requires an explicit port and supports the container's declared network interface.
The tool validates provider settings, cookie names, and positive lifetimes through the current tenant contract.

The fixture uses an empty cookie domain and permits HTTP for its loopback origin.
The service enables CORS and tenant header selection.
The tool does not accept a database URL, an overwrite option, or production import arguments.

## Output and runtime

Run the executable with closed standard input.
The output parent directory must exist.
The output directory must not exist.

```sh
CI=1 /absolute/path/tauth-test-fixture \
  --input .cache/smoke/fixture.json \
  --output-dir .cache/smoke/prepared </dev/null
```

An existing output directory causes an error before database access.
A rejected declaration creates no output directory.
A failed preparation removes its incomplete output.
The tool generates fresh encryption material for each successful preparation.
Equivalent declarations produce equivalent logical state, not identical encrypted bytes.

| File | Contract |
| --- | --- |
| `tauth.db` | The isolated owner, App, tenant, and encrypted configuration store. |
| `service.yaml` | Service settings with the generated encryption key and `sqlite:///tauth-fixture/tauth.db`. |
| `validator.yaml` | The existing independent validator schema shown below. |
| `receipt.json` | The schema, input SHA-256, build identity, App ID, tenant ID, and mount path. |

The service configuration does not contain a `tenants` field.
The receipt does not contain signing keys or encryption material.
The validator export contains only this shape:

```yaml
tenants:
  - id: prompt-bubbles-smoke
    jwt_signing_key: synthetic-test-signing-key
    session_cookie_name: prompts_session
```

Mount the complete prepared directory at `/tauth-fixture` with database write access.
Start the ordinary service with `--config /tauth-fixture/service.yaml`.
Use the listener port declared in the fixture input.
Mount `validator.yaml` separately at the consumer's declared validator path.
Keep this prepared store for service restarts.
Do not run preparation again to restart the service.
Keep normal development startup and hosted deployment separate from this test setup.

## Validation and limits

```sh
CI=1 make test-test-fixture </dev/null
CI=1 make ci </dev/null
```

The CLI acceptance verifies rejected inputs, existing-data preservation, encrypted secrets, and backend validator authorization.
The container acceptance builds the current production service image from source.
It verifies the actual application tenant's nonce and an existing-store restart.
The consumer must separately verify compatibility with its selected service image and record that image's digest.

The fixture tool does not enroll a production owner or issue browser sessions.
A nonce response proves active tenant configuration, not Google authentication.
The backend authorization test uses synthetic signed claims.
These checks do not prove live provider connectivity or a completed Google login.
