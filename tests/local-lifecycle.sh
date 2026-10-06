#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export TAUTH_LOCAL_RUNTIME="$(mktemp -d)"
export TAUTH_LOCAL_PROJECT="tauth-local-test-$$"
export TAUTH_LOCAL_WEB_PORT=18083
export TAUTH_LOCAL_API_PORT=18082
trap 'docker compose -f local/compose.yml down --volumes --remove-orphans; rm -rf "${TAUTH_LOCAL_RUNTIME}"' EXIT
make up
native_platform="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')"
frontend_container="$(docker compose -f local/compose.yml ps --quiet frontend)"
frontend_platform="$(docker container inspect "${frontend_container}" --format '{{.ImageManifestDescriptor.Platform.OS}}/{{.ImageManifestDescriptor.Platform.Architecture}}')"
if [[ "${frontend_platform}" != "${native_platform}" ]]; then
  printf 'Frontend platform %s does not match Docker platform %s.\n' "${frontend_platform}" "${native_platform}" >&2
  exit 1
fi
printf 'Native frontend platform verified: %s\n' "${frontend_platform}"
curl --fail --silent "http://localhost:${TAUTH_LOCAL_API_PORT}/.well-known/oauth-authorization-server" |
  python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["issuer"]=="http://localhost:18082"'
node tests/local-console.browser.cjs
key_digest="$(shasum -a 256 "${TAUTH_LOCAL_RUNTIME}/runtime.env")"
docker compose -f local/compose.yml exec -T tauth sh -c 'test -s /data/tauth.db; printf retained > /data/lifecycle-test'
make up
make down
make up
test "${key_digest}" = "$(shasum -a 256 "${TAUTH_LOCAL_RUNTIME}/runtime.env")"
docker compose -f local/compose.yml exec -T tauth sh -c 'test -s /data/tauth.db; test "$(cat /data/lifecycle-test)" = retained; rm /data/lifecycle-test'
node tests/local-console.browser.cjs
make down
test -z "$(docker compose -f local/compose.yml ps --quiet)"
make down
printf '%s\n' TAUTH_LOCAL_LIFECYCLE_OK
