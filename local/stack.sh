#!/usr/bin/env bash
set -euo pipefail
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_root}"
compose=(docker compose --file local/compose.yml)
export TAUTH_LOCAL_RUNTIME="${TAUTH_LOCAL_RUNTIME:-${repository_root}/.cache/tauth-local}"
runtime="${TAUTH_LOCAL_RUNTIME}"
console_origin="http://localhost:${TAUTH_LOCAL_WEB_PORT:-8081}"
api_origin="http://localhost:${TAUTH_LOCAL_API_PORT:-8082}"

case "${1:?expected up or down}" in
  down)
    "${compose[@]}" down --remove-orphans
    printf '%s\n' 'TAuth stopped. The database and local keys remain available.'
    exit 0
    ;;
  up) ;;
  *) printf '%s\n' 'Expected up or down.' >&2; exit 2 ;;
esac

docker info >/dev/null
TAUTH_LOCAL_PLATFORM="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')"
export TAUTH_LOCAL_PLATFORM
mkdir -p "${runtime}"
if [[ ! -f "${runtime}/runtime.env" ]]; then
  google_client_id="${TAUTH_LOCAL_GOOGLE_CLIENT_ID:-611549676198-d8800qv64voofseor1qod1euto5duivu.apps.googleusercontent.com}"
  [[ "${google_client_id}" =~ ^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$ ]] || {
    printf '%s\n' 'TAUTH_LOCAL_GOOGLE_CLIENT_ID must be a Google Web client ID.' >&2
    exit 2
  }
  encryption_key="$(openssl rand -base64 32)"
  session_key="$(openssl rand -hex 32)"
  {
    printf 'TAUTH_TENANT_ENCRYPTION_KEY=%s\n' "${encryption_key}"
    printf 'TAUTH_CONSOLE_SESSION_KEY=%s\n' "${session_key}"
    printf 'TAUTH_CONSOLE_GOOGLE_CLIENT_ID=%s\n' "${google_client_id}"
    printf 'TAUTH_CONSOLE_ORIGIN=%s\n' "${console_origin}"
  } > "${runtime}/runtime.env.tmp"
  mv "${runtime}/runtime.env.tmp" "${runtime}/runtime.env"
fi

if ! grep -q '^TAUTH_LOCAL_OAUTH_SIGNING_KEY_BASE64=' "${runtime}/runtime.env"; then
  oauth_signing_key="$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null | base64 | tr -d '\n')"
  printf 'TAUTH_LOCAL_OAUTH_SIGNING_KEY_BASE64=%s\n' "${oauth_signing_key}" >> "${runtime}/runtime.env"
fi
export TAUTH_LOCAL_API_ORIGIN="${api_origin}"

mkdir -p "${runtime}/site/app"
cp -R docs/. "${runtime}/site/"
cp -R web/app/. "${runtime}/site/app/"
cp web/tauth.js "${runtime}/site/tauth.js"
printf '{"api_origin":"%s"}\n' "${api_origin}" > "${runtime}/site/app/runtime.json"

"${compose[@]}" build tauth
"${compose[@]}" run --rm --no-deps tauth --config /config/service.yaml console-bootstrap --tenant-file /config/console.yaml
"${compose[@]}" up --detach --remove-orphans --wait --wait-timeout 90
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 --max-time 5 \
  "${console_origin}/app/" >/dev/null
curl --fail --silent --show-error --max-time 5 \
  "${api_origin}/.well-known/tauth-console" >/dev/null
printf 'TAuth is ready.\nConsole: %s/app/\nAPI: %s\nStop with make down.\n' "${console_origin}" "${api_origin}"
