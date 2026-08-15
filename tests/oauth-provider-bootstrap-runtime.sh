#!/usr/bin/env bash
set -euo pipefail

readonly image_name="tauth-oauth-provider-bootstrap:contract-$$"
readonly health_path="/health"
readonly metadata_path="/.well-known/oauth-authorization-server"
readonly expected_status="200"
readonly readiness_attempt_count="100"
readonly issuer="https://tauth-api.mprlab.com"

umask 077
test_root="$(mktemp -d)"
config_path="${test_root}/config.yaml"
data_path="${test_root}/data"
doctor_output_path="${test_root}/doctor.json"
health_output_path="${test_root}/health.body"
metadata_output_path="${test_root}/metadata.json"
container_id=""
readonly test_private_key_base64="$(
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null |
    base64 |
    tr -d '\n'
)"

cleanup() {
  cleanup_status=$?
  if [ -n "${container_id}" ]; then
    docker container rm --force "${container_id}" >/dev/null 2>&1 || true
  fi
  docker image rm "${image_name}" >/dev/null 2>&1 || true
  rm -rf "${test_root}"
  exit "${cleanup_status}"
}
trap cleanup EXIT

mkdir -p "${data_path}"
printf '%s\n' \
  'server:' \
  '  listen_addr: ":8080"' \
  '  database_url: "sqlite:///data/tauth.db"' \
  '  enable_cors: false' \
  '' \
  'oauth:' \
  '  enabled: true' \
  "  issuer: \"${issuer}\"" \
  "  authorization_endpoint: \"${issuer}/oauth/authorize\"" \
  "  token_endpoint: \"${issuer}/oauth/token\"" \
  "  revocation_endpoint: \"${issuer}/oauth/revoke\"" \
  "  jwks_uri: \"${issuer}/oauth/jwks\"" \
  "  login_endpoint: \"${issuer}/oauth/login\"" \
  "  consent_endpoint: \"${issuer}/oauth/consent\"" \
  '  authorization_request_ttl: "5m"' \
  '  authorization_code_ttl: "1m"' \
  '  active_signing_key_id: "oauth-bootstrap"' \
  '  signing_keys:' \
  '    - id: "oauth-bootstrap"' \
  "      private_key_base64: \"${test_private_key_base64}\"" \
  '  client_metadata:' \
  '    request_timeout: "3s"' \
  '    maximum_bytes: 5120' \
  '    minimum_cache_ttl: "1m"' \
  '    maximum_cache_ttl: "1h"' \
  '' \
  'tenants:' \
  '  - id: "existing"' \
  '    display_name: "Existing Tenant"' \
  '    tenant_origins: ["https://existing.example.com"]' \
  '    google_web_client_id: "existing.apps.googleusercontent.com"' \
  '    jwt_signing_key: "existing-session-signing-key"' \
  '    session_cookie_name: "session_existing"' \
  '    refresh_cookie_name: "refresh_existing"' \
  '    session_ttl: "15m"' \
  '    refresh_ttl: "720h"' \
  '    nonce_ttl: "5m"' >"${config_path}"

docker build --pull --tag "${image_name}" .

if ! docker run --rm --network none \
  --mount "type=bind,src=${config_path},dst=/config/config.yaml,readonly" \
  "${image_name}" doctor /config/config.yaml --json >"${doctor_output_path}"; then
  cat "${doctor_output_path}" >&2
  exit 1
fi

if ! grep -Eq '"valid": ?true' "${doctor_output_path}"; then
  cat "${doctor_output_path}" >&2
  exit 1
fi

container_id="$(docker run --detach \
  --publish "127.0.0.1::8080" \
  --mount "type=bind,src=${config_path},dst=/config/config.yaml,readonly" \
  --mount "type=bind,src=${data_path},dst=/data" \
  "${image_name}" --config /config/config.yaml)"
host_port="$(docker container inspect --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}' "${container_id}")"
health_url="http://127.0.0.1:${host_port}${health_path}"
metadata_url="http://127.0.0.1:${host_port}${metadata_path}"

health_status=""
for attempt in $(seq 1 "${readiness_attempt_count}"); do
  health_status="$(curl --connect-timeout 1 --max-time 1 --output "${health_output_path}" --silent --write-out '%{http_code}' "${health_url}" || true)"
  if [ "${health_status}" = "${expected_status}" ]; then
    break
  fi
  if ! docker container inspect "${container_id}" >/dev/null 2>&1; then
    docker container logs "${container_id}" >&2 || true
    exit 1
  fi
  sleep 0.1
done

if [ "${health_status}" != "${expected_status}" ]; then
  docker container logs "${container_id}" >&2 || true
  exit 1
fi

metadata_status="$(curl --connect-timeout 1 --max-time 1 \
  --output "${metadata_output_path}" \
  --silent \
  --show-error \
  --write-out '%{http_code}' \
  "${metadata_url}")"
if [ "${metadata_status}" != "${expected_status}" ] || ! grep -Fq "\"issuer\":\"${issuer}\"" "${metadata_output_path}"; then
  cat "${metadata_output_path}" >&2
  exit 1
fi

printf '%s\n' 'TAUTH_OAUTH_PROVIDER_BOOTSTRAP_RUNTIME_OK'
