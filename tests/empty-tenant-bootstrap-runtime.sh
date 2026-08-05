#!/usr/bin/env bash
set -euo pipefail

readonly image_name="tauth-empty-tenant-bootstrap:contract-$$"
readonly container_port="8080/tcp"
readonly health_path="/health"
readonly inactive_auth_path="/auth/nonce"
readonly expected_health_status="200"
readonly expected_inactive_auth_status="403"
readonly readiness_attempt_count="100"

test_root="$(mktemp -d)"
config_path="${test_root}/config.yaml"
data_path="${test_root}/data"
doctor_output_path="${test_root}/doctor.json"
health_output_path="${test_root}/health.body"
auth_output_path="${test_root}/auth.body"
container_id=""

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
  '  enable_cors: true' \
  '  cors_allowed_origins:' \
  '    - "https://accounts.google.com"' \
  '  cors_allowed_origin_exceptions:' \
  '    - "https://accounts.google.com"' \
  '  enable_tenant_header_override: false' \
  '' \
  'tenants: []' >"${config_path}"

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

if grep -q '"tenant_ids"' "${doctor_output_path}"; then
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
auth_url="http://127.0.0.1:${host_port}${inactive_auth_path}"

health_status=""
for attempt in $(seq 1 "${readiness_attempt_count}"); do
  health_status="$(curl --connect-timeout 1 --max-time 1 --output "${health_output_path}" --silent --write-out '%{http_code}' "${health_url}" || true)"
  if [ "${health_status}" = "${expected_health_status}" ]; then
    break
  fi
  if ! docker container inspect "${container_id}" >/dev/null 2>&1; then
    docker container logs "${container_id}" >&2 || true
    exit 1
  fi
  sleep 0.1
done

if [ "${health_status}" != "${expected_health_status}" ]; then
  docker container logs "${container_id}" >&2 || true
  exit 1
fi

auth_status="$(curl --connect-timeout 1 --max-time 1 \
  --header 'Origin: https://no-tenant.example.invalid' \
  --output "${auth_output_path}" \
  --silent \
  --show-error \
  --write-out '%{http_code}' \
  "${auth_url}")"
if [ "${auth_status}" != "${expected_inactive_auth_status}" ]; then
  cat "${auth_output_path}" >&2
  exit 1
fi

printf '%s\n' 'TAUTH_EMPTY_TENANT_BOOTSTRAP_RUNTIME_OK'
