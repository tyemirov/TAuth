#!/usr/bin/env bash
set -euo pipefail

readonly fixture_root="tests/fixtures/deployment-config"
readonly valid_fixture="${fixture_root}/browser-demo.json"
readonly unknown_fixture="${fixture_root}/unknown-field.json"
readonly missing_fixture="${fixture_root}/missing-output.json"
readonly fixture_secret="fixture-renderer-secret-at-least-32-characters"
readonly missing_fixture_secret="fixture-missing-output-secret-at-least-32-characters"

umask 077
test_root="$(mktemp -d)"
binary_path="${test_root}/tauth"
config_path="${test_root}/config.yml"
doctor_path="${test_root}/doctor.json"
stderr_path="${test_root}/stderr"

cleanup() {
  cleanup_status=$?
  rm -rf "${test_root}"
  exit "${cleanup_status}"
}
trap cleanup EXIT

go build -o "${binary_path}" ./cmd/server
"${binary_path}" render-deployment-config <"${valid_fixture}" >"${config_path}"
"${binary_path}" validate-service-config "${config_path}" >"${doctor_path}"
rg -q '"valid":true' "${doctor_path}"
if rg -q '^tenants:' "${config_path}"; then
  echo 'renderer emitted obsolete runtime tenant configuration' >&2
  exit 1
fi
rg -Fq 'tenant_encryption_key: ${TAUTH_TENANT_ENCRYPTION_KEY}' "${config_path}"
rg -Fq 'enable_tenant_header_override: true' "${config_path}"
rg -Fq 'issuer: https://auth.example.invalid' "${config_path}"

if "${binary_path}" render-deployment-config <"${unknown_fixture}" >/dev/null 2>"${stderr_path}"; then
  printf '%s\n' 'renderer accepted an unknown request field' >&2
  exit 1
fi
grep -Fq 'deployment_config.invalid_request' "${stderr_path}"
grep -Fq 'unknown field "unknown"' "${stderr_path}"

if "${binary_path}" render-deployment-config <"${missing_fixture}" >/dev/null 2>"${stderr_path}"; then
  printf '%s\n' 'renderer accepted a missing private output' >&2
  exit 1
fi
grep -Fq 'deployment_config.invalid_output' "${stderr_path}"
grep -Fq 'google-web-client-id' "${stderr_path}"

if grep -Fq "${fixture_secret}" "${stderr_path}" || grep -Fq "${missing_fixture_secret}" "${stderr_path}"; then
  printf '%s\n' 'renderer exposed a private output in diagnostics' >&2
  exit 1
fi

node tests/deployment-config-renderer-cases.mjs "${binary_path}" "${valid_fixture}"

printf '%s\n' 'TAUTH_DEPLOYMENT_CONFIG_RENDERER_OK'
