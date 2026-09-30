#!/usr/bin/env bash
set -euo pipefail

application_root="$1"
gateway_executable="$2"
go_executable="$3"
if ! command -v "$gateway_executable" >/dev/null 2>&1; then
  printf 'Gateway runtime is unavailable: %s. Install a released runtime and add its command directory to PATH.\n' "$gateway_executable" >&2
  exit 2
fi
operator_root="${MPRLAB_GATEWAY_OPERATOR_ROOT:-$HOME/.config/mprlab-gateway}"
# Use only the canonical files for their owned values.
unset TAUTH_TENANT_ENCRYPTION_KEY MPRLAB_TAUTH_MANAGEMENT_URL MPRLAB_TAUTH_PROVISIONING_CREDENTIALS
while IFS= read -r variable_name; do unset "$variable_name"; done < <(compgen -v DEPLOY_SUDO_PASSWORD_)
set -a
source "$application_root/.mprlab/deploy/.env"
source "$operator_root/private.env"
set +a
cd "$application_root"
exec "$go_executable" run ./deployment/rollout "$application_root" "$gateway_executable"
