#!/usr/bin/env bash
set -euo pipefail

application_root="$1"
gateway_executable="$2"
go_executable="$3"
if ! command -v "$gateway_executable" >/dev/null 2>&1; then
  printf 'Gateway runtime is unavailable: %s. Install a released runtime and add its command directory to PATH.\n' "$gateway_executable" >&2
  exit 2
fi
cd "$application_root"
exec "$gateway_executable" bootstrap-run --repo-root "$application_root" --operation app-deploy -- \
  "$go_executable" run ./deployment/rollout "$application_root" "$gateway_executable"
