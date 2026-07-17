#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy.sh [--dry-run]

Loads the required local .env.deploy operator binding. A dry run validates the
configured Make directory and target without executing its recipe. A deploy
executes that exact target.

Options:
  --dry-run  Validate the local deployment binding without executing it
  --help     Show this help text
USAGE
}

dry_run="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      dry_run="true"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

command -v make >/dev/null 2>&1 || { printf '%s\n' 'error: make is required' >&2; exit 1; }

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
deployment_config="${repository_root}/.env.deploy"
[[ -f "${deployment_config}" ]] || {
  printf 'error: local deployment config not found: %s\n' "${deployment_config}" >&2
  printf '%s\n' 'copy .env.deploy.example to .env.deploy and set the local operator binding' >&2
  exit 1
}

DEPLOY_DIRECTORY=""
DEPLOY_MAKE_TARGET=""
set -a
source "${deployment_config}"
set +a

[[ -n "${DEPLOY_DIRECTORY}" ]] || { printf '%s\n' 'error: DEPLOY_DIRECTORY is required in .env.deploy' >&2; exit 1; }
[[ "${DEPLOY_DIRECTORY}" == /* ]] || { printf '%s\n' 'error: DEPLOY_DIRECTORY must be an absolute path' >&2; exit 1; }
[[ -d "${DEPLOY_DIRECTORY}" ]] || { printf 'error: DEPLOY_DIRECTORY does not exist: %s\n' "${DEPLOY_DIRECTORY}" >&2; exit 1; }
[[ -n "${DEPLOY_MAKE_TARGET}" ]] || { printf '%s\n' 'error: DEPLOY_MAKE_TARGET is required in .env.deploy' >&2; exit 1; }
[[ "${DEPLOY_MAKE_TARGET}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || {
  printf 'error: DEPLOY_MAKE_TARGET is invalid: %s\n' "${DEPLOY_MAKE_TARGET}" >&2
  exit 1
}

set +e
make --no-print-directory --directory "${DEPLOY_DIRECTORY}" --question "${DEPLOY_MAKE_TARGET}" >/dev/null 2>&1
target_status=$?
set -e
[[ "${target_status}" -le 1 ]] || {
  printf 'error: configured deployment Make target is unavailable: %s in %s\n' "${DEPLOY_MAKE_TARGET}" "${DEPLOY_DIRECTORY}" >&2
  exit 1
}

if [[ "${dry_run}" == "true" ]]; then
  printf 'deployment_config=%s\n' "${deployment_config}"
  printf 'deployment_directory=%s\n' "${DEPLOY_DIRECTORY}"
  printf 'deployment_make_target=%s\n' "${DEPLOY_MAKE_TARGET}"
  printf '%s\n' 'deployment_status=validated'
  exit 0
fi

exec make --no-print-directory --directory "${DEPLOY_DIRECTORY}" "${DEPLOY_MAKE_TARGET}"
