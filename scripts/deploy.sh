#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy.sh [--dry-run]

Parses the required local .env.deploy operator binding as data. A dry run
validates the configured Make directory and target without executing its
recipe. A deploy executes that exact target.

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
[[ -f "${deployment_config}" && ! -L "${deployment_config}" ]] || {
  printf 'error: local deployment config not found: %s\n' "${deployment_config}" >&2
  printf '%s\n' 'run: install -m 0600 .env.deploy.example .env.deploy; then set the local operator binding' >&2
  exit 1
}
[[ "$(find "${deployment_config}" -prune -type f -perm 0600 -print)" == "${deployment_config}" ]] || {
  printf '%s\n' 'error: .env.deploy must be a regular non-symlink file with mode 0600' >&2
  exit 1
}

DEPLOY_DIRECTORY=""
DEPLOY_MAKE_TARGET=""
deploy_directory_seen="false"
deploy_make_target_seen="false"
deployment_config_line_number=0
while IFS= read -r deployment_config_line || [[ -n "${deployment_config_line}" ]]; do
  deployment_config_line_number=$((deployment_config_line_number + 1))
  if [[ -z "${deployment_config_line}" || "${deployment_config_line}" == \#* ]]; then
    continue
  fi
  [[ "${deployment_config_line}" == *=* ]] || {
    printf 'error: invalid .env.deploy assignment at line %s\n' "${deployment_config_line_number}" >&2
    exit 1
  }
  deployment_config_key="${deployment_config_line%%=*}"
  deployment_config_value="${deployment_config_line#*=}"
  [[ "${deployment_config_key}" =~ ^[A-Z][A-Z0-9_]*$ ]] || {
    printf 'error: invalid .env.deploy key at line %s\n' "${deployment_config_line_number}" >&2
    exit 1
  }
  [[ -n "${deployment_config_value}" && "${deployment_config_value}" != [[:space:]]* && "${deployment_config_value}" != *[[:space:]] ]] || {
    printf 'error: invalid .env.deploy value for %s\n' "${deployment_config_key}" >&2
    exit 1
  }
  case "${deployment_config_key}" in
    DEPLOY_DIRECTORY)
      [[ "${deploy_directory_seen}" == "false" ]] || {
        printf '%s\n' 'error: DEPLOY_DIRECTORY is duplicated in .env.deploy' >&2
        exit 1
      }
      DEPLOY_DIRECTORY="${deployment_config_value}"
      deploy_directory_seen="true"
      ;;
    DEPLOY_MAKE_TARGET)
      [[ "${deploy_make_target_seen}" == "false" ]] || {
        printf '%s\n' 'error: DEPLOY_MAKE_TARGET is duplicated in .env.deploy' >&2
        exit 1
      }
      DEPLOY_MAKE_TARGET="${deployment_config_value}"
      deploy_make_target_seen="true"
      ;;
    *)
      printf 'error: unknown .env.deploy key: %s\n' "${deployment_config_key}" >&2
      exit 1
      ;;
  esac
done <"${deployment_config}"

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
