#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy.sh [options]

Deploys the published TAuth image through mprlab-gateway after verifying that
the release image has been published. TAuth serves its API and shared helper
from the app container, so this command does not publish GitHub Pages.

Options:
  --gateway-dir <path>  Gateway checkout. Default: $GATEWAY_DIR or sibling ../mprlab-gateway
  --image <value>       Image repository. Default: $DOCKER_IMAGE or ghcr.io/tyemirov/tauth
  --tag <value>         Release tag. Default: v* tag pointing at HEAD
  --skip-ci             Skip local make ci deployment gate
  --skip-image-verify   Skip release/latest image digest verification
  --skip-backend        Skip gateway deployment
  --help                Show this help text
USAGE
}

env_or_default() {
  local name="$1"
  local fallback="$2"
  local value=""
  if [[ -v "${name}" ]]; then
    value="${!name}"
  fi
  if [[ -n "${value}" ]]; then
    printf "%s\n" "${value}"
  else
    printf "%s\n" "${fallback}"
  fi
}

GATEWAY_DIR="$(env_or_default GATEWAY_DIR "")"
IMAGE_REPOSITORY="$(env_or_default DOCKER_IMAGE ghcr.io/tyemirov/tauth)"
TAG="$(env_or_default DEPLOY_TAG "")"
SKIP_CI="false"
SKIP_IMAGE_VERIFY="false"
SKIP_BACKEND="false"
DEFAULT_BRANCH="master"

image_digest() {
  local image_ref="$1"
  docker buildx imagetools inspect "${image_ref}" | awk '/^Digest:/ { print $2; exit }'
}

image_digest_or_empty() {
  local image_ref="$1"
  docker buildx imagetools inspect "${image_ref}" 2>/dev/null | awk '/^Digest:/ { print $2; exit }'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gateway-dir)
      [[ $# -ge 2 ]] || { echo "error: --gateway-dir requires a value" >&2; exit 1; }
      GATEWAY_DIR="$2"
      shift 2
      ;;
    --image)
      [[ $# -ge 2 ]] || { echo "error: --image requires a value" >&2; exit 1; }
      IMAGE_REPOSITORY="$2"
      shift 2
      ;;
    --tag)
      [[ $# -ge 2 ]] || { echo "error: --tag requires a value" >&2; exit 1; }
      TAG="$2"
      shift 2
      ;;
    --skip-ci)
      SKIP_CI="true"
      shift
      ;;
    --skip-image-verify)
      SKIP_IMAGE_VERIFY="true"
      shift
      ;;
    --skip-backend)
      SKIP_BACKEND="true"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

command -v git >/dev/null 2>&1 || { echo "error: git is required" >&2; exit 1; }

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

resolve_gateway_dir() {
  local candidate
  if [[ -n "${GATEWAY_DIR}" ]]; then
    printf "%s\n" "${GATEWAY_DIR}"
    return
  fi
  for candidate in "${repo_root}/../mprlab-gateway" "../mprlab-gateway"; do
    if [[ -d "${candidate}" ]]; then
      printf "%s\n" "${candidate}"
      return
    fi
  done
}

GATEWAY_DIR="$(resolve_gateway_dir)"
[[ -n "${GATEWAY_DIR}" ]] || { echo "error: gateway checkout not found; set GATEWAY_DIR=/path/to/mprlab-gateway or pass --gateway-dir" >&2; exit 1; }
[[ -d "${GATEWAY_DIR}" ]] || { echo "error: gateway checkout not found: ${GATEWAY_DIR}" >&2; exit 1; }

if [[ "${SKIP_BACKEND}" != "true" ]]; then
  timeout -k 30s -s SIGKILL 30s git fetch origin "${DEFAULT_BRANCH}" --tags

  current_branch="$(git rev-parse --abbrev-ref HEAD)"
  if [[ "${current_branch}" != "${DEFAULT_BRANCH}" ]]; then
    echo "error: deployment is allowed only from branch '${DEFAULT_BRANCH}' (current: '${current_branch}')" >&2
    exit 1
  fi

  if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: working tree is dirty; commit or stash changes before deploying" >&2
    exit 1
  fi

  head_sha="$(git rev-parse HEAD)"
  remote_master_sha="$(git rev-parse "origin/${DEFAULT_BRANCH}")"
  if [[ "${head_sha}" != "${remote_master_sha}" ]]; then
    echo "error: local ${DEFAULT_BRANCH} is not at origin/${DEFAULT_BRANCH}; pull/push first" >&2
    exit 1
  fi

  if [[ -z "${TAG}" ]]; then
    TAG="$(git tag --points-at HEAD --list 'v*' --sort=-version:refname | head -n 1)"
  fi
  [[ -n "${TAG}" ]] || { echo "error: no v* release tag points at HEAD; run make release from ${DEFAULT_BRANCH} first or pass the release tag" >&2; exit 1; }
  if [[ "${TAG}" != v* ]]; then
    echo "error: deploy tag must be a v* release tag (got: ${TAG})" >&2
    exit 1
  fi
  tag_sha="$(git rev-list -n 1 "${TAG}" 2>/dev/null || true)"
  if [[ -z "${tag_sha}" || "${tag_sha}" != "${head_sha}" ]]; then
    echo "error: deploy tag ${TAG} does not point at HEAD; run make release from ${DEFAULT_BRANCH} first" >&2
    exit 1
  fi
fi

if [[ -z "${TAG}" && "${SKIP_IMAGE_VERIFY}" != "true" ]]; then
  TAG="$(git tag --points-at HEAD --list 'v*' --sort=-version:refname | head -n 1)"
fi

if [[ "${SKIP_CI}" != "true" && "${SKIP_BACKEND}" != "true" ]]; then
  echo "==> [deploy] Running make ci before deployment"
  timeout -k 1200s -s SIGKILL 1200s make ci
fi

if [[ "${SKIP_IMAGE_VERIFY}" != "true" ]]; then
  command -v docker >/dev/null 2>&1 || { echo "error: docker is required for image verification" >&2; exit 1; }
  docker buildx version >/dev/null 2>&1 || { echo "error: docker buildx is required for image verification" >&2; exit 1; }
  echo "==> [deploy] Verifying ${IMAGE_REPOSITORY}:latest matches release ${TAG}"
  latest_digest="$(image_digest "${IMAGE_REPOSITORY}:latest")"
  [[ -n "${latest_digest}" ]] || { echo "error: could not resolve digest for ${IMAGE_REPOSITORY}:latest" >&2; exit 1; }

  release_image_tags=()
  if [[ "${TAG}" == v* ]]; then
    release_image_tags+=("${TAG#v}")
  fi
  release_image_tags+=("${TAG}")

  matched_release_tag=""
  resolved_release_digests=()
  for release_image_tag in "${release_image_tags[@]}"; do
    release_digest="$(image_digest_or_empty "${IMAGE_REPOSITORY}:${release_image_tag}")"
    if [[ -z "${release_digest}" ]]; then
      resolved_release_digests+=("${release_image_tag}=missing")
      continue
    fi
    resolved_release_digests+=("${release_image_tag}=${release_digest}")
    if [[ "${release_digest}" == "${latest_digest}" ]]; then
      matched_release_tag="${release_image_tag}"
      break
    fi
  done

  if [[ -z "${matched_release_tag}" ]]; then
    echo "error: ${IMAGE_REPOSITORY}:latest digest ${latest_digest} does not match release aliases for ${TAG}: ${resolved_release_digests[*]}; run make publish first" >&2
    exit 1
  fi
  echo "==> [deploy] Verified ${IMAGE_REPOSITORY}:latest matches ${matched_release_tag}"
fi

if [[ "${SKIP_BACKEND}" != "true" ]]; then
  echo "==> [deploy] Deploying TAuth through mprlab-gateway"
  timeout --foreground -k 1200s -s SIGKILL 1200s make -C "${GATEWAY_DIR}" deploy-tauth-backend
fi

echo "TAuth deploy complete"
