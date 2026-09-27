#!/usr/bin/env bash
set -euo pipefail
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
mkdir "${scratch}/source" "${scratch}/artifact"
# Reproduce a publication checkout without ignored local configuration.
git ls-files --cached --others --exclude-standard --deduplicate -z -- docker/pages/Dockerfile docs web .dockerignore |
  while IFS= read -r -d '' source; do
    if test -f "${source}"; then
      printf '%s\0' "${source}"
    fi
  done |
  tar --null -T - -cf - |
  tar -xf - -C "${scratch}/source"
artifact="${scratch}/artifact"
docker build --file "${scratch}/source/docker/pages/Dockerfile" --target pages --output "type=local,dest=${artifact}" "${scratch}/source"
for asset in index.html tauth.js app/index.html app/workspace.js app/integration.js app/client.js app/runtime.json app/vendor/mpr-ui.js app/vendor/mpr-ui.css; do
  test -s "${artifact}/${asset}"
done
cmp web/tauth.js "${artifact}/tauth.js"
cmp web/app/runtime.json "${artifact}/app/runtime.json"
printf '%s\n' 'TAUTH_CONSOLE_PAGES_OK'
