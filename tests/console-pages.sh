#!/usr/bin/env bash
set -euo pipefail
artifact="$(mktemp -d)"
trap 'rm -rf "${artifact}"' EXIT
docker build --file docker/pages/Dockerfile --target pages --output "type=local,dest=${artifact}" .
for asset in index.html tauth.js app/index.html app/workspace.js app/integration.js app/client.js app/runtime.json app/vendor/mpr-ui.js app/vendor/mpr-ui.css; do
  test -s "${artifact}/${asset}"
done
cmp web/tauth.js "${artifact}/tauth.js"
printf '%s\n' 'TAUTH_CONSOLE_PAGES_OK'
