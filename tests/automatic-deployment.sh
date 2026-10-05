#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "$0")/.." && pwd -P)"
test_root="$(mktemp -d)"
image="tauth-automatic-cutover:contract-$$"
volume="tauth-automatic-cutover-$$"
source_container=""
service_container=""
writer_volume=""
cleanup() {
  status=$?
  if [ -n "$source_container" ]; then docker container rm --force "$source_container" >/dev/null; fi
  if [ -n "$service_container" ]; then docker container rm --force "$service_container" >/dev/null; fi
  if [ -n "$writer_volume" ]; then docker volume rm "$writer_volume" >/dev/null; fi
  docker volume rm "$volume" >/dev/null
  docker image rm "$image" >/dev/null
  rm -rf "$test_root"
  exit "$status"
}
trap cleanup EXIT
mkdir -p "$test_root/remote/state/tauth"
TAUTH_AUTOMATIC_DEPLOYMENT_ROOT="$test_root" make test-deployment-migration
docker build --tag "$image" "$repository_root" >"$test_root/build.log" 2>&1
docker volume create "$volume" >/dev/null
docker run --rm --entrypoint=/bin/sh --mount "type=volume,src=$volume,dst=/data" \
  --mount "type=bind,src=$test_root,dst=/fixture,readonly" "$image" -c 'cp /fixture/tauth.db /data/tauth.db'
# The host retains its materialized configuration independently of any container.
cp "$test_root/source.yaml" "$test_root/remote/state/tauth/config.tauth.yml"

package_root="$(python3 -c 'from pathlib import Path; print((Path.home()/".local/share/mprlab-gateway/active").resolve())')"
export ANSIBLE_CONFIG="$package_root/runtime/deploy/ansible/ansible.cfg"
TAUTH_AUTOMATIC_ROOT="$test_root" TAUTH_AUTOMATIC_IMAGE="$image" TAUTH_AUTOMATIC_VOLUME="$volume" \
TAUTH_AUTOMATIC_DOCKER="$(command -v docker)" TAUTH_AUTOMATIC_CONTEXT="$(docker context show)" python3 - <<'PY'
import json,os,pathlib
p=pathlib.Path(os.environ['TAUTH_AUTOMATIC_ROOT'])
inventory={'all':{'children':{'gateway':{'hosts':{'cutover-fixture':{'ansible_connection':'local','mprlab_runtime_root':str(p/'remote'),'mprlab_docker_cli':os.environ['TAUTH_AUTOMATIC_DOCKER'],'mprlab_docker_context':os.environ['TAUTH_AUTOMATIC_CONTEXT']}}}}}}
(p/'inventory.json').write_text(json.dumps(inventory))
variables={'tauth_cutover_image':os.environ['TAUTH_AUTOMATIC_IMAGE'],'tauth_cutover_volume':os.environ['TAUTH_AUTOMATIC_VOLUME'],'tauth_cutover_id':'20260930-tenant-console','tauth_cutover_plan':str(p/'plan.json'),'tauth_cutover_key':str(p/'key')}
(p/'variables.json').write_text(json.dumps(variables))
PY
# An unrelated volume writer must fail before a database change.
source_container="$(docker run --detach --network=none --entrypoint=sh \
  --mount "type=volume,src=$volume,dst=/data" "$image" -c 'sleep 86400')"
before="$(docker run --rm --entrypoint=sha256sum --mount "type=volume,src=$volume,dst=/data,readonly" "$image" /data/tauth.db)"
if "$package_root/toolchain/bin/ansible-playbook" -i "$test_root/inventory.json" \
  "$repository_root/deployment/rollout/cutover.yml" --extra-vars "@$test_root/variables.json" >"$test_root/writer-rejection.log" 2>&1; then
  printf 'Unrelated writer was accepted.\n' >&2; exit 1
fi
after="$(docker run --rm --entrypoint=sha256sum --mount "type=volume,src=$volume,dst=/data,readonly" "$image" /data/tauth.db)"
[ "$before" = "$after" ]
[ "$(docker inspect --format '{{.State.Running}}' "$source_container")" = true ]
docker container rm --force "$source_container" >/dev/null
source_container=""
# The first migration must succeed with no previous service container.
"$package_root/toolchain/bin/ansible-playbook" -i "$test_root/inventory.json" \
  "$repository_root/deployment/rollout/cutover.yml" --extra-vars "@$test_root/variables.json"
# The independent console repair must run after the original receipt is complete.
python3 - "$test_root" <<'PYFIXTURE'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
(root/'console-plan.json').write_text(json.dumps({'expected_client_id':'existing-google-client','client_id':'corrected-console.apps.googleusercontent.com','console_origin':'https://console.example.com'}))
variables=json.loads((root/'variables.json').read_text())
variables.update(tauth_cutover_id='20261005-console-google-client',tauth_cutover_plan=str(root/'console-plan.json'))
(root/'console-variables.json').write_text(json.dumps(variables))
PYFIXTURE
source_container="$(docker run --detach --network=none --entrypoint=sh \
  --mount "type=volume,src=$volume,dst=/data" "$image" -c 'sleep 86400')"
before="$(docker run --rm --entrypoint=sha256sum --mount "type=volume,src=$volume,dst=/data,readonly" "$image" /data/tauth.db)"
if "$package_root/toolchain/bin/ansible-playbook" -i "$test_root/inventory.json" \
  "$repository_root/deployment/rollout/console-google-client.yml" --extra-vars "@$test_root/console-variables.json" >"$test_root/console-writer-rejection.log" 2>&1; then
  printf 'Unrelated console migration writer was accepted.\n' >&2; exit 1
fi
after="$(docker run --rm --entrypoint=sha256sum --mount "type=volume,src=$volume,dst=/data,readonly" "$image" /data/tauth.db)"
[ "$before" = "$after" ]
[ "$(docker inspect --format '{{.State.Running}}' "$source_container")" = true ]
docker container rm --force "$source_container" >/dev/null
source_container="$(docker run --detach --network=none --entrypoint=sh \
  --label com.docker.compose.service=tauth-api \
  --mount "type=volume,src=$volume,dst=/data" "$image" -c 'sleep 86400')"
"$package_root/toolchain/bin/ansible-playbook" -i "$test_root/inventory.json" \
  "$repository_root/deployment/rollout/console-google-client.yml" --extra-vars "@$test_root/console-variables.json"
[ "$(docker inspect --format '{{.State.Running}}' "$source_container")" = false ]
docker container rm "$source_container" >/dev/null
source_container=""
service_container="$(docker run --detach --publish 127.0.0.1::8080 \
  --mount "type=volume,src=$volume,dst=/data" \
  --mount "type=bind,src=$test_root/service.yaml,dst=/config/config.yml,readonly" \
  "$image" --config=/config/config.yml)"
port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}' "$service_container")"
for attempt in $(seq 1 100); do
  status="$(curl --silent --output "$test_root/health" --write-out '%{http_code}' "http://127.0.0.1:$port/health" || true)"
  if [ "$status" = 200 ]; then break; fi
  sleep 0.1
done
if [ "$status" != 200 ]; then docker logs "$service_container"; exit 1; fi
token="$(cat "$test_root/session-token")"
status="$(curl --silent --output "$test_root/profile.json" --write-out '%{http_code}' \
  --header 'Origin: https://console.example.com' --header 'X-TAuth-Tenant: product' \
  --header "Cookie: product_session=$token" "http://127.0.0.1:$port/me")"
if [ "$status" != 200 ]; then cat "$test_root/profile.json"; exit 1; fi
extra_token="$(cat "$test_root/rsvp-session-token")"
status="$(curl --silent --output "$test_root/rsvp-profile.json" --write-out '%{http_code}' \
  --header 'Origin: https://rsvp.example.com' --header 'X-TAuth-Tenant: rsvp-production' \
  --header "Cookie: rsvp_session=$extra_token" "http://127.0.0.1:$port/me")"
if [ "$status" != 200 ]; then cat "$test_root/rsvp-profile.json"; exit 1; fi
gateway_token="$(cat "$test_root/gateway-token")"
status="$(curl --silent --output "$test_root/configuration.json" --write-out '%{http_code}' \
  --header "Authorization: Bearer $gateway_token" \
  "http://127.0.0.1:$port/api/management/tenants/product/configuration")"
if [ "$status" != 200 ]; then cat "$test_root/configuration.json"; exit 1; fi
status="$(curl --silent --output "$test_root/denied.json" --write-out '%{http_code}' \
  --header "Authorization: Bearer $gateway_token" \
  "http://127.0.0.1:$port/api/management/tenants/tauth-console/configuration")"
if [ "$status" != 403 ]; then cat "$test_root/denied.json"; exit 1; fi
status="$(curl --silent --output "$test_root/rsvp-denied.json" --write-out '%{http_code}' \
  --header "Authorization: Bearer $gateway_token" \
  "http://127.0.0.1:$port/api/management/tenants/rsvp-production/configuration")"
if [ "$status" != 403 ]; then cat "$test_root/rsvp-denied.json"; exit 1; fi
# Completed deployments need no source file and must preserve the running service.
rm "$test_root/remote/state/tauth/config.tauth.yml"
"$package_root/toolchain/bin/ansible-playbook" -i "$test_root/inventory.json" \
  "$repository_root/deployment/rollout/cutover.yml" --extra-vars "@$test_root/variables.json"
[ "$(docker inspect --format '{{.State.Running}}' "$service_container")" = true ]
"$package_root/toolchain/bin/ansible-playbook" -i "$test_root/inventory.json" \
  "$repository_root/deployment/rollout/console-google-client.yml" --extra-vars "@$test_root/console-variables.json"
[ "$(docker inspect --format '{{.State.Running}}' "$service_container")" = true ]
# Gateway removes a contribution by suspending the tenant with its current resource ETag.
status="$(curl --silent --dump-header "$test_root/tenant.headers" --output "$test_root/tenant.json" --write-out '%{http_code}' \
  --header "Authorization: Bearer $gateway_token" \
  "http://127.0.0.1:$port/api/management/tenants/product")"
if [ "$status" != 200 ]; then cat "$test_root/tenant.json"; exit 1; fi
tenant_etag="$(awk 'tolower($1) == "etag:" { sub(/\r$/, "", $2); print $2 }' "$test_root/tenant.headers")"
[ -n "$tenant_etag" ]
status="$(curl --silent --output "$test_root/suspended.json" --write-out '%{http_code}' \
  --request PATCH --header 'Content-Type: application/json' \
  --header "Authorization: Bearer $gateway_token" --header "If-Match: $tenant_etag" \
  --data '{"state":"suspended"}' "http://127.0.0.1:$port/api/management/tenants/product")"
if [ "$status" != 200 ]; then cat "$test_root/suspended.json"; exit 1; fi
python3 - "$test_root/suspended.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['state'] == 'suspended'
PY
status="$(curl --silent --output "$test_root/suspended-profile.json" --write-out '%{http_code}' \
  --header 'Origin: https://console.example.com' --header 'X-TAuth-Tenant: product' \
  --header "Cookie: product_session=$token" "http://127.0.0.1:$port/me")"
if [ "$status" != 404 ]; then printf 'Suspended tenant authentication returned %s, expected 404.\n' "$status" >&2; exit 1; fi
# A separate pending database exercises shutdown of a present TAuth writer.
writer_volume="${volume}-writer"
docker volume create "$writer_volume" >/dev/null
docker run --rm --entrypoint=/bin/sh --mount "type=volume,src=$writer_volume,dst=/data" \
  --mount "type=bind,src=$test_root,dst=/fixture,readonly" "$image" -c 'cp /fixture/tauth.db /data/tauth.db'
cp "$test_root/source.yaml" "$test_root/remote/state/tauth/config.tauth.yml"
source_container="$(docker run --detach --network=none --entrypoint=sh \
  --label com.docker.compose.service=tauth-api \
  --mount "type=volume,src=$writer_volume,dst=/data" "$image" -c 'sleep 86400')"
python3 - "$test_root/variables.json" "$writer_volume" <<'PYV'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
variables=json.loads(p.read_text())
variables['tauth_cutover_volume']=sys.argv[2]
p.write_text(json.dumps(variables))
PYV
"$package_root/toolchain/bin/ansible-playbook" -i "$test_root/inventory.json" \
  "$repository_root/deployment/rollout/cutover.yml" --extra-vars "@$test_root/variables.json"
[ "$(docker inspect --format '{{.State.Running}}' "$source_container")" = false ]
printf 'Automatic cutover without a source container, writer rejection, preserved sessions, credential isolation, repeated deployment, and tenant removal passed.\n'
