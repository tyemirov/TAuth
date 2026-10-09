#!/usr/bin/env bash
set -euo pipefail

readonly image_name="tauth-managed-proxy-trust:contract-$$"
readonly network_name="tauth-managed-proxy-trust-$$"
readonly caddy_image="caddy:2.10.2-alpine"
readonly client_image="curlimages/curl:8.12.1"
readonly origin="https://proxy-trust.example.invalid"
readonly encryption_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
readonly readiness_attempt_count=100

test_root="$(mktemp -d)"
service_id=""
proxy_id=""
caller_id=""
network_id=""
image_created=false

report_cleanup_failure() {
  printf 'Cleanup failed: %s\n' "$1" >&2
  if [ "$cleanup_status" -eq 0 ]; then cleanup_status=1; fi
}

cleanup() {
  cleanup_status=$?
  if [ "$cleanup_status" -ne 0 ]; then
    for container_id in "$service_id" "$proxy_id"; do
      if [ -n "$container_id" ]; then docker logs "$container_id" >&2 || true; fi
    done
  fi
  for container_id in "$caller_id" "$proxy_id" "$service_id"; do
    if [ -n "$container_id" ]; then
      if ! docker container rm --force --volumes "$container_id" >/dev/null; then
        report_cleanup_failure "remove container $container_id"
      fi
    fi
  done
  if [ -n "$network_id" ]; then
    if ! docker network rm "$network_id" >/dev/null; then
      report_cleanup_failure "remove network $network_id"
    fi
  fi
  if [ "$image_created" = true ]; then
    if ! docker image rm "$image_name" >/dev/null; then
      report_cleanup_failure "remove image $image_name"
    fi
  fi
  if ! rm -rf "$test_root"; then
    report_cleanup_failure "remove temporary directory $test_root"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

mkdir -p "$test_root/data"
cat >"$test_root/import-source.yaml" <<EOF
server:
  listen_addr: ":8080"
  database_url: "sqlite:///data/tauth.db"
tenants:
  - id: "proxy-trust"
    display_name: "Proxy trust"
    tenant_origins: ["$origin"]
    google_web_client_id: "fixture.apps.googleusercontent.com"
    jwt_signing_key: "fixture-proxy-trust-signing-key"
    session_cookie_name: "session_proxy_trust"
    refresh_cookie_name: "refresh_proxy_trust"
    session_ttl: "15m"
    refresh_ttl: "720h"
    nonce_ttl: "5m"
EOF
TAUTH_TEST_SOURCE="$test_root/import-source.yaml" \
TAUTH_TEST_SERVICE="$test_root/fixture-service.yaml" \
TAUTH_TEST_DATABASE="$test_root/data/tauth.db" \
TAUTH_TEST_RUNTIME_DATABASE_URL="sqlite:///data/tauth.db" \
make test-database-fixture

docker build --tag "$image_name" . >"$test_root/build.log" 2>&1 || { cat "$test_root/build.log" >&2; exit 1; }
image_created=true
docker run --rm --interactive --network none "$image_name" render-deployment-config \
  <tests/fixtures/deployment-config/browser-demo.json >"$test_root/config.yaml"
docker image inspect "$caddy_image" >/dev/null 2>&1 || docker pull "$caddy_image"
docker image inspect "$client_image" >/dev/null 2>&1 || docker pull "$client_image"

network_id="$(docker network create "$network_name")"
subnet="$(docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "$network_id")"
proxy_addresses="$(python3 -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); print(n.network_address+10,n.network_address+11)' "$subnet")"
read -r first_proxy_address second_proxy_address <<<"$proxy_addresses"

service_id="$(docker run --detach --network "$network_id" --network-alias tauth \
  --publish 127.0.0.1::8080 \
  --env "TAUTH_TENANT_ENCRYPTION_KEY=$encryption_key" \
  --env TAUTH_TRUSTED_PROXY_HOSTS=mprlab-caddy \
  --env TAUTH_TRUSTED_PROXY_LOOKUP_TIMEOUT=1s \
  --mount "type=bind,src=$test_root/config.yaml,dst=/config/config.yaml,readonly" \
  --mount "type=bind,src=$test_root/data,dst=/data" \
  "$image_name" --config /config/config.yaml)"
service_started_at="$(docker inspect --format '{{.State.StartedAt}}' "$service_id")"
service_port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}' "$service_id")"

wait_for_health() {
  local health_url="$1" status=""
  for attempt in $(seq 1 "$readiness_attempt_count"); do
    status="$(curl --insecure --connect-timeout 1 --max-time 1 --silent --output /dev/null --write-out '%{http_code}' "$health_url" || true)"
    if [ "$status" = 200 ]; then return; fi
    if [ "$(docker inspect --format '{{.State.Running}}' "$service_id")" != true ]; then break; fi
    sleep 0.1
  done
  printf 'Service readiness failed: %s returned %s\n' "$health_url" "$status" >&2
  return 1
}
wait_for_health "http://127.0.0.1:$service_port/health"

cat >"$test_root/Caddyfile" <<'EOF'
{
  auto_https disable_redirects
}
https://localhost {
  tls internal
  reverse_proxy tauth:8080
}
EOF
start_proxy() {
  proxy_id="$(docker run --detach --network "$network_id" --network-alias mprlab-caddy \
    --ip "$1" --publish 127.0.0.1::443 \
    --mount "type=bind,src=$test_root/Caddyfile,dst=/etc/caddy/Caddyfile,readonly" \
    "$caddy_image")"
  proxy_port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "443/tcp") 0).HostPort}}' "$proxy_id")"
  wait_for_health "https://localhost:$proxy_port/health"
}

assert_response() {
  local subject="$1" expected_status="$2" expected_text="$3"
  local status
  status="$(tail -n 1 "$test_root/response")"
  if [ "$status" != "$expected_status" ] || ! rg --fixed-strings --quiet "$expected_text" "$test_root/response"; then
    printf '%s: expected HTTP %s containing %s\n' "$subject" "$expected_status" "$expected_text" >&2
    cat "$test_root/response" >&2
    exit 1
  fi
}

proxy_requests() {
  curl --insecure --silent --show-error --connect-timeout 2 --max-time 5 \
    --request POST \
    --header "Origin: $origin" --header 'X-TAuth-Tenant: proxy-trust' \
    --write-out '\n%{http_code}\n' "https://localhost:$proxy_port/auth/nonce" >"$test_root/response"
  assert_response 'HTTPS proxy nonce' 200 'nonce'
  curl --insecure --silent --show-error --connect-timeout 2 --max-time 5 \
    --data 'grant_type=invalid' --write-out '\n%{http_code}\n' \
    "https://localhost:$proxy_port/oauth/token" >"$test_root/response"
  assert_response 'HTTPS proxy OAuth' 400 'unsupported_grant_type'
}

untrusted_requests() {
  docker run --rm --network "$network_id" "$client_image" \
    --silent --show-error --connect-timeout 2 --max-time 5 \
    --request POST \
    --header "Origin: $origin" --header 'X-TAuth-Tenant: proxy-trust' \
    --header 'X-Forwarded-Proto: https' --write-out '\n%{http_code}\n' \
    http://tauth:8080/auth/nonce >"$test_root/response"
  assert_response 'Unrelated container nonce' 400 'https_required'
  docker run --rm --network "$network_id" "$client_image" \
    --silent --show-error --connect-timeout 2 --max-time 5 \
    --header 'X-Forwarded-Proto: https' --data 'grant_type=invalid' \
    --write-out '\n%{http_code}\n' http://tauth:8080/oauth/token >"$test_root/response"
  assert_response 'Unrelated container OAuth' 400 'https_required'
}

start_proxy "$first_proxy_address"
proxy_requests
untrusted_requests

docker container rm --force --volumes "$proxy_id" >/dev/null
proxy_id=""
untrusted_requests
start_proxy "$second_proxy_address"
proxy_requests
untrusted_requests

caller_id="$(docker run --detach --network "$network_id" --ip "$first_proxy_address" \
  --entrypoint /bin/sh "$client_image" -c 'sleep 120')"
for route in /auth/nonce /oauth/token; do
  docker exec "$caller_id" curl --silent --show-error --connect-timeout 2 --max-time 5 \
    --request POST \
    --header "Origin: $origin" --header 'X-TAuth-Tenant: proxy-trust' \
    --header 'X-Forwarded-Proto: https' --write-out '\n%{http_code}\n' \
    "http://tauth:8080$route" >"$test_root/response"
  assert_response "Previous proxy address $route" 400 'https_required'
done
[ "$(docker inspect --format '{{.State.StartedAt}}' "$service_id")" = "$service_started_at" ]
printf '%s\n' 'TAUTH_MANAGED_PROXY_TRUST_OK'
