#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$repository_root"
mkdir -p .cache
fixture_root="$(mktemp -d "$repository_root/.cache/test-fixture-runtime-XXXXXX")"
image="tauth-test-fixture-runtime:contract-$$"
container=""
cleanup() {
  status=$?
  cleanup_status=0
  if [ "$status" != 0 ] && [ -n "$container" ]; then docker container logs "$container" >&2 || cleanup_status=1; fi
  if [ -n "$container" ]; then docker container rm --force "$container" >/dev/null || cleanup_status=1; fi
  docker image rm "$image" >/dev/null || cleanup_status=1
  rm -rf "$fixture_root" || cleanup_status=1
  if [ "$status" = 0 ]; then status=$cleanup_status; fi
  exit "$status"
}
trap cleanup EXIT

make build-test-fixture
python3 - "$fixture_root/input.json" <<'PY'
import json,pathlib,sys
request={'schema':'tauth.test-fixture.v1','test_only':True,'app_id':'fixture-runtime-app','server':{'listen_addr':':8081'},'tenant':{'id':'fixture-runtime-application','display_name':'Runtime fixture application','origin':'http://localhost:32123','google_web_client_id':'fixture-web.apps.googleusercontent.com','google_native_client_id':'fixture-native.apps.googleusercontent.com','jwt_signing_key':'synthetic-runtime-test-key','session_cookie_name':'runtime_session','refresh_cookie_name':'runtime_refresh','session_ttl':'30m','refresh_ttl':'720h','nonce_ttl':'10m'}}
request['accounts']={name:{'subject':'fixture-'+name,'email':name+'@example.com','display_name':name,'avatar_url':'https://example.com/avatar.png','state':state} for name,state in [('active','active'),('disabled','disabled')]}
pathlib.Path(sys.argv[1]).write_text(json.dumps(request))
PY
.cache/tauth-test-fixture --input "$fixture_root/input.json" --output-dir "$fixture_root/prepared" </dev/null

docker build --tag "$image" .
printf 'Fixture service acceptance image: '
docker image inspect "$image" --format '{{.Id}}'
docker run --rm --entrypoint /bin/sh "$image" -c 'test ! -e /usr/local/bin/tauth-test-fixture'
container="$(docker run --detach --publish 127.0.0.1::8081 --mount "type=bind,src=$fixture_root/prepared,dst=/tauth-fixture" "$image" --config /tauth-fixture/service.yaml)"
port="$(docker container port "$container" 8081/tcp | awk -F: '{print $NF}')"

verify_runtime() {
  python3 - "$port" "$fixture_root/prepared/receipt.json" <<'PY'
import base64,hashlib,hmac,http.client,json,pathlib,sys,time,urllib.error,urllib.request
base='http://127.0.0.1:'+sys.argv[1]
for attempt in range(100):
    try:
        with urllib.request.urlopen(base+'/health',timeout=1) as response:
            if response.status==200: break
    except (urllib.error.URLError,TimeoutError,http.client.RemoteDisconnected): pass
    time.sleep(.1)
else: raise SystemExit('Fixture service did not become healthy')
for tenant,status in [('fixture-runtime-application',200),('absent-fixture-tenant',404)]:
    request=urllib.request.Request(base+'/auth/nonce',method='POST',headers={'Origin':'http://localhost:32123','X-TAuth-Tenant':tenant})
    try:
        with urllib.request.urlopen(request,timeout=2) as response:
            actual=response.status
            data=json.load(response)
    except urllib.error.HTTPError as error:
        actual=error.code
        data=json.load(error)
    assert actual==status,(tenant,actual,data)
    if status==200: assert isinstance(data.get('nonce'),str) and data['nonce']
accounts=json.loads(pathlib.Path(sys.argv[2]).read_text())['accounts']
for alias,status in [('active',200),('disabled',403),('unknown',404)]:
    account=accounts.get(alias,{'user_id':'acct_00000000000000000000000000000000','email':'unknown@example.com'})
    now=int(time.time())
    encode=lambda data: base64.urlsafe_b64encode(json.dumps(data,separators=(',',':')).encode()).rstrip(b'=')
    data=encode({'alg':'HS256','typ':'JWT'})+b'.'+encode({'iss':'tauth','sub':account['user_id'],'user_id':account['user_id'],'tenant_id':'fixture-runtime-application','user_email':account['email'],'iat':now,'nbf':now-1,'exp':now+600})
    token=data+b'.'+base64.urlsafe_b64encode(hmac.new(b'synthetic-runtime-test-key',data,hashlib.sha256).digest()).rstrip(b'=')
    request=urllib.request.Request(base+'/me',headers={'Origin':'http://localhost:32123','X-TAuth-Tenant':'fixture-runtime-application','Cookie':'runtime_session='+token.decode()})
    try:
        with urllib.request.urlopen(request,timeout=2) as response: actual=response.status;payload=response.read().decode()
    except urllib.error.HTTPError as error: actual=error.code;payload=error.read().decode()
    assert actual==status,(alias,actual,payload)
    if status==200: assert account['user_id'] in payload and account['email'] in payload,payload
    else: assert json.loads(payload)=={'error':'account_disabled' if alias=='disabled' else 'account_not_found'},payload
print('Real service accepted the persisted active account and rejected disabled and unknown sessions.')
PY
}
verify_runtime
docker restart "$container" >/dev/null
port="$(docker container port "$container" 8081/tcp | awk -F: '{print $NF}')"
verify_runtime
printf 'Source-built production service restart accepted the existing fixture without initialization.\n'
