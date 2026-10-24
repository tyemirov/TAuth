#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "$0")/.." && pwd -P)"
package_root="$(python3 -c 'from pathlib import Path; print((Path.home()/".local/share/mprlab-gateway/active").resolve())')"
gateway="$package_root/runtime/bin/mprlab-gateway"
python="$package_root/toolchain/bin/python"
ansible="$package_root/toolchain/bin/ansible-playbook"
test_root="$(mktemp -d)"
test_root="$(cd "$test_root" && pwd -P)"
cleanup() {
  status=$?
  rm -rf "$test_root"
  exit "$status"
}
trap cleanup EXIT
application="$test_root/application"
mkdir -p "$application/.mprlab/deploy"

"$python" - "$repository_root/.mprlab/deploy/resources.yml" "$application" "$test_root" <<'PY'
import json
from pathlib import Path
import sys
import yaml

source, application, fixture = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
document = yaml.safe_load(source.read_text())
root = document['mprlab_resources']
root.pop('environment_file', None)
root['inputs'] = {name: 'synthetic-unused-input' for name in root.get('inputs', {})}
root['inputs'].update({'CAPTURED_FIRST_PASSWORD': 'synthetic-first-host-value', 'CAPTURED_SECOND_PASSWORD': 'synthetic-second-host-value'})
root['hosts'] = {
    'fixture-first': {'ansible_become_password': 'CAPTURED_FIRST_PASSWORD'},
    'fixture-second': {'ansible_become_password': 'CAPTURED_SECOND_PASSWORD'},
}
root['ci'] = {'enabled': False}
(application / '.mprlab/deploy/resources.yml').write_text(yaml.safe_dump(document, sort_keys=False))
(fixture / 'inventory.json').write_text(json.dumps({'all': {'hosts': {
    name: {'ansible_connection': 'local'}
    for name in ['fixture-first', 'fixture-second', 'fixture-unbound']
}}}))
(fixture / 'verify.yml').write_text('''---
- name: Verify captured rollout host inputs
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    expected_first: synthetic-first-host-value
    expected_second: synthetic-second-host-value
  tasks:
    - name: Require isolated captured authentication
      no_log: true
      ansible.builtin.assert:
        quiet: true
        that:
          - hostvars['fixture-first'].ansible_become_password == expected_first
          - hostvars['fixture-second'].ansible_become_password == expected_second
          - hostvars['fixture-first'].ansible_become_password != hostvars['fixture-second'].ansible_become_password
          - hostvars['fixture-unbound'].ansible_become_password is not defined
''')
PY

git -C "$application" init --quiet --initial-branch=master
git -C "$application" add .mprlab/deploy/resources.yml
export ANSIBLE_CONFIG="$package_root/runtime/deploy/ansible/ansible.cfg"
status=0
"$gateway" bootstrap-run --repo-root "$application" --operation app-deploy -- \
  "$ansible" -i "$test_root/inventory.json" "$test_root/verify.yml" >"$test_root/native.log" 2>&1 || status=$?
if rg -q -e 'synthetic-first-host-value' -e 'synthetic-second-host-value' "$test_root/native.log"; then
  printf 'Captured rollout diagnostics exposed a synthetic private input.\n' >&2
  exit 1
fi
if [ "$status" -ne 0 ]; then
  cat "$test_root/native.log" >&2
  exit "$status"
fi
printf 'Captured rollout host inputs passed through the installed Gateway and native Ansible.\n'

# The public wrapper must select inputs through Gateway before it starts rollout.
"$python" - "$application" "$gateway" "$repository_root/deployment/deploy.sh" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys
import yaml

application, gateway, wrapper = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
manifest = application / '.mprlab/deploy/resources.yml'
document = yaml.safe_load(manifest.read_text())
(application / 'run').write_text('''import json, os, subprocess, sys
from pathlib import Path
os.environ["MPRLAB_GATEWAY_EXECUTABLE"] = sys.argv[3]
request = json.dumps({"root": sys.argv[2], "keys": ["TAUTH_TENANT_ENCRYPTION_KEY"]})
result = subprocess.run([sys.argv[3], "private-environment-operation"], input=request, text=True, capture_output=True)
if result.returncode:
    sys.stderr.write(result.stderr)
    sys.exit(result.returncode)
captured_key = json.loads(result.stdout)["TAUTH_TENANT_ENCRYPTION_KEY"]
assert captured_key == os.environ["EXPECTED_WRAPPER_INPUT"]
if os.environ.get("VERIFY_NESTED_CAPTURE") == "1":
    root = Path(sys.argv[2])
    (root / "config/selected.env").write_text("TAUTH_TENANT_ENCRYPTION_KEY=changed-file-value-after-capture\\n")
    nested = root / "verify-nested.py"
    nested.write_text("import json, os, subprocess, sys\\n"
                      "request = json.dumps({'root': sys.argv[1], 'keys': ['TAUTH_TENANT_ENCRYPTION_KEY']})\\n"
                      "result = subprocess.run([sys.argv[2], 'private-environment-operation'], input=request, text=True, capture_output=True)\\n"
                      "assert result.returncode == 0, result.stderr\\n"
                      "assert json.loads(result.stdout)['TAUTH_TENANT_ENCRYPTION_KEY'] == os.environ['EXPECTED_WRAPPER_INPUT'], 'nested capture changed the key'\\n"
                      "print('nested captured key preserved')\\n")
    environment = dict(os.environ)
    environment["TAUTH_TENANT_ENCRYPTION_KEY"] = captured_key
    command = [sys.argv[3], "bootstrap-run", "--repo-root", str(root), "--operation", "app-deploy", "--", sys.executable, str(nested), str(root), sys.argv[3]]
    nested_result = subprocess.run(command, env=environment, text=True, capture_output=True)
    assert nested_result.returncode == 0, nested_result.stdout + nested_result.stderr
    assert "nested captured key preserved" in nested_result.stdout
print("wrapper captured input verified")
''')
(application / '.mprlab/deploy/.env').write_text('exit 91\n')
operator = application / 'operator'
operator.mkdir()
(operator / 'private.env').write_text('exit 92\n')
base_environment = {key: value for key, value in os.environ.items() if key != 'TAUTH_TENANT_ENCRYPTION_KEY'}
base_environment['MPRLAB_GATEWAY_OPERATOR_ROOT'] = str(operator)
for name, selection, ambient, file_value, diagnostic in [
    ('process-only', None, 'synthetic-process-value', None, None),
    ('alternate-file', 'config/selected.env', None, 'synthetic-file-value', None),
    ('process-precedence', 'config/selected.env', 'synthetic-process-value', 'synthetic-file-value', None),
    ('nested-key-stability', 'config/selected.env', None, 'synthetic-file-value', None),
    ('missing-reference', None, None, None, 'undefined environment reference TAUTH_TENANT_ENCRYPTION_KEY'),
    ('missing-selected-file', 'config/missing.env', 'synthetic-process-value', None, 'manifest.environment_file'),
]:
    selected = document['mprlab_resources']
    selected.pop('environment_file', None)
    selected['inputs']['TAUTH_TENANT_ENCRYPTION_KEY'] = '${TAUTH_TENANT_ENCRYPTION_KEY}'
    if selection is not None:
        selected['environment_file'] = selection
    if file_value is not None:
        path = application / selection
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('TAUTH_TENANT_ENCRYPTION_KEY=' + file_value + '\n')
    manifest.write_text(yaml.safe_dump(document, sort_keys=False))
    environment = dict(base_environment)
    if ambient is not None:
        environment['TAUTH_TENANT_ENCRYPTION_KEY'] = ambient
    environment['EXPECTED_WRAPPER_INPUT'] = ambient or file_value or ''
    environment['VERIFY_NESTED_CAPTURE'] = '1' if name == 'nested-key-stability' else '0'
    result = subprocess.run(['bash', wrapper, str(application), gateway, sys.executable], env=environment, text=True, capture_output=True)
    output = result.stdout + result.stderr
    if any(secret in output for secret in ['synthetic-process-value', 'synthetic-file-value']):
        raise SystemExit(name + ': exposed a synthetic private input')
    if diagnostic is None:
        if result.returncode or 'wrapper captured input verified' not in output:
            raise SystemExit(name + ': wrapper did not reach captured input consumer\n' + output)
    elif result.returncode == 0 or diagnostic not in output or 'wrapper captured input verified' in output:
        raise SystemExit(name + ': invalid input did not stop before rollout\n' + output)
print('Public deployment wrapper input selection and redaction passed.')
PY
