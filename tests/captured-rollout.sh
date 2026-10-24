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
