#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "$0")/.." && pwd -P)"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT
application_root="$fixture_root/application with spaces"
runtime_bin="$fixture_root/runtime bin"
tools_bin="$fixture_root/tools"
make_command="$(command -v make)"
git_command="$(command -v git)"
mkdir -p "$application_root" "$runtime_bin" "$tools_bin"
cp "$repository_root/Makefile" "$application_root/Makefile"
mkdir -p "$application_root/deployment" "$application_root/.mprlab/deploy"
git -C "$application_root" init --quiet
application_root="$(cd "$application_root" && pwd -P)"
ln -s "$git_command" "$tools_bin/git"
ln -s "$(command -v dirname)" "$tools_bin/dirname"
ln -s "$(command -v bash)" "$tools_bin/bash"

# The application Makefile is real. Only its external Gateway dependency is controlled.
cat > "$fixture_root/gateway.c" <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) {
    char directory[4096];
    if (getcwd(directory, sizeof(directory)) == NULL) return 1;
    printf("cwd=%s\n", directory);
    for (int index = 1; index < argc; index++) printf("arg=%s\n", argv[index]);
    const char *operator_root = getenv("MPRLAB_GATEWAY_OPERATOR_ROOT");
    printf("operator=%s\n", operator_root == NULL ? "" : operator_root);
    if (getenv("TEST_GATEWAY_VERIFY_CAPTURE") != NULL) {
        const char *names[] = {"TAUTH_TENANT_ENCRYPTION_KEY", "MPRLAB_TAUTH_MANAGEMENT_URL", "MPRLAB_TAUTH_PROVISIONING_CREDENTIALS", "DEPLOY_SUDO_PASSWORD_INHERITED"};
        const char *expected[] = {"inherited-key", "inherited-url", "inherited-map", "inherited-sudo"};
        for (int index = 0; index < 4; index++) {
            const char *actual = getenv(names[index]);
            if (actual == NULL || strcmp(actual, expected[index]) != 0) return 43;
        }
        if (getenv("DEPLOY_SUDO_PASSWORD_FIXTURE") != NULL) return 43;
        printf("capture-inputs=unchanged\n");
    }
    if (getenv("TEST_GATEWAY_FAILURE") != NULL) {
        fprintf(stderr, "gateway fixture failure\n");
        return 42;
    }
    return 0;
}
C
cc "$fixture_root/gateway.c" -o "$runtime_bin/mprlab-gateway"
unset MPRLAB_GATEWAY_EXECUTABLE MAKEFLAGS MFLAGS MAKEOVERRIDES TEST_GATEWAY_FAILURE TEST_GATEWAY_VERIFY_CAPTURE DEPLOY_SUDO_PASSWORD_FIXTURE
export MPRLAB_GATEWAY_OPERATOR_ROOT="$fixture_root/operator with spaces"

mkdir -p "$MPRLAB_GATEWAY_OPERATOR_ROOT"
printf 'exit 91\n' > "$application_root/.mprlab/deploy/.env"
printf 'exit 92\n' > "$MPRLAB_GATEWAY_OPERATOR_ROOT/private.env"
for selection in path explicit; do
  arguments=()
  gateway_selection=mprlab-gateway
  command_path="$runtime_bin:$tools_bin"
  if [ "$selection" = explicit ]; then
    arguments+=("MPRLAB_GATEWAY_EXECUTABLE=$runtime_bin/mprlab-gateway")
    command_path="$tools_bin"
    gateway_selection="$runtime_bin/mprlab-gateway"
  fi
expected="$(printf 'cwd=%s\narg=deploy\narg=--app-root\narg=%s\noperator=%s\ncapture-inputs=unchanged' \
  "$application_root" "$application_root" "$MPRLAB_GATEWAY_OPERATOR_ROOT")"
  actual="$(TEST_GATEWAY_VERIFY_CAPTURE=1 TAUTH_TENANT_ENCRYPTION_KEY=inherited-key MPRLAB_TAUTH_MANAGEMENT_URL=inherited-url \
    MPRLAB_TAUTH_PROVISIONING_CREDENTIALS=inherited-map DEPLOY_SUDO_PASSWORD_INHERITED=inherited-sudo \
    PATH="$command_path" "$make_command" --no-print-directory -s -C "$application_root" deploy \
    "GO=$runtime_bin/mprlab-gateway" "${arguments[@]}")"
  if [ "$actual" != "$expected" ]; then printf 'Unexpected deployment capture boundary (%s)\n%s\n' "$selection" "$actual" >&2; exit 1; fi

  arguments=()
  if [ "$selection" = explicit ]; then
    arguments+=("MPRLAB_GATEWAY_EXECUTABLE=$fixture_root/missing runtime")
  fi
  status=0
  PATH="$tools_bin" "$make_command" --no-print-directory -s -C "$application_root" deploy "${arguments[@]}" > "$fixture_root/deploy-missing.log" 2>&1 || status=$?
  [ "$status" -eq 2 ]
  grep -F 'Gateway runtime is unavailable:' "$fixture_root/deploy-missing.log" >/dev/null
  if grep -F 'arg=' "$fixture_root/deploy-missing.log"; then exit 1; fi
done
status=0
TEST_GATEWAY_FAILURE=1 PATH="$runtime_bin:$tools_bin" "$make_command" --no-print-directory -s -C "$application_root" deploy \
  "GO=$runtime_bin/mprlab-gateway" > "$fixture_root/deploy-failure.log" 2>&1 || status=$?
[ "$status" -eq 2 ]
grep -F 'gateway fixture failure' "$fixture_root/deploy-failure.log" >/dev/null
grep -F 'Error 42' "$fixture_root/deploy-failure.log" >/dev/null

for operation in release publish; do
  status=0
  PATH="$runtime_bin:$tools_bin" "$make_command" --no-print-directory -s -C "$application_root" "$operation" > "$fixture_root/removed-$operation.log" 2>&1 || status=$?
  if [ "$status" -ne 2 ]; then
    printf 'Removed production target %s returned status %s\n' "$operation" "$status" >&2
    exit 1
  fi
  grep -F "No rule to make target" "$fixture_root/removed-$operation.log" >/dev/null
  if grep -F 'arg=' "$fixture_root/removed-$operation.log"; then exit 1; fi
done

printf 'Installed Gateway Make integration passed.\n'
