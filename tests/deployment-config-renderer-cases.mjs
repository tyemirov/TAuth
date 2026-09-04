import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const [binaryPath, fixturePath] = process.argv.slice(2);
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));

function browserTenant(id, origins) {
  const contribution = structuredClone(fixture.contributions[1]);
  contribution.owner = id;
  const tenant = contribution.desired.tenant;
  tenant.id = id;
  tenant.origins = origins;
  tenant.cookie.session_name = `session_${id}`;
  tenant.cookie.refresh_name = `refresh_${id}`;
  delete tenant.google_native_clients;
  delete tenant.apple_oauth;
  delete tenant.oauth;
  return contribution;
}

function render(contributions) {
  return execFileSync(binaryPath, ['render-deployment-config'], {
    input: JSON.stringify({ schema_version: 1, contributions }),
    encoding: 'utf8',
  });
}

for (const [name, origins, expectedOverride] of [
  ['shared', ['https://shared.example.invalid', 'https://shared.example.invalid'], true],
  ['normalized', ['https://shared.example.invalid', 'https://SHARED.example.invalid'], true],
  ['distinct', ['https://first.example.invalid', 'https://second.example.invalid'], false],
]) {
  const output = render(origins.map((origin, index) => browserTenant(`browser_${index}`, [origin])));
  assert.equal(output.includes(`enable_tenant_header_override: ${expectedOverride}`), true, name);
}

const singleTenant = render([
  browserTenant('single', ['https://shared.example.invalid', 'https://accounts.google.com']),
]);
assert.equal(singleTenant.includes('enable_tenant_header_override: false'), true);

function rejectRequest(request, errorCode) {
  const result = spawnSync(binaryPath, ['render-deployment-config'], {
    input: JSON.stringify(request),
    encoding: 'utf8',
  });
  assert.ifError(result.error);
  assert.equal(result.status, 1, errorCode);
  assert.equal(result.stdout, '', 'invalid requests must not emit config');
  assert.equal(result.stderr.includes(errorCode), true, errorCode);
  for (const contribution of fixture.contributions) {
    for (const output of Object.values(contribution.outputs)) {
      assert.equal(result.stderr.includes(output.value), false, 'diagnostics must not include output values');
    }
  }
}

for (const request of [{ schema_version: 1 }, { schema_version: 1, contributions: null }]) {
  rejectRequest(request, 'deployment_config.invalid_request');
}
const bootstrap = render([]);
assert.equal(bootstrap.includes('tenants: []'), true);
assert.equal(bootstrap.includes('oauth:'), false);

for (const [settings, errorCode] of [
  [{ enabled: false, password_signup: { enabled: true } }, 'tenant.account_management_disabled'],
  [{ enabled: false, email_verification_ttl: 'invalid' }, 'tenant.invalid_email_verification_ttl'],
  [{ enabled: false, password_reset_ttl: '0s' }, 'tenant.invalid_password_reset_ttl'],
]) {
  const contribution = browserTenant('account', ['https://ui.example.invalid']);
  contribution.desired.tenant.account_management = settings;
  rejectRequest({ schema_version: 1, contributions: [contribution] }, errorCode);
}

const disabledAccount = browserTenant('disabled', ['https://ui.example.invalid']);
disabledAccount.desired.tenant.account_management = {
  enabled: false,
  password_signup: { enabled: false },
  email_verification_ttl: '40m',
  password_reset_ttl: '20m',
};
const disabledOutput = render([disabledAccount]);
assert.equal(/account_management:\s+enabled: false/.test(disabledOutput), true);
assert.equal(disabledOutput.includes('email_verification_ttl: 40m'), true);
assert.equal(disabledOutput.includes('password_reset_ttl: 20m'), true);

delete disabledAccount.desired.tenant.account_management;
assert.equal(render([disabledAccount]).includes('account_management:'), false);
