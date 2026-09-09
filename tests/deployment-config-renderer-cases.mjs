import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const renderCommand = 'render-deployment-config';
const invalidRequestCode = 'deployment_config.invalid_request';
const invalidOutputCode = 'deployment_config.invalid_output';
const githubTenantKind = 'tauth_github_tenant';
const githubClientOutput = 'github-client-id';
const githubSecretOutput = 'github-client-secret';

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
  return execFileSync(binaryPath, [renderCommand], {
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
  const result = spawnSync(binaryPath, [renderCommand], {
    input: JSON.stringify(request),
    encoding: 'utf8',
  });
  assert.ifError(result.error);
  assert.equal(result.status, 1, errorCode);
  assert.equal(result.stdout, '', 'invalid requests must not emit config');
  assert.equal(result.stderr.includes(errorCode), true, errorCode);
  const supplied = Array.isArray(request.contributions) ? request.contributions : [];
  for (const contribution of [...fixture.contributions, ...supplied]) {
    for (const output of Object.values(contribution.outputs)) {
      assert.equal(result.stderr.includes(output.value), false, 'diagnostics must not include output values');
    }
  }
}

for (const request of [{ schema_version: 1 }, { schema_version: 1, contributions: null }]) {
  rejectRequest(request, invalidRequestCode);
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

const githubTenant = browserTenant('github', ['https://ui.example.invalid']);
githubTenant.kind = githubTenantKind;
githubTenant.desired.kind = githubTenantKind;
delete githubTenant.desired.tenant.google_web_client_id;
delete githubTenant.desired.tenant.password_auth;
delete githubTenant.desired.tenant.account_management;
githubTenant.desired.tenant.github_oauth = {
  enabled: true,
  client_id: { resource: 'private', output: githubClientOutput },
  client_secret: { resource: 'private', output: githubSecretOutput },
  redirect_uri: 'https://auth.example.invalid/auth/github/callback',
  scopes: ['read:user', 'user:email'],
};
githubTenant.outputs = {
  'jwt-signing-key': fixture.contributions[1].outputs['jwt-signing-key'],
  [githubClientOutput]: { value: 'fixture-github-client' },
  [githubSecretOutput]: { value: 'fixture-github-private-secret' },
};
githubTenant.desired.tenant.oauth = structuredClone(fixture.contributions[1].desired.tenant.oauth);
githubTenant.desired.tenant.oauth.resources[0].scopes[0].identity_providers = ['github'];
const githubRequest = { schema_version: 1, contributions: [fixture.contributions[0], githubTenant] };
const githubOutput = render(githubRequest.contributions);
assert.match(githubOutput, /google_web_client_id: ""/);
assert.match(githubOutput, /github_oauth:\s+enabled: true/);
assert.match(githubOutput, /identity_providers:\s+- github/);
assert.equal(githubOutput.includes(githubTenant.outputs[githubClientOutput].value), true);
assert.equal(githubOutput.includes(githubTenant.outputs[githubSecretOutput].value), true);
assert.equal(githubOutput.includes('fixture.apps.googleusercontent.com'), false);

for (const change of [
  tenant => { delete tenant.desired.tenant.github_oauth; },
  tenant => { tenant.desired.tenant.github_oauth.enabled = false; },
  tenant => { tenant.desired.kind = fixture.contributions[1].kind; },
  tenant => { tenant.kind = fixture.contributions[1].kind; },
]) {
  const request = structuredClone(githubRequest);
  change(request.contributions[1]);
  rejectRequest(request, invalidRequestCode);
}
for (const name of [githubClientOutput, githubSecretOutput]) {
  const request = structuredClone(githubRequest);
  delete request.contributions[1].outputs[name];
  rejectRequest(request, invalidOutputCode);
}
