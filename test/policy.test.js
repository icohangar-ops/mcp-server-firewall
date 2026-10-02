import assert from 'node:assert/strict';
import { test } from 'node:test';
import { JevProvider, StaticPolicyProvider } from '../src/jev-hook.js';
import { buildChildEnv, evaluateCall, normalizePolicy } from '../src/policy.js';

const policy = normalizePolicy({
  tools: { allow: ['read_file', 'echo', 'fetch_url'] },
  filesystem: { allowedRoots: ['/tmp/allowed-root'] },
  network: { allowedDomains: ['api.example.com'] },
  env: { allow: ['PATH', 'DEMO_VISIBLE'] },
  redactArgKeys: ['api_key'],
});

// --- tool allowlist -------------------------------------------------------

test('allowlisted tool with benign args is allowed', () => {
  const v = evaluateCall(policy, 'echo', { text: 'hello' });
  assert.equal(v.decision, 'allow');
});

test('non-allowlisted tool is denied', () => {
  const v = evaluateCall(policy, 'delete_file', { path: '/tmp/allowed-root/x' });
  assert.equal(v.decision, 'deny');
  assert.match(v.reason, /not in the policy tool allowlist/);
});

// --- filesystem scoping ---------------------------------------------------

test('path inside an allowed root is allowed', () => {
  const v = evaluateCall(policy, 'read_file', { path: '/tmp/allowed-root/note.txt' });
  assert.equal(v.decision, 'allow');
});

test('path outside the allowed roots is denied', () => {
  const v = evaluateCall(policy, 'read_file', { path: '/etc/passwd' });
  assert.equal(v.decision, 'deny');
  assert.match(v.reason, /outside the policy filesystem allowlist/);
});

test('path traversal out of an allowed root is denied', () => {
  const v = evaluateCall(policy, 'read_file', {
    path: '/tmp/allowed-root/../../etc/passwd',
  });
  assert.equal(v.decision, 'deny');
});

// --- network egress -------------------------------------------------------

test('URL to an allowlisted domain is allowed', () => {
  const v = evaluateCall(policy, 'fetch_url', { url: 'https://api.example.com/data' });
  assert.equal(v.decision, 'allow');
});

test('URL to a subdomain of an allowlisted domain is allowed', () => {
  const v = evaluateCall(policy, 'fetch_url', { url: 'https://v1.api.example.com/data' });
  assert.equal(v.decision, 'allow');
});

test('URL to a non-allowlisted domain is denied', () => {
  const v = evaluateCall(policy, 'fetch_url', { url: 'https://evil.example.org/steal' });
  assert.equal(v.decision, 'deny');
  assert.match(v.reason, /network egress/);
});

// --- redaction ------------------------------------------------------------

test('sensitive argument keys produce allow-with-redaction and scrubbed args', () => {
  const v = evaluateCall(policy, 'echo', { text: 'hi', api_key: 'super-secret' });
  assert.equal(v.decision, 'allow-with-redaction');
  assert.equal(v.redactedArgs.api_key, '***REDACTED***');
  assert.equal(v.redactedArgs.text, 'hi');
});

// --- env brokering --------------------------------------------------------

test('buildChildEnv copies only allowlisted variables', () => {
  const env = buildChildEnv(policy, {
    PATH: '/usr/bin',
    DEMO_VISIBLE: 'yes',
    AWS_SECRET_ACCESS_KEY: 'should-not-cross',
    OPENAI_API_KEY: 'should-not-cross',
  });
  assert.deepEqual(env, { PATH: '/usr/bin', DEMO_VISIBLE: 'yes' });
});

test('buildChildEnv omits allowlisted variables that are not set', () => {
  const env = buildChildEnv(policy, { PATH: '/usr/bin' });
  assert.deepEqual(env, { PATH: '/usr/bin' });
});

// --- Jev hook -------------------------------------------------------------

test('static provider always abstains (static policy stands)', async () => {
  const p = new StaticPolicyProvider();
  assert.equal(await p.evaluate({ tool: 'read_file', args: { path: '/etc/passwd' } }), null);
});

test('jev provider abstains when no API key is configured', async () => {
  const p = new JevProvider({ apiKey: undefined });
  assert.equal(await p.evaluate({ tool: 'read_file', args: {} }), null);
});

test('jev provider denies when the exceeds-purpose probability beats the threshold', async () => {
  const fakeFetch = async () => ({
    ok: true,
    json: async () => ({ answers: { exceeds_purpose: { noul: 0.93 } } }),
  });
  const p = new JevProvider({ apiKey: 'test-key-not-real', threshold: 0.5, fetchImpl: fakeFetch });
  const v = await p.evaluate({ tool: 'read_file', args: { path: '/etc/passwd' } });
  assert.equal(v.decision, 'deny');
  assert.match(v.reason, /Jev hook/);
});

test('jev provider abstains (falls back) when the API errors', async () => {
  const fakeFetch = async () => {
    throw new Error('network down');
  };
  const p = new JevProvider({ apiKey: 'test-key-not-real', fetchImpl: fakeFetch });
  assert.equal(await p.evaluate({ tool: 'read_file', args: {} }), null);
});
