#!/usr/bin/env node
// Demo: run the firewall proxy in front of the example echo server and
// watch it enforce policy.
//
//   npm run demo
//
// Scenario:
//   1. read_file inside the allowed root           -> passes
//   2. read_file /etc/passwd (outside the roots)    -> DENIED by policy
//   3. delete_file (not in the tool allowlist)      -> DENIED by policy
//   4. print_env shows the upstream server only sees env vars the policy
//      brokered to it -- a TOP_SECRET variable set on the proxy process
//      never reaches the upstream server.
// Finally the JSONL audit log is printed.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const demoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-fw-demo-'));
const dataFile = path.join(demoDir, 'hello.txt');
fs.writeFileSync(dataFile, 'hello from inside the allowed root\n');
const auditPath = path.join(demoDir, 'audit.log');
const policyPath = path.join(demoDir, 'policy.json');

fs.writeFileSync(
  policyPath,
  JSON.stringify(
    {
      server: {
        command: process.execPath,
        args: [path.join(repoRoot, 'examples', 'echo-server.js')],
      },
      tools: { allow: ['read_file', 'echo', 'print_env'] },
      filesystem: { allowedRoots: [demoDir] },
      network: { allowedDomains: [] },
      env: { allow: ['PATH', 'DEMO_VISIBLE'] },
      redactArgKeys: ['api_key', 'token', 'password'],
      jev: { enabled: false },
      auditLog: auditPath,
    },
    null,
    2,
  ),
);

console.log(`demo workspace (the allowed root): ${demoDir}\n`);

const proxy = spawn(
  process.execPath,
  [path.join(repoRoot, 'src', 'proxy.js'), '--policy', policyPath],
  {
    cwd: repoRoot,
    env: {
      ...process.env,
      DEMO_VISIBLE: 'allowlisted-and-visible',
      TOP_SECRET_SHOULD_NOT_LEAK: 'hunter2',
    },
    stdio: ['pipe', 'pipe', 'inherit'],
  },
);

// Minimal MCP client: match responses to requests by id.
let nextId = 1;
const waiters = new Map();
const rl = readline.createInterface({ input: proxy.stdout, crlfDelay: Infinity });
rl.on('line', (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  const w = waiters.get(msg.id);
  if (w) {
    waiters.delete(msg.id);
    w(msg);
  }
});
function call(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`timeout waiting for response to ${method}`)),
      5000,
    );
    waiters.set(id, (msg) => {
      clearTimeout(timer);
      resolve(msg);
    });
    proxy.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}

let failures = 0;
function check(label, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `\n      ${detail}` : ''}`);
  if (!ok) failures++;
}

try {
  const init = await call('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'demo-client', version: '0.0.0' },
  });
  console.log(
    `connected through the firewall to upstream: ${init.result.serverInfo.name} ${init.result.serverInfo.version}\n`,
  );

  const okRead = await call('tools/call', {
    name: 'read_file',
    arguments: { path: dataFile },
  });
  check(
    'read_file inside the allowed root passes',
    okRead.result?.content?.[0]?.text?.includes('hello from inside') ?? false,
    `result: ${JSON.stringify(okRead.result?.content?.[0]?.text ?? okRead.error)}`,
  );

  const badRead = await call('tools/call', {
    name: 'read_file',
    arguments: { path: '/etc/passwd' },
  });
  check(
    'read_file /etc/passwd is denied by policy',
    Boolean(badRead.error),
    `error: ${badRead.error?.message}`,
  );

  const badTool = await call('tools/call', {
    name: 'delete_file',
    arguments: { path: dataFile },
  });
  check(
    'delete_file (not in the tool allowlist) is denied',
    Boolean(badTool.error),
    `error: ${badTool.error?.message}`,
  );
  check('the file still exists after the denied delete', fs.existsSync(dataFile));

  const envRes = await call('tools/call', { name: 'print_env', arguments: {} });
  const visibleKeys = JSON.parse(envRes.result.content[0].text);
  check(
    'upstream sees the allowlisted DEMO_VISIBLE variable',
    visibleKeys.includes('DEMO_VISIBLE'),
    `upstream env keys: ${visibleKeys.join(', ')}`,
  );
  check(
    'upstream cannot see TOP_SECRET_SHOULD_NOT_LEAK',
    !visibleKeys.includes('TOP_SECRET_SHOULD_NOT_LEAK'),
  );
} finally {
  proxy.stdin.end();
}

await new Promise((r) => setTimeout(r, 300));
console.log(`\n--- audit log (${auditPath}) ---`);
console.log(
  fs.existsSync(auditPath) ? fs.readFileSync(auditPath, 'utf8').trim() : '(no audit log written)',
);
proxy.kill();
fs.rmSync(demoDir, { recursive: true, force: true });

console.log(
  failures === 0
    ? '\nDemo OK: the firewall enforced every policy decision.'
    : `\nDemo FAILED: ${failures} check(s) failed.`,
);
process.exit(failures === 0 ? 0 : 1);
