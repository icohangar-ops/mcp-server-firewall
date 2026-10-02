#!/usr/bin/env node
// mcp-server-firewall: a capability-scoped stdio proxy for MCP servers.
//
// MCP is JSON-RPC 2.0 over stdio (newline-delimited JSON). This proxy sits
// between the MCP client and the upstream MCP server:
//
//   client  <--stdio-->  firewall proxy  <--stdio-->  upstream server
//
// The upstream server is spawned as a child process with a brokered
// environment (only policy-allowlisted variables). Every tools/call request
// from the client is inspected against the policy before it is forwarded:
//
//   deny                -> never forwarded; the client gets a JSON-RPC error
//                          (-32001) explaining the policy block
//   allow-with-redaction-> forwarded with sensitive argument values replaced
//   allow               -> forwarded as-is
//
// Everything is written to a JSONL audit log. All diagnostics go to stderr;
// stdout carries only protocol messages for the client.
//
// Usage:
//   node src/proxy.js --policy policy.json [--audit-log audit.log]

import { spawn } from 'node:child_process';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { AuditLog } from './audit-log.js';
import { createDecisionProvider } from './jev-hook.js';
import { buildChildEnv, evaluateCall, loadPolicy } from './policy.js';

const POLICY_ERROR_CODE = -32001; // JSON-RPC server-defined error range

export class McpFirewallProxy {
  constructor({
    policy,
    auditLog = new AuditLog(null),
    provider = null,
    input = process.stdin,
    output = process.stdout,
    errorOutput = process.stderr,
    spawnImpl = spawn,
  }) {
    this.policy = policy;
    this.auditLog = auditLog;
    this.provider = provider;
    this.input = input;
    this.output = output;
    this.errorOutput = errorOutput;
    this.spawnImpl = spawnImpl;
    this.child = null;
    this.pending = new Map(); // request id -> { method, tool, decision, reason }
  }

  start() {
    const env = buildChildEnv(this.policy);
    this.child = this.spawnImpl(this.policy.server.command, this.policy.server.args, {
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.child.on('error', (err) => {
      this.errorOutput.write(`[mcp-server-firewall] upstream spawn error: ${err.message}\n`);
    });
    // Upstream stderr is diagnostic, not protocol: pass it through to ours.
    this.child.stderr.on('data', (d) => this.errorOutput.write(d));

    const clientLines = readline.createInterface({ input: this.input, crlfDelay: Infinity });
    clientLines.on('line', (line) => {
      void this.handleClientLine(line);
    });

    const upstreamLines = readline.createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    upstreamLines.on('line', (line) => this.handleUpstreamLine(line));

    return this.child;
  }

  async handleClientLine(line) {
    if (!line.trim()) return;
    let msg = null;
    try {
      msg = JSON.parse(line);
    } catch {
      msg = null;
    }
    const isObject = msg !== null && typeof msg === 'object' && !Array.isArray(msg);
    const isRequest = isObject && 'id' in msg && 'method' in msg;

    if (isRequest && msg.method === 'tools/call') {
      const tool = msg.params?.name;
      const args = msg.params?.arguments ?? {};
      let verdict = evaluateCall(this.policy, tool, args);
      let forwardLine = line;

      // Optional semantic hook: can only escalate an allow to a deny.
      if (verdict.decision !== 'deny' && this.provider) {
        const hookVerdict = await this.provider.evaluate({ tool, args });
        if (hookVerdict?.decision === 'deny') verdict = hookVerdict;
      }

      if (verdict.decision === 'allow-with-redaction' && verdict.redactedArgs) {
        forwardLine = JSON.stringify({
          ...msg,
          params: { ...msg.params, arguments: verdict.redactedArgs },
        });
      }

      this.auditLog.write({
        direction: 'request',
        id: msg.id ?? null,
        method: msg.method,
        tool: tool ?? null,
        decision: verdict.decision,
        reason: verdict.reason,
      });

      if (verdict.decision === 'deny') {
        const errorResponse = {
          jsonrpc: '2.0',
          id: msg.id,
          error: {
            code: POLICY_ERROR_CODE,
            message: `Blocked by mcp-server-firewall policy: ${verdict.reason}`,
            data: { decision: 'deny', reason: verdict.reason },
          },
        };
        this.output.write(JSON.stringify(errorResponse) + '\n');
        this.auditLog.write({
          direction: 'response',
          id: msg.id ?? null,
          method: msg.method,
          tool: tool ?? null,
          decision: 'deny',
          reason: verdict.reason,
          synthetic: true,
        });
        return;
      }

      this.pending.set(String(msg.id), {
        method: msg.method,
        tool: tool ?? null,
        decision: verdict.decision,
        reason: verdict.reason,
      });
      this.child.stdin.write(forwardLine + '\n');
      return;
    }

    // Everything else (initialize, tools/list, notifications, responses to
    // any server-initiated requests, ...) is forwarded uninspected.
    this.auditLog.write({
      direction: 'request',
      id: isObject ? (msg.id ?? null) : null,
      method: isObject ? (msg.method ?? null) : null,
      tool: null,
      decision: 'forwarded',
      reason: 'not a tools/call request; forwarded without inspection',
    });
    if (isRequest) {
      this.pending.set(String(msg.id), { method: msg.method, tool: null, decision: 'forwarded' });
    }
    this.child.stdin.write(line + '\n');
  }

  handleUpstreamLine(line) {
    if (!line.trim()) return;
    let msg = null;
    try {
      msg = JSON.parse(line);
    } catch {
      msg = null;
    }
    const isObject = msg !== null && typeof msg === 'object' && !Array.isArray(msg);
    if (isObject && 'id' in msg && ('result' in msg || 'error' in msg)) {
      const info = this.pending.get(String(msg.id));
      this.auditLog.write({
        direction: 'response',
        id: msg.id ?? null,
        method: info?.method ?? null,
        tool: info?.tool ?? null,
        decision: info?.decision ?? 'forwarded',
        reason: info?.reason ?? null,
        ok: 'result' in msg,
      });
      this.pending.delete(String(msg.id));
    } else {
      this.auditLog.write({
        direction: 'response',
        id: isObject ? (msg.id ?? null) : null,
        method: isObject ? (msg.method ?? null) : null,
        tool: null,
        decision: 'forwarded',
        reason: null,
      });
    }
    this.output.write(line + '\n');
  }
}

function parseCliArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--policy') out.policy = argv[++i];
    else if (argv[i] === '--audit-log') out.auditLog = argv[++i];
  }
  return out;
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isMain) {
  const cli = parseCliArgs(process.argv.slice(2));
  const policyPath = cli.policy ?? 'policy.json';
  const policy = loadPolicy(policyPath);
  const auditLog = new AuditLog(cli.auditLog ?? policy.auditLog);
  const provider = createDecisionProvider(policy);
  const proxy = new McpFirewallProxy({ policy, auditLog, provider });
  proxy.start();
  proxy.child.on('exit', (code) => process.exit(code ?? 0));
  process.stdin.on('end', () => {
    try {
      proxy.child.stdin.end();
    } catch {
      // upstream already gone
    }
  });
}
