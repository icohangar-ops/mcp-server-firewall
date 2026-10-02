// Vercel serverless demo endpoint for mcp-server-firewall.
//
// Evaluates three sample tools/call requests against the example policy
// using the real policy engine (src/policy.js) and returns the decisions as
// JSON. No upstream server is spawned — this exercises the static decision
// layer only, exactly as the proxy does before forwarding.

import { normalizePolicy, evaluateCall } from '../src/policy.js';

// Same shape as policy.example.json, inlined so the function is
// self-contained (no policy file to resolve at runtime).
const SAMPLE_POLICY = {
  tools: { allow: ['read_file', 'echo', 'print_env'] },
  filesystem: { allowedRoots: ['/srv/app-data'] },
  network: { allowedDomains: ['api.example.com'] },
  env: { allow: ['PATH', 'HOME'] },
  redactArgKeys: ['api_key', 'token', 'password'],
  jev: { enabled: false, threshold: 0.5 },
};

const SAMPLE_CALLS = [
  {
    label: 'read inside the allowed root',
    tool: 'read_file',
    args: { path: '/srv/app-data/report.txt' },
  },
  {
    label: 'read of /etc/passwd — outside every allowed root',
    tool: 'read_file',
    args: { path: '/etc/passwd' },
  },
  {
    label: 'delete_file — a tool the upstream offers but the policy does not allowlist',
    tool: 'delete_file',
    args: { path: '/srv/app-data/report.txt' },
  },
];

export default async function handler(req, res) {
  try {
    const policy = normalizePolicy(SAMPLE_POLICY);
    const results = SAMPLE_CALLS.map(({ label, tool, args }) => {
      const { decision, reason } = evaluateCall(policy, tool, args);
      return { case: label, tool, args, decision, reason };
    });

    res.status(200).json({
      product: 'mcp-server-firewall',
      policy: {
        toolAllowlist: policy.tools.allow,
        filesystemAllowedRoots: policy.filesystem.allowedRoots,
        networkAllowedDomains: policy.network.allowedDomains,
        envAllowlist: policy.env.allow,
      },
      results,
    });
  } catch (err) {
    res.status(500).json({ error: 'demo failed', detail: String(err?.message ?? err) });
  }
}
