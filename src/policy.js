// Policy loading, normalization, and the static decision engine.
//
// A policy is a JSON document (see policy.example.json):
//   server:      how to spawn the upstream MCP server { command, args }
//   tools.allow: the only tool names the client may call
//   filesystem.allowedRoots: path arguments must resolve inside one of these
//                roots. If the "allowedRoots" key is present (even empty),
//                filesystem enforcement is ON and paths outside are denied.
//   network.allowedDomains: URL arguments must point at these domains (or a
//                subdomain). Enforcement is ON iff the key is present.
//   env.allow:   the ONLY environment variables the upstream process is
//                spawned with (env brokering -- secrets not listed here never
//                reach the upstream server).
//   redactArgKeys: argument keys whose values are replaced with a redaction
//                marker before the call is forwarded.
//   jev:         optional semantic hook settings { enabled, threshold }
//   auditLog:    default audit log path (overridable with --audit-log)

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const DECISION_ALLOW = 'allow';
export const DECISION_DENY = 'deny';
export const DECISION_ALLOW_REDACTED = 'allow-with-redaction';
export const REDACTED = '***REDACTED***';

export function loadPolicy(policyPath) {
  const raw = fs.readFileSync(policyPath, 'utf8');
  return normalizePolicy(JSON.parse(raw));
}

export function normalizePolicy(p = {}) {
  const fsCfg = p.filesystem ?? {};
  const netCfg = p.network ?? {};
  return {
    server: {
      command: p.server?.command ?? 'node',
      args: p.server?.args ?? [],
    },
    tools: { allow: [...(p.tools?.allow ?? [])] },
    filesystem: {
      enforce: Object.prototype.hasOwnProperty.call(fsCfg, 'allowedRoots'),
      allowedRoots: (fsCfg.allowedRoots ?? []).map((r) => path.resolve(expandHome(r))),
    },
    network: {
      enforce: Object.prototype.hasOwnProperty.call(netCfg, 'allowedDomains'),
      allowedDomains: (netCfg.allowedDomains ?? []).map((d) => String(d).toLowerCase()),
    },
    env: { allow: [...(p.env?.allow ?? ['PATH'])] },
    redactArgKeys: (p.redactArgKeys ?? []).map((k) => String(k).toLowerCase()),
    jev: {
      enabled: Boolean(p.jev?.enabled ?? false),
      threshold: typeof p.jev?.threshold === 'number' ? p.jev.threshold : 0.5,
    },
    auditLog: p.auditLog ?? 'audit.log',
  };
}

function expandHome(p) {
  if (p === '~') return os.homedir();
  if (typeof p === 'string' && p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

const PATH_KEY_RE = /path|file|dir|folder/i;

// A string argument "looks like a path" when its key names it as one
// (path, filePath, directory, ...) or the value itself is an absolute or
// explicitly relative path.
export function looksLikePath(key, value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  if (key && PATH_KEY_RE.test(key)) return true;
  return (
    value.startsWith('/') ||
    value.startsWith('./') ||
    value.startsWith('../') ||
    value.startsWith('~/') ||
    /^[a-zA-Z]:[\\/]/.test(value)
  );
}

export function isWithinRoots(candidate, roots) {
  const resolved = path.resolve(expandHome(candidate));
  return roots.some((root) => resolved === root || resolved.startsWith(root + path.sep));
}

export function looksLikeUrl(value) {
  return typeof value === 'string' && /^https?:\/\//i.test(value);
}

export function domainAllowed(hostname, allowedDomains) {
  const host = String(hostname).toLowerCase();
  return allowedDomains.some((d) => host === d || host.endsWith('.' + d));
}

function walkStrings(value, key, visit) {
  if (typeof value === 'string') {
    visit(key, value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v) => walkStrings(v, key, visit));
    return;
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) walkStrings(v, k, visit);
  }
}

function redactValue(value, redactKeys) {
  if (Array.isArray(value)) return value.map((v) => redactValue(v, redactKeys));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = redactKeys.includes(k.toLowerCase()) ? REDACTED : redactValue(v, redactKeys);
    }
    return out;
  }
  return value;
}

function containsRedactableKey(value, redactKeys) {
  if (Array.isArray(value)) return value.some((v) => containsRedactableKey(v, redactKeys));
  if (value && typeof value === 'object') {
    return Object.entries(value).some(
      ([k, v]) => redactKeys.includes(k.toLowerCase()) || containsRedactableKey(v, redactKeys),
    );
  }
  return false;
}

// Evaluate one tools/call request against the static policy.
// Returns { decision, reason, redactedArgs? }.
export function evaluateCall(policy, toolName, args = {}) {
  if (!policy.tools.allow.includes(toolName)) {
    return {
      decision: DECISION_DENY,
      reason: `tool "${toolName}" is not in the policy tool allowlist`,
    };
  }

  let denyReason = null;
  walkStrings(args ?? {}, null, (key, value) => {
    if (denyReason) return;
    if (looksLikeUrl(value)) {
      if (policy.network.enforce) {
        let host = null;
        try {
          host = new URL(value).hostname;
        } catch {
          host = null;
        }
        if (!host || !domainAllowed(host, policy.network.allowedDomains)) {
          denyReason = `network egress to "${host ?? value}" is not in the policy domain allowlist`;
        }
      }
      return;
    }
    if (looksLikePath(key, value) && policy.filesystem.enforce) {
      if (!isWithinRoots(value, policy.filesystem.allowedRoots)) {
        const roots = policy.filesystem.allowedRoots.join(', ') || '(no roots configured)';
        denyReason = `path "${value}" is outside the policy filesystem allowlist: ${roots}`;
      }
    }
  });
  if (denyReason) return { decision: DECISION_DENY, reason: denyReason };

  if (policy.redactArgKeys.length > 0 && containsRedactableKey(args ?? {}, policy.redactArgKeys)) {
    return {
      decision: DECISION_ALLOW_REDACTED,
      reason: 'call allowed; sensitive argument values redacted before forwarding',
      redactedArgs: redactValue(args ?? {}, policy.redactArgKeys),
    };
  }

  return { decision: DECISION_ALLOW, reason: 'allowed by policy' };
}

// Env brokering: build the environment the upstream process is spawned
// with. Only variables named in policy.env.allow are copied over -- anything
// else in the proxy's own environment (API keys, cloud credentials, ...)
// never reaches the upstream server.
export function buildChildEnv(policy, baseEnv = process.env) {
  const out = {};
  for (const key of policy.env.allow) {
    if (baseEnv[key] !== undefined) out[key] = baseEnv[key];
  }
  return out;
}
