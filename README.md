# mcp-server-firewall

A capability-scoped proxy that sits between an MCP (Model Context Protocol)
client and an upstream MCP server, so the server only ever gets the powers
your policy grants it — not the keys to the machine.

<!-- product-screenshots:start -->
## Product screenshots

MCP policy-firewall overview; its sample tool-call demo was not run.

![mcp-server-firewall interface](docs/screenshots/product-overview.png)

Captured locally and non-interactively from [source commit 7ec2a0b548f0](https://github.com/icohangar-ops/mcp-server-firewall/tree/7ec2a0b548f042c16e37e65aa2dfcd3eef1bd2f5); mcp policy-firewall overview; its sample tool-call demo was not run.
<!-- product-screenshots:end -->

## The problem

> "MCP is a security joke." — r/mcp

They're not wrong. A typical MCP server runs as a local process with
effectively **root-equivalent access**: it can read any file the user can
read (`~/.ssh`, `~/.aws`, your `.env`), make arbitrary network requests,
spawn processes, and see every environment variable in its parent process —
including cloud credentials and API keys it has no business touching. There
is no sandbox, no permission model, and no audit trail. Installing an MCP
server today is closer to running an untrusted binary than calling an API.

`mcp-server-firewall` is the governed gateway that should have been in the
middle from the start.

## What it enforces

Every `tools/call` request is inspected **before** it reaches the upstream
server, and gets one of three decisions:

| Decision | Meaning |
|---|---|
| `allow` | Forwarded as-is. |
| `allow-with-redaction` | Forwarded, but values of policy-named sensitive argument keys (`api_key`, `token`, ...) are replaced with `***REDACTED***` first. |
| `deny` | Never forwarded. The client receives a JSON-RPC error (`-32001`) explaining exactly which policy rule blocked the call. |

Policy controls four capability surfaces:

- **Tool allowlist** — the client can only call tools you name. Everything
  else is denied, including tools the upstream advertises.
- **Filesystem scope** — arguments that look like paths (path-like argument
  names, or absolute/relative path values) must resolve inside configured
  `allowedRoots`. `..` traversal is resolved before the check, so
  `/allowed/../../etc/passwd` does not escape.
- **Network egress** — URL arguments must point at allowlisted domains (or
  their subdomains). Everything else is denied.
- **Env brokering** — the upstream process is spawned with *only* the
  environment variables named in the policy. A server that dumps its own
  environment finds your allowlisted variables and nothing else: no cloud
  keys, no tokens, no secrets to exfiltrate.

And **everything is logged**: a JSONL audit log records each request and
response with the policy decision and the human-readable reason.

## Architecture

MCP is JSON-RPC 2.0, newline-delimited, over stdio. The firewall is a
hand-rolled stdio proxy in dependency-free Node.js — no packages to install,
nothing in the middle but this code:

```
┌──────────────┐   stdio    ┌───────────────────────────┐   stdio    ┌────────────────┐
│  MCP client  │ ─────────▶ │     mcp-server-firewall   │ ─────────▶ │ upstream MCP   │
│ (Claude, IDE,│            │                           │            │ server (child  │
│  your agent) │ ◀───────── │  1. parse tools/call      │ ◀───────── │ process,       │
└──────────────┘            │  2. policy decision       │            │ brokered env)  │
                            │  3. forward / deny /      │            └────────────────┘
                            │     redact                  │
                            │  4. audit-log everything  │
                            └───────────────────────────┘
```

- `src/proxy.js` — the proxy: spawns the upstream, forwards protocol
  messages, intercepts `tools/call`, emits policy errors, matches responses
  to decisions.
- `src/policy.js` — policy loading and the static decision engine
  (allowlist, path/URL checks, redaction, env brokering).
- `src/audit-log.js` — the append-only JSONL audit log.
- `src/jev-hook.js` — the optional semantic decision hook (below).
- `examples/echo-server.js` — a tiny hand-rolled MCP server used by the demo
  and tests, exposing `read_file`, `echo`, `print_env`, and a deliberately
  dangerous `delete_file`.

## Quickstart

Requires Node 20+. No dependencies to install.

```bash
# Run the self-contained demo (creates a temp allowed-root, runs the proxy
# in front of the example server, exercises allow + deny paths, prints the
# audit log):
npm run demo

# Run the tests (policy unit tests + an end-to-end proxy test):
npm test

# Use it for real: point a policy at your MCP server, then point your MCP
# client at the proxy instead of the server.
cp policy.example.json policy.json   # edit to taste
npm start                            # node src/proxy.js --policy policy.json
```

In your MCP client config, wherever you would have put the server's
`command`/`args`, put the firewall instead:

```json
{
  "mcpServers": {
    "my-server-through-firewall": {
      "command": "node",
      "args": ["/path/to/mcp-server-firewall/src/proxy.js", "--policy", "/path/to/policy.json"]
    }
  }
}
```

## Policy configuration walkthrough

See `policy.example.json` for the full shape:

```jsonc
{
  // How to spawn the upstream server (cwd is inherited).
  "server": { "command": "node", "args": ["examples/echo-server.js"] },

  // The ONLY tools the client may call.
  "tools": { "allow": ["read_file", "echo", "print_env"] },

  // Path arguments must resolve inside one of these roots.
  // Enforcement is ON whenever the "allowedRoots" key is present —
  // an empty list denies all path arguments.
  "filesystem": { "allowedRoots": ["/tmp/mcp-fw-demo"] },

  // URL arguments must target these domains (subdomains allowed).
  // Same rule: key present = enforcement on.
  "network": { "allowedDomains": ["api.example.com"] },

  // The upstream process is spawned with ONLY these environment variables.
  "env": { "allow": ["PATH", "HOME"] },

  // Argument keys scrubbed to "***REDACTED***" before forwarding.
  "redactArgKeys": ["api_key", "token", "password"],

  // Optional semantic hook (see below).
  "jev": { "enabled": false, "threshold": 0.5 },

  // Audit log path (overridable with --audit-log).
  "auditLog": "audit.log"
}
```

Audit log lines look like:

```json
{"ts":"2026-10-02T08:07:44.996Z","direction":"request","id":3,"method":"tools/call","tool":"read_file","decision":"deny","reason":"path \"/etc/passwd\" is outside the policy filesystem allowlist: /tmp/mcp-fw-demo"}
```

## The Jev hook (optional)

Static rules can't judge intent. For calls the static policy *allows*, the
firewall can consult a semantic decision provider — currently
[TypeSafe AI's Jev](https://typesafe.ai), a "System One" model that returns
typed decisions with calibrated probabilities instead of text. The hook asks
one question per call:

> *Does this call exceed the tool's stated purpose?* (`noul` — a yes/no
> probability)

If the probability exceeds the policy threshold (`jev.threshold`), the call
is denied with the probability recorded in the audit log as the reason.

To enable it:

1. Set `"jev": { "enabled": true, "threshold": 0.5 }` in your policy.
2. Put your key in the environment: `JEV_API_KEY=...` (see `.env.example`).
   The key is only ever sent as a Bearer token to
   `https://api.typesafe.ai/v1/systemone` — it is never logged, never
   written to the audit log, and never passed to the upstream server (it's
   not in the env allowlist).

With no key configured, the hook abstains and the firewall runs on static
policy alone — that is the default. Any Jev error or timeout also falls back
to the static decision: the hook can only escalate an allowed call to a
deny, never weaken a static deny, and never take the proxy down.

## Scope notes

This is a reference implementation, deliberately small and readable:

- Stdio transport only (the overwhelmingly common local-server case).
- Path/URL detection is heuristic: path-like argument names and absolute or
  explicitly relative values are checked anywhere in the argument tree.
- The policy engine is synchronous and deterministic; the Jev hook is the
  only async, probabilistic layer, and it is strictly opt-in.

## Offered by Cubiczan

`mcp-server-firewall` productizes Cubiczan's **Governed MCP Gateway** — the
policy, brokering, and audit layer we deploy between AI agents and the
systems they touch, as part of governed agent deployments for high-trust
operators. If your team is adopting MCP (or agents generally) faster than
your security review can keep up, this is the checkpoint that lets you say
yes safely: [cubiczan.com](https://cubiczan.com) · sam@cubiczan.com
