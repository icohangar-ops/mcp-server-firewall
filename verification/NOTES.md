# Verification notes — mcp-server-firewall

`Firewall.lean` in this directory is a Lean 4 (core library only) model of
the policy/proxy logic in `../src/policy.js`, `../src/proxy.js`, and
`../src/jev-hook.js`. Build/check it with:

```sh
lean Firewall.lean        # Lean 4.34.1, no lake project, no Mathlib
```

There is no `sorry`, `admit`, `native_decide`, or custom axiom in the file.
A `#print axioms` audit (run on a scratch copy) shows every theorem depends
only on the standard Lean axioms `propext`, `Classical.choice`, `Quot.sound`
(several depend on none at all).

Line numbers below refer to the sources as of 2026-10-03.

## Definition mapping

| Lean definition | Source | Notes |
|---|---|---|
| `Decision` (`allow` / `deny` / `allowWithRedaction`) | `policy.js:23–25` | The `DECISION_ALLOW` / `DECISION_DENY` / `DECISION_ALLOW_REDACTED` string constants. |
| `evaluateCall toolAllowed argViolation hasRedactable` | `policy.js:135–179` (`evaluateCall`) | Abstracted over the three boolean inputs, in the source's check order; see the input mapping below. |
| `applyHook static hook` | `proxy.js:96–99`, contract in `jev-hook.js:1–20` | `none` models a provider abstention (`null`); `some d` models a returned verdict object with decision `d`. In practice providers only ever return `null` or `{decision: 'deny'}` (`jev-hook.js:24–28`, `43–97`). |
| `Id`, `Info`, `Pending` | `proxy.js:56`, record shape at `140–145`, `161` | `pending` is a JS `Map` keyed by `String(msg.id)`; `Info` drops the `reason` field, which no session invariant depends on. |
| `Pending.insert` / `Pending.remove` | `proxy.js:140`, `161` (`pending.set`) / `proxy.js:186` (`pending.delete`) | Lookup is `pending.get` at `proxy.js:176`. |
| `recordRequest` | `proxy.js:117–146` | Captures the control flow: the deny branch returns at line 138 after writing the synthetic error, *before* `pending.set` at line 140; any other verdict is recorded and forwarded at line 146. |
| `buildChildEnv allow env` | `policy.js:184–190` (`buildChildEnv`) | Abstraction difference: the JS iterates `policy.env.allow` and copies values out of `process.env`; the model filters the environment list by key membership. The set of keys handed to the child is the same; see discrepancy 7. Used at `proxy.js:62`. |
| `domainAllowed host domains` | `policy.js:92–95` | Direct transcription: `domains.any (fun d => host == d ‖ host.endsWith ("." ++ d))`. The JS additionally lowercases the host (`policy.js:93`) and `normalizePolicy` lowercases the allowlist (`policy.js:48`); the model assumes already-normalized inputs. |

### `evaluateCall` input mapping

| Model input | JavaScript |
|---|---|
| `toolAllowed` | `policy.tools.allow.includes(toolName)`, `policy.js:136` |
| `argViolation` | `denyReason ≠ null` after the `walkStrings` scan, `policy.js:143–167`. One boolean collapses both checks: URL branch (`146–159`, domain allowlist via `domainAllowed`, only when `network.enforce`) and path branch (`160–165`, `isWithinRoots`, only when `filesystem.enforce`). |
| `hasRedactable` | `policy.redactArgKeys.length > 0 && containsRedactableKey(args ?? {}, policy.redactArgKeys)`, `policy.js:169` (with `containsRedactableKey` at `123–132`). |

## Theorem mapping

### Static engine — `policy.js:135–179`

| Theorem | Property |
|---|---|
| `evaluateCall_deny_of_not_tool_allowed` | (a) `toolAllowed = false` ⇒ deny, whatever the arguments. The allowlist (`policy.js:136–141`) is checked first and is absolute. |
| `evaluateCall_not_deny_checks_passed` | (b) Non-deny ⇒ `toolAllowed = true ∧ argViolation = false`: anything forwarded passed every static check. |
| `evaluateCall_redacted_of_redactable` | (c) `evaluateCall true false true = allowWithRedaction` (`policy.js:169–175`). |
| `evaluateCall_eq_deny_iff` | Exact characterization: deny ⇔ not allowlisted ∨ argument violation. |
| `evaluateCall_eq_redacted_iff` | Exact characterization of `allowWithRedaction`. |

### Jev hook — `proxy.js:96–99`, `jev-hook.js`

| Theorem | Property |
|---|---|
| `applyHook_deny_absorbing` | (d) `applyHook deny h = deny` for all `h`. The hook branch is guarded by `verdict.decision !== 'deny'` (`proxy.js:96`), so a static deny is final. |
| `applyHook_eq_static_or_deny` | (e) `applyHook s h = s ∨ applyHook s h = deny`: the hook can only escalate, matching the replacement condition `hookVerdict?.decision === 'deny'` (`proxy.js:98`). |
| `applyHook_eq_allow_imp` | (f₁) Final `allow` ⇒ static was `allow`. In particular a static `allowWithRedaction` can never be silently upgraded to a plain `allow` (which would drop the redaction step at `proxy.js:101–106`). |
| `applyHook_eq_redacted_imp` | (f₂) Final `allowWithRedaction` ⇒ static was `allowWithRedaction`: the hook cannot manufacture a redaction verdict either (in the JS its object has no `redactedArgs`, so this case cannot arise at runtime). |
| `applyHook_none` | Abstention (`null`) leaves the static verdict untouched — the failure mode of every Jev error path (`jev-hook.js:44, 73, 84, 93–96`). |
| `applyHook_some_deny` | A hook deny always escalates (Jev denies when `p > threshold`, `jev-hook.js:85–91`). |

### Pending session map — `proxy.js`

| Theorem | Property |
|---|---|
| `recordRequest_deny` | (g) A denied request leaves `pending` *exactly* unchanged (deny returns at `proxy.js:138`, before `set` at `140`). |
| `recordRequest_deny_absent` | (g, corollary) An id absent before a denied request is still absent after it. |
| `Pending.insert_self` / `Pending.insert_other` | `set` then `get` on the same id returns the stored record; other ids are unaffected. |
| `recordRequest_forwarded` | (h₁) A forwarded request is findable under its id when the upstream response arrives (`pending.get`, `proxy.js:176`). |
| `Pending.remove_self`, `recordRequest_then_response` | (h₂) The first response for an id consumes the entry (`pending.delete`, `proxy.js:186`); a later lookup returns `none`. |
| `Pending.remove_other`, `Pending.remove_other_intact` | (h₃) Removing one id leaves other ids' entries intact — attribution is strictly per-id. |

### Env brokering — `policy.js:184–190`

| Theorem | Property |
|---|---|
| `buildChildEnv_key_allowlisted` | (i) Every `(k, v)` in the brokered environment satisfies `k ∈ allowlist`. Contrapositive: a secret in the proxy's environment that is not allowlisted never reaches the child (the guarantee stated at `policy.js:11–13`). |
| `buildChildEnv_subset` | The brokered environment contains nothing that was not in the base environment. |

### Domain allowlist — `policy.js:92–95`

| Theorem | Property |
|---|---|
| `domainAllowed_iff` | The boolean is exactly the source's existential: `∃ d ∈ domains, host = d ∨ host.endsWith ("." ++ d)`. |
| `domainAllowed_evil_suffix` | (j₁) `domainAllowed "evil-example.com" ["example.com"] = false` — the dot-prefixed suffix blocks suffix attacks. |
| `domainAllowed_subdomain` | (j₂) `domainAllowed "api.example.com" ["example.com"] = true`. |
| `domainAllowed_exact` | (j₃) `domainAllowed "example.com" ["example.com"] = true`. |
| `domainAllowed_domain_as_subdomain` | (j₄) `domainAllowed "example.com.evil.com" ["example.com"] = false`. |
| `domainAllowed_self` | Every allowlisted domain allows itself. |

Proof note for (j): `String.endsWith` in Lean 4.34 is implemented via the
slice/pattern machinery and does not reduce in the kernel, so `rfl`/`decide`
fail on it directly. The proofs bridge through the core lemmas
`String.Slice.endsWith_string_iff` / `String.Slice.endsWith_string_eq_false_iff`
to a suffix statement about character lists, which the kernel decides.

## Discrepancies and risks noticed in the source

1. **Duplicate request ids corrupt attribution (confirmed).** `pending` is a
   plain `Map` keyed by `String(msg.id)` (`proxy.js:56`). A second
   `tools/call` reusing an in-flight id silently overwrites the first entry
   (`proxy.js:140`). The first upstream response consumes the (second
   request's) entry (`proxy.js:186`), and the second response finds nothing:
   it is audited with `method`/`tool` = `null` and `decision: 'forwarded'`
   (`proxy.js:180–182`) but is **still forwarded to the client**
   (`proxy.js:197`). The Lean theorems (h₁–h₃) hold per-operation; the gap
   is that nothing enforces id uniqueness. A related collision: JSON-RPC
   numeric id `1` and string id `"1"` are the same key after `String(...)`
   coercion.

2. **Unsolicited upstream responses are forwarded to the client.**
   `handleUpstreamLine` writes every upstream line to the client
   (`proxy.js:197`) whether or not its id is in `pending`. An upstream
   server can therefore inject a response with a guessed in-flight id —
   delivering it to the client *and* consuming the pending entry, so the
   genuine response is later logged unattributed (see 1). The firewall
   inspects only client→server `tools/call`; the reverse direction is a
   pass-through.

3. **Non-`tools/call` client messages are forwarded uninspected** — by
   design (`proxy.js:150–163`, audit reason "not a tools/call request;
   forwarded without inspection"), but the set is broader than the comment
   suggests: it includes `initialize`, `tools/list`, notifications (no
   `id`, audited with `id: null` at `proxy.js:152`), client responses to
   server-initiated requests, and **unparseable lines**: if `JSON.parse`
   throws, `msg` is `null` (`proxy.js:80–86`) and the raw line falls
   through to be written verbatim to the upstream child's stdin
   (`proxy.js:163`). Garbage in is garbage forwarded.

4. **URL check runs before the path check** in the `walkStrings` callback
   (`policy.js:146–165`): the URL branch returns unconditionally, so a
   string that looks like a URL is never path-checked. Consequences:
   (i) with network enforcement *off*, URL-shaped values skip the
   filesystem check entirely, even under path-like keys; (ii) with network
   enforcement *on*, a value matching the `^https?://` regex that
   `new URL(...)` cannot parse yields `host = null` and is denied
   (`policy.js:150–156`) rather than falling through to the path check.
   Also, first-violation-wins (`if (denyReason) return`, `policy.js:145`)
   makes the *reported reason* depend on `Object.entries` traversal order
   (the decision itself does not).

5. **Path detection is heuristic; redaction key matching is
   case-insensitive.** `looksLikePath` (`policy.js:71–81`, key regex at
   line 69) only fires for keys matching `/path|file|dir|folder/i` or
   values starting with `/`, `./`, `../`, `~/` or a drive letter — a bare
   relative path like `secrets.txt` under a key named e.g. `name` is never
   filesystem-checked. Conversely the scan visits *every* nested string,
   so an ordinary string value starting with `/` is treated as a path.
   Redaction, by contrast, lowercases both sides (`policy.js:51`,
   `111–121`, `123–132`) and recurses through nested objects and arrays.

6. **`isWithinRoots` mishandles the filesystem root.**
   `resolved === root || resolved.startsWith(root + path.sep)`
   (`policy.js:85`): with `allowedRoots: ["/"]`, the prefix test becomes
   `startsWith("//")`, which no resolved path satisfies — a policy that
   tries to allow everything actually denies every path except `/` itself.
   (Non-root trailing slashes are fine: `normalizePolicy` runs them
   through `path.resolve`, `policy.js:44`.)

7. **Env-brokering direction / model difference.** `buildChildEnv`
   (`policy.js:184–190`) iterates the *allowlist*, so an allowlisted
   variable that is unset is silently absent, and the child receives **no**
   default environment beyond the allowlist (default allow is just
   `['PATH']`, `policy.js:50`). The Lean model filters an environment
   *list*; since a JS env object has unique keys, the only divergence
   would be duplicate keys in a hypothetical list env (model keeps all
   copies, JS keeps one) — the proved key-membership guarantee (i) is
   unaffected.

8. **The hook sees unredacted arguments over the network.** When Jev is
   enabled, `provider.evaluate({ tool, args })` is called with the
   original arguments (`proxy.js:95`), and `JevProvider` POSTs them to
   `https://api.typesafe.ai/v1/systemone` (`jev-hook.js:48–71`). Redaction
   (`proxy.js:101–106`) protects the upstream MCP server only — values in
   `redactArgKeys` are still disclosed to the hook provider. Also, on a
   hook deny the whole verdict object is replaced (`proxy.js:98`), so the
   static reason is lost from the audit trail.

9. **Forwarding order is not arrival order when a provider is
   configured.** `handleClientLine` is `async` and invoked fire-and-forget
   per line (`proxy.js:68–70`); two `tools/call` lines interleave at the
   `await` on `proxy.js:97`, so `pending.set` / child-stdin writes happen
   in provider-completion order. Per-call decisions are independent, so
   policy correctness is unaffected, but audit ordering can differ from
   wire order.

10. **Trailing-dot hostnames fail closed.** `domainAllowed("example.com.",
    ["example.com"])` is false (not equal, and it does not end with
    `".example.com"`). Conservative and safe, but a client using FQDN
    root-dot hostnames would be denied unexpectedly.

11. **`tools/call` with a missing `params.name`** yields `tool = undefined`,
    which is not in the allowlist and is denied (`policy.js:136`) — a safe
    default, worth knowing since the audit entry records `tool: null`
    (`proxy.js:112`).

12. **Upstream→client requests are uninspected too.** Server-initiated
    requests (sampling, elicitation) have `id` + `method` but no
    `result`/`error`, so they take the `else` branch of
    `handleUpstreamLine` (`proxy.js:187–196`) and reach the client with
    audit decision `'forwarded'`. The firewall is one-directional by
    design; the audit label makes it look as inspected as everything else.
