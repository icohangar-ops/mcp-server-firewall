/-
  Firewall.lean — a formal model of the policy / proxy logic of
  mcp-server-firewall (src/policy.js, src/proxy.js, src/jev-hook.js).

  Self-contained: Lean 4 core library only. No Mathlib, no lake project,
  no `sorry` / `admit` / custom axioms. Compile with:

      lean Firewall.lean

  The model abstracts the JavaScript at the level of the *decisions* it
  makes; see NOTES.md (same directory) for the exact source mapping of
  every definition and theorem.
-/

namespace Firewall

/-! ## Decisions -/

/-- The three verdicts of the static policy engine.
    Models `DECISION_ALLOW` / `DECISION_DENY` / `DECISION_ALLOW_REDACTED`
    (policy.js, lines 23–25). -/
inductive Decision where
  | allow
  | deny
  | allowWithRedaction
deriving DecidableEq, Repr, Inhabited

/-! ## The static policy engine: `evaluateCall` -/

/-- Abstraction of `evaluateCall` (policy.js, lines 135–179) over its three
    boolean inputs:

    * `toolAllowed`   — `policy.tools.allow.includes(toolName)`
      (policy.js, line 136);
    * `argViolation`  — the `walkStrings` scan inside `evaluateCall`
      (policy.js, lines 143–167) found a string that violates an *enforced*
      check: a URL whose host is not allowlisted while network enforcement
      is on, or a path-like string resolving outside every allowed root
      while filesystem enforcement is on (i.e. `denyReason` was set);
    * `hasRedactable` — `policy.redactArgKeys.length > 0 &&
      containsRedactableKey(args, policy.redactArgKeys)`
      (policy.js, line 169).

    The JavaScript checks run in exactly this order, first hit wins:
    allowlist → argument violation → redaction → allow. -/
def evaluateCall (toolAllowed argViolation hasRedactable : Bool) : Decision :=
  if !toolAllowed then Decision.deny
  else if argViolation then Decision.deny
  else if hasRedactable then Decision.allowWithRedaction
  else Decision.allow

/-- (a) The tool allowlist is absolute: a tool that is not allowlisted is
    denied, regardless of its arguments. (policy.js, lines 136–141.) -/
theorem evaluateCall_deny_of_not_tool_allowed (argViolation hasRedactable : Bool) :
    evaluateCall false argViolation hasRedactable = Decision.deny := by
  cases argViolation <;> cases hasRedactable <;> rfl

/-- (b) Anything the static engine forwards (any non-deny verdict) passed
    *every* static check: the tool was allowlisted and no argument
    violation was found. -/
theorem evaluateCall_not_deny_checks_passed {toolAllowed argViolation hasRedactable : Bool}
    (h : evaluateCall toolAllowed argViolation hasRedactable ≠ Decision.deny) :
    toolAllowed = true ∧ argViolation = false := by
  cases toolAllowed <;> cases argViolation <;> cases hasRedactable <;>
    simp [evaluateCall] at h ⊢

/-- (c) An allowlisted tool with clean arguments and a redactable key is
    forwarded with redaction. (policy.js, lines 169–175.) -/
theorem evaluateCall_redacted_of_redactable :
    evaluateCall true false true = Decision.allowWithRedaction :=
  rfl

/-- Exact characterization of a static deny: it happens iff the tool is not
    allowlisted or an argument violation was found. -/
theorem evaluateCall_eq_deny_iff {toolAllowed argViolation hasRedactable : Bool} :
    evaluateCall toolAllowed argViolation hasRedactable = Decision.deny ↔
      toolAllowed = false ∨ argViolation = true := by
  cases toolAllowed <;> cases argViolation <;> cases hasRedactable <;>
    simp [evaluateCall]

/-- Exact characterization of a static allow-with-redaction. -/
theorem evaluateCall_eq_redacted_iff {toolAllowed argViolation hasRedactable : Bool} :
    evaluateCall toolAllowed argViolation hasRedactable = Decision.allowWithRedaction ↔
      toolAllowed = true ∧ argViolation = false ∧ hasRedactable = true := by
  cases toolAllowed <;> cases argViolation <;> cases hasRedactable <;>
    simp [evaluateCall]

/-! ## The semantic (Jev) hook: escalation only -/

/-- The hook step in `handleClientLine` (proxy.js, lines 96–99), combined
    with the provider contract (jev-hook.js, lines 3–20): the provider is
    consulted only when the static verdict is not `deny`, and its verdict
    replaces the static one only when it is `deny`; `none` models an
    abstention (`null` in the JavaScript). `applyHook` is the resulting
    final verdict as a total function of the static verdict and the
    (possibly absent) hook verdict. -/
def applyHook : Decision → Option Decision → Decision
  | Decision.deny, _ => Decision.deny
  | _s, some Decision.deny => Decision.deny
  | s, _ => s

/-- (d) A static deny is absorbing: the hook is never even consulted, and no
    hook verdict can resurrect a denied call. (proxy.js, line 96.) -/
theorem applyHook_deny_absorbing (h : Option Decision) :
    applyHook Decision.deny h = Decision.deny :=
  rfl

/-- (e) The hook can only escalate: the final verdict is either the static
    verdict, or `deny`. -/
theorem applyHook_eq_static_or_deny (s : Decision) (h : Option Decision) :
    applyHook s h = s ∨ applyHook s h = Decision.deny := by
  cases s with
  | deny => exact Or.inr rfl
  | allow =>
    cases h with
    | none => exact Or.inl rfl
    | some d =>
      cases d with
      | deny => exact Or.inr rfl
      | allow => exact Or.inl rfl
      | allowWithRedaction => exact Or.inl rfl
  | allowWithRedaction =>
    cases h with
    | none => exact Or.inl rfl
    | some d =>
      cases d with
      | deny => exact Or.inr rfl
      | allow => exact Or.inl rfl
      | allowWithRedaction => exact Or.inl rfl

/-- (f₁) The hook can never upgrade a verdict to `allow`: if the final
    verdict is `allow`, the static verdict already was. In particular a
    static `allowWithRedaction` can never be silently upgraded to a plain
    `allow` (dropping the redaction) by the hook. -/
theorem applyHook_eq_allow_imp (s : Decision) (h : Option Decision)
    (heq : applyHook s h = Decision.allow) : s = Decision.allow := by
  cases s with
  | deny => exact absurd heq (by simp [applyHook])
  | allow => rfl
  | allowWithRedaction =>
    cases h with
    | none => exact absurd heq (by simp [applyHook])
    | some d =>
      cases d with
      | deny => exact absurd heq (by simp [applyHook])
      | allow => exact absurd heq (by simp [applyHook])
      | allowWithRedaction => exact absurd heq (by simp [applyHook])

/-- (f₂) The hook can never produce `allowWithRedaction` either: if the
    final verdict carries redaction, the static verdict already did. -/
theorem applyHook_eq_redacted_imp (s : Decision) (h : Option Decision)
    (heq : applyHook s h = Decision.allowWithRedaction) :
    s = Decision.allowWithRedaction := by
  cases s with
  | deny => exact absurd heq (by simp [applyHook])
  | allow =>
    cases h with
    | none => exact absurd heq (by simp [applyHook])
    | some d =>
      cases d with
      | deny => exact absurd heq (by simp [applyHook])
      | allow => exact absurd heq (by simp [applyHook])
      | allowWithRedaction => exact absurd heq (by simp [applyHook])
  | allowWithRedaction => rfl

/-- A hook abstention (`none` — the provider returned `null`) leaves the
    static verdict untouched. -/
theorem applyHook_none (s : Decision) : applyHook s none = s := by
  cases s with
  | deny => rfl
  | allow => rfl
  | allowWithRedaction => rfl

/-- The hook escalates exactly when it says `deny` (and the static verdict
    was not already `deny`). -/
theorem applyHook_some_deny (s : Decision) :
    applyHook s (some Decision.deny) = Decision.deny := by
  cases s with
  | deny => rfl
  | allow => rfl
  | allowWithRedaction => rfl

/-! ## The pending-request session map -/

/-- JSON-RPC request ids, after the proxy's `String(msg.id)` coercion
    (proxy.js, lines 140, 161, 176, 186). -/
abbrev Id := String

/-- What the proxy remembers about an in-flight request: the
    `{ method, tool, decision, reason }` record stored in the `pending`
    map (proxy.js, lines 56, 140–145, 161). `reason` is irrelevant to the
    session invariants and is omitted. -/
structure Info where
  method : String
  tool : Option String
  decision : Decision
deriving DecidableEq, Repr

/-- The pending map, modeled as a total lookup function (the JavaScript
    `Map` of proxy.js line 56, with absence represented by `none`). -/
abbrev Pending := Id → Option Info

/-- `pending.set(String(id), info)` (proxy.js, lines 140, 161). -/
def Pending.insert (p : Pending) (id : Id) (info : Info) : Pending :=
  fun k => if k = id then some info else p k

/-- `pending.delete(String(id))` (proxy.js, line 186). -/
def Pending.remove (p : Pending) (id : Id) : Pending :=
  fun k => if k = id then none else p k

/-- The proxy's bookkeeping for one client request: if the final verdict
    is `deny`, the proxy answers the client itself with a synthetic
    JSON-RPC error and returns *before* `pending.set` (proxy.js,
    lines 117–138 vs. 140), so the map is untouched; otherwise the request
    is recorded and forwarded upstream. -/
def recordRequest (p : Pending) (id : Id) (final : Decision) (info : Info) :
    Pending :=
  if final = Decision.deny then p else Pending.insert p id info

theorem Pending.insert_self (p : Pending) (id : Id) (info : Info) :
    (p.insert id info) id = some info := by
  simp [Pending.insert]

theorem Pending.insert_other {p : Pending} {id k : Id} (info : Info)
    (h : k ≠ id) : (p.insert id info) k = p k := by
  simp [Pending.insert, h]

theorem Pending.remove_self (p : Pending) (id : Id) :
    (p.remove id) id = none := by
  simp [Pending.remove]

theorem Pending.remove_other {p : Pending} {id k : Id} (h : k ≠ id) :
    (p.remove id) k = p k := by
  simp [Pending.remove, h]

/-- (g) A denied request never enters the pending map: the map is exactly
    unchanged — in particular an id that was absent stays absent, so no
    stale entry can later be attributed to the denied call. -/
theorem recordRequest_deny (p : Pending) (id : Id) (info : Info) :
    recordRequest p id Decision.deny info = p :=
  rfl

/-- Corollary of (g): after a denied request, the id still maps to
    `none` if it did before. -/
theorem recordRequest_deny_absent {p : Pending} {id : Id} (info : Info)
    (h : p id = none) : (recordRequest p id Decision.deny info) id = none := by
  rw [recordRequest_deny]; exact h

/-- (h₁) A forwarded (non-denied) request is recorded under its id: a
    subsequent upstream response with that id finds the entry
    (`pending.get`, proxy.js line 176). -/
theorem recordRequest_forwarded {p : Pending} {id : Id} {final : Decision}
    (info : Info) (h : final ≠ Decision.deny) :
    (recordRequest p id final info) id = some info := by
  simp [recordRequest, h, Pending.insert]

/-- (h₂) When the upstream response arrives, the entry is consumed:
    `pending.delete` makes the lookup return `none` again (proxy.js,
    line 186). A second response with the same id therefore finds nothing
    and is logged unattributed — see NOTES.md on duplicate ids. -/
theorem recordRequest_then_response {p : Pending} {id : Id} {final : Decision}
    (info : Info) (_h : final ≠ Decision.deny) :
    ((recordRequest p id final info).remove id) id = none :=
  Pending.remove_self _ _

/-- (h₃) Traffic for one id does not disturb entries for other ids:
    removing id `id` leaves the entry for `k ≠ id` intact (proxy.js,
    lines 176–186 key everything by the exact stringified id). -/
theorem Pending.remove_other_intact {p : Pending} {id k : Id} (h : k ≠ id) :
    (p.remove id) k = p k :=
  Pending.remove_other h

/-! ## Env brokering: `buildChildEnv` -/

/-- Abstraction of `buildChildEnv` (policy.js, lines 184–190): the child
    process environment contains exactly the base-environment entries
    whose key is on `policy.env.allow`. (The JavaScript iterates the
    allowlist and copies matching values out of `process.env`; filtering
    the environment list by key membership, as here, yields the same set
    of keys — see NOTES.md.) -/
def buildChildEnv (allow : List String) (env : List (String × String)) :
    List (String × String) :=
  env.filter (fun kv => kv.1 ∈ allow)

/-- (i) Every variable handed to the upstream child has an allowlisted
    key. Contrapositively: a secret present in the proxy's own environment
    but not on `policy.env.allow` can never reach the child process.
    This is the brokering guarantee stated in policy.js, lines 11–13 and
    181–190. -/
theorem buildChildEnv_key_allowlisted (allow : List String)
    (env : List (String × String)) {k : String} {v : String}
    (h : (k, v) ∈ buildChildEnv allow env) : k ∈ allow := by
  have h2 := (List.mem_filter.mp h).2
  exact of_decide_eq_true h2

/-- The brokered environment also contains nothing that was not already in
    the base environment. -/
theorem buildChildEnv_subset (allow : List String)
    (env : List (String × String)) : buildChildEnv allow env ⊆ env := by
  intro kv hkv
  exact (List.mem_filter.mp hkv).1

/-! ## The domain allowlist: `domainAllowed` -/

/-- `domainAllowed` (policy.js, lines 92–95): a host is allowed iff it
    equals some allowlisted domain or is a proper subdomain of one
    (ends with `"." ++ d`). The leading dot in the suffix is what blocks
    suffix attacks such as `evil-example.com` vs. `example.com`. Modeled
    as a `Bool`, exactly as the JavaScript returns a boolean.

    Note on proofs: `String.endsWith` does not reduce in the Lean kernel
    (it is implemented via the slice/pattern machinery), so the concrete
    host checks (j₁, j₂, j₄) are proved by bridging through
    `String.Slice.endsWith_string_iff` / `..._eq_false_iff` to a suffix
    statement about character lists, which the kernel *can* decide. No
    `native_decide` is used anywhere in this file: the only axioms any
    theorem depends on are the standard `propext`, `Classical.choice`,
    and `Quot.sound`. -/
def domainAllowed (host : String) (domains : List String) : Bool :=
  domains.any (fun d => host == d || host.endsWith ("." ++ d))

/-- The `Bool` model is the existential from the source, stated as a
    proposition. -/
theorem domainAllowed_iff (host : String) (domains : List String) :
    domainAllowed host domains = true ↔
      ∃ d ∈ domains, host = d ∨ host.endsWith ("." ++ d) = true := by
  unfold domainAllowed
  rw [List.any_eq_true]
  constructor
  · intro h
    obtain ⟨d, hd, hp⟩ := h
    refine ⟨d, hd, ?_⟩
    cases hbe : (host == d) with
    | true => exact Or.inl (beq_iff_eq.mp hbe)
    | false => exact Or.inr (by simpa [hbe] using hp)
  · intro h
    obtain ⟨d, hd, hor⟩ := h
    refine ⟨d, hd, ?_⟩
    cases hor with
    | inl he => simp [he]
    | inr he => simp [he]

/-- (j₁) Suffix attack blocked: `evil-example.com` is *not* a subdomain of
    `example.com`, because the required suffix is `.example.com` (with the
    dot), not `example.com`. -/
theorem domainAllowed_evil_suffix :
    domainAllowed "evil-example.com" ["example.com"] = false := by
  have h1 : ("evil-example.com").endsWith ".example.com" = false := by
    show ("evil-example.com".toSlice.endsWith ".example.com") = false
    rw [String.Slice.endsWith_string_eq_false_iff]
    decide
  simp [domainAllowed, h1]

/-- (j₂) A genuine subdomain is allowed. -/
theorem domainAllowed_subdomain :
    domainAllowed "api.example.com" ["example.com"] = true := by
  have h1 : ("api.example.com").endsWith ".example.com" = true := by
    show ("api.example.com".toSlice.endsWith ".example.com") = true
    rw [String.Slice.endsWith_string_iff]
    exact ⟨['a', 'p', 'i'], rfl⟩
  simp [domainAllowed, h1]

/-- (j₃) The allowlisted domain itself is allowed. -/
theorem domainAllowed_exact :
    domainAllowed "example.com" ["example.com"] = true :=
  rfl

/-- (j₄) A lookalike that merely *contains* the domain as a substring of a
    longer registrable domain is blocked: `example.com.evil.com` is a
    subdomain of `evil.com`, not of `example.com`. -/
theorem domainAllowed_domain_as_subdomain :
    domainAllowed "example.com.evil.com" ["example.com"] = false := by
  have h1 : ("example.com.evil.com").endsWith ".example.com" = false := by
    show ("example.com.evil.com".toSlice.endsWith ".example.com") = false
    rw [String.Slice.endsWith_string_eq_false_iff]
    decide
  simp [domainAllowed, h1]

/-- Any allowlisted domain allows itself. -/
theorem domainAllowed_self {d : String} {domains : List String}
    (h : d ∈ domains) : domainAllowed d domains = true := by
  rw [domainAllowed_iff]
  exact ⟨d, h, Or.inl rfl⟩

end Firewall
