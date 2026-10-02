// DecisionProvider hook: an optional semantic layer on top of the static
// policy engine.
//
// A provider's evaluate({ tool, args }) returns either:
//   - null                     -> abstain; the static policy decision stands
//   - { decision: 'deny', reason } -> escalate to a deny
//
// Providers are only consulted when the static decision is allow /
// allow-with-redaction; a static deny is final and never reaches a provider.
//
// JevProvider asks TypeSafe AI's Jev "System One" model a single noul
// (yes/no probability) question -- "does this call exceed the tool's stated
// purpose?" -- and denies when the probability exceeds the policy threshold.
// Jev is built for exactly this: fast, cheap, typed decisions with calibrated
// probabilities (POST https://api.typesafe.ai/v1/systemone, model
// "jev-latest", Bearer auth via the JEV_API_KEY environment variable).
//
// StaticPolicyProvider is the default fallback: with no key configured the
// firewall is a pure static-policy proxy. Any Jev error, timeout, or
// unexpected response shape also falls back to abstaining -- the hook can
// only ever escalate an allowed call to a deny, never weaken a static deny,
// and never takes the proxy down.

export class StaticPolicyProvider {
  async evaluate() {
    return null;
  }
}

export class JevProvider {
  constructor({
    apiKey,
    threshold = 0.5,
    endpoint = 'https://api.typesafe.ai/v1/systemone',
    fetchImpl = globalThis.fetch,
  } = {}) {
    this.apiKey = apiKey;
    this.threshold = threshold;
    this.endpoint = endpoint;
    this.fetchImpl = fetchImpl;
  }

  async evaluate({ tool, args, toolPurpose } = {}) {
    if (!this.apiKey || typeof this.fetchImpl !== 'function') return null;
    try {
      const res = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          // The key is used only as a Bearer token here. It is never logged,
          // never written to the audit log, and never printed.
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          state: JSON.stringify({ tool, arguments: args ?? {} }),
          model: 'jev-latest',
          questions: {
            exceeds_purpose: {
              type: 'noul',
              instructions:
                `Does this tool call exceed the tool's stated purpose` +
                (toolPurpose ? ` ("${toolPurpose}")` : '') +
                `? Answer yes if the call reaches for data, paths, or systems ` +
                `beyond what a tool named "${tool}" is plausibly meant to touch.`,
              criteria: {
                true: "The call goes beyond the tool's stated purpose",
                false: "The call is within the tool's stated purpose",
              },
            },
          },
        }),
      });
      if (!res || !res.ok) return null;
      const data = await res.json();
      const answer = data?.answers?.exceeds_purpose;
      const p =
        typeof answer === 'number'
          ? answer
          : typeof answer?.noul === 'number'
            ? answer.noul
            : typeof answer?.probability === 'number'
              ? answer.probability
              : null;
      if (p === null) return null;
      if (p > this.threshold) {
        return {
          decision: 'deny',
          reason:
            `Jev hook: ${p.toFixed(2)} probability that this call exceeds the ` +
            `tool's stated purpose (threshold ${this.threshold})`,
        };
      }
      return null;
    } catch {
      return null;
    }
  }
}

// Wire up the provider for a policy: Jev when explicitly enabled AND a key
// is present in the environment, static fallback otherwise.
export function createDecisionProvider(policy, env = process.env) {
  if (policy?.jev?.enabled && env.JEV_API_KEY) {
    return new JevProvider({ apiKey: env.JEV_API_KEY, threshold: policy.jev.threshold });
  }
  return new StaticPolicyProvider();
}
