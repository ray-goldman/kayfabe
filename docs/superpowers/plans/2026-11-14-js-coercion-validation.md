# JavaScript Coercion Before Validation Implementation Plan

> **For agentic workers:** Implement task by task with red/green tests, source review, and verification before publication.

**Goal:** Detect the verified missing-label credential path without warning on validated or deliberately defaulted values.

**Architecture:** A bounded project check analyzes visible JS/TS function declarations and call edges. It reports a `String` conversion of an unknown, request-derived parameter only when a downstream validator rejects non-strings but accepts the converted missing value, and a visible call path reaches a persistence/credential sink. Unsupported or ambiguous syntax yields no new finding.

**Tech Stack:** Native Node.js, existing project rule interface. No dependencies or target execution.

**Evidence:** `output/kayfabe-coercion-study-2026-11-14/assessment.md`; themcp-club parent `1e68c1e5...` and fixed `9628273...`. Source is untrusted data.

## Tasks

- [x] Add a vulnerable/fixed three-file corpus pair and focused safe/unsafe controls. Confirm red against current scanner.
- [x] Add bounded `src/js-coercion-validation.js` proof and one project rule. Require request-field call, `unknown` source parameter, direct `String(param)` argument, visible callee/validator/persistence chain, allowlist acceptance of `undefined`, and no direct pre-coercion terminating type check. Output finding at coercion line; no target-specific names.
- [x] Run focused green and full native tests/corpus. Scan the pinned app parent/fix source excerpts offline and compare finding identities. Review the source twice for false positives and false negatives; fix any confirmed issues.
- [x] Run all seven established benchmarks unchanged and compare exact unit transitions, including original/localized CVE separately. Document coverage limits.

Release follows the verified benchmark and review gates: publish the PR, wait for required CI, merge, and verify main.

## Limits

The rule does not infer auth or exploitability from a function name. A statically unsupported call graph or validator remains unreported. The app pair is exposed development evidence, never an independent benchmark. Keep the seven keys, policies, scoring code, denominators, and older corpus bytes unchanged.
