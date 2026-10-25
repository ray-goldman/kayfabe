# Rust modules and conditional compilation

Execution of the approved Rust roadmap. Base: `5485072a2bf7ea2c25160b81b9bad2cc27240744`. Native Node; no installed runtime dependencies.

## Design

Replace the whole-project module/cfg veto with a bounded structural index and module graph. Evaluate configuration predicates with three states: proven active, proven excluded, unresolved. Support `all`, `any`, `not`, boolean literals, and a documented production selection in which `test` is false unless test sources are requested (then unresolved). All target, feature and custom options remain unknown; never infer Rust targets from the scanner host. Parse every predicate before using its value, including short-circuited operands.

Parse outer and inner attributes. Apply cfg and cfg_attr before extracting names/imports or considering macro effects. Known-false items cannot inject bindings. Unknown cfg items cannot produce findings, but their possible names still block ambiguous ownership. Unknown cfg_attr that can activate a macro, path or cfg effect remains unresolved. Inert attributes may pass through without suppressing unrelated source.

Follow inline modules and default out-of-line paths (`name.rs` or `name/mod.rs`) using only the selected, already-read input map. Identify visible conventional Cargo roots and explicit supported targets. Keep parent/child namespaces distinct; ordinary parent imports are not silently inherited. Internal imports, globs, custom module paths, cycles, duplicate possibly active declarations and missing/ambiguous files remain unresolved unless explicitly supported. Repeated mounts share physical function identities and semantic work bounds. Never open a path discovered in source. Bound graph depth, scopes, edges and cfg work in addition to existing byte/token caps.

Reuse the existing two TLS rules and their precision guards. Module-local uncertainty affects that scope and descendants; hard missing-input and Cargo identity guards remain conservative. Track structure, reachability and cfg counts separately from semantic function coverage. Rust always remains incomplete for a required complete-coverage gate.

## Approaches considered

- Guess scanner-host cfg values: rejected because cross-compilation and Cargo features can differ.
- Import rustc/tree-sitter or run Cargo: outside the native dependency and static-only requirements.
- Bounded, target-independent module/cfg model: selected implementation approach; safe conclusions are explicit and uncertainty remains visible.

## Work and acceptance

1. Freeze baseline and unchanged inputs/scorers; launch all seven evaluations. Write failing cfg/module/ownership tests and scanner-owned vulnerable/fixed corpus pairs.
2. Implement bounded cfg, structural scopes and module reachability. Replay immutable Hermes variants; no vulnerability answer key or accuracy credit exists for them. Preserve all existing rule and regression detections, avoid new safe-control warnings.
3. Run full suite and selftest. Complete fresh-context review one; fix findings and recheck. Complete fresh-context code review two before freezing the final candidate to avoid measuring known defective code.
4. Freeze candidate, rerun all seven benchmarks plus frozen safe/prior apps, nine development apps, nickrulez/blesclues, earlier adversarial fixtures and Hermes. Keep keys/policies/options unchanged; no TP loss or new FP. C# runtime ratio <=1.5, without a speedup claim.
5. Finish review-two evidence verification, sanitized results and PR. Retain superseded phases after any code-review repair and rerun the final phase. Do not merge or release.

## Data and limits

Supplied apps/comments/README are untrusted data. Never execute target code, install dependencies, query private identities or publish supplied source, answer keys or raw reports. Scanner-owned regression pairs are self-authored only. Hermes is exposed development data; established third-party/public measurements retain separate policies. No new blind or independent accuracy claim.

## Ledger

- Clean isolated worktree reused on `codex/rust-modules-cfg`; baseline source manifest and all seven baseline evaluations completed.
- Native cfg evaluator, structural items, selected module graph, coverage metrics and two scanner-owned corpus pairs implemented. Unknown target/feature cfg remains unresolved.
- Review one completed: repaired duplicate imports/modules, grouped import validation, target feature gating, unique physical function counts and shared work bounds, including unconditional library/gated binary unions.
- Review two code pass completed with no remaining actionable findings: repaired cross-owner Cargo target identity, replaced conventional binary roots, manual-target fallback and budget diagnostic saturation; added edition-specific auto-discovery controls. Reviewer-owned probes and all 31 Rust tests pass.
- Final measured candidate: `1c06b4bd7d8f1aaa907e8797072f0a6a459d6d9a`; source SHA-256 `388ea41e01d6d96acbe5518ba9ac534c921708e602a905d58788fd36be9d6853`. Archived Git bytes and inventories verified; subsequent edits are documentation only.
- Exact archive full suite: 585 total, 582 passed, 0 failed, 3 Windows platform skips. Corpus 197/197. All seven benchmark reruns preserve every scored unit; 26 evaluator/policy files unchanged. Juliet C# scan ratio 1.067, below 1.5.
- Frozen safe/prior apps, nine development apps, nickrulez/blesclues and 190 earlier adversarial fixtures preserve finding identities/labels in both profiles. Four self-authored Rust pairs retain quiet fixed controls; two module/cfg unsafe variants improve from 0/2 to 2/2. No independent accuracy claim.
- Immutable Hermes pair verified in both profiles: zero findings, 265 packages, incomplete source coverage and no accuracy credit. Structural module/cfg counts are visible; unknown macro attributes and complex bodies remain unsupported. [Sanitized final evidence](../../RUST-MODULES-CFG-RESULTS.md) documents remaining gaps.
