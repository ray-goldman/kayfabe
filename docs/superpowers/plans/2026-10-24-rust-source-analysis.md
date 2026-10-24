# Bounded Rust source analysis

Approved roadmap execution, 2026-10-24. Base: `17f7dcee48b964d5d48115d5d664a29300f05c7a`.

## Contract

Implement a native, bounded Rust lexer and structural function/chain analysis. The first rules identify a built reqwest client with explicit literal `true` for invalid certificate or hostname acceptance. Resolve crate identity through visible Cargo declarations and imports; decline ambiguous bindings, custom crates and unsupported control flow. Last setting wins. A setting without a subsequent build is not a finding. Unknown methods and expressions invalidate the chain proof.

Support ASCII/raw identifiers, nested comments, escaped/raw/byte/C strings, characters, lifetimes, balanced token trees, plain function declarations, simple imports and contiguous client-builder chains. Do not expand macros, evaluate cfg, resolve modules or traits, follow builder variables or interprocedural data flow. Files and functions outside this subset remain explicitly partial. Resource limits: 1 MiB/file, 100,000 tokens/file, 128 delimiter/comment depth, 255 raw string hashes, 32 MiB/project, 4,096 Rust files and 400,000 aggregate tokens (checked after each bounded file). No fallback regex verdicts for Rust. Hostname findings require an explicit native TLS backend.

Hermes is previously exposed development data with no frozen vulnerability answer key. Replay both immutable variants and verify bytes. No accuracy score or automated credit for its manual findings. Keep aggregate body admission, auth intent, upstream deadlines and cross-file taint as explicit gaps. Separate executable arguments, FFI and inbound self-signed certificates must not trigger these rules.

## Sequence and gates

1. Freeze base and run all seven existing evaluations with unchanged keys, scorer, policy and options. Write failing lexer, chain, coverage, ownership and corpus tests.
2. Implement lexer, structural analysis, manifest ownership, two TLS rules and report integration. Add scanner-owned vulnerable/fixed corpus pairs and hostile-input controls. Keep source coverage incomplete for Rust, with lexical/function counts distinct from semantic breadth.
3. Run full tests and selftest. Fresh-context review one; repair and verify all actionable issues before freezing candidate.
4. Freeze candidate, rerun all seven evaluations and additional frozen safe apps, prior frozen apps, nine supplied apps, adversarial fixtures, nickrulez/blesclues and Hermes. No existing TP loss or FP increase; C# runtime ratio <=1.5. No tuning against held-out results: any such use retires the phase to development and requires a new recorded phase.
5. Fresh-context review two of code and evidence; repair/rerun as needed. Publish sanitized aggregate results and supported syntax/gaps. Open and attach PR only after both reviews; do not merge.

## Provenance and privacy

Self-authored pairs measure regressions only. Keep third-party benchmark numbers separate. Freeze all input bytes before/after, retain prior runs, and record scanner commit plus source hash. Never execute supplied code, install dependencies, query online advisories for targets or publish supplied source, keys or raw reports.

## Execution ledger

- Base archive and source manifest recorded locally; all seven baseline evaluations completed.
- Lexer, structural checks, two scanner-owned corpus pairs and partial report integration implemented. Initial full suite: 565 tests, 562 passed, zero failed, three Windows platform skips; 195/195 corpus pairs.
- Fresh-context review one completed. Fixed crate cfg, proc/cfg_attr expansion, external module reachability, optional/build-only/local-library identities, normalized alias collisions, explicit termination and invalid lexical tokens. Canonical controls retain findings; redaction and excluded-test handling verified. No remaining actionable findings in that pass.
- First frozen candidate completed all seven evaluations and additional replays. Its phase is preserved as a superseded development run after fresh code review found visible Cargo-config identity, excluded-test context, nested builder argument and terminating-import alias defects. These fixes came from scanner-owned review probes; no new held-out set was used or tuned against.
- Fixed those boundaries with regression tests. Chained or cyclic imports remain unsupported. Final pre-freeze suite: 568 tests, 565 passed, zero failed, three platform skips; 195/195 corpus pairs. Candidate v2 measurement and second-review evidence acceptance pending.
