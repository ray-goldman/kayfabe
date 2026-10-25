# Rust modules and cfg handling

The native Rust layer indexes module items before applying the two [TLS configuration checks](RUST-SOURCE-ANALYSIS.md). It reads selected input bytes only. It never invokes Cargo, rustc, build scripts or target programs.

## Supported structure

Conventional Cargo library and binary roots, supported explicit target paths, inline modules, and default external `name.rs` / `name/mod.rs` paths are indexed. Explicit binary names replace their conventional paths. Edition 2015 manual-target manifests disable default auto-discovery; explicit flags are respected. Unresolved editions do not establish modern auto-discovery defaults. Exactly one selected file must match an external module. Parent imports are not inherited by child modules. Unreachable files are not promoted into an existing crate's namespace. An unconditional library remains active when a feature-gated binary shares its source. See [Cargo target configuration](https://doc.rust-lang.org/cargo/reference/cargo-targets.html).

For compatibility with earlier standalone-source scans, a manifest with no discovered roots, no manual targets and no disabled discovery flags can fall back to flat `main.rs`, flat `lib.rs`, or its sole selected Rust file regardless of that file's directory. This fallback does not establish a Cargo build target. Explicit example, integration-test and benchmark declarations do not become production roots and prevent this fallback.

Custom module paths, target files owned by a nearer nested Cargo manifest, missing or ambiguous files, duplicate possibly active modules, cycles, internal imports, globs and imports through import aliases remain unresolved. A target cannot borrow a nested package's dependency identity. Lookups use the scanner's existing input map; source text cannot cause another file read. Macro definitions, item expansion and unknown attributes prevent semantic proofs in the affected scope and descendants. Unrelated siblings can still be analyzed. Missing inputs and uncertain Cargo ownership retain the existing project guards.

## Configuration policy

Predicates have three states: proven active, proven excluded, unresolved. The bounded grammar supports boolean literals, `all`, `any`, `not`, option names and string values. Every operand is parsed before its result is used. Malformed predicates remain unresolved.

`test` is false under the default production-source selection. With tests included it is unresolved: the scan does not reconstruct separate compiler invocations. Platform, feature and custom options remain unknown regardless of the machine running Kayfabe. Cargo binaries with required features are conditional unless the same source is independently an unconditional target.

Outer and inner `cfg` / `cfg_attr` are applied before bindings and macro effects. Proven-disabled items cannot shadow names. Unknown branches produce no high-confidence findings and their possible bindings still block ambiguous resolution. An unknown `cfg_attr` can pass when its possible effect is inert, such as `windows_subsystem`; the unknown condition is still counted. A possible macro, path or conditional effect remains unresolved.

## Bounds and coverage

Cfg evaluation permits 4,096 tokens, depth 32 and 256 attributes. Structural indexing permits depth 64 and 100,000 items. The graph permits 4,096 contexts, depth 64 and 200,000 item visits. A shared one-million-token work budget covers context and function analysis. Existing file/project byte and token caps also apply. Budget failures emit fixed diagnostic codes and suppress affected semantic proofs.

`coverage.source.rust` adds reachable, conditional, excluded and unreachable file counts, module scopes, excluded/unknown items and unknown condition counts. Module/item counts describe graph contexts: a file mounted twice can contribute twice. Discovered and analyzed function counts describe unique physical functions, so repeated mounts cannot inflate the analyzed-function ratio. Structural reachability does not imply runtime reachability or successful type checking.

Rust remains incomplete and fails a required complete-coverage gate. Flat builder expressions are still the only supported semantic subset. Helpers, complex bodies, macro expansion, ownership, authorization and cross-file taint remain gaps.

## Hermes and regression data

The immutable Hermes pair is exposed development data without a vulnerability answer key. It exercises module/cfg indexing, but unresolved macro attributes and complex functions still limit semantic coverage. Neither variant explicitly disables reqwest TLS verification; zero TLS findings is expected and receives no accuracy credit.

Four scanner-owned Rust vulnerable/fixed pairs cover the two flat TLS cases and the added module/cfg cases. They measure regressions only. Established benchmarks retain their unchanged keys, policies and separate result tables.
