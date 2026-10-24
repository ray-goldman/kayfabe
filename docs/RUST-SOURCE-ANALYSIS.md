# Bounded Rust source checks

Kayfabe reads Rust tokens and recognizes a small set of client-builder expressions. It does not compile or execute Rust, install Cargo dependencies, expand macros or claim full Rust coverage.

## Initial checks

| Rule | Required evidence | Safe controls |
|---|---|---|
| `RUST-TLS-001`, CWE-295 | A resolved reqwest client builder explicitly sets `danger_accept_invalid_certs(true)` and then calls `build()` | Default validation, literal `false`, a later reset to `false`, unknown values or APIs, no build |
| `RUST-TLS-002`, CWE-297 | The same evidence for `danger_accept_invalid_hostnames(true)`, plus explicit `use_native_tls()` as the final selected backend | Rustls backend, unresolved/default backend, hostname validation enabled |

These are unsafe client-configuration candidates. They establish neither a reachable network request nor successful exploitation. Unknown settings invalidate that setting's proof; unknown builder methods invalidate the entire chain. A later literal value wins. Separate builder variables and helper returns are not followed. Imports through another import alias, including cycles, suppress semantic proofs rather than hiding a known terminating API.

Supported constructors are `Client::builder()` and `ClientBuilder::new()`, including `reqwest::blocking`. Simple, renamed and grouped `use` imports can resolve these types. Crate aliases must come from visible normal Cargo dependencies identifying registry reqwest. Optional, workspace-inherited, target-only, build-only, custom-source and conflicting dependencies are unresolved. Visible `.cargo/config` or `.cargo/config.toml` prevents an ownership claim because source replacement is not resolved. Local library names and normalized alias collisions are rejected. Missing or malformed metadata cannot establish ownership. Configuration outside the scan root, including machine and environment settings, is not inspected.

## Syntax and limits

The lexer handles ASCII and raw identifiers, lifetimes, character literals, escaped/raw/byte/C strings, nested comments and balanced token trees. Comments and literals never become executable API evidence. Lexical completion means tokenization succeeded within these limits; it is not a rustc syntax or type check.

The semantic subset consists of plain functions with flat statements and contiguous builder chains, including eagerly evaluated nested call arguments. Branches, loops, returns, await, closures, nested blocks, generics, question-mark propagation and attributed functions are excluded. Selected known terminating APIs (`exit`, `abort`, `panic_any`, `resume_unwind`, `handle_alloc_error`) and their direct import aliases exclude the containing function. Visible never-returning function types (`-> !`) suppress project semantic proofs. This is not general helper reachability analysis. Module graphs are unsupported: visible `mod` declarations suppress semantic checks across the selected Rust inputs. Macro definitions, item macro expansion, unknown macro attributes, cfg_attr, crate-level cfg and extern-crate rebinding also suppress semantic checks. This deliberately limits detection until their effects can be resolved.

Limits are 1 MiB and 100,000 tokens per file; 128 nested delimiters or block comments; 255 raw-string hashes; and 4,096 files, 32 MiB of source, 32 MiB of manifests and 400,000 tokens per project. A final file can reach the per-file token cap before the aggregate check stops further input. Budget failures produce fixed diagnostic codes, with no target text. Any missing input that could affect ownership prevents semantic proofs.

## Reading coverage

`coverage.source.rust` reports eligible/tokenized files, discovered/analyzed functions, resolved builder chains and diagnostic counts. Function counts describe the supported checks, not complete parsing, taint coverage or vulnerability recall. Files omitted by a budget are reported separately. Excluded tests do not enter the coverage denominator.

Rust always keeps `coverage.source.status` incomplete and fails an explicitly required complete-coverage gate. Cargo inventory and advisory coverage remain separate. A passing severity gate with zero Rust findings is not a clean security assessment.

## Hermes and remaining gaps

The immutable Hermes original/fixed pair is previously exposed development data with no frozen vulnerability answer key. Its source exercises raw strings, lifetimes, attributes, FFI and macros. It receives no accuracy score or automated credit for manual findings. The initial checks add no Hermes finding: its reqwest builders do not explicitly disable certificate or hostname validation.

The original aggregate body-admission concern remains a manual review question. Following the fixed variant's shared semaphore, permit lifetime, host/auth guards and response stream requires control flow and ownership analysis beyond this phase. Finite `to_bytes` limits, `unsafe`, separate arguments to a fixed executable, loopback/listen settings and an inbound self-signed certificate are not vulnerability evidence by themselves. Cross-file taint, authorization intent, SSRF origin control and upstream deadlines remain gaps.

Two scanner-owned vulnerable/fixed corpus pairs provide regression coverage only. They are not independent evaluation data. Established benchmarks and supplied applications retain their separate labels and policies.

See [the frozen measurements and review summary](RUST-SOURCE-RESULTS.md) for the exact scanner version, unchanged benchmark decisions and Hermes coverage counts.

References: [Rust tokens](https://doc.rust-lang.org/reference/tokens.html), [Rust use declarations](https://doc.rust-lang.org/reference/items/use-declarations.html), [reqwest 0.12.28 ClientBuilder](https://docs.rs/reqwest/0.12.28/reqwest/struct.ClientBuilder.html).
