# Bounded Java String proofs

Continue reducing existing Java false positives without suppressing vulnerable twins. Start from merged main `01583453a71af3254ca4277eff848029b6d27d04`. Execute two sequential measured cycles: direct character-copy output, then a narrowly proved String.charAt intrinsic in the existing opaque-helper effect grammar. Select the second cycle only after the first is accepted; reassess if a candidate produces no original-policy false-positive reduction.

## Approach

Use current-call Boolean proofs and existing independent-return evaluation. A general HTML capability would require new stream-state semantics; a full Java resolver or ordered-map engine is substantially wider. Those remain later work. The selected approach keeps rendering and prior-output replay unchanged and rejects uncertain syntax/ownership.

Cycle 1 supports only a bare String binding's zero-argument toCharArray conversion as the sole argument of a complete top-level print/println call. Existing contextBefore must establish genuine HTML document text. Reuse independentOutputValuesAt to prove the binding's entire provenance, including effect-free private helper calls. No array storage, alias, slice, cast, member/call base or general constant shortcut is added. The proof creates no bytes, encoding or replay fact. Extract the existing complete-current-statement check once for formatter and copy consumers, preserving formatter behavior exactly.

String spelling alone is not nominal evidence. Add a separately bounded canonical-String scope check using the existing nongeneric class/caller header readers. Reject malformed/static/wildcard imports, noncanonical String imports, root/source/same-package String shadows, generic type variables, unknown inherited member-type scope and interfaces. Support no explicit superclass/Object, or an unshadowed explicitly imported/qualified canonical javax/jakarta HttpServlet parent already required by output context. No general classpath resolver is claimed. These strict guards belong only to new consumers and must not narrow existing summaries or formatter paths.

Cycle 2 admits exactly bareLocal.charAt(decimalIntLiteral) inside the opaque-helper effect proof. The receiver is a method-body-root local declared earlier as String with one supported literal initializer and no other writes anywhere in the method, including dead branches or statements after return. Use real lexical binding identities, absolute half-open UTF-16 source offsets, and deferred full-body validation so a later same-spelled declaration or reassignment cannot certify an earlier use. Nested/switch-local declarations, aliases and computed indices remain unsupported.

Apply the accepted canonical String scope at the callee position only when the new atom is encountered; bodies without it retain their prior eligibility. Reuse the existing scalar evaluator for exact literal and call slices with one cumulative intrinsic allowance of at most 512 units per body, charged against the same 10,000-unit context on success and failure, including its exhaustion sentinel. No replenishment or cross-context cache. Every syntactic arm still passes the effect grammar; every return still passes the existing fresh localOnly proof. No caller facts, parameter receivers/indices, encoder or older helper facts, arbitrary calls, encoding claims or output/replay changes are added.

## Gates

Native Node >=20, no installed runtime dependencies. Targets are static untrusted data; never execute/build/test/install them. Keep quarantine and redaction. Do not publish private apps, keys, case IDs, local paths or raw findings.

All seven original source inventories, answer keys, scorers, policies, commands/options, unit identities and denominators remain unchanged. Original and localized CVE policies stay separate. Each shipping cycle must remove at least one pre-existing original-policy false positive, with zero TP-to-FN and TN-to-FP transitions against both its accepted predecessor and this campaign's initial C4 baseline. Do not use benchmark/file/name allowlists or enlarge existing proof budgets.

Preserve every earlier corpus byte and the full package test command. Baseline floors: 1161 tests, 1158 passed, exactly 3 existing Windows skips, corpus210. Require full suite/corpus, all compatibility tiers, five generated sets, 190 adversarial fixtures, exact scoped self-audit dispositions and C# runtime <=1.5x. Generated sets remain self-authored regressions; exposed evaluations are not blind accuracy evidence.

Two distinct exact-head source reviews pass before each candidate freeze. Independently review measurement tooling before it runs, and exact successful results/publication privacy before PR. Merge only after required Tests CI passes at the final head, retaining measured ancestry via a merge commit. Verify actual merged main's complete publication tree and full suite/corpus before acceptance. Retain immutable old campaign evidence; new tooling and outputs live only in the new private campaign root.

Reusing C4 raw baseline requires verifying its acceptance/reviews/result/evidence/descriptor/source/archive/key pins and complete non-documentation Git equality to actual starting main, including workflow/configuration/dependency files. Keep measured and merged identities distinct. Candidates are freshly scanned; baseline reuse is explicitly reported as historical verified evidence.

Reference semantics: [Java SE25 String](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/String.html). String is final and immutable; conversion creates a character copy and charAt addresses UTF-16 code units. This does not establish the identity of a same-spelled user-defined type.
