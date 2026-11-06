# Established benchmark precision

Improve measured precision on an existing dataset, preserving every previously detected labeled vulnerability and adding no labeled false positives. Generated examples alone do not meet the acceptance gate.

The seven established evaluations remain separate: C# Juliet, OWASP Java, Java Juliet, SARD PHP, original CVE parent/fix pairs, supplied mixed-language apps, and the earlier .NET apps. Keep original keys, scoring code, policy and denominators unchanged. Report localized CVE experiments separately. All are exposed development evaluations; none becomes independent or blind through this work. Self-authored examples provide regression evidence only.

## Chosen scope

Extend the native Java constant proof in two bounded places. First, SQL assembly fragments inside a complete member `execute` call may be proved independently of the positive SQL sink rule's receiver-name list. This is a removal-only proof: require complete balanced arguments and account for every matching fragment and call in the window. Never change positive sink matching to make the score improve. Second, distinguish Java class literals from nested declarations and accept exact, pure class-literal auxiliary arguments when proving SQL calls. A class literal does not make an unknown SQL expression safe.

Keep unknown syntax, dynamic arguments, mutable arrays, ambiguous bindings, nested declarations, anonymous classes, escaping values, incomplete calls and budget exhaustion fail-closed. Preserve the current bounds. No filename, benchmark name, receiver-variable name or key-derived special cases. Add vulnerable/safe regression pairs with adversarial controls for each proof extension.

## Deferred work

Do not suppress the supplied JavaScript redirect: the same application exposes arbitrary `eval` and prototype mutation, invalidating its global-identity proof. Do not resolve ambiguous C# `String` via incomplete project inventories: the original framework reference/build closure is unavailable. C# SQL append handling requires additional array/source ownership work. Keep these limitations explicit instead of changing labels or bypassing proof requirements.

## Ship gates

- Fresh baseline from main 4c683a63591335cc06c18ebdb9b4ca44e36b1db1; candidate source frozen only after both code review passes.
- At least one existing labeled FP becomes TN or FN becomes TP; no TP becomes FN and no TN becomes FP in any of the seven datasets. Compare identities as well as totals.
- Rerun all seven plus previous frozen app sets, nine supplied apps, nickrulez, blesclues, Hermes, all five generated sets and adversarial controls. Investigate identity changes outside the intended cohort.
- Existing corpus remains 205/205; all tests pass with the documented existing Windows skips. Native Node >=20, no installed runtime dependencies, offline benchmark measurements, no target execution.
- Preserve target quarantine, redact secrets, and publish no full private apps, answer keys or raw finding material. Publish only owned minimal fixtures and sanitized aggregates.
- Two fresh code review passes, a final measurement/privacy review, required CI at the exact PR head, then report the measured gain and remaining limitations. Existing authorization covers opening and merging the improvement PR after CI passes; no release or repository-permission changes.

Review-driven follow-on: also preserve the two already supported local-constant return/wrapper controls identified in source review. A compatibility exception may reuse only the unchanged original sink pattern, a method that passed the original declaration guard, and an independent local-only proof of every argument. That proof must disable helper-return and caller-parameter summaries throughout recursion. New generic execute contexts, methods newly admitted by class literals, and helper-derived facts retain the complete statement-envelope requirement. Do not claim that all previously quiet helper/wrapper forms are restored or that arbitrary returned values are safe.

The previous five-cycle campaign and its evidence remain immutable. New source freezes, logs and measurement outputs live in a separate evidence namespace.
