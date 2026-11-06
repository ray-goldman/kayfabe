# C# constant sink proofs

For existing SQL and process candidates, the constant proof reads the complete
selected call or assignment inside a uniquely identified method. A candidate line
selects sink starts; expressions can continue onto later lines. Separate lines
remain separate candidates, while every matching sink beginning on the same line
must pass. Line widths preserve CRLF characters so source and token offsets agree.
SQL constructors are anchored at `new`, including when `SqlCommand` begins on a
later line. Every selected-line sink anchor must belong to the chosen method;
a field initializer sharing that line prevents a method-only safety proof.
The same unique-method gate applies before either proof path, including local
functions beginning on the candidate line. Newly multiline expressions in methods
with unsupported binding forms (foreach, catch, lambdas, anonymous delegates,
out declarations, patterns, switch or fixed) defer to the scoped value proof;
the legacy collector cannot resolve those bindings from a sibling literal.

Primary-constructor class, struct and record headers do not count as methods.
Plain primary parameter names are retained as unknown inputs in their members,
including when a disjoint sibling block declares a same-named literal. Generic,
partial, nested and unsupported primary ownership shapes do not gain a proof.
Primary default parameters and base initializers, and explicit constructor
initializers, select parser fallback because executable header behavior is not
modeled. Coverage counts actual discovered method bodies and records unsupported
primary headers separately. This does not infer primary input values from callers.
Known constructor-header diagnostics carry their owning type's source range.
An existing local proof in a disjoint type can proceed only when every parser
error is one of these scoped diagnostics. Lexical and structural errors still
block all proofs; the file remains incomplete for parser and project coverage.
Newly eligible primary-owner methods also apply unsupported-binding guards to
single-line sinks. Their legacy local proof requires exact keyword scalar types;
unresolved `var`, `String`, aliases and other named types cannot inherit a
same-named sibling literal. Empty primary parameter lists use the same boundary.
Primary-member proofs decline bounded query starts (`from ... in`) before either
proof path; range-variable values are unresolved even for literal enumerables.
Exact tokens distinguish genuine query syntax from standalone `from`/`@from`
identifiers and string/comment text. Relevant null-coalescing and split compound
assignments invalidate primary-member values; unrelated mutations do not.
Balanced parenthesized write targets and ref operands also invalidate their
relevant bindings before proof acceptance, including field/helper fallback.
This identifies unsupported writes rather than inferring alias values. The
shared recognizer uses the existing 20,000-token ceiling and a fixed linear
work budget; malformed or over-budget operands decline proof.
Complete multiline sinks in ordinary methods use this same conservative type,
mutation and query boundary before either proof path. Scoped fallback uses a
separate strict model, including helper and field writes, so an unsupported
callee cannot restore a rejected proof. Ordinary single-line legacy behavior
remains outside this extension; it is not certified by these guards. The earlier
multiline extension had exposed those legacy weaknesses to additional candidates;
the integration repair restores their warnings. Contextual `var` is unresolved
even with a literal initializer: absence of a local type declaration is not
closed-compilation evidence about imported or externally declared named types.
Keyword `string` literal controls remain supported.

`Process.Start` supports one or two arguments and requires both the executable and
argument text to be proved constant. `.Arguments` and `.CommandText` assignments
require a complete right-hand expression ending with a semicolon. `SqlCommand`
construction and the supported raw SQL methods require constant SQL text in the
first argument; connection objects and parameter values are not executable SQL.
Nested calls still use the existing bounded private-helper/value proof.
All-named calls have a separate, deliberately narrow invocation proof: one
uniquely declared, explicitly private static helper with required unique keyword
`string` parameters, keyword `string` return type, and body containing only
`return <formal>;`. Every actual must be one non-interpolated string literal
token, including unused actuals. Regular, verbatim and raw strings qualify;
UTF-8 literals, identifiers, conversions, getters, calls, parenthesized values,
conditions and other expressions do not. Names are case-sensitive and escaped
identifiers normalize consistently; the invocation maps each actual to its
formal binding identity, independent of written argument order. No helper result
is cached across calls. Mixed, missing, extra, empty, duplicate or unknown names,
optional/ref/out/in/params forms, overloads, generics and helper writes decline
this proof. Unqualified calls qualify; an unshadowed same-owner static receiver
also requires a closed owner header with no explicit base list. An inherited
field or property can otherwise supply the apparently type-named receiver.
Caller catch/delegate/query bindings remain outside this named-call subset.
Unresolved caller occurrences of the helper or static receiver name also decline
the proof, including deconstructed bindings and method-group references.

An unqualified call in an ordinary inherited owner can qualify because the known
private member is applicable by built-in string identity conversion for every
named actual; lookup therefore resolves at that owner without guessing external
base members. The base's spelling supplies no evidence. Inapplicable/custom-type declarations,
generic owners/bases, foreign receivers, shadowed names and multiple owners
remain unknown. Existing positional behavior and the all-visible-callers proof
for a sink physically inside a helper remain separate; one safe invocation
never establishes safety of that helper's input at every caller.
The argument classifier scans the complete top-level conditional structure:
matched ternary colons preserve positional compatibility, while extra label
colons and unmatched questions decline proof before positional fallback.
Conditional element access (`values?[0]`) does not require a ternary colon.
Because `? [` can also begin a collection-expression ternary arm, the bounded
classifier preserves either balanced structural reading using possible/required
pending counts. This preserves existing positional compatibility without
establishing a type, value or purity proof for the unused actual. Named actuals
remain literal-only, and arbitrary malformed nested syntax is not validated.

Each value-proof query has one shared 65,536-unit expansion budget, charged for
expression tokens, binding visits, named caller/body traversal, call-site scans,
helper expansions and return/write alternatives. Recursive calls share the same
budget; exhaustion retains the candidate. Later queries receive fresh budgets.
Raw SQL method calls retain bounded generic type argument support, including
qualified names, nested generic types and simple array types before the call.

Missing or mismatched delimiters, unknown values or mutations, ambiguous method
ownership, and unsupported expressions retain candidates. The two-megabyte file,
50,000-character method, 256-token value expression, and depth bounds remain.
Interpolated strings and broader type/helper inference remain outside this
extension. Regex candidate coverage is unchanged; these are bounded syntactic
proofs rather than complete C# analysis.

The separate source-const-member interpolation proof can isolate a known explicit
constructor-initializer diagnostic after independently checking its exact type
bounds and constructor tokens. The affected type and overlapping types cannot
supply constants or sink ownership. Every token and type remains in the global
shadow, duplicate, import and build-input checks. Primary executable headers,
unknown errors and malformed syntax still reject this proof.

MVC SQL detection opts into the same bounded initializer isolation for type
metadata: a DbContext declaration and its literal auto-property shape can still
be inspected while all methods in the unsupported owner remain ineligible.
The opt-in method metadata distinguishes constructor-owner isolation from the
general unsupported-syntax flag. MVC excludes isolated owners, then applies its
existing action grammar, including FromQuery, FromRoute, FromForm and FromHeader
parameters; general index consumers still reject those attributed headers.
Other project-index consumers retain their existing behavior. Parser completeness
and fallback-file counts remain unchanged; the opt-in index separately reports
isolated constructor files. The shared validator caps source at 100,000 characters,
tokens at 20,000 and diagnostics at 512. It does not parse or evaluate initializer
expressions or claim executable-header coverage.
