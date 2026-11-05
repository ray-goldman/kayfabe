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
The ordinary non-primary legacy query/compound-write weaknesses predate this
ownership change and remain separate backlog work.

`Process.Start` supports one or two arguments and requires both the executable and
argument text to be proved constant. `.Arguments` and `.CommandText` assignments
require a complete right-hand expression ending with a semicolon. `SqlCommand`
construction and the supported raw SQL methods require constant SQL text in the
first argument; connection objects and parameter values are not executable SQL.
Nested calls still use the existing bounded private-helper/value proof.
Raw SQL method calls retain bounded generic type argument support, including
qualified names, nested generic types and simple array types before the call.

Missing or mismatched delimiters, unknown values or mutations, ambiguous method
ownership, and unsupported expressions retain candidates. The two-megabyte file,
50,000-character method, 256-token value expression, and depth bounds remain.
Interpolated strings and broader type/helper inference remain outside this
extension. Regex candidate coverage is unchanged; these are bounded syntactic
proofs rather than complete C# analysis.
