# C# constant sink proofs

For existing SQL and process candidates, the constant proof reads the complete
selected call or assignment inside a uniquely identified method. A candidate line
selects sink starts; expressions can continue onto later lines. Separate lines
remain separate candidates, while every matching sink beginning on the same line
must pass. Line widths preserve CRLF characters so source and token offsets agree.

`Process.Start` supports one or two arguments and requires both the executable and
argument text to be proved constant. `.Arguments` and `.CommandText` assignments
require a complete right-hand expression ending with a semicolon. `SqlCommand`
construction and the supported raw SQL methods require constant SQL text in the
first argument; connection objects and parameter values are not executable SQL.
Nested calls still use the existing bounded private-helper/value proof.

Missing or mismatched delimiters, unknown values or mutations, ambiguous method
ownership, and unsupported expressions retain candidates. The two-megabyte file,
50,000-character method, 256-token value expression, and depth bounds remain.
Interpolated strings and broader type/helper inference remain outside this
extension. Regex candidate coverage is unchanged; these are bounded syntactic
proofs rather than complete C# analysis.
