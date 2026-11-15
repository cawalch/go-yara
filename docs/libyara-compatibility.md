# libyara Compatibility Matrix

This document records deliberate compile-time and semantic compatibility differences between `go-yara` and `libyara` (`4.6.0`). Where `go-yara` intentionally keeps warning-based or permissive defaults for existing rule corpora, pass `compiler.WithStrictLibyaraCompatibility(true)` to enforce `libyara`-matching compile-time rejections.

Each row below is verified against `libyara 4.6.0` in [libyara_compatibility_differential_test.go](../tests/integration/libyara_compatibility_differential_test.go).

| Construct / Area | libyara `4.6.0` | go-yara (default) | go-yara (`WithStrictLibyaraCompatibility(true)`) | Rationale |
| --- | --- | --- | --- | --- |
| Negative range lower bound (`$a in (-5..5)`, `for any of ($a) in (-5..5) : ($)`) | Error: `range lower bound can not be negative` | Rejected (compile error) | Rejected (compile error) | Prevents inverted truth values where negative bounds behave differently from `libyara` compilation rules. |
| Reversed constant range (`for all i in (5..1) : (i == 0)`, `$a in (5..1)`) | Error: `range lower bound must be less than upper bound` | Rejected (compile error) | Rejected (compile error) | Compile-time constant range inversion is rejected early to match `libyara`. |
| Dynamic range with variable bound (`$a in (-1..filesize)`) | Accepted | Accepted | Accepted | Runtime-computed bounds are evaluated dynamically in both engines. |
| Indexed string count (`#a[0] == 0`, `#[1]`) | Syntax error: `unexpected '['` | Rejected (syntax error) | Rejected (syntax error) | `#` counts total string occurrences and does not accept `[i]` indexing (unlike `@a[i]` and `!a[i]`). |
| Wildcard in string declaration (`$nomatch* = "zzz"`) | Syntax error: `unexpected string identifier with wildcard` | Rejected (syntax error) | Rejected (syntax error) | Wildcard patterns belong in condition string sets, not `strings:` declarations. |
| Empty wildcard string set (`any of ($z*)`, `for any of ($z*) : (true)`) | Error: `undefined string "$z*"` | Accepted (evaluates false) | Rejected (`undefined string "$z*"`) | Preserves permissive default for rulesets sharing templates/prefilters while offering strict `libyara` pre-check parity. |
| Empty `them` string set (`any of them` in rule with no strings) | Error: `undefined string "$*"` | Accepted (evaluates false) | Rejected (`undefined string "$*"`) | Same stance as empty wildcard string sets. |
| Unreferenced string (`rule u { strings: $a = "abc" condition: true }`) | Error: `unreferenced string "$a"` | Accepted with `WarningUnusedString` | Rejected (`unreferenced string "$a"`) | Default mode reports `unused-string` warnings so benign unused patterns do not abort compilation; strict mode matches `libyara`. |
| Suppressed unreferenced string (`$_a = "abc"`) | Accepted (`$_` suppresses error) | Accepted (no warning) | Accepted | Matches `libyara`'s `$_` suppression convention in both modes. |
| Anonymous unreferenced string (`$ = "abc"`) | Error: `unreferenced string "$"` | Accepted with `WarningUnusedString` | Rejected (`unreferenced string "$"` ) | Anonymous strings do not carry the `$_` suppression prefix and are rejected under strict mode. |
| Percentage quantifier outside `1..100` (`0%`, `101%` literal/folded) | Error: `percentage must be between 1 and 100 (inclusive)` | Rejected (compile error) | Rejected (compile error) | Enforced unconditionally (`#515`). |
| Mixed greedy/ungreedy regex quantifiers (`/a+b??/`) | Error: `greedy and ungreedy quantifiers can't be mixed` | Rejected (compile error) | Rejected (compile error) | Enforced unconditionally for rule regex strings (`#514`). |
| Expression quantifiers (`(1+1) of them`, `#a of them`, `for uint8(255) of them : ($)`) | Accepted | Accepted | Accepted | Enforced unconditionally (`#516`). |
| Duplicate `meta:` keys (`meta: hash = "1" hash = "2"`) | Accepted | Accepted | Accepted | Multiple metadata entries with the same key are preserved. |
