# YARA Specification Gap Analysis

This document tracks gaps between go-yara and the official YARA specification (YARA 4.5.3).

**Methodology**: Comparison against `yara/docs/writingrules.rst` and implementation code review.

**Legend**:
- ✅ Implemented
- ⚠️ Partially implemented
| `imported rule reference` (via `include`) | ✅ | `include` directive resolves and parses external files; rules from included files are part of the same `Program` and referenceable |
- 📝 Implementation detail differs from spec

---

## 1. String Definitions

| Feature | Status | Notes |
|---------|--------|-------|
| Text strings (`$a = "hello"`) | ✅ | Fully implemented |
| Hex strings (`$a = { DE AD BE EF }`) | ✅ | Including wildcards, jumps, alts |
| Regex strings (`$a = /abc.*/`) | ✅ | Including modifiers |
| Anonymous strings (`$ = "..."`) | ✅ | ID assignment via `assignAnonymousStringIdentifiers()` |
| String modifiers: `ascii` | ✅ | Implemented |
| String modifiers: `wide` | ✅ | Implemented |
| String modifiers: `nocase` | ✅ | Implemented |
| String modifiers: `fullword` | ✅ | Implemented at match time in `MatchContext` |
| String modifiers: `private` (string-level) | ✅ | Parsed, compiled, and enforced — private strings filtered from `RuleMatch.Matches` and CLI output |
| String modifiers: `xor` | ✅ | Both no-arg and range forms |
| String modifiers: `xor N` | ✅ | Range form |
| String modifiers: `base64` | ✅ | With custom alphabets |
| String modifiers: `base64wide` | ✅ | With custom alphabets |
| String modifiers: `base64 "alphabet"` | ✅ | Custom alphabet |
| Hex string not-operator (`~xx`) | ✅ | Implemented — `~` prefix handled by `parseHexAtom` |
| Hex string wildcards (`??`) | ✅ | Implemented |
| Hex string jumps (`- min,max`) | ✅ | Implemented |
| Hex string alternatives (`( AA \\| BB )`) | ✅ | Implemented |
| Hex string word alignment | ✅ | N/A — not a YARA feature (anchor `@` syntax is the closest concept) |
| Hex string binary operators | ✅ | N/A — not a YARA feature (alternatives `( AA | BB )` already work) |

---

## 2. Conditions — Boolean & Arithmetic

| Feature | Status | Notes |
|---------|--------|-------|
| `and`, `or`, `not` | ✅ | Short-circuit evaluation |
| `defined` | ✅ | `OpDefined` opcode |
| `undefined` value semantics | ✅ | Propagates through numeric ops; falsy in boolean context |
| Arithmetic: `+`, `-`, `*`, `/`, `%` | ✅ | Implemented |
| Bitwise: `&`, `|`, `^`, `<<`, `>>` | ✅ | Implemented |
| Comparisons: `==`, `!=`, `<`, `<=`, `>`, `>=` | ✅ | Implemented |
| Parenthesized expressions | ✅ | Implemented |

---

## 3. Conditions — String Operators

| Feature | Status | Notes |
|---------|--------|-------|
| `#a` (count) | ✅ | `OpCount` |
| `@a` / `@a[i]` (offset) | ✅ | `OpOffset` |
| `!a` / `!a[i]` (length) | ✅ | `OpStringLength` |
| `$a` (match) | ✅ | `OpFound` |
| `$a in (start..end)` | ✅ | `OpFoundIn` |
| `$a in (#b..#c)` | ✅ | Range expression compiled dynamically |
| `$a in (0..filesize)` | ✅ | Implemented |
| `$a in (b..c)` (generic range) | ✅ | Implemented |
| `$a at $b` | ✅ | `OpFoundAt` |
| `$a at entrypoint` | ✅ | Implemented |
| `$a at 0` | ✅ | Implemented |
| `#a in (min..max)` | ✅ | `OpCountIn` emitted by `compileCountInRange`; interpreter handler `executeCountInRange` |
| `#a in (min..max) of ($a*)` | ✅ | `OpCountInOf` emitted by `compileOfExpression`; interpreter handler `executeCountInOf` (PR #122) |
| `#a in (min..max) of ($a*)` (wildcard) | ✅ | Semantic validator and type checker allow `$a*` identifiers; compiler expands via `expandStringSetIdentifier` (PR #123) |
| `for any of ($a*) in (0..100) : ($)` | ✅ | Parser parses `in (range)` on `ForLoop`; compiler emits constraint marker; interpreter filters matches |
| `for any of ($a*) at (0..100) : ($)` | ✅ | Parser parses `at offset` on `ForLoop`; compiler emits constraint marker; interpreter filters matches |
| `N of ($a*) in (0..100)` | ✅ | `OpOfFoundIn` emitted by `compileOfExpression`; interpreter handler `executeOfFoundIn` |
| `N of ($a*) at offset` | ✅ | `OpOfFoundAt` emitted by `compileOfExpression`; interpreter handler `executeOfFoundAt` |
| `N % of ($a*) in (0..100)` | ✅ | `OpOfPercentIn` emitted; interpreter handler `executeOfPercentIn` |
| `N % of ($a*) at offset` | ✅ | `OpOfPercentAt` emitted; interpreter handler `executeOfPercentAt` |
| `of ($a, $b, $c)` | ✅ | String list in `of` expressions |
| `length of` | ✅ | `OpLengthOf` opcode; parser handles `length of ($a)`, `length of them`, `length of them*`, `length of them**`; compiler resolves string set indices; interpreter sums match lengths (PR #128) |
| `of them` | ✅ | Implemented |
| `all of them` | ✅ | Implemented |
| `any of them` | ✅ | Implemented |
| `none of them` | ✅ | Implemented |
| `N of them` | ✅ | Numeric quantifiers |
| `N percent of them` | ✅ | `PercentExpression` AST node; Pratt parser detects `N % OF`; `OpOfPercent` opcode; `executeOfPercentOperation` handler |
| `of ($foo*)` | ✅ | Wildcard string sets via `$foo*` syntax; `expandStringSetIdentifier` resolves prefix matches |

---

## 4. Conditions — String Functions

| Feature | Status | Notes |
|---------|--------|-------|
| `startswith` | ✅ | Implemented |
| `endswith` | ✅ | Implemented |
| `matches` (regex) | ✅ | `OpMatches` |
| `contains` | ✅ | Implemented |
| `icontains` | ✅ | Case-insensitive contains |
| `istartswith` | ✅ | Case-insensitive startswith |
| `iendswith` | ✅ | Case-insensitive endswith |
| `iequals` | ✅ | Case-insensitive equals |
| `uint8`, `uint16`, `uint32` | ✅ | `OpReadInt+3..5`; single integer offset arg, verified end-to-end |
| `int8`, `int16`, `int32` | ✅ | `OpReadInt+0..2`; signed variants |
| `uint8be`, `uint16be`, `uint32be` | ✅ | `OpReadInt+9..11`; big-endian via `executeReadIntOpBE` |
| `int8be`, `int16be`, `int32be` | ✅ | `OpReadInt+6..8`; signed big-endian |
| `int64`, `uint64`, `int64be`, `uint64be` | 📝 | go-yara extension — not in upstream YARA 4.5.3 (its lexer matches only `u?int(8|16|32)(be)?`). Implemented as `OpReadInt+12..15` |

---

## 5. Conditions — Loops & Quantifiers

| Feature | Status | Notes |
|---------|--------|-------|
| `for any i in (0..n) : ($a at i)` | ✅ | `OpIterStartIntRange` |
| `for all i in (0..n) : (...)` | ✅ | Implemented |
| `for none i in (0..n) : (...)` | ✅ | Implemented |
| `for any of them : ($)` | ✅ | `OpIterStartStringSet` |
| `for all of them : ($)` | ✅ | Implemented |
| `for none of them : ($)` | ✅ | Implemented |
| `for any of ($a, $b) : (...)` | ✅ | String set iteration |
| `for any of ($a*) : (...)` | ✅ | Wildcard string set iteration |
| `for any of ($a*) in (0..100) : ($)` | ✅ | Range-constrained string set iteration |
| `for any of ($a*) at (0..100) : ($)` | ✅ | Offset-constrained string set iteration |
| `for any s in ("text1", "text2") : ($a matches s)` | ✅ | `OpIterStartTextStringSet` implemented |
| `for any i in (0..n) : (...)` | ✅ | Implemented — numeric for-loop ranges via `*ast.BinaryOp` (DOT) |
| `for any s in ($*) : ($s)` | ✅ | Implemented — `compileForLoop()` handles `*ast.Identifier` ranges; supports `$*`, `them`, `$a*` |
| `for any s in ("a", "b") : (s of them)` | ✅ | N/A — invalid YARA syntax (confirmed by reference YARA) |

---

## 6. Conditions — Rule References

| Feature | Status | Notes |
|---------|--------|-------|
| `RuleName` (rule reference) | ✅ | `OpPushRuleRef` resolves rule index via `ruleIndexMap`; `executePushRuleRef` looks up `ruleResults` and pushes boolean |

---

## 7. Conditions — Special Identifiers

| Feature | Status | Notes |
|---------|--------|-------|
| `entrypoint` | ✅ | `OpEntrypoint` |
| `filesize` | ✅ | `OpFilesize` |
| `itersmax` | ✅ | YARA compile-time constant (`ITERSMAX`). Implemented as `WithItersmax` `ScannerOption`; enforced in `executeIterNext` |

---

## 8. Conditions — Hash Functions

| Feature | Status | Notes |
|---------|--------|-------|
| `md5("string", start, end)` | ✅ | Implemented in interpreter |
| `sha1("string", start, end)` | ✅ | Implemented in interpreter |
| `sha256("string", start, end)` | ✅ | Implemented in interpreter |
| `md5(0, filesize)` | ✅ | Full file hash |
| `md5($a, $a.length)` | ✅ | String-based hash |

---

## 9. Conditions — String Operations

| Feature | Status | Notes |
|---------|--------|-------|
| `concat` | ✅ | Implemented |
| `length` (string) | ✅ | Implemented |
| `substr` | ✅ | Implemented |
| `toupper` | ✅ | Implemented |
| `tolower` | ✅ | Implemented |
| `format` | ✅ | Implemented |
| `str2bool` | ✅ | Implemented |
| `int2str` | ✅ | Implemented |
| `bool2str` | ✅ | Implemented |
| `int2double` | ✅ | Implemented |

---

## 10. Rule Modifiers

| Feature | Status | Notes |
|---------|--------|-------|
| `private rule` | ✅ | `IsPrivate` stored in `CompiledRule`; excluded from `MatchedRules` but evaluated internally and referenceable |
| `global rule` | ✅ | `IsGlobal` stored in `CompiledRule`; two-pass evaluation enforces all-global-must-match semantics |

---

## 11. Tags

| Feature | Status | Notes |
|---------|--------|-------|
| `{tag1, tag2}` | ✅ | `Tags []string` stored in `CompiledRule`; exposed in `RuleMatch` for public API |

---

## 12. Metadata

| Feature | Status | Notes |
|---------|--------|-------|
| `meta` section | ✅ | `Meta map[string]any` stored in `CompiledRule`; exposed in `RuleMatch` |
| `author = "name"` | ✅ | Stored and accessible at runtime via `RuleMatch.Meta` |
| `date = "2024-01-01"` | ✅ | Stored and accessible at runtime |
| `version = 1` | ✅ | Stored and accessible at runtime |

---

## 13. Modules

| Feature | Status | Notes |
|---------|--------|-------|
| `import "pe"` | ❌ | Not implemented |
| `import "cuckoo"` | ❌ | Not implemented |
| `import "hash"` | ❌ | Not implemented |
| `import "math"` | ❌ | Not implemented |
| `import "debug"` | ❌ | Not implemented |
| `import "elm"` | ❌ | Not implemented |
| `import "dotnet"` | ❌ | Not implemented |
| `import "crypto"` | ❌ | Not implemented |
| `import "macho"` | ❌ | Not implemented |
| `import "elf"` | ❌ | Not implemented |
| `import "pe"` (module functions like `pe.imphash()`) | ❌ | `emitModuleFunctionCall` pushes 0 (stubbed) |
| `import "math"` (`math.rand()`, `math.rand_range()`) | ❌ | Not implemented |

---

## 14. Include Directive

| Feature | Status | Notes |
|---------|--------|-------|
| `include "file.yar"` | ✅ | Implemented with base dir resolution |
| Include depth limits | ✅ | `MaxIncludeDepth` config |
| Include size limits | ✅ | `MaxIncludeSize` config |

---

## 15. External Variables

| Feature | Status | Notes |
|---------|--------|-------|
| External variable declarations | ✅ | `external` keyword parsed |
| Runtime external variable injection | ✅ | `CompiledProgram.SetExternalVariables()`, `Scanner.SetExternalVariables()`, `WithExternalVariables()` |

---

## 16. Regex Features

| Feature | Status | Notes |
|---------|--------|-------|
| Character classes `[abc]`, `[^abc]` | ✅ | Implemented |
| Shorthand classes `\\d`, `\\w`, `\\s` | ✅ | Implemented |
| Quantifiers `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}` | ✅ | Implemented |
| Alternation `\\|` | ✅ | Implemented |
| Grouping `()` | ✅ | Implemented |
| Anchors `^`, `$` | ✅ | Implemented |
| Escaped characters | ✅ | Implemented |
| Case-insensitive flag `(?i)` | ✅ | Implemented |
| Dot-all flag `(?s)` | ✅ | Implemented |
| Unicode flag `(?u)` | ✅ | Implemented |
This document tracks gaps between go-yara and the official YARA specification (YARA 4.5.3). It is updated as features are implemented and verified. The analysis is based on comparing the go-yara implementation with the YARA documentation at `yara/docs/writingrules.rst` and code review of the YARA source.

**Summary**: ✅ 15/15 implemented · ⚠️ 0 partial · ❌ 1/15 missing (module system). The 64-bit `int64/uint64` data-read variants are a go-yara extension (📝), not an upstream YARA feature.

---

## 17. Unreferenced Strings

| Feature | Status | Notes |
|---------|--------|-------|
| Warning on unreferenced strings | ✅ | Warning emitted |
| `$_` prefix suppresses warning | ✅ | Implemented |

---

## 18. Scanner / Execution

| Feature | Status | Notes |
|---------|--------|-------|
| Single file scanning | ✅ | Implemented |
| Multiple rules scanning | ✅ | Implemented |
| Tag-based rule filtering | ✅ | `WithTagsFilter` scanner option; skips non-global rules lacking matching tags |
| Global rule auto-execution | ✅ | Two-pass evaluation: all global rules must match before non-global rules reported |
| Private rule exclusion from references | ✅ | Private rules excluded from `MatchedRules` output; still referenceable internally |
| Callback-based matching | ✅ | Scanner callbacks |
| Scan timeout / cancellation | ✅ | Context-based cancellation |
| `itersmax` enforcement | ✅ | `WithItersmax` scanner option; `executeIterNext` enforces limit per-scan |

---

## Gap Closure Plan

### Priority 1: High-impact condition operators

#### 1.1 `#a in (min..max)` — Count range check ✅ DONE
**Files**: `compiler/condition_compiler.go`, `compiler/interpreter_strings.go`, `semantic/type_checker.go`, `semantic/types.go`
**Work**:
- Parser: Already supported (expression parser creates `StringCount IN (min..max)` AST)
- Compiler: Added `compileCountInRange` in `handleSpecialOperators` to emit `OpCountIn` with range operands
- Interpreter: Added `executeCountInRange` to check if count falls within range
- Semantic: Updated `checkInOperator` and `inferInOperatorType` to accept integer (count) on left
**Tests**: `TestInterpreterCountInRange`, `TestCountInRangeEndToEnd`

#### 1.2 `for any of ($a*) in (0..100) : ($)` — Range-constrained string set iteration ✅ DONE
**Status**: ✅ Implemented
**Files**: `ast/nodes.go`, `parser/quantifier_parser.go`, `compiler/condition_compiler.go`, `compiler/interpreter_iter.go`
**Implementation**:
- AST: Added `InRange` and `AtOffset` fields to `ForLoop`
- Parser: Parse `in (range)` and `at offset` after quantifier target in `parseForLoop`/`parseQuantifier` and `parseForLoopOverStrings`
- Compiler: `compileForLoopOverStrings` emits constraint marker (0=no constraint, 1=in range, 2=at offset) on stack before `OpIterStartStringSet`
- Interpreter: `executeIterStartStringSet` reads constraint marker and filters matches accordingly
- Also added `N of ($a*) in (min..max)` via `OpOfFoundIn` and `N of ($a*) at offset` via `OpOfFoundAt` in `compileOfExpression`
- Also added `N % of ($a*) in (min..max)` via `OpOfPercentIn` and `N % of ($a*) at offset` via `OpOfPercentAt`
**Tests**: `TestInterpreterOfFoundIn`, `TestInterpreterOfFoundAt`, `TestOfFoundInEndToEnd`, `TestOfFoundAtEndToEnd`, `TestForLoopInRangeEndToEnd`, `TestForLoopAtOffsetEndToEnd`

#### 1.3 (merged into 1.2) ✅ DONE

#### 1.4 `percent` quantifier — `50 % of them`
**Status**: ✅ Implemented
**Files**: `ast/nodes.go`, `ast/visitor.go`, `ast/builder.go`, `parser/expression_parser.go`, `compiler/condition_compiler.go`, `compiler/bytecode.go`, `compiler/interpreter.go`, `compiler/interpreter_strings.go`, `semantic/validator.go`
**Implementation**:
- AST: Added `PercentExpression` with `Pos` and `Value` fields
- Visitor: Added `VisitPercentExpression` to `ControlFlowVisitor` and `BaseVisitor`
- Parser: Detected `N % OF` in Pratt parser binary expression loop (avoids conflict with modulo operator)
- Compiler: Emits `OpOfPercent` with percentage and string set on stack
- Interpreter: `executeOfPercentOperation` calculates `(matched * 100) / total >= percent`
- Semantic: Validates percentage value is integer
**Tests**: `TestInterpreterOfPercent` (unit), `TestOfPercentEndToEnd` (full pipeline)

#### 1.5 `#a in (min..max) of ($a*)` — Count-in-of with range (PR #122)
**Status**: ✅ Implemented
**Files**: `compiler/bytecode.go`, `compiler/condition_compiler.go`, `compiler/interpreter_strings.go`, `compiler/interpreter.go`, `compiler/compiler_test.go`, `compiler/interpreter_test.go`
**Implementation**:
- Bytecode: Added `OpCountInOf` opcode
- Compiler: `compileOfExpression` detects `#a in (min..max) of (...)` and emits `OpCountInOf` with `[setIndex, min, max]` stack layout
- Interpreter: `executeCountInOf` counts matches within range and pushes boolean
- Tests: `TestCountInOfEndToEnd`, `TestInterpreterCountInOf`

#### 1.6 Wildcard string sets `$a*` in quantifiers (PR #123)
**Status**: ✅ Implemented
**Files**: `semantic/validator.go`, `semantic/type_checker.go`, `compiler/condition_compiler.go`, `compiler/compiler_test.go`
**Implementation**:
- Semantic: `tryAlternativeIdentifierLookups` recognizes `$... *` identifiers as valid wildcard string sets (`TypeBoolean`)
- Type checker: `checkIdentifier` allows wildcard string set identifiers
- Compiler: `resolveStringSetIndex` calls `expandStringSetIdentifier` for wildcard identifiers instead of interning literal name
- Tests: `TestWildcardStringSetEndToEnd` covering `any of ($a*)`, `all of ($a*)`, `#a in (1..3) of ($a*)`, `2 of ($a*)`, multiple wildcards, zero-match ranges

### Priority 2: Text string set iteration

#### 2.1 `for any s in ("text1", "text2") : (...)` — Text string set iteration
**Files**: `compiler/condition_compiler.go`, `compiler/interpreter_iter.go`
**Work**:
- Compiler: Emit `OpIterStartTextStringSet` with text string set
- Interpreter: Implement `executeIterStartTextStringSet`

### Priority 3: Metadata, Tags, Rule Modifiers

#### 3.1 Tags storage and filtering
**Status**: ✅ Implemented
**Files**: `compiler/rule_compiler.go`, `compiler/scanner.go`
**Done**:
- ✅ `Tags []string` stored in `CompiledRule` from AST
- ✅ `Tags` exposed in `RuleMatch` for public API
- ✅ Tags available in scan results

#### 3.2 Metadata storage
**Status**: ✅ Implemented
**Files**: `compiler/rule_compiler.go`, `compiler/scanner.go`
**Done**:
- ✅ `Meta map[string]any` stored in `CompiledRule`
- ✅ Metadata exposed in `RuleMatch` for public API
- ✅ Supports `MetaString`, `MetaInt`, `MetaBool`

#### 3.3 Global rule enforcement
**Status**: ✅ Implemented
**Files**: `compiler/scanner.go`, `compiler/rule_compiler.go`
**Done**:
- ✅ `IsGlobal bool` stored in `CompiledRule`
- ✅ Two-pass evaluation: all rules evaluated, then MatchedRules built
- ✅ ALL global rules must match before non-global rules are reported
- ✅ Non-global rules skipped when any global rule fails

#### 3.4 Private rule enforcement
**Status**: ✅ Implemented
**Files**: `compiler/scanner.go`, `compiler/rule_compiler.go`
**Done**:
- ✅ `IsPrivate bool` stored in `CompiledRule`
- ✅ Private rules not reported in `MatchedRules`
- ✅ Still evaluated internally and tracked in `RuleResults`
- ✅ Can be referenced by other rules

### Priority 4: Unreferenced string warning suppression

#### 4.1 `$_` prefix suppression
**Status**: ✅ Implemented
**Files**: `compiler/compiler.go`
**Done**:
- ✅ Skip warning in `checkUnusedStrings` when identifier starts with `$_`

### Priority 2: Text string set iteration

#### 2.1 `$a matches s` in for loops
**Status**: ✅ Implemented
**Files**: `compiler/condition_compiler.go`, `compiler/interpreter_iter.go`
**Done**:
- ✅ `OpIterStartTextStringSet` opcode and handler
- ✅ Text strings iterated in for loops, usable with `matches` operator

#### 2.2 `s of them` in for loops
**Status**: ❌ Not standard YARA — `of` is a prefix quantifier, not an infix operator

### Priority 5: Module system (out of scope for now)

Module loading and execution is a large feature requiring:
- Module registration system
- Module function compilation
- Module data structures
- Individual module implementations (pe, elf, macho, hash, math, etc.)

This is tracked separately and not part of the initial gap closure plan.

---

## Implementation Order

1. **`#a in (min..max)`** — ✅ Done. Smallest change, single opcode already defined
2. **`percent` quantifier** — ✅ Done. Lexer + parser + compiler, moderate complexity
3. **`for..of` with `in (range)` / `at offset`** — ✅ Done. AST + parser + compiler + interpreter
4. **Text string set iteration** — ✅ Done. Compiler + interpreter
5. **Tags + Metadata storage** — ✅ Done. Compiler only
6. **Global/Private rule enforcement** — ✅ Done. Scanner + compiler
7. **`$_` prefix suppression** — ✅ Done. Simple compiler change
8. **`#a in (min..max) of ($a*)`** — ✅ Done (PR #122). Compiler + interpreter
9. **Wildcard string sets `$a*` in quantifiers** — ✅ Done (PR #123). Semantic + compiler

## Remaining Gaps

### Tag-based scan filtering (✅)
Implemented in `compiler/scanner.go` via `WithTagsFilter` scanner option. The Scanner skips non-global rules that don't have any matching tag. Global rules are always evaluated regardless of tag filter, matching YARA semantics.

### Bugs Fixed During Review
- **`not $y` stack underflow**: `compileNotOperator` incorrectly compiled `not $string` as `emitStringIdentifier + OpLength`, which expected 2 stack operands but only 1 was pushed. Fixed to use `compileExpression + OpNot` consistently.
- **Private strings in API**: `Scanner.Scan` now filters private strings from `RuleMatch.Matches`, matching YARA semantics.

### Module system (❌, out of scope)
Module loading and execution is a large feature requiring a module registration system, function compilation, and individual module implementations.
