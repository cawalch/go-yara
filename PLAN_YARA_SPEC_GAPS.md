# YARA Specification Gap Analysis

This document tracks gaps between go-yara and the official YARA specification (YARA 4.5.3).

**Methodology**: Comparison against `yara/docs/writingrules.rst` and implementation code review.

**Legend**:
- ✅ Implemented
- ⚠️ Partially implemented
- ❌ Not implemented
- 📝 Implementation detail differs from spec

---

## 1. String Definitions

| Feature | Status | Notes |
|---------|--------|-------|
| Text strings (`$a = "hello"`) | ✅ | Fully implemented |
| Hex strings (`$a = { DE AD BE EF }`) | ✅ | Including wildcards, jumps, alts, not-operator |
| Regex strings (`$a = /abc.*/`) | ✅ | Including modifiers |
| Anonymous strings (`$ = "..."`) | ✅ | ID assignment via `assignAnonymousStringIdentifiers()` |
| String modifiers: `ascii` | ✅ | Implemented |
| String modifiers: `wide` | ✅ | Implemented |
| String modifiers: `nocase` | ✅ | Implemented |
| String modifiers: `fullword` | ✅ | Implemented at match time in `MatchContext` |
| String modifiers: `private` (string-level) | ⚠️ | Parsed into AST but not enforced (private strings excluded from certain contexts) |
| String modifiers: `xor` | ✅ | Both no-arg and range forms |
| String modifiers: `xor N` | ✅ | Range form |
| String modifiers: `base64` | ✅ | With custom alphabets |
| String modifiers: `base64wide` | ✅ | With custom alphabets |
| String modifiers: `base64 "alphabet"` | ✅ | Custom alphabet |
| Hex string not-operator (`!xx`) | ✅ | Implemented |
| Hex string wildcards (`??`) | ✅ | Implemented |
| Hex string jumps (`- min,max`) | ✅ | Implemented |
| Hex string alternatives (`( AA \\| BB )`) | ✅ | Implemented |
| Hex string word alignment | ✅ | `align` keyword |
| Hex string binary operators | ✅ | `&`, `|` in hex strings |

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
| `#a in (min..max) of ($a*)` | ❌ | Not implemented |
| `for any of ($a*) in (0..100) : ($)` | ✅ | Parser parses `in (range)` on `ForLoop`; compiler emits constraint marker; interpreter filters matches |
| `for any of ($a*) at (0..100) : ($)` | ✅ | Parser parses `at offset` on `ForLoop`; compiler emits constraint marker; interpreter filters matches |
| `N of ($a*) in (0..100)` | ✅ | `OpOfFoundIn` emitted by `compileOfExpression`; interpreter handler `executeOfFoundIn` |
| `N of ($a*) at offset` | ✅ | `OpOfFoundAt` emitted by `compileOfExpression`; interpreter handler `executeOfFoundAt` |
| `N % of ($a*) in (0..100)` | ✅ | `OpOfPercentIn` emitted; interpreter handler `executeOfPercentIn` |
| `N % of ($a*) at offset` | ✅ | `OpOfPercentAt` emitted; interpreter handler `executeOfPercentAt` |
| `of ($a, $b, $c)` | ✅ | String list in `of` expressions |
| `of ($a*)` | ✅ | Wildcard string sets |
| `of them` | ✅ | Implemented |
| `all of them` | ✅ | Implemented |
| `any of them` | ✅ | Implemented |
| `none of them` | ✅ | Implemented |
| `N of them` | ✅ | Numeric quantifiers |
| `N percent of them` | ❌ | `percent` keyword not parsed |

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
| `uint8`, `uint16`, `uint32`, `uint64` | ✅ | Implemented |
| `int8`, `int16`, `int32`, `int64` | ✅ | Implemented |
| `uint8be`, `uint16be`, `uint32be`, `uint64be` | ✅ | Big-endian variants |
| `int8be`, `int16be`, `int32be`, `int64be` | ✅ | Big-endian variants |

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
| `for any s in ("text1", "text2") : ($a matches s)` | ❌ | `OpIterStartTextStringSet` unimplemented |
| `for any s in ("a", "b") : (s of them)` | ❌ | Text string set iteration |

---

## 6. Conditions — Rule References

| Feature | Status | Notes |
|---------|--------|-------|
| `RuleName` (rule reference) | ⚠️ | `emitRuleReference` pushes 0 (stubbed) |
| `imported rule reference` | ❌ | Not implemented |

---

## 7. Conditions — Special Identifiers

| Feature | Status | Notes |
|---------|--------|-------|
| `entrypoint` | ✅ | `OpEntrypoint` |
| `filesize` | ✅ | `OpFilesize` |
| `itersmax` | ✅ | `OpItersmax` |

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
| `private rule` | ⚠️ | Parsed into AST but not enforced in scanner |
| `global rule` | ⚠️ | Parsed into AST but not enforced in scanner |

---

## 11. Tags

| Feature | Status | Notes |
|---------|--------|-------|
| `{tag1, tag2}` | ⚠️ | Parsed into AST but not stored in `CompiledRule` or used by scanner |

---

## 12. Metadata

| Feature | Status | Notes |
|---------|--------|-------|
| `meta` section | ⚠️ | Parsed into AST but not stored in `CompiledRule` |
| `author = "name"` | ⚠️ | Parsed but not accessible at runtime |
| `date = "2024-01-01"` | ⚠️ | Parsed but not accessible at runtime |
| `version = 1` | ⚠️ | Parsed but not accessible at runtime |

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
| Runtime external variable injection | ✅ | `SetExternalVariables()` |

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
| Capture groups with backreferences | ❌ | Not implemented (consistent with YARA spec) |

---

## 17. Unreferenced Strings

| Feature | Status | Notes |
|---------|--------|-------|
| Warning on unreferenced strings | ✅ | Warning emitted |
| `$_` prefix suppresses warning | ❌ | Not implemented |

---

## 18. Scanner / Execution

| Feature | Status | Notes |
|---------|--------|-------|
| Single file scanning | ✅ | Implemented |
| Multiple rules scanning | ✅ | Implemented |
| Tag-based rule filtering | ❌ | Tags not stored/used |
| Global rule auto-execution | ❌ | Global modifier not enforced |
| Private rule exclusion from references | ❌ | Private modifier not enforced |
| Callback-based matching | ✅ | Scanner callbacks |
| Scan timeout / cancellation | ✅ | Context-based cancellation |
| `itersmax` enforcement | ⚠️ | `OpItersmax` pushes value but enforcement unclear |

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

### Priority 2: Text string set iteration

#### 2.1 `for any s in ("text1", "text2") : (...)` — Text string set iteration
**Files**: `compiler/condition_compiler.go`, `compiler/interpreter_iter.go`
**Work**:
- Compiler: Emit `OpIterStartTextStringSet` with text string set
- Interpreter: Implement `executeIterStartTextStringSet`

### Priority 3: Metadata, Tags, Rule Modifiers

#### 3.1 Tags storage and filtering
**Files**: `compiler/rule_compiler.go`, `compiler/types.go` (or equivalent)
**Work**:
- Add `Tags []string` to `CompiledRule`
- Store tags during compilation
- Implement tag-based rule filtering in scanner

#### 3.2 Metadata storage
**Files**: `compiler/rule_compiler.go`
**Work**:
- Add `Meta map[string]any` to `CompiledRule`
- Store metadata during compilation

#### 3.3 Global rule enforcement
**Files**: `compiler/scanner.go`, `compiler/rule_compiler.go`
**Work**:
- Store global flag in `CompiledRule`
- Auto-execute global rules in scanner

#### 3.4 Private rule enforcement
**Files**: `compiler/scanner.go`, `compiler/condition_compiler.go`
**Work**:
- Store private flag in `CompiledRule`
- Exclude private rules from rule references

### Priority 4: Unreferenced string warning suppression

#### 4.1 `$_` prefix suppression
**Files**: `compiler/compiler.go`
**Work**:
- In `collectReferencedStrings` check, skip warning if identifier starts with `$_`

### Priority 5: Module system (out of scope for now)

Module loading and execution is a large feature requiring:
- Module registration system
- Module function compilation
- Module data structures
- Individual module implementations (pe, elf, macho, hash, math, etc.)

This is tracked separately and not part of the initial gap closure plan.

---

## Implementation Order

1. **`#a in (min..max)`** — Smallest change, single opcode already defined
2. **`percent` quantifier** — Lexer + parser + compiler, moderate complexity
3. **`for..of` with `in (range)` / `at offset`** — AST + parser + compiler + interpreter
4. **Text string set iteration** — Compiler + interpreter
5. **Tags + Metadata storage** — Compiler only
6. **Global/Private rule enforcement** — Scanner + compiler
7. **`$_` prefix suppression** — Simple compiler change
