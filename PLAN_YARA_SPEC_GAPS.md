# YARA Spec Gap Analysis & Closure Plan (go-yara)

Date: 2026-01-31
Scope: Evaluate go-yara vs YARA writing-rules spec; identify gaps; define implementation and test plan.

## Status Update (2026-02-08)
Recent changes:
- Added runtime support for built-in hash/text functions: `md5`, `sha1`, `sha256`, `tostring`, `int`, `concat`.
- For-loops now support `for any/all/none of (string set) : (expr)` and numeric counts like `for 2 of (...) : (expr)`.
  - `$` can be used inside the loop condition as a placeholder for the current string identifier.
- Hex strings now parse and match alternatives, jumps, wildcards, and masked bytes at runtime.
- String modifiers: `fullword` enforced at match time; `xor` supports no-arg and range forms; `base64`/`base64wide` accept custom alphabets.
- Base64 alignment variants (3 offsets) are generated for `base64`/`base64wide`.

## Current Remaining Gaps (2026-02-08)
- **Modules/imports**: `import` is parsed but modules are not loaded or executed.
- **Rule modifiers**: `private` / `global` are parsed but not enforced at runtime.
- **String modifiers**:
- **For-loops**:
  - No support for `#/@/!` placeholders without identifiers (e.g., `#`, `@`, `!` referring to current string).
  - Range loops only support literal integer ranges; no dynamic ranges.
- **Regex**: Parser/compiler cover a subset; advanced constructs can fail.
- **Module function calls**: Compiled as placeholders (return zero), not real module values.

## 1) Scope + Goals

- Align parsing/semantic/execution with YARA writing-rules behavior.
- Close spec gaps that affect correctness and compatibility.
- Add automated tests to validate fixes end-to-end.

## 2) Current Coverage Summary

- Lexer + parser cover core grammar: rules, tags, meta, strings, conditions.
- AST supports Of/For nodes and string modifiers with optional values.
- Compiler/interpreter support basic text/regex matching and bytecode flow.
- Includes are processed with size + recursion safeguards.

## 3) Major Gaps vs Spec (by behavior)

### 3.1 String Modifiers

- XOR:
  - Only a single integer arg is parsed (e.g., `xor 0x42`).
  - No support for `xor` with no args or a range (`xor`, `xor(1-255)`), which should default to 0..255.
- Base64:
  - No parser support for `base64("alphabet")` / `base64wide("alphabet")` custom alphabets.
- Fullword:
  - Parsed but not enforced at match time (word-boundary checks missing).

### 3.2 Hex Strings

- Hex grammar is flattened into placeholder bytes:
  - Alternatives `(...)` choose first only.
  - Jumps `[min-max]` encoded as markers but not matched semantically.
  - Wildcards/masked bytes are not matched correctly.
- Result: hex patterns match incorrectly vs spec.

### 3.3 Condition Operators

- `in` operator is not parsed as a binary operator (token exists but not treated as comparison op).
- `matches` semantics are incorrect (uses matches from string section rather than regex vs operand string).
- String operations (`contains`, `startswith`, `endswith`, `iequals`, and i-variants) are not executed by the interpreter.
- String literals in conditions compile to lengths instead of actual values, which blocks correct string ops.

### 3.4 Quantifiers / Control Flow

- `of` semantics are incomplete:
  - Interpreter supports only `them` or a single string; count logic is effectively `>=1`.
  - No proper handling of `any/all/none/n of ($a,$b,...)`.
- `for` semantics are stubbed:
  - `for` collapses to a trivial `of them` expression.
  - No variable binding, range iteration, or condition evaluation.
- Placeholders `#`, `@`, `!` inside `for ... of` are not supported.

### 3.5 Modules + Rule Modifiers

- `import` is logged, but module calls return placeholder values.
- `global` / `private` rule modifiers parsed but not enforced at runtime.

## 4) Implementation Plan (Phase by Phase)

### Phase 0: Baseline + Safety

- Add/expand regression harness to run interpreter on sample inputs.
- Ensure existing tests continue to pass.

### Phase 1: Parsing & AST Support

1. Treat `IN` as a comparison operator:
   - Update token classifier for comparison ops.
   - Add binary strategy handling for `IN` in parser.
2. Extend string modifier parsing:
   - `xor`:
     - Accept `xor` (no args) => default range.
     - Accept `xor(min-max)` range.
     - Accept `xor` with single int (still supported).
   - `base64`/`base64wide`:
     - Accept optional `("alphabet")` string literal.
3. Add placeholder nodes for `#/@/!` when used without identifiers in `for ... of`.

Deliverables:

- Parser updates + AST nodes as needed.
- Parser unit tests for new syntax.

### Phase 2: String Compiler & Matching

1. Hex-string matcher correctness:
   - Replace current placeholder encoding with a proper matcher.
   - Options:
     - Build an NFA/DFA for hex patterns.
     - Translate hex pattern to a regex-like VM compatible with existing regex engine.
2. Fullword enforcement:
   - Word-boundary checks on match results.
   - Must respect ASCII/Unicode boundary semantics per YARA (likely ASCII word chars).
3. XOR ranges and no-arg XOR:
   - Option A: Expand to multiple patterns (size may explode).
   - Option B: Implement XOR-aware matching at runtime.
4. Base64 alphabet:
   - Pass alphabet through modifiers and use existing decoder logic.

Deliverables:

- Correct hex matching.
- Fullword boundary enforcement.
- XOR range behavior.
- Base64 alphabet support.

### Phase 3: Condition Semantics

1. String literals must compile to actual string values (not lengths).
2. `matches`:
   - Evaluate regex against string value at runtime.
3. String ops in interpreter:
   - Implement `contains`, `startswith`, `endswith`, `iequals`, and i-variants.
4. `in` operator:
   - Parse + compile to `OpFoundIn` path with proper range semantics.

Deliverables:

- Interpreter opcode implementations.
- End-to-end tests validating string ops + `matches` + `in`.

### Phase 4: Quantifiers & For-loops

1. `of` semantics:
   - Implement count logic for any/all/none/n-of.
   - Support lists and `them`.
2. `for ... of`:
   - Implement `for` loop semantics (iteration + predicate evaluation).
   - Add support for placeholders `#/@/!` in `for ... of`.
3. `for ... in` with variable binding and range evaluation.

Deliverables:

- Quantifier execution correctness.
- For-loop semantics.
- Tests for each pattern.

### Phase 5: Modules + Rule Modifiers

1. Modules:
   - Add module registry.
   - Implement minimal module access or fail fast with clear errors.
2. Rule modifiers:
   - Enforce `private`/`global` at runtime and compilation output.

Deliverables:

- Module interface + basic implementation.
- Modifier enforcement tests.

## 5) Test Plan (Gap Closure Validation)

### Parser Tests

- `xor` modifiers:
  - `xor`, `xor(1-255)`, `xor 0x42`.
- `base64("alphabet")` and `base64wide("alphabet")`.
- `in` operator parsing.
- `for ... of` with `#/@/!` placeholders.

### Compiler/Interpreter Tests

- Hex patterns:
  - Wildcards `??`, masked bytes `A?`/`?A`, jumps `[1-3]`, alternatives `(AA|BB)`.
- Fullword:
  - Positive and negative boundary matches.
- XOR:
  - No-arg XOR (0..255), range XOR, single XOR value.
- Base64:
  - Default alphabet and custom alphabet.
- String ops:
  - contains/startswith/endswith/iequals + case-insensitive variants.
- `matches`:
  - Regex vs literal string values.
- `in`:
  - `$a in (start..end)`.
- Quantifiers:
  - any/all/none/n-of on list and `them`.
  - `for ... of` with placeholders.
  - `for ... in` range with variable use.

### Integration

- Convert `test_regression/` into `go test` integration tests.
- Add CI coverage for new tests.

## 6) Risks + Mitigations

- Hex matcher complexity:
  - Start with correctness over performance; optimize later.
- XOR range expansion:
  - Avoid pattern explosion; prefer runtime XOR-aware matching.
- String ops semantics:
  - Ensure string values are represented in bytecode/interpreter.

## 7) Execution Order (Milestones)

1. Parser + AST enhancements.
2. String literal value compilation + string ops in interpreter.
3. `in` operator end-to-end.
4. Hex matcher correctness.
5. XOR ranges + base64 alphabets.
6. Fullword enforcement.
7. Quantifier semantics + for-loops.
8. Modules + rule modifiers.

## 8) Deliverables Checklist

- [ ] Parser supports XOR range/no-arg + base64 alphabet + IN.
- [ ] Interpreter supports string ops + matches correctly.
- [ ] Hex patterns match per spec.
- [ ] Fullword enforced.
- [ ] Quantifiers and for-loops correct.
- [ ] Regression tests automated in `go test`.
- [ ] CI updated if needed.
