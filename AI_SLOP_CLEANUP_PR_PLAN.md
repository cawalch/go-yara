# AI Slop / High-Impact Cleanup PR Plan

**Date:** 2026-05-15  
**Scope:** Go cleanup that reduces LoC and architectural hops without changing YARA behavior or hot-path performance.  
**Method:** Reamer symbol/search/context, FlowTrace call/impact traces, churn metrics, `staticcheck`, `golangci-lint`, `go test ./...`, and Go style references.

## Validation baseline

- `go test ./...` passes.
- `golangci-lint run ./...` reports 0 issues.
- `staticcheck ./...` reports only two deprecated fuzz-test uses of `lexer.NewWithRecovery`.
- Recent churn hot spots: `compiler/condition_compiler.go` (44 commits), `compiler/interpreter.go` (30), `parser/parser.go` (29), `semantic/type_checker.go` (27), `compiler/emitter.go` (20), `cmd/main.go` (19).
- Go style reference: Go Code Review Comments emphasizes simple, idiomatic packages and avoiding unnecessary abstraction: https://go.dev/wiki/CodeReviewComments. Go module layout reference: https://go.dev/doc/modules/layout.

## Executive recommendation

Open a cleanup PR series, not one huge PR. The highest impact PR is to restore a production scanner API around the existing shared automaton, then delete duplicated scan setup from CLI/streaming/tests. This can reduce repeated hot-path scans from `rules × data` to one shared text scan plus per-rule condition evaluation.

Suggested PR order:

1. **PR 1:** Production `Scanner` / shared automaton scan path.
2. **PR 2:** Parser strategy collapse into direct Pratt parser helpers.
3. **PR 3:** Test-suite cleanup: remove/skip generated TODO gap tests that currently pass while logging missing errors.
4. **PR 4:** Opcode/read-function cleanup and BE 64-bit opcode collision fix.
5. **PR 5:** CLI `flag` package rewrite and API centralization.
6. **PR 6:** Interpreter file split/declarative handler registration, preserving current table-dispatch performance.

---

## P0 — Shared automaton is built in production but only consumed by test-only scanner code

### Evidence

- `compiler/compiler.go:558-605` builds `CompiledProgram.SharedAutomaton` and `SharedLookup`.
- `compiler/rule_compiler.go:807-832` stores `SharedAutomaton` on `CompiledProgram`.
- Non-test references to `SharedAutomaton` are only construction/storage; no production scan uses it.
- `compiler/scanner_test.go:17` explicitly says the scanner types were “moved from scanner.go — dead in production, kept for tests/benchmarks”.
- `compiler/streaming_processor.go:380-401` loops through every rule and runs each rule automaton per chunk.
- `cmd/main.go:514-620` has separate interpreter/match-context setup instead of using a shared scanner API.

### Why this is massive

Current production execution pays to build a shared automaton, then does not use it. Multi-rule scans still walk the input per rule in CLI/streaming-style paths. This is both AI-slop-like dead architecture and a missed performance win.

### Proposed refactor

- Move the reusable `Scanner`, `ScanResult`, and `RuleMatch` types from `compiler/scanner_test.go` into production, likely `compiler/scanner.go`.
- Expose:
  - `func NewScanner(program *CompiledProgram) *Scanner`
  - `func (cp *CompiledProgram) Scan(data []byte) (*ScanResult, error)` convenience wrapper
  - `ScanFile` / `ScanReader` wrappers if wanted.
- Use `SharedAutomaton` only for text patterns. Continue local regex and hex matching per rule until correctness is proven for shared hex routing.
- Update CLI execute mode and streaming code to call the production scanner instead of rebuilding per-rule match contexts.
- Delete the duplicated test-only scanner implementation.

### Expected impact

- LoC reduction: medium/high immediately by deleting duplicated scan setup; more if streaming and CLI share one engine.
- Performance: high for multi-rule text scans; expected complexity moves from `O(numRules × data)` text automaton scans toward `O(data + numRules condition evaluation)`.
- Risk: moderate. Needs regression coverage for text/regex/hex/xor/wide/private strings and multi-rule references.

---

## P1 — Parser strategy framework is over-engineered and contains compatibility fallback slop

### Evidence

- Parser strategy-related files are large: `parser/context.go` 205 LoC, `parser/strategies.go` 477, `parser/primary.go` 678, `parser/expression_parser.go` 513.
- FlowTrace around expression parsing shows `ParseExpression → parseBinaryExpressionWithPrecedence → StrategyRegistry.FindBinaryStrategy → strategy.Parse`, i.e. multiple dynamic abstraction hops to create ordinary AST nodes.
- Most strategy `Parse` implementations in `parser/strategies.go:220-340` just return the same `&ast.BinaryOp{...}`.
- `parser/expression_parser.go:503-505` has the clearest AI-slop smell: unsupported compatibility-mode tokens become basic identifiers because “This allows tests to pass without full implementation”.
- `TokenClassifier` is a broad interface even though implementations are a single `DefaultTokenClassifier` value used throughout parser files.

### Proposed refactor

- Replace `StrategyRegistry`, `PrimaryExpressionStrategy`, `BinaryExpressionStrategy`, `UnaryExpressionStrategy`, `ParseContext`, and `ParseResult` with direct helper functions:
  - `precedence(tok token.Type) (prec int, ok bool)`
  - `parsePrimary() switch current.Type`
  - `parseUnary()` and `parsePostfix()` direct functions
  - `parseOfTarget()` direct function for YARA-specific `of` handling.
- Delete compatibility-mode fallback that fabricates identifiers for unsupported syntax. Tests should either assert correct errors or be explicit `t.Skip` spec gaps.

### Expected impact

- LoC reduction: high, likely hundreds of lines across parser files.
- Performance: neutral or better; removes interface dispatch and heap-prone wrapper objects during parsing.
- Risk: moderate/high; expression parsing is broad. Do this after preserving parser test fixtures and adding snapshot tests for representative YARA expressions.

---

## P1 — Passing tests that log “expected error but got none” hide real gaps

### Evidence

- `rg 'TODO: Expected .* but got none - gap detected' --glob '*.go'` finds 29 occurrences.
- Hot examples:
  - `parser/parser_incomplete_test.go`
  - `parser/parser_stress_test.go`
  - `tests/integration/error_propagation_test.go`
  - `tests/integration/full_pipeline_test.go`
  - `tests/integration/multi_rule_test.go`
  - `tests/integration/rule_execution_test.go`
  - `compiler/anonymous_strings_edge_test.go`

### Problem

These tests pass while recording known failures as log lines. That creates false confidence, inflates LoC, and makes cleanup risky because broken behavior appears green.

### Proposed refactor

- Convert known spec gaps to explicit `t.Skipf("known gap: ...")` or table metadata like `knownGap: true`.
- Convert tests for behavior that should already be supported to `t.Fatalf`.
- Collapse generated stress tables into smaller semantic fixtures plus fuzz tests.

### Expected impact

- LoC reduction: high in tests, potentially thousands of generated-looking lines.
- Quality: high; failures become actionable.
- Runtime performance: unaffected.

---

## P1 — Opcode collision: `int64be`/`uint64be` are emitted but collide with `NOP`/`HALT`

### Evidence

- `compiler/bytecode.go:151-168` assigns read opcodes `OpReadInt = 240` through `OpUint64be = 255`.
- `compiler/bytecode.go:172-175` also assigns `OpNop = 254` and `OpHalt = 255`.
- `compiler/interpreter.go:456-458` comments that `OpInt64be` and `OpUint64be` share values with `OpNop`/`OpHalt` and are handled as NOP/HALT.
- `compiler/condition_compiler.go:1440-1443` still maps `uint64be` and `int64be` function names to those colliding opcodes.

### Proposed refactor

- Either allocate non-colliding opcodes for BE 64-bit reads, or reject those functions clearly at compile time until opcode space is redesigned.
- Add regression tests for `int64be(offset)` and `uint64be(offset)`.

### Expected impact

- LoC reduction: low, but correctness impact is high.
- Performance: unaffected.
- Risk: low if covered by tests.

---

## P2 — Interpreter is a 2,386-line monolith with 118 `execute*` methods

### Evidence

- `compiler/interpreter.go` is 2,386 LoC.
- It has 118 `func (i *Interpreter) execute...` methods.
- `compiler/interpreter.go:352-499` has a 148-line global `init()` dispatch table.
- There are many one-line wrappers for arithmetic/comparison/read/string operations around shared helpers.

### Proposed refactor

- Keep the current `[256]OpcodeHandler` dispatch table for speed.
- Split files by category:
  - `interpreter_stack.go`
  - `interpreter_arith.go`
  - `interpreter_compare.go`
  - `interpreter_strings.go`
  - `interpreter_iter.go`
  - `interpreter_read.go`
- Replace repetitive wrapper functions with declarative registrations where possible:
  - `registerBinary(OpIntAdd, func(a,b Value) (Value,error) { ... })`
  - or small typed helper tables for comparison/read operations.
- Avoid reflection/generic dispatch in the VM hot loop. Generate closures at init time if necessary, but keep `executeOpcode` unchanged.

### Expected impact

- LoC reduction: medium.
- Maintainability: high; current file is a churn hotspot and difficult to review.
- Performance: neutral if dispatch remains table based.

---

## P2 — Type checker creates closures and maps for simple operator classification

### Evidence

- `semantic/type_checker.go:118-207` locates handlers via several helper functions and returns `BinaryOpHandler` closures.
- `semantic/type_checker.go:220-290` creates closure wrappers that simply call methods like `checkArithmeticOp`.
- `semantic/type_checker.go:160-173` allocates a `map[token.Type]bool` inside `getStringHandler`.

### Proposed refactor

- Replace handler factories with one direct `switch binaryOp.Op` in `checkBinaryOp`.
- Use switch-based token classification instead of per-call maps.
- Keep the existing `checkArithmeticOp`, `checkBitwiseOp`, etc. functions as the real logic.

### Expected impact

- LoC reduction: medium.
- Performance: small but free; removes allocations/closures during semantic analysis.
- Risk: low with existing type checker tests.

---

## P2 — CLI hand-rolls flag parsing and ignores unknown flags

### Evidence

- `cmd/main.go:37-183` manually parses flags with `os.Args`.
- `parseValueFlag` returns `nil` for unknown flags, so unknown flags are silently ignored.
- Error formatting uses `fmt.Errorf("--%s ...", flag)` while `flag` already includes `--`, producing messages like `----data requires...`.
- `cmd/main.go` is 616 LoC and includes execution orchestration that should live in compiler/scanner APIs.

### Proposed refactor

- Use the standard `flag` package or a small `FlagSet` wrapper.
- Reject unknown flags by default.
- Move execution logic to compiler APIs after PR 1; keep `cmd/main.go` as CLI glue.

### Expected impact

- LoC reduction: medium.
- Go idiom compliance: high.
- Performance: unaffected.

---

## P3 — Lazy stats retain mutable compiler state

### Evidence

- `compiler/rule_compiler.go:52-115` resets one `RuleCompiler` per rule and stores `ruleCompiler: rc` in every `CompiledRule`.
- `compiler/rule_compiler.go:640-729` computes stats lazily through `cr.ruleCompiler.getCompilationStats()`.
- Because the same compiler instance is reused and reset across rules, stats can describe the most recent compiler state rather than the specific compiled rule.

### Proposed refactor

- Snapshot stats at compile time into the `CompiledRule`.
- Remove `ruleCompiler *RuleCompiler` from `CompiledRule`.

### Expected impact

- LoC reduction: low.
- Correctness/ownership clarity: medium.
- Risk: low.

---

## P3 — Placeholder production APIs advertise estimates/features without implementation

### Evidence

- `compiler/compiler.go:881-910` exposes `EstimateCompilationTime` and `GetMemoryRequirements` with TODO comments saying a real implementation would use profiling or AST complexity.
- `GetSupportedFeatures` includes broad feature claims; ensure they match actual semantic/compiler support before presenting as public API.

### Proposed refactor

- Remove placeholder estimate methods unless used.
- Or make them clearly documented heuristics and test their contract.

### Expected impact

- LoC reduction: low.
- API trust: medium.

---

## Suggested GitHub CLI workflow

```bash
git checkout -b cleanup/production-scanner-shared-automaton
# implement PR 1
go test ./...
golangci-lint run ./...
staticcheck ./...
git add .
git commit -m "compiler: restore production scanner using shared automaton"
gh pr create --draft \
  --title "compiler: restore production scanner and remove duplicated scan paths" \
  --body-file AI_SLOP_CLEANUP_PR_PLAN.md
```

For later PRs, branch from main after PR 1 merges and keep each change mechanically reviewable.

## Risk controls for all cleanup PRs

- Keep `go test ./...` and existing regression files green.
- Add targeted tests before deleting compatibility behavior.
- Benchmark before/after for scanner/interpreter changes:
  - `make perf-automaton`
  - `make perf-quick`
  - `go test ./compiler -bench=BenchmarkDispatch -benchmem`
- Do not change VM dispatch style unless benchmarks prove no regression.
- Treat parser cleanup as behavior-preserving first; spec fixes should be separate commits or PRs.

---

## Work log — cleanup/production-scanner-shared-automaton

Status: implementation started on branch `cleanup/production-scanner-shared-automaton`.

Changes made locally:

- Restored production `compiler.Scanner` in `compiler/scanner.go`.
- Added `CompiledProgram.Scan`, `ScanReader`, `ScanFile`, and `NewScanner` helpers.
- Moved scanner implementation out of `compiler/scanner_test.go`, leaving only tests/benchmarks there.
- Updated shared automaton construction to use concrete per-rule automaton entries, preserving alternate encodings such as wide/base64 variants.
- Shared automaton now routes text patterns only; regex and hex remain per-rule local engines for correctness.
- Updated CLI non-streaming execution to use `CompiledProgram.Scan` instead of hand-building match contexts and interpreters per rule.
- Deleted now-unused CLI interpreter setup helpers.
- Added regression tests for hex scanning and wide text through the shared automaton.

Validation:

- `go test ./...` passes.
- `golangci-lint run ./...` passes with 0 issues.
- `staticcheck ./...` still only reports the pre-existing deprecated fuzz helper warnings in parser/semantic fuzz tests.

Docs note: this work log is intentionally local-only and must not be committed.
- `go test ./compiler -bench=BenchmarkMultiRuleScanner -benchmem -run '^$'`: 1.68 ms/op, 282,769 B/op, 2,050 allocs/op on Apple M3 Max.

---

## Work log — cleanup/type-checker-binary-dispatch

Status: implementation started after PR #109 merged.

Changes made locally:

- Simplified `semantic.TypeChecker.checkBinaryOp` to a direct operator `switch`.
- Deleted the `BinaryOpHandler` function type, handler lookup chain, closure factories, and per-call string-operator map.
- Preserved existing specialized check methods (`checkArithmeticOp`, `checkBitwiseOp`, etc.) and behavior.

Impact:

- `semantic/type_checker.go`: -160 LoC net in the binary operator dispatch region.
- Removes closure allocation opportunities and unnecessary dispatch hops from the semantic-analysis path identified by FlowTrace.

Validation:

- `go test ./semantic` passes.
- `go test ./...` passes.
- `golangci-lint run ./...` passes with 0 issues.
- `staticcheck ./...` still only reports pre-existing deprecated fuzz helper warnings in parser/semantic fuzz tests.

Docs note: this work log is intentionally local-only and must not be committed.

---

## Work log — cleanup/fix-be64-read-opcodes

Status: implementation started after PR #110 merged.

Reamer/FlowTrace notes:

- `code_search` confirmed `OpReadInt` now starts at 224 and `OpInt64be`/`OpUint64be` no longer render as `NOP`/`HALT`.
- `code_references(OpUint64be)` shows the range checks, compiler function map, emitter validation, and interpreter dispatch now point at the non-colliding opcode.
- `flow_trace(executeReadInt64be)` confirms the new wrapper routes to `executeReadIntOpBE(8, true)` and then to `readIntBE`.

Changes made locally:

- Moved data read opcode range from 240-255 to 224-239 so all 16 read opcodes fit without colliding with `OpConcat`, `OpNop`, or `OpHalt`.
- Registered `OpInt64be` and `OpUint64be` in the interpreter dispatch table.
- Added `executeReadInt64be` and `executeReadUint64be` wrappers.
- Updated opcode classification/stringification to bound type-function ranges explicitly and keep `OpConcat` as a string opcode.
- Added collision tests for all read opcodes.
- Added interpreter tests for 64-bit little- and big-endian read opcodes.
- Added compiled scanner tests for `int64`, `uint64`, `int64be`, and `uint64be` rule functions.

Validation:

- `go test ./compiler ./cmd` passes.
- `go test ./...` passes.
- `golangci-lint run ./...` passes with 0 issues.
- `staticcheck ./...` still only reports pre-existing deprecated fuzz helper warnings in parser/semantic fuzz tests.

Docs note: this work log is intentionally local-only and must not be committed.
