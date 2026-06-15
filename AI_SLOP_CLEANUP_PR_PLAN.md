# Cleanup Backlog

This document tracks the remaining high-impact cleanup work for `go-yara`.
Older generated Reamer/FlowTrace reports were removed because they contradicted
each other and described tool behavior rather than project work. Use this file
as the current, commit-safe cleanup backlog.

## Current State

Several previously planned cleanup items have already landed:

- Production scanner API exists in `compiler/scanner.go`.
- `CompiledProgram.Scan`, `ScanReader`, `ScanFile`, and `NewScanner` are
  available.
- CLI non-streaming execution uses `CompiledProgram.Scan`.
- CLI argument parsing uses `flag.NewFlagSet`.
- Parser strategy files named in older plans are no longer present.
- Big-endian 64-bit read opcodes no longer collide with `OpNop` or `OpHalt`;
  read opcodes occupy `224..239`, while `OpNop` and `OpHalt` remain `254` and
  `255`.
- Compiled rule stats are captured as per-rule snapshots, and `GetStats`
  returns a defensive copy.
- Streaming mode is documented and presented as chunked pattern matching, not
  full rule condition evaluation.
- Known-gap tests use explicit helper metadata, and non-gap expected errors fail
  when no error is produced.

## Cleanup Principles

- Keep behavior changes separate from mechanical cleanup.
- Prefer small PRs that can be reviewed independently.
- Add or preserve tests before deleting compatibility behavior.
- Keep VM dispatch table performance intact unless benchmarks prove an
  alternative is safe.
- Run `go test ./...` before merging when Go is available.

## Next PR Candidates

### 1. Split Interpreter By Opcode Category

The interpreter is still a high-churn area. Keep the existing `[256]OpcodeHandler`
dispatch table, but group implementation files by behavior so future opcode
work is easier to review.

Suggested shape:

- stack and control operations
- arithmetic and comparison operations
- string and regex operations
- iterator operations
- file/read operations

Acceptance criteria:

- No opcode value changes.
- No behavior changes.
- Existing interpreter and compiler tests continue to pass.

### 2. Audit Placeholder Public APIs

Review exported helpers that advertise estimates or broad support claims, such
as compilation time or memory requirement estimates. Either remove unused
placeholder APIs or document them clearly as heuristics with a tested contract.

Acceptance criteria:

- Public API docs do not overclaim precision.
- Unsupported or heuristic behavior is named directly.
- README and package docs stay consistent.

## Validation Checklist

Use the smallest relevant check set for each PR, then broaden before merge:

```bash
go test ./...
go test ./compiler ./parser ./semantic ./tests/integration
go test ./compiler -bench=BenchmarkMultiRuleScanner -benchmem -run '^$'
```

Optional quality checks when available:

```bash
golangci-lint run ./...
staticcheck ./...
```
