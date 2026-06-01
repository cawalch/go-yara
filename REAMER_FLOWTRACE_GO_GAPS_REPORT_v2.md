# Reamer & FlowTrace Go Effectiveness Report — v2

**Date**: 2026-05-12  
**Previous Report**: 2025-05-10 (v1)  
**Codebase**: go-yara (190 Go files, 3043+ indexed symbols)  
**Index Health**: ✅ Full coverage  

---

## Executive Summary

**Major improvements since v1.** `flow_trace` and `flow_impact` (for functions/methods) now work on Go — both were completely broken in v1. `code_callers` now correctly resolves Go methods called through struct field accessors, closing a key P1 gap. `code_pattern_search` kind mode works for Go when using correct Go AST node names.

**`flow_path` remains completely non-functional** on Go, and `flow_impact` still cannot resolve callers for struct types. These are the remaining P0 gaps.

### Grade Changes Since v1

| Tool | v1 Grade | v2 Grade | Delta |
|------|----------|----------|-------|
| **flow_trace** | **F** (broken) | **A-** (works well) | 🟢 **CLOSED** |
| **flow_path** | **F** (broken) | **F** (still broken) | 🔴 Still open |
| **flow_impact** | **F** (broken) | **B+** (works for funcs/methods; broken for structs) | 🟡 **Partial** |
| code_callers | **B-** | **A** | 🟢 **CLOSED** |
| code_pattern_search | **B** | **B+** | 🟡 Improved |
| code_flow_trace | **B+** | **B+** | ⚪ No change |
| code_references | **B-** | **B-** | ⚪ No change |
| code_imports | **B** | **B-** | 🔴 Slight regression (noise still present) |
| code_search_symbols | **A** | **A** | ⚪ No change |
| code_semantic_search | **A** | **A** | ⚪ No change |
| code_outline | **A** | **A** | ⚪ No change |
| code_context | **A** | **A** | ⚪ No change |
| code_related | **A-** | **A-** | ⚪ No change |

---

## Test Matrix — v2

| Tool | Scenario | v1 Result | v2 Result | Status |
|------|----------|-----------|-----------|--------|
| **flow_trace** | `Execute` (method on `*Interpreter`) | ❌ "No symbol found" | ✅ 39 symbols, 42 edges, rich call tree | 🟢 FIXED |
| **flow_trace** | `CompileRule` (method on `*RuleCompiler`) | ❌ "No symbol found" | ✅ 21 symbols, 38 edges, full compilation tree | 🟢 FIXED |
| **flow_trace** | `SearchIter` backward callers | ❌ "No symbol found" | ⚠️ Found self only, no callers | 🟡 PARTIAL |
| **flow_trace** | `AddString` forward trace | ❌ "No symbol found" | ✅ 3 symbols, 3 edges | 🟢 FIXED |
| **flow_path** | `NewInterpreter` → `Execute` | ❌ "No symbol found" | ❌ "No paths found within depth limit" | 🔴 STILL BROKEN |
| **flow_path** | `CompileRule` → `SearchIter` | ❌ "No symbol found" | ❌ "No paths found within depth limit" | 🔴 STILL BROKEN |
| **flow_impact** | `Execute` (method) | ❌ "No symbol found" | ✅ 27 callers across 5 files | 🟢 FIXED |
| **flow_impact** | `NewInterpreter` (function) | ❌ "No symbol found" | ✅ 63 callers across 14 files | 🟢 FIXED |
| **flow_impact** | `CompileRule` (method) | ❌ "No symbol found" | ✅ 23 callers across 3 files | 🟢 FIXED |
| **flow_impact** | `ACAutomaton` (struct) | ❌ "No symbol found" | ⚠️ Found root but 0 callers | 🟡 PARTIAL |
| **flow_impact** | `Lexer` (struct) | ❌ "No symbol found" | ⚠️ Found root but 0 callers | 🟡 PARTIAL |
| code_callers | `SearchIter` callers | ❌ 0 results | ✅ 17 callers incl. production code | 🟢 FIXED |
| code_callers | `Execute` callers | ⚠️ Partial | ✅ 20+ callers found | 🟢 IMPROVED |
| code_flow_trace | `SearchIter` backward | ❌ 0 callers | ⚠️ Found fuzz test callers, missed production callers | 🟡 PARTIAL |
| code_pattern_search | `method_declaration` kind | ❌ No matches | ✅ 5 matches | 🟢 FIXED |
| code_pattern_search | `type_declaration` kind | ❌ Not tested | ✅ 5 matches | 🟢 WORKS |
| code_pattern_search | `interface_type` kind | ❌ No matches | ✅ 5 matches | 🟢 FIXED |
| code_pattern_search | `function_declaration` + `min_params=3` | ❌ No matches | ✅ 5 matches (production code) | 🟢 FIXED |
| code_imports | `query="ACAutomaton"` | ❌ Empty | ❌ Returns imports from ACAutomaton's file, not importers of it | 🔴 STILL BROKEN |
| code_imports | `path="compiler/interpreter.go"` | ⚠️ String literal noise | ⚠️ Still returns `return "nan"` as `import nan` | 🔴 STILL BROKEN |
| code_references | `ACAutomaton` | ⚠️ Self-references only | ⚠️ Still self-references only (receiver types) | 🔴 STILL BROKEN |

---

## Gaps Closed Since v1

### ✅ CLOSED #1: `flow_trace` Go Support (was P0)

**v1**: All 15+ queries across 8 symbols returned "No symbol found".  
**v2**: Successfully resolves methods, functions. Produces rich call trees.

Example output for `flow_trace("Execute", both, depth=3)`:
```
Execute [method] interpreter.go:336
├─ Reset [method] interpreter.go:314
│  ├─ Interpreter [struct] interpreter.go:54
│  ├─ NewInterpreter [function] interpreter.go:135
│  │  ├─ TestInterpreterStackOperations [function] compiler_test.go:3488
│  │  ├─ TestInterpreterDebugMode [function] debug_test.go:10
│  │  ├─ BenchmarkDispatchPushPop [function] dispatch_bench_test.go:23
│  │  └─ ... (30+ more callers)
```
Stats: **39 symbols, 42 edges** — excellent depth for a 3-hop trace.

### ✅ CLOSED #2: `code_callers` Field Accessor Resolution (was P1 #4)

**v1**: `code_callers("SearchIter")` returned 0 results because `SearchIter` is called via `rule.Automaton.SearchIter()` (struct field indirection).  
**v2**: Returns **17 callers** including both critical production callers:
- `compiler/match_context.go:42` — `rule.Automaton.SearchIter(data)`
- `compiler/streaming_processor.go:404` — `rule.Automaton.SearchIter(chunk)`

### ✅ CLOSED #3: `code_pattern_search` Go AST Node Kinds (was P2 #7)

**v1**: `method_definition`, `interface_declaration` returned no results.  
**v2**: Works with **correct Go AST kind names**:

| Go AST Kind | v1 Name (TS/JS) | v2 Result |
|-------------|-----------------|-----------|
| `method_declaration` | `method_definition` | ✅ 5+ matches |
| `function_declaration` | `function_declaration` | ✅ 5+ matches |
| `type_declaration` / `type_spec` | N/A | ✅ 5+ matches |
| `interface_type` | `interface_declaration` | ✅ 5+ matches |

**Root cause of v1 failure**: The report used TypeScript/JS AST kind names (`method_definition`, `interface_declaration`). Go's tree-sitter uses different names (`method_declaration`, `interface_type`). This was a naming confusion, not a tool bug.

### ✅ CLOSED #4: `min_params`/`max_params` for Go (was P2 #8)

**v1**: `function_declaration` kind with `min_params=3` returned no results.  
**v2**: Returns correct results when using `lang=go`:
- `assertAnonymousStringResult` (5 params)
- `parseRegexEscape` (4 params)
- `NewInstructionWithOperand` (4 params)
- etc.

**Root cause**: Same as above — needed correct Go AST kind name + `lang=go`.

---

## Remaining Open Gaps

### 🔴 CRITICAL: `flow_path` Completely Non-Functional on Go (P0)

**Status**: Unchanged since v1.  
**Test**: All path-finding queries return "No paths found within depth limit."

| Query | Result |
|-------|--------|
| `NewInterpreter` → `Execute` | No paths found |
| `CompileRule` → `SearchIter` | No paths found |
| `Lex` → `Execute` | Source: "No symbol found matching 'Lex' in lexer" |

Note: `flow_path` can resolve individual symbols (e.g., `NewInterpreter` and `Execute` both exist in the graph), but the pathfinding algorithm fails to connect them despite a clear call chain: `NewInterpreter` → creates `Interpreter` → `.Execute()` is called.

**Hypothesis**: The pathfinding algorithm may not traverse through struct instantiation or method receiver edges. Since Go's call chains often involve creating a struct then calling methods on it, this is a fundamental gap for Go codebases.

**Impact**: `flow_path` provides zero value for Go codebases.

### 🔴 CRITICAL: `flow_impact` Returns 0 Callers for Go Structs (P0/P1)

**Status**: Partially improved since v1 (at least finds the struct now).  
**Test**:

| Target | Type | Callers Found | Expected |
|--------|------|---------------|----------|
| `Execute` | method | ✅ 27 | ~27 |
| `NewInterpreter` | function | ✅ 63 | ~63 |
| `CompileRule` | method | ✅ 23 | ~23 |
| `ACAutomaton` | struct | ❌ 0 | ~15+ |
| `Lexer` | struct | ❌ 0 | ~10+ |

**Root cause**: `flow_impact` only traverses call-graph edges (function→function). Struct types don't have direct callers — they're referenced through field declarations, constructor return types, and method receivers. The impact analysis doesn't follow these reference edges.

**Impact**: Cannot assess the blast radius of struct changes, which are among the most impactful refactoring targets.

### 🟡 MODERATE: `code_flow_trace` Backward Direction Weak for Go Indirection (P1)

**Status**: Partially improved.  
**Test**: `code_flow_trace("SearchIter", backward)` now finds fuzz test callers but still misses the 2 production callers in `match_context.go` and `streaming_processor.go`.

The production callers use the pattern `rule.Automaton.SearchIter()` where `Automaton` is a struct field of type `*ACAutomaton`. The backward trace doesn't follow this indirection.

**Mitigation**: `code_callers` now correctly resolves these callers, so this gap is covered by an alternative tool.

### 🟡 MODERATE: `code_references` Self-Reference Noise (P1 #6)

**Status**: Unchanged.  
**Test**: `code_references("ACAutomaton")` returns 15+ results, all within `ahocorasick.go` itself — these are method receiver declarations (`func (ac *ACAutomaton) MethodName()`). None of the external files that use `ACAutomaton` (like `compiler.go`, `rule_compiler.go`, `match_context.go`) appear in results.

Even with `kind="identifier"` filtering, results are limited to the defining file. Production references like:
- `CompiledRule.Automaton *ACAutomaton` (field declaration)
- `rule.Automaton.SearchIter()` (method call via field)
- `NewACAutomaton()` (constructor call)

are not found.

### 🟡 MODERATE: `code_imports` Query Mode Broken (P3 #9)

**Status**: Unchanged.  
**Test**: `code_imports(query="ACAutomaton")` returns imports from `ahocorasick.go` and `ahocorasick_test.go` (files with "ACAutomaton" in their path or content), not files that import/use the `ACAutomaton` type.

The query mode appears to do text/path matching rather than symbol-resolution-based import querying.

### 🟡 MODERATE: `code_imports` String Literal Noise (P3 #10)

**Status**: Unchanged.  
**Test**: `code_imports(path="compiler/interpreter.go")` still returns string literals as imports:

```
compiler/interpreter.go:1488 import nan (external:external)      ← `return "nan"`
compiler/interpreter.go:1491 import inf (external:external)      ← `return "inf"`
compiler/interpreter.go:1500 import string (external:external)   ← `return "string"`
compiler/interpreter.go:1502 import undefined (external:external) ← `return "undefined"`
```

22 real imports are returned correctly, but 8+ false positives from string literals dilute the results.

---

## Updated Issue/Task Recommendations

### P0 — FlowTrace Path Finding & Struct Impact

| # | Issue | Description | v1 # | Status |
|---|-------|-------------|------|--------|
| 1 | **`flow_path` pathfinding fails on Go** | All path queries return empty. The algorithm doesn't traverse through struct instantiation or method receiver edges. Both source and target symbols resolve individually but no path is found between them. | v1#1 | 🔴 Unchanged |
| 2 | **`flow_impact` returns 0 callers for Go structs** | Struct types like `ACAutomaton` and `Lexer` report 0 callers. Only functions/methods work. Need to follow type-reference edges (field declarations, constructor returns, embedded types). | v1#1 | 🟡 Improved (at least finds the struct now) |

### P1 — Caller/Reference Resolution

| # | Issue | Description | v1 # | Status |
|---|-------|-------------|------|--------|
| 3 | **`code_flow_trace` backward misses production callers** | `SearchIter` backward trace finds fuzz callers but misses `match_context.go` and `streaming_processor.go`. Covered by `code_callers` as workaround. | v1#5 | 🟡 Partial |
| 4 | **`code_references` self-reference noise** | Queries for `ACAutomaton` return only receiver-type references within the defining file. External type usages not found. | v1#6 | 🔴 Unchanged |

### P3 — Import Analysis

| # | Issue | Description | v1 # | Status |
|---|-------|-------------|------|--------|
| 5 | **`code_imports` query mode does path matching** | `query="ACAutomaton"` finds files with ACAutomaton in their path, not files that use the type. | v1#9 | 🔴 Unchanged |
| 6 | **`code_imports` string literal false positives** | `return "nan"` reported as `import nan`. 8+ false positives per file. | v1#10 | 🔴 Unchanged |

### P4 — Documentation

| # | Issue | Description | v1 # | Status |
|---|-------|-------------|------|--------|
| 7 | **Document Go AST kind names for `code_pattern_search`** | Go uses `method_declaration`, `interface_type`, `type_spec` — not the TS/JS names `method_definition`, `interface_declaration`. Users need a reference table. | New | 🟡 Needs docs |

---

## v1 Issues Closed

| v1 # | Issue | Resolution |
|-------|-------|------------|
| v1#1 | FlowTrace symbol resolver doesn't find Go symbols | ✅ Fixed — `flow_trace` and `flow_impact` now resolve Go methods and functions |
| v1#2 | FlowTrace needs Go-specific symbol disambiguation | ✅ Fixed — bare names resolve correctly without qualified names |
| v1#3 | Add `lang` parameter to FlowTrace tools | ⚪ N/A — works without `lang` parameter now |
| v1#4 | `code_callers` misses callers through struct field accessors | ✅ Fixed — `SearchIter` now finds 17 callers |
| v1#7 | `code_pattern_search` kind mode doesn't support Go AST nodes | ✅ Fixed — correct Go kind names work (`method_declaration`, `interface_type`, etc.) |
| v1#8 | `code_pattern_search` min_params/max_params doesn't work for Go | ✅ Fixed — works with correct kind name + `lang=go` |

---

## Comparison: Reamer Tools vs Traditional Tools (v2)

| Task | Best Reamer Tool | Traditional | Token Savings | Quality vs v1 |
|------|-----------------|-------------|---------------|---------------|
| Find function definition | `code_search_symbols` | grep | ~60% | ⚪ Same (was A) |
| Find callers | `code_callers` | grep | ~30% | 🟢 **Better** (now resolves field accessors) |
| Trace call chains | `flow_trace` | Manual grep | ~70% | 🟢 **Much better** (was completely broken) |
| Impact analysis (funcs) | `flow_impact` | grep + callers | ~60% | 🟢 **Works now** (was broken) |
| Impact analysis (structs) | `flow_impact` | grep | N/A | 🔴 Still broken |
| Path between functions | `flow_path` | Manual trace | N/A | 🔴 Still broken |
| Search by concept | `code_semantic_search` | grep -i | ~80% | ⚪ Same |
| Budget-aware context | `code_context` | Read whole files | ~85% | ⚪ Same |
| AST structural search | `code_pattern_search` | grep patterns | ~40% | 🟢 **Works now** with correct Go kinds |

---

## Test Environment

- **Codebase**: go-yara, 190 Go files across 8+ packages
- **Go patterns tested**: methods with receivers, standalone functions, struct types, interfaces, type aliases, iterator functions, embedded fields, module imports, field accessor indirection
- **Test date**: 2026-05-12
- **Comparison baseline**: v1 report dated 2025-05-10

---

*Report generated via systematic re-testing of all v1 gaps. Each tool was called with the same queries as v1 plus additional verification tests.*
