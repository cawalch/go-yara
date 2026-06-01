# Reamer / pi-flowtrace issue assessment from go-yara cleanup work

**Repo under review:** `cawalch/go-yara`  
**Tool repos to file against:** `cawalch/reamer`, `cawalch/pi-flowtrace`  
**Context:** Multi-PR cleanup work on `go-yara` using Reamer + FlowTrace heavily. The tools were useful overall, but several failure modes repeatedly affected confidence and workflow speed.

---

## Executive summary

The biggest reliability issue is **index freshness / ID consistency while editing uncommitted Go files**. Several Reamer and FlowTrace calls returned stale or impossible results immediately after edits, then succeeded later after the index refreshed. The second issue is **symbol-id mismatch**: `code_search_symbols` returned IDs that `code_read_symbol` resolved to unrelated symbols. The third issue is FlowTrace-specific: **recursive `both` traces and shared-helper backward expansion produce large noisy trees**, while **constant/opcode-table mediated dispatch** is invisible to `flow_path`.

These are high-value fixes because Reamer/FlowTrace are most useful during active refactors, exactly when files are changing and call graphs need to remain trustworthy.

---

# Issues for `cawalch/reamer`

## 1. `code_read_symbol(id)` returned unrelated symbols from IDs returned by `code_search_symbols`

### What happened

During the review, `code_search_symbols` returned symbol IDs for `compiler/interpreter.go`, but `code_read_symbol` using those IDs read completely different files/symbols.

Examples observed:

```text
code_search_symbols("init", path="compiler/interpreter.go")
→ #1519 function init — compiler/interpreter.go:352-432

code_read_symbol({id: 1519})
→ compiler/match_context.go:26-77 function PopulateMatchContext
```

```text
code_search_symbols("executeMainLoop", path="compiler/interpreter.go")
→ #1546 method executeMainLoop — compiler/interpreter.go:501-534

code_read_symbol({id: 1546})
→ compiler/regression_test.go:9-76 function TestRegressionRules
```

```text
code_search_symbols("compileExpression", path="compiler/condition_compiler.go")
→ #1182 method compileExpression — compiler/condition_compiler.go:193-218

code_read_symbol({id: 1182})
→ compiler/hex_pattern.go:17 constant HexTokenWildcard
```

### Expected behavior

A symbol ID returned by `code_search_symbols` should be stable and should round-trip exactly through `code_read_symbol` in the same session/index generation.

### Actual behavior

The ID resolved to an unrelated symbol in a different file. This is worse than a miss because it can silently mislead the agent.

### Suspected cause

Likely one of:

- stale in-memory ID map vs refreshed SQLite rows;
- rowid reuse / mismatch between symbol search and symbol read tables;
- asynchronous indexing changing IDs between tool calls without generation checks;
- symbol IDs not globally stable but exposed as if they are.

### Suggested fix

- Add an index generation/version to symbol-search results and reject `code_read_symbol` if the generation changed.
- Prefer stable symbol IDs based on `(file path, startLine, endLine, name, kind, signature hash)` instead of raw rowid.
- Make `code_read_symbol` validate that the resolved symbol name/path still match the requested ID metadata; if not, return a hard error.
- Optionally allow `code_read_symbol` to accept the full tuple returned by search, not only ID.

---

## 2. Freshness: newly edited/uncommitted files were temporarily invisible, while status did not make this obvious

### What happened

After adding `compiler/scanner.go` in PR #109 work, the file existed and tests passed, but symbol/FlowTrace queries could not find new symbols immediately.

Observed sequence:

```text
Created compiler/scanner.go with:
  func (s *Scanner) Scan(data []byte) (*ScanResult, error)
  func (cp *CompiledProgram) Scan(data []byte) (*ScanResult, error)

gofmt + go test ./... passed.

flow_trace(name="Scan", path="compiler/scanner.go")
→ No symbol found matching "Scan" in compiler/scanner.go
```

Later, after the index caught up, Reamer found the symbols correctly:

```text
code_search_symbols("Scan", path="compiler/scanner.go")
→ #1637 method Scan — compiler/scanner.go:103-107
→ #1640 method Scan — compiler/scanner.go:131-181
```

Another example during PR #111 work:

```text
Added TestScannerRead64Functions to compiler/scanner_test.go.

code_search_symbols("TestScannerRead64Functions", path="compiler/scanner_test.go")
→ No symbols found

ffgrep("TestScannerRead64Functions", path="compiler/scanner_test.go")
→ found it at line 145
```

Later, after refresh:

```text
code_search_symbols("TestScannerRead64Functions", path="compiler/scanner_test.go")
→ #3893 function TestScannerRead64Functions — compiler/scanner_test.go:145-173
```

### Expected behavior

When files are edited in the active working tree, Reamer should either:

1. index them before answering; or
2. report clearly that results are stale; or
3. fall back to direct parsing for a path-specific query.

### Actual behavior

Queries returned “No symbol found,” which looked like a code/query mistake rather than index lag.

### Context that may help debug

At one point after refresh, `code_index_status` showed:

```json
{
  "files": 213,
  "symbols": 3675,
  "staleFiles": 0,
  "missingFiles": 0,
  "needsRescan": false,
  "indexed": 216,
  "skipped": 210
}
```

The `indexed > files` and high `skipped` counters are confusing. Earlier, before refresh completed, status did not give an obvious “your new file is not indexed yet” signal.

### Suggested fix

- Track file mtime/content hash for every query path and compare with index metadata.
- If a path-specific query targets a stale/unindexed file, synchronously index that file or return `STALE_INDEX_FOR_PATH` with the file path.
- Add `lastIndexedAt`, `workingTreeMTime`, `indexGeneration`, and `dirtyPaths`/`pendingPaths` to `code_index_status`.
- Consider a `fresh=true` option for tools that blocks until the relevant file is indexed.
- For new untracked files, make path-specific tools parse directly or explicitly say “file exists but is not in index yet.”

---

## 3. Test symbol discovery was temporarily inconsistent

### What happened

`code_search_symbols` initially could not find a new Go test function in `compiler/scanner_test.go`, while `ffgrep` found it immediately. Later it was indexed.

### Expected behavior

For path-scoped symbol searches, test functions should be indexed with the same freshness guarantees as production functions. If tests are intentionally deprioritized, the tool should say so.

### Actual behavior

Transient “No symbols found” looked like a parser/search failure.

### Suggested fix

Same as freshness issue, plus include whether test files are currently indexed/skipped in `code_index_status`.

---

## 4. `code_outline(compact=true)` can be misleading for test files

### What happened

```text
code_outline(path="compiler/scanner_test.go", compact=true)
→ No exported symbols or types found.
```

This is technically correct because compact mode shows exported symbols, but in test files most useful functions are unexported `Test...` functions.

### Expected behavior

For `*_test.go`, compact mode should probably include `Test*`, `Benchmark*`, and `Fuzz*` functions, or at least say “compact mode hides unexported test functions.”

### Suggested fix

Special-case Go test files in compact outline:

- include `Test*`, `Benchmark*`, `Fuzz*` even if unexported;
- or return a note: “No exported symbols; N test functions hidden by compact mode.”

---

# Issues for `cawalch/pi-flowtrace`

## 5. FlowTrace was subject to the same index freshness lag and returned false “No symbol found” results

### What happened

Immediately after adding `compiler/scanner.go`, Reamer later found `Scan` methods, but FlowTrace initially failed:

```text
flow_trace(name="Scan", path="compiler/scanner.go", direction="forward")
→ No symbol found matching "Scan" in compiler/scanner.go
```

The symbol existed and tests passed. Later Reamer indexed it and `code_search_symbols` found both `Scan` methods.

### Expected behavior

FlowTrace path-scoped lookups should either wait for the relevant file to be indexed or report stale/unindexed file status.

### Suggested fix

- Share Reamer freshness diagnostics/generation checks.
- Before returning “No symbol found” for a path-specific query, verify that the path is indexed at the current working-tree content hash.
- If not fresh, return a stale-index diagnostic instead of “No symbol found.”

---

## 6. `flow_trace(direction="both")` can explode through shared helper callers and obscure the root question

### What happened

Tracing `executeReadIntOpBE` with `direction="both"` produced a huge tree dominated by callers of shared helpers like `validateStackUnderflow`, rather than focusing on the root’s callers and callees.

Example:

```text
flow_trace("executeReadIntOpBE", direction="both", depth=3)
→ root executeReadIntOpBE
  ├─ validateStackUnderflow
  │  ├─ executeIterStartStringSet
  │  ├─ executeIterNext
  │  ├─ executeIterCondition
  │  ├─ executePop
  │  ├─ executeBitwiseNot
  │  ├─ executeNotOperation
  │  └─ ... many more
```

This happens because `executeReadIntOpBE` calls a highly shared helper, and recursive `both` expansion follows that helper backward to every other caller.

### Expected behavior

For “both” at depth > 1, common expectation is:

- show direct callers of root;
- show direct callees of root;
- continue forward from root callees, but do not expand backward from every shared callee unless requested.

### Actual behavior

The trace becomes dominated by unrelated sibling callers of shared helpers.

### Suggested fix

Add a traversal mode such as:

- `direction="root-both"`: root callers + root callees, then forward only;
- `suppressSharedHelperBackrefs=true`;
- `maxCallersPerCallee` / `fanoutLimit`;
- rank/prune nodes with high fan-in (`validateStackUnderflow`, `push`, `pop`, etc.).

---

## 7. FlowPath cannot represent constant/opcode-table mediated dispatch

### What happened

We tried to connect compiler emission to interpreter execution for `uint64be/int64be`:

```text
flow_path(
  from="compileFunctionCall",
  to="executeReadIntOpBE",
  fromPath="compiler/condition_compiler.go",
  toPath="compiler/interpreter.go"
)
→ No paths found within depth limit.
```

But Reamer references show the semantic connection:

```text
condition_compiler.go:
  "uint64be": OpUint64be

interpreter.go:
  opcodeTable[OpUint64be] = (*Interpreter).executeReadUint64be

executeReadUint64be -> executeReadIntOpBE(8, false)
```

### Expected behavior

A plain call graph may not be expected to solve bytecode/dataflow dispatch, but for this project pattern the tool could at least expose a “constant-mediated dispatch” path:

```text
compileFunctionCall
  emits OpUint64be
  opcodeTable[OpUint64be]
  executeReadUint64be
  executeReadIntOpBE
```

### Suggested fix

Add optional edges for common dispatch-table patterns:

- map/slice assignment: `opcodeTable[CONST] = handler`
- switch on constants/opcodes
- compiler/emitter functions that emit the same constant

Even a low-confidence edge would be useful if marked as such:

```text
compileFunctionCall --emits constant?--> OpUint64be --dispatch-table?--> executeReadUint64be
```

---

## 8. FlowTrace output can omit newly-added direct wrappers until index refresh

### What happened

After adding:

```go
func (i *Interpreter) executeReadInt64be() error  { return i.executeReadIntOpBE(8, true) }
func (i *Interpreter) executeReadUint64be() error { return i.executeReadIntOpBE(8, false) }
```

An early backward trace from `executeReadIntOpBE` still listed only the previous six BE wrappers:

```text
executeReadInt8be
executeReadInt16be
executeReadInt32be
executeReadUint8be
executeReadUint16be
executeReadUint32be
```

After index refresh, tracing the wrapper directly worked:

```text
flow_trace("executeReadInt64be", direction="forward")
→ executeReadInt64be -> executeReadIntOpBE -> readIntBE
```

### Expected behavior

Same as freshness issue: do not return a seemingly complete caller set if the file has changed and caller edges are stale.

### Suggested fix

Expose graph-generation freshness and warn when callers/callees come from stale graph data.

---

# Cross-tool recommendations

## A. Add index generation/freshness metadata to every result

Every Reamer/FlowTrace result should include something like:

```json
{
  "indexGeneration": 12345,
  "freshForPaths": ["compiler/interpreter.go"],
  "staleForPaths": [],
  "untrackedButParsed": ["compiler/scanner.go"]
}
```

This would make it obvious whether failures are code facts or index facts.

## B. For path-specific queries, prefer correctness over speed

If the user passes `path="compiler/scanner.go"`, the tool should ensure that exact file is fresh, even if the global index is still catching up.

## C. Add a `forceRefresh` or `fresh` parameter

Useful for active coding:

```json
code_search_symbols({"query":"Scan", "path":"compiler/scanner.go", "fresh": true})
flow_trace({"name":"Scan", "path":"compiler/scanner.go", "fresh": true})
```

## D. Distinguish “not found” from “not indexed yet”

Current “No symbol found” conflates:

- genuinely absent symbol;
- wrong query/path;
- unindexed new file;
- stale index;
- ID mismatch.

Separate diagnostics would save a lot of agent/tool time.

## E. Add stable symbol handles

Avoid exposing raw row IDs as durable handles unless they are stable for the life of the session/index generation.

Possible handle:

```text
compiler/interpreter.go:352-432:init:function:<signature-hash>
```

## F. Better default FlowTrace traversal for large Go projects

For root investigations, avoid recursive backward expansion through shared helpers by default, or show it behind an explicit option.

---

# Positive notes

Despite the issues, the tools were very useful:

- Reamer quickly surfaced churn hotspots and symbol/reference evidence.
- `code_references(OpUint64be)` was excellent for verifying the opcode fix touched all relevant compiler/emitter/interpreter sites.
- Once fresh, `code_search_symbols` and `code_outline` gave accurate Go symbol ranges.
- FlowTrace was helpful for verifying local wrapper-to-helper routes such as `executeReadInt64be -> executeReadIntOpBE -> readIntBE`.

The main need is not more features; it is stronger freshness/consistency guarantees and clearer diagnostics when the index is not current.

---

# Filed issues

## cawalch/reamer

- https://github.com/cawalch/reamer/issues/222 — Symbol IDs from code_search_symbols can resolve to unrelated symbols
- https://github.com/cawalch/reamer/issues/223 — Path-scoped queries need freshness checks for new/edited files
- https://github.com/cawalch/reamer/issues/224 — Go test files: compact outline should include or mention Test/Benchmark/Fuzz functions

## cawalch/pi-flowtrace

- https://github.com/cawalch/pi-flowtrace/issues/147 — Path-scoped traces need freshness checks for new/edited files
- https://github.com/cawalch/pi-flowtrace/issues/148 — direction=both expands through shared helper callers and creates noisy traces
- https://github.com/cawalch/pi-flowtrace/issues/149 — flow_path should optionally model constant/opcode-table mediated dispatch
