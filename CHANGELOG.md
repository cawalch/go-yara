# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Features
* **Standard YARA CLI Tooling Parity**: Added standard YARA positional syntax (`go-yara [OPTIONS] RULES_FILE TARGET`), recursive directory scanning (`-r`, `--recursive`) with multi-threaded worker pools (`-p`, `--threads`), match string and offset reporting (`-s`, `--print-strings`), metadata reporting (`-m`, `--print-meta`), tag printing (`-g`, `--print-tags`), match count reporting (`-c`, `--count`), tag/identifier filtering (`-t`, `-i`), unsatisfied rule negation (`-n`, `--negate`), zero-match fast scan (`--fast-scan`, `--no-matches`), and structured JSON output (`--json`) for SIEM/pipeline ingestion.
* **Integer Enumeration For-Loops**: Added support for integer enumeration iteration in rule conditions (e.g., `for any i in (1, 2, 3) : (...)`), implementing `OpIterStartIntEnum`, semantic tuple type checking, and libyara 4.5.8 differential parity proofs.

### Performance
* **Zero-Allocation & Match-Free Scan Modes (`WithoutMatches`, `WithoutRuleResults`)**: Added `WithoutMatches()` / `WithIncludeMatches(bool)` and `WithoutRuleResults()` / `WithIncludeRuleResults(bool)` scanner options. Skipping detailed match map materialization and rule result allocation drops production scan memory by **91.6%** (9,360 B/op $\to$ 784 B/op) and reduces allocations from 41 down to 2 allocs/op (and 0 allocs on clean rejections).

### Testing & Quality
* **Differential Fuzzing Expansion & Libyara Oracle Parity**: Expanded `TestLibyaraDifferentialCorpus` and `FuzzLibyaraDifferential` with anonymous string normalization (`$_anon_N` translation enabling libyara CLI match span reporting), string count `#` condition support, and seed corpus coverage for integer enumeration, proximity loops, bitwise operator precedence, integer division, and anonymous string sets.

### Documentation
* Streamlined `README.md` following Google developer technical prose guidelines, condensed feature lists, simplified benchmark tables, and removed outdated AST visitor references.

---

## [v0.7.2] - 2026-10-19

### Features
* **CLI Version Flag**: Added `--version` / `-v` flag to the command-line tool to display build version information ([#344](https://github.com/cawalch/go-yara/pull/344)).

### Refactoring & Code Pruning
* **Semantic Analysis Consolidation**: Removed orphaned `semantic.TypeChecker` and monolithic `ast.Visitor` hierarchy, standardizing entirely on `semantic.Validator` ([#339](https://github.com/cawalch/go-yara/pull/339)).
* **Bytecode & Compiler Cleanup**: Pruned dead bytecode emission helpers, condition compiler routines, and regex bytecode methods ([#340](https://github.com/cawalch/go-yara/pull/340), [#341](https://github.com/cawalch/go-yara/pull/341)).
* **Legacy Atom Engine Removal**: Removed legacy atom extraction structures in favor of unified prefilter indexing ([#342](https://github.com/cawalch/go-yara/pull/342)).
* **Interpreter Pruning**: Removed vestigial interpreter debug mode, execution plan generation, and unused string helpers ([#343](https://github.com/cawalch/go-yara/pull/343)).

### CI & Release
* Hardened release workflow artifact packaging and upload steps ([#344](https://github.com/cawalch/go-yara/pull/344)).

---

## [v0.7.1] - 2026-10-18

### Performance
* **Two-Pointer Proximity Loop Linearization (`OpProximity`)**: Added dedicated `OpProximity` opcode and zero-allocation two-pointer evaluation in `MatchContext.hasProximity`, accelerating string ordering and distance loops (`@b[j] > @a[i] and @b[j] - @a[i] < K`) from $O(N \cdot M)$ nested interpreter loops to $O(N + M)$ time ([#334](https://github.com/cawalch/go-yara/pull/334)).
* **$O(\log N)$ Binary Search Offset Lookups**: Replaced linear string match offset scans with binary search over sorted match offsets and short-circuited set evaluation, eliminating pathological latency on large match sets ([#335](https://github.com/cawalch/go-yara/pull/335)).
* **End-to-End Scanning Throughput**: Reduced proximity-heavy condition evaluations across 24,000+ files from >900s timeouts down to ~1.0s (>1,000x speedup), enabling registry-scale corpus sweeps across 59,000+ files (2.7 GB) in 3.6s.

### Fixes
* **Bounded `for`-Loop Body Parsing**: Bounded parenthesized `for`-loop bodies to terminate at the matching closing parenthesis rather than greedily consuming trailing `or` / `and` binary operators in chained condition expressions ([#336](https://github.com/cawalch/go-yara/pull/336)).

---

## [v0.7.0] - 2026-10-18

### Performance
* **$O(1)$ Epoch Generation Rule Reset**: Replaced the $O(K)$ candidate rule cleanup loop across `candidateRuleIndices` with an epoch generation counter (`s.scanEpoch uint32`), completely eliminating per-scan slice clears. Delivers **+9.5% throughput** on alternation rejects and **+8.5% throughput** on pattern matches with zero allocations ([#332](https://github.com/cawalch/go-yara/pull/332)).
* **Swiss Table Map Iteration Elimination**: Replaced hash map iteration in `regexByteSetCandidateCache.reset` with a direct slice backing `[]*regexByteSetCacheEntry` and precomputed `sharedHasTextOrAlternative` at compile time, reducing map iteration runtime by **65%** ([#331](https://github.com/cawalch/go-yara/pull/331)).
* **Struct Field Alignment & GC Truncation**: Realigned core internal structures via `fieldalignment` audit (`prefilterDedupKey` 72B $\to$ 56B, `anchorInfo` 24B $\to$ 16B, `acStringInfo` 64B $\to$ 56B), dropping into smaller allocator size classes and placing pointer fields at struct heads to allow GC mark scans to terminate early ([#330](https://github.com/cawalch/go-yara/pull/330)).
* **Thompson VM Instruction Layout**: Dropped vestigial `splitID` byte from alternation instructions (`[op][u16 rel]`), shrinking opcode memory footprint by **25%** ([#329](https://github.com/cawalch/go-yara/pull/329)).
* **Credential Stream & Log Optimizations**: Fixed gate evaluation paths to eliminate allocations on large multi-pattern alternation matches ([#308](https://github.com/cawalch/go-yara/pull/308)).
* **Dead Map & Anchor Pruning**: Eliminated dead map ops, lazy regex anchor sampling, and slab allocs ([#307](https://github.com/cawalch/go-yara/pull/307)).
* **Overall Throughput**: **+9.80% geometric-mean throughput improvement** vs `v0.6.0`, up to **+80.3%** on prefilter gate passes, and a **20% reduction** in production allocations.

### Hardening & Testing
* **Tier-2 Scanning Engine Mutation Hardening**: Added 140+ mutation tests across regex byte sets, hex patterns, regex match cost, and candidate rule selection, improving mutant kill efficacy to 76.0% (and ~90% on `regex_byte_set.go`) ([#327](https://github.com/cawalch/go-yara/pull/327)).
* **Tier-1 Prefilter & Scanner Mutation Hardening**: Added extensive mutation coverage across core scanning routines ([#326](https://github.com/cawalch/go-yara/pull/326)).
* **Regex Engine Mutation Hardening Suite**: Hardened the entire regular expression subsystem against surviving mutants:
  * VM execution matrix and instruction dispatch ([#325](https://github.com/cawalch/go-yara/pull/325)).
  * Atom extraction and exact/inexact literal boundary heuristics ([#324](https://github.com/cawalch/go-yara/pull/324)).
  * Parser escape and range handling ([#323](https://github.com/cawalch/go-yara/pull/323)).
  * Capture replay and submatch boundary tracking ([#322](https://github.com/cawalch/go-yara/pull/322)).
  * Bytecode compiler, lexer, and pool allocation ([#319](https://github.com/cawalch/go-yara/pull/319)).
  * First-byte gating and class sequences ([#318](https://github.com/cawalch/go-yara/pull/318)).
* **Wordmatch & Gate Mutations**: Killed surviving mutants in wordmatch verification, required-strings gating, and capture replays ([#310](https://github.com/cawalch/go-yara/pull/310)).

### Fixes
* **CI Quality Gate**: Fixed race condition when previous matrix jobs are cancelled, ensuring the quality gate skips cancelled jobs cleanly ([#328](https://github.com/cawalch/go-yara/pull/328)).
* **Binary Serialization**: Preserved `forbiddenStrings` during compiled program binary serialization and guarded prefilter edge cases ([#309](https://github.com/cawalch/go-yara/pull/309)).

---

## [v0.6.0] - 2026-10-17

### Performance
* **Flat Aho-Corasick DFA Tables**: Flattened state transitions into power-of-two transition tables (`[][256]uint16` / `[][256]int32`), reducing state lookup latency ([#306](https://github.com/cawalch/go-yara/pull/306)).
* **Dense Boolean Rule Results**: Replaced sparse map lookups during condition resolution with a dense boolean vector `ruleResultsDense []bool` for $O(1)$ rule dependency checks ([#305](https://github.com/cawalch/go-yara/pull/305)).
* **Zero-Allocation VM Batch Reuse**: Reusable `VMBatch` allocation pool across concurrent pattern evaluations ([#303](https://github.com/cawalch/go-yara/pull/303)).
* **Streaming Hex Matching**: Implemented callback-driven hex matching and exact slice capacity preallocation ([#300](https://github.com/cawalch/go-yara/pull/300), [#301](https://github.com/cawalch/go-yara/pull/301)).

### Features
* Supported `defined` operator, rejected hex alternation unbounded jumps, and guarded constant division-by-zero ([#291](https://github.com/cawalch/go-yara/pull/291)).

---

## [v0.5.0] - 2026-10-12

### Fixes & Differential Parity
* **YARA Specification Parity**: Resolved 15 differential divergences against standard YARA behavior ([#273](https://github.com/cawalch/go-yara/issues/273)-[#287](https://github.com/cawalch/go-yara/issues/287), [#289](https://github.com/cawalch/go-yara/issues/289), [#290](https://github.com/cawalch/go-yara/pull/290)):
  * Corrected operator precedence to match specification.
  * Fixed modulo-by-zero handling in arithmetic expressions.
  * Corrected `@a[N]` string offset indexing semantics.
  * Aligned `fullword` word boundary character classifications with `isalnum()`.
  * Preserved regex occurrence lengths and greedy quantifier boundaries.

---

## [v0.4.0] - 2026-10-11

### Performance
* **Regex Terminal Loop Acceleration**: Fast-forwarded greedy terminal loops and short-circuited already-satisfied boolean condition trees ([#271](https://github.com/cawalch/go-yara/pull/271)).
* **Match Span Bounds**: Added `WithMaxMatchSpan` option and CLI flag `--max-match-span` to bound regex expansion distance and prevent exponential backtracking ([#272](https://github.com/cawalch/go-yara/pull/272)).

---

## [v0.3.0] - 2026-10-10

### Performance
* **Teddy SIMD Multi-Pattern Prefiltering**: Hardware-accelerated multi-literal prefiltering inspired by Hyperscan's Teddy algorithm, achieving 7–11+ GB/s across 2–64 patterns on ARM NEON and x86 AVX2 ([#270](https://github.com/cawalch/go-yara/pull/270)).
* **Case-Insensitive Acceleration**: Vectorized `nocase` ASCII case-folding across 16-byte, 32-byte, and 64-byte vector lanes ([#269](https://github.com/cawalch/go-yara/pull/269)).

---

## [v0.2.0] - 2026-10-10

### Features
* Introduced streaming memory block scanning (`BlockScanner`) with non-contiguous virtual address offsets.
* Added `hash` (MD5, SHA-1, SHA-256) and `math` (entropy, mean, deviation) built-in modules.
* Added versioned binary cache serialization (`MarshalBinary` / `UnmarshalCompiledProgram`).

---

## [v0.1.1] - 2026-10-06

### Fixes & Hardening
* Hardened regular expression parsing diagnostics and character class validation.
* Fixed CodeQL bounds check alerts on string slicing.
* Added OpenSSF Scorecard supply-chain workflows and automated Cosign bundle signing.

---

## [v0.1.0] - 2026-10-03

### Initial Release
* First public release of `go-yara`: 100% pure Go YARA compiler, scanner, and CLI.
* Strict recursive-descent parser, typed AST, and compile-time semantic analysis.
* Aho-Corasick literal automaton and Thompson VM regex engine.
* Zero CGO dependencies.
