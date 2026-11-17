# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

* Cancellable SIMD Teddy scans no longer skip candidates at or beyond the 1 MiB cancellation window. Kernel searches are bounded between cancellation checks and retain overlap for prefixes crossing window boundaries (part of [#540](https://github.com/cawalch/go-yara/issues/540)).

### Performance

* Scan consecutive root misses in the ordinary 16-bit Aho–Corasick loop without repeating the outer state check for every byte, preserving match order and callback termination.

* Restore empty-regex lookahead with reader snapshots instead of rescanning the source prefix, preserving token positions while avoiding offset-dependent lexer work (part of [#543](https://github.com/cawalch/go-yara/issues/543)).

* Parse size literals directly without compiling a regular expression per call, eliminating successful-parse allocations while preserving syntax and overflow errors (part of [#543](https://github.com/cawalch/go-yara/issues/543)).

* Reject ineligible regex terminal-loop fast paths before constructing byte predicates, reducing setup work for ordinary consuming instructions; simplify consecutive compact-prefilter root misses to avoid repeated state checks (part of [#545](https://github.com/cawalch/go-yara/issues/545)).

* Reused the frozen PE ordinal lookup tables for `pe.imphash()` and resolved DLL kinds once per import library, removing two duplicate package-level maps while preserving historical hashes (part of [#544](https://github.com/cawalch/go-yara/issues/544)). Kept the short-input compact prefilter kernel out of dispatch inlining to avoid the AMD64 throughput regression exposed by this cleanup.

## [v0.10.1] - 2026-11-16

### Fixed

* **High-EPS compact prefilter and hot-path regressions:** Eliminated redundant double/triple-pass compact prefilter scans on non-fanout `>=256 B` corpora while preserving Teddy SIMD gating under `GOEXPERIMENT=simd`, tracked dirty `ruleResultsDense` slots via `clearRuleResultsIfDirty()` instead of unconditional dense clears, guarded non-empty `fastSeen` clears and prefilter hook timing, skipped redundant 256-byte `rootIsDense`/`rootCandidateCursor` probes in `search16`/`search32`, and moved hook `defer` wrappers out of `MatchesWithContext`, `compactPrefilterRejects`, and `preparePatternScan` ([#536](https://github.com/cawalch/go-yara/pull/536)).
* **Documentation build probe:** Referenced built-in functions directly in the module catalog generator probe ([#534](https://github.com/cawalch/go-yara/pull/534)).

### Performance & CI

* **Measured benchmark gains (`Intel Xeon 6975P-C`, CI scalar suite vs. `main`):** `HighEPSSelectivity/mixed` improved by 62.6%–80.4% (`clean` 574.1 → 182.9 ns, `sparse` 588.8 → 191.4 ns, `dense` 2,329 → 870.8 ns, `near_miss` 1,833.5 → 359.2 ns), `HighEPSParallel10K/mixed/sparse` improved by 51.7% (173.7 → 83.96 ns), and overall scalar geomean across the 27-benchmark gate improved by 45.5% ([#536](https://github.com/cawalch/go-yara/pull/536)).
* **Performance regression gate & CI efficiency:** Added `TestHighEPSZeroAllocationContracts` and `scripts/perf_gate.sh` (`make perf-gate`) comparing scalar and `GOEXPERIMENT=simd` runs with `benchstat`, path-filtered CI change detection, combined `-race` + coverage test execution, package-scoped fuzzing (`scripts/fuzz_all.sh --packages`), and Go/libyara oracle caching ([#536](https://github.com/cawalch/go-yara/pull/536)).

## [v0.10.0] - 2026-11-15

### Upgrade notes

* **Compiled caches:** New programs use format **20** (adding `ModuleRegex` / `OpPushRegex` in format 19 and byte-deterministic sorted map encodings in format 20); the reader accepts formats **4–20** (`v0.9.0` writes format 18 and cannot read formats 19–20). Recompile rules from source to gain deterministic `MarshalBinary`/`WriteTo` output and compiled rule validation. Keep separate caches for rollback.
* **Go toolchain:** Minimum supported Go toolchain is now **Go 1.27.0** across `go.mod`, CI, and docs.
* **Pure-Go PE module:** Rules can now `import "pe"` without CGO or external bindings (`go-pe` is compiled in as a pure-Go dependency); non-PE rules incur zero PE parser or heap overhead.

### Changed

* Updated the minimum supported Go toolchain version to Go 1.27.0 across module metadata, CI workflows, and documentation, adopted Go 1.27 standard library idioms across compiler/regex/semantic/CLI packages, removed dead regex literal helpers, and streamlined scanner prefilter/cancellation fast paths ([#491](https://github.com/cawalch/go-yara/pull/491)).

### Added

* **Pure-Go PE module (`pe`):**
  * Headers, sections, `section_index(name)` / `section_index(file_offset)`, `rva_to_offset(rva)`, `overlay.offset` / `overlay.size`, `is_dll()`, `is_32bit()`, `is_64bit()`, and `is_dotnet()` ([#452](https://github.com/cawalch/go-yara/pull/452), [#461](https://github.com/cawalch/go-yara/pull/461), [#462](https://github.com/cawalch/go-yara/pull/462), [#485](https://github.com/cawalch/go-yara/pull/485)–[#487](https://github.com/cawalch/go-yara/pull/487), [#502](https://github.com/cawalch/go-yara/issues/502), [#532](https://github.com/cawalch/go-yara/pull/532)).
  * `declared_extent` and `input_truncated` fields so rules can detect truncated PE inputs explicitly ([#501](https://github.com/cawalch/go-yara/issues/501), [#532](https://github.com/cawalch/go-yara/pull/532)).
  * Standard imports (`number_of_imports`, `number_of_imported_functions`, `import_details`, `imports` queries by name, ordinal, and compiled `(dll_regex, function_regex)`, plus `ws2_32`/`wsock32`/`oleaut32` ordinal display alias resolution), `imphash()`, standard exports (`number_of_exports`, `export_details`, `export_timestamp`, `dll_name`, `exports` / `exports_index` queries by name, ordinal, and regex), and bounded chunked `calculate_checksum()` ([#453](https://github.com/cawalch/go-yara/pull/453)–[#460](https://github.com/cawalch/go-yara/pull/460), [#483](https://github.com/cawalch/go-yara/pull/483), [#488](https://github.com/cawalch/go-yara/pull/488), [#490](https://github.com/cawalch/go-yara/pull/490), [#493](https://github.com/cawalch/go-yara/pull/493), [#494](https://github.com/cawalch/go-yara/pull/494)).
  * Resource metadata and locale queries (`number_of_resources`, `resources`, `resource_timestamp`, `resource_version`), plus `version_info`, `version_info_list`, and `number_of_version_infos` ([#506](https://github.com/cawalch/go-yara/pull/506), [#507](https://github.com/cawalch/go-yara/pull/507)).
  * MSVC Rich header metadata and queries (`rich_signature.offset`, `length`, `key`, `raw_data`, `clear_data`, `version_data`, `version(...)`, `toolid(...)`) and CodeView `pdb_path` ([#508](https://github.com/cawalch/go-yara/pull/508), [#509](https://github.com/cawalch/go-yara/pull/509)).
  * Authenticode signature metadata and explicit offline integrity verification (`number_of_signatures`, `signatures`, `countersignatures`, `is_signed`) without claiming CA trust ([#497](https://github.com/cawalch/go-yara/pull/497), [#499](https://github.com/cawalch/go-yara/pull/499)).
  * Documented the native PE input-availability, file-offset vs. process-memory separation, `pe.number_of_imports > 0` guard recommendation for `pe.imphash()`, and cooperative cancellation contract in [native PE RFC](docs/design/rfc_native_pe_module.md) and [PE module docs](docs/pe-module.md), and added the pinned YARA Forge `20261108` PE capability report ([docs/pe-capability-report.md](docs/pe-capability-report.md)) and fixture matrix suite ([#489](https://github.com/cawalch/go-yara/pull/489), [#495](https://github.com/cawalch/go-yara/pull/495), [#504](https://github.com/cawalch/go-yara/issues/504)).
* Added `ModuleRegex`, `CompiledRegex`, `RegexValue`, `CompileModuleRegex`, and `ModuleContext.Done()` alongside lexer function-argument regex literal support (`(` / `,` contexts), `OpPushRegex`, and format 19 serialization ([#492](https://github.com/cawalch/go-yara/pull/492)).
* **Strict compatibility and condition quantifiers:** Added `WithStrictLibyaraCompatibility(true)` for libyara compile-time rejections (unreferenced strings, empty wildcard string sets) and general expression quantifiers in `of` and `for` conditions ([#527](https://github.com/cawalch/go-yara/pull/527), [#528](https://github.com/cawalch/go-yara/pull/528)).
* **Borrowed evidence and zero-copy captures:** Added `WithBorrowedEvidence(true)` scanner option allowing `Capture.Data` to alias scanned input byte slices directly with 3-index capacity clipping, eliminating byte copying during evidence extraction ([#361](https://github.com/cawalch/go-yara/issues/361), [#449](https://github.com/cawalch/go-yara/pull/449)).
* **Direct streaming JSON serialization:** Added `AppendEvidenceJSON` and `WriteEvidenceJSON` (plus `(*EvidenceFinding).AppendJSON` and `(*Capture).AppendJSON`) for reflection-free, deterministic streaming JSON encoding of evidence findings ([#361](https://github.com/cawalch/go-yara/issues/361), [#449](https://github.com/cawalch/go-yara/pull/449)).

### Fixed

* **YARA Forge corpus compatibility:** Fixed six lexer, parser, and semantic gaps (`strings:` section state past 500-byte hex lookback, duplicate `meta:` keys without condition variable binding, negative integers in `meta:`, arithmetic expression parenthesized range upper bounds, postfix `.` stopping before `..`, and numeric/keyword string identifiers on `!`/`@`/`#`) ([#496](https://github.com/cawalch/go-yara/pull/496)).
* **Compiler, interpreter, and regex correctness:**
  * Made `MarshalBinary` and `WriteTo` byte-deterministic (format 20) ([#529](https://github.com/cawalch/go-yara/pull/529)).
  * Validated corrupt compiled artifacts (`ErrCorruptProgram` via `Validate`) and bounded bytecode interpreter execution ([#520](https://github.com/cawalch/go-yara/pull/520)).
  * Rejected invalid hex jump bounds and bounded jump matching by reachable input ([#521](https://github.com/cawalch/go-yara/pull/521)).
  * Preserved strict parse error details, source positions, and rule context ([#500](https://github.com/cawalch/go-yara/pull/500)).
  * Enforced libyara int64 overflow and shift parity, percentage quantifier compile-time bounds (1–100), rejection of mixed greedy/ungreedy regex quantifiers, lifted budget cap on chained lazy dot ranges with budget telemetry, and left `entrypoint` undefined outside PE inputs ([#523](https://github.com/cawalch/go-yara/pull/523)–[#526](https://github.com/cawalch/go-yara/pull/526), [#530](https://github.com/cawalch/go-yara/pull/530)).
  * Empty module collections and integer ranges now evaluate to false for `any`, `all`, and `none`, undefined integer range bounds produce false instead of a scan error, and numeric `0` loop quantifiers use `none` semantics ([#496](https://github.com/cawalch/go-yara/pull/496)).

### Performance

* **Scan, allocation, and serialization hotpaths:** Eliminated whole-buffer `O(N)` fallback hex jump scans on unreachable jumps, added pooled `MatchContext` size-classes for pattern verification, and reduced `MarshalBinary` allocations ([#531](https://github.com/cawalch/go-yara/pull/531)).
* **Unused module setup:** Cached the immutable built-in registry, semantic signatures, schemas, and function-ID bindings, and serialized only module functions referenced per rule. Text-only compilation drops from 88.47 KiB/507 allocations to 62.57 KiB/195 allocations on Go 1.26.9 and 1.27.3; representative text artifacts shrink from 6,206 to 5,316 bytes, and non-PE scans retain zero PE allocations ([#482](https://github.com/cawalch/go-yara/pull/482)).
* **Entropy-weighted atom selection & two-tier prefiltering:** Introduced Shannon entropy, character class diversity, and corpus-wide IDF scoring in prefix atom selection plus two-tier prefilter rejection gating for non-text corpora ([#450](https://github.com/cawalch/go-yara/pull/450)).
* **Evidence pooling:** Replaced per-finding field map allocations and occurrence tracking with scanner-managed pooled buffers in borrowed mode ([#449](https://github.com/cawalch/go-yara/pull/449)).

## [v0.9.0] - 2026-11-02

### Upgrade notes

* **Compiled caches:** New programs use format **18**; the reader accepts formats **4–18**. v0.8.2 writes format 7 and cannot read format 18. Recompile rules from source to pick up corrected match-selection and verification metadata; accepting an older artifact does not regenerate its bytecode. Keep versioned caches during mixed-version deployments and rollback.
* **Reader scans:** Legacy unbounded regex artifacts without a finite verification horizon require recompilation or an explicit `WithMaxMatchSpan` before reader scanning. Otherwise, the scan fails before reading input. Input buffering is bounded independently of stream length; accumulated occurrences, returned bytes, and evidence can still grow.
* The Go requirement remains **1.26.0**. Experimental SIMD paths require a separate **Go 1.27+ / `GOEXPERIMENT=simd`** build; release CLI binaries use the default build. Built-in module coverage is unchanged: native PE/ELF modules are not added.

### Fixed

* **Regex occurrence selection:** Preserve greedy/lazy endpoints and branch priority across literal alternatives, bounded and unbounded repetitions, optional entries, literal affixes, anchors, and atomless matching. Correct ASCII/wide selection, zero-length fullword occurrences, and fullword endpoint retries. These fixes affect counts, offsets, lengths, and conditions as well as boolean matches ([#379](https://github.com/cawalch/go-yara/pull/379)–[#432](https://github.com/cawalch/go-yara/pull/432)).
* **Verification bounds:** Preserve atom ordering and suffix bounds, handle oversized finite prefixes symbolically, and apply verification limits relative to selected atoms ([#421](https://github.com/cawalch/go-yara/pull/421), [#423](https://github.com/cawalch/go-yara/pull/423), [#424](https://github.com/cawalch/go-yara/pull/424), [#426](https://github.com/cawalch/go-yara/pull/426), [#427](https://github.com/cawalch/go-yara/pull/427)).
* **Streaming:** Retain header bytes across chunks, propagate lookahead read errors, and finalize bounded/unbounded regex occurrences only when their decision horizon and boundary context are available or EOF is reached ([#374](https://github.com/cawalch/go-yara/pull/374), [#375](https://github.com/cawalch/go-yara/pull/375), [#387](https://github.com/cawalch/go-yara/pull/387), [#428](https://github.com/cawalch/go-yara/pull/428)).
* **Conditions and fixed offsets:** Propagate undefined integer reads and match-query offsets, preserve scalar coercion in Boolean identity folds, support scalar operands of logical `not`, and retain only eligible fixed-offset text/regex/hex matches ([#373](https://github.com/cawalch/go-yara/pull/373), [#398](https://github.com/cawalch/go-yara/pull/398), [#400](https://github.com/cawalch/go-yara/pull/400), [#402](https://github.com/cawalch/go-yara/pull/402)–[#404](https://github.com/cawalch/go-yara/pull/404)).

### Performance

* **Regex verification:** Reuse failed verification work, accelerate eligible terminal bounded character classes, and share consuming transitions across groups of 4–64 compatible bounded acyclic regexes. Unsupported patterns retain the existing verifier; general cyclic combined-NFA execution is not added ([#433](https://github.com/cawalch/go-yara/pull/433), [#439](https://github.com/cawalch/go-yara/pull/439)–[#441](https://github.com/cawalch/go-yara/pull/441)).
* **Large-corpus prefiltering:** Diversify shared prefix atoms and select rarer fixed-offset mandatory atoms. Experimental SIMD adds ARM64/AVX2 rejection for inputs of at least 256 bytes when a complete cover fits at most 64 distinct prefix sets. Candidate inputs fall through to exact scanning and can pay for both passes ([#435](https://github.com/cawalch/go-yara/pull/435)–[#438](https://github.com/cawalch/go-yara/pull/438)).
* **Evidence ownership:** Reduce capture/correlation allocation using result-owned chunks and bounded reusable scratch. Returned evidence remains independent of input mutation, scanner reuse, and closure. The original match-heavy benchmark drops from 701 to 449 KB and 2,075 to 1,053 allocations per scan; borrowed evidence is not introduced ([#434](https://github.com/cawalch/go-yara/pull/434)).
* **Compilation:** Bound identifier-suggestion edit-distance work while preserving diagnostics, reduce bounded-NFA preparation overhead, and avoid repeated dense automaton growth copies ([#441](https://github.com/cawalch/go-yara/pull/441)–[#443](https://github.com/cawalch/go-yara/pull/443)).

Measurements compare individual changes with their preceding commits, not v0.8.2 with the complete release. On the qualified diagnostic-heavy Signature-Base subset, #442 improves resilient loading 3.87× on native AMD64 and 5.20× on ARM64; #443 adds a further 4.8%/2.4% improvement and reduces allocated bytes by 9.4%. Synthetic shared-prefix regex cases improve substantially, but none of the three representative corpora in #441 activated the new combined-NFA or bounded-class plans. Smaller compile controls in #443 slowed by up to 3.7%; SIMD tail hits can cost more. See the linked PRs for eligibility, hardware, methodology, and tradeoffs.

### Maintenance and validation

* Consolidate scanner execution, streaming accumulation, match-context finalization, regex byte-set analysis, and differential scan coverage; reuse range searches for exact occurrence queries ([#364](https://github.com/cawalch/go-yara/pull/364), [#388](https://github.com/cawalch/go-yara/pull/388)–[#396](https://github.com/cawalch/go-yara/pull/396)).
* Extend libyara differential regressions across scan modes, serialization, scanner reuse, and chunk boundaries. CI includes native AMD64/ARM64 SIMD jobs and 53 fuzz targets; the final implementation commit passed all applicable checks with 83.9% statement coverage.

## [v0.8.2] - 2026-10-25

### Fixed

* **Constant-Memory Streaming**: Replaced `io.ReadAll` inside `Scanner.ScanReader` and `ScanReaderWithContext` with sequential sliding-window streaming ($C + W$ memory), eliminating buffer slurping and OOM crashes on unbounded/large streams ([#352](https://github.com/cawalch/go-yara/issues/352), [#360](https://github.com/cawalch/go-yara/pull/360)).
* **Exact Boundary Deduplication**: Invariant claims matches uniquely by the chunk containing their terminal byte offset (`absEnd > primaryStart && absEnd <= primaryEnd`), guaranteeing zero duplicates and zero missed boundary patterns across chunk seams. Preserved `fullword` boundary context using non-consuming 2-byte lookahead.
* **Stream Condition Evaluation**: Evaluates complete rule condition ASTs at EOF, supporting exact stream `filesize`, fixed header inspections (`uint16(0)` via 64 KB block retention), counts (`#a`), offsets (`@a`), lengths (`!a`), boolean logic (`$a and $b`, `not $c`), global rules, and evidence extraction.
* **Build Metadata**: Ignore root release build and archive directories so later cross-platform builds do not acquire `vcs.modified=true` from earlier generated outputs.

### Added

* **Fast Early-Exit Boolean Scan**: Added `MatchesReader` and `MatchesReaderWithContext` on `Scanner` and `CompiledProgram`, plus `WithStreamEarlyTermination(true)` option. Halts stream reading on chunk 0 once monotonic rule conditions are satisfied (54.7 µs latency, 191 GB/s effective throughput).
* **Stream Tuning Options**: Added `WithStreamChunkSize` (default 1 MB) and `WithStreamOverlapSize` (default: auto ruleset maximum pattern span).

### Documentation

* Updated README, input scanning guides, compatibility, and performance documentation to reflect constant-memory streaming semantics ($C + W$) for `ScanReader`.
* Added architectural RFC for native pure-Go PE parsing and Authenticode inspection ([#359](https://github.com/cawalch/go-yara/issues/359)).

## [v0.8.1] - 2026-10-24

### Fixed

* Populate opt-in scan phase timings and prefilter decision durations; emit per-pattern profiles with an explicit marker for unavailable candidate counts. Account consistently for detailed, boolean, rule-list, single-block, and accumulated-block scans. Finalize telemetry before successful completion hooks, include elapsed time for started scans that fail, and keep counters-only early stops free of timing updates.
* Report per-rule loop-iteration deltas and avoid attributing stale match-context data to a rule rejected before pattern collection. Pattern profiles describe retained occurrences and logical candidate hits, without input data.

### Maintenance

* Update the pinned CodeQL, Node setup, and GitHub Pages actions (#355–#358). Retain TypeScript 5.9.3 because the TypeScript 7 update is incompatible with the current Astro checker.

### Documentation

* Document populated phase timers, pattern-profile callbacks, completion ordering, and scan-method counter scope with an executable telemetry example and updated diagram.
* Add eight selectable playground examples and optional evidence extraction with values redacted inside the worker, bounded findings and field rows, and browser privacy checks. Document hooks, telemetry limitations, and semantic analysis with executable examples and diagrams.

* Expand documentation with executable rule-pattern, result, sparse-block, external-variable, callback-loading, compilation-diagnostic, cancellation, and recursive CLI examples; add block-boundary and serialization diagrams.
* Add executable credential evidence and offline private-key validation examples, with extraction-status guidance and a validation flow diagram.
* Add an on-demand browser playground built from the documented release, with rule/input budgets, bounded displayed results, a hard Wasm memory ceiling, and worker timeouts. Gate documentation deployment on Chromium, Firefox, and WebKit checks.

* Publish nine task-oriented documentation pages with Astro Starlight on GitHub Pages. Test displayed Go and CLI examples against the stable release and current source, generate version and API reference details, validate links, and require a prose review before documenting each release.
* Add diagrams for the scan pipeline, scanner ownership, host-module binding, and experimental browser integration. Include a reproducible browser-worker and WASI spike against v0.8.0; no Wasm binaries or supported JavaScript API are included in the release.

## [v0.8.0] - 2026-10-24

### Compatibility

* **Compiled Programs**: New artifacts use format version 7, including structured module schemas, assertion programs, and overload result types. Formats 4–6 remain readable; older binaries cannot load format-7 artifacts. Rebind external variables, custom module handlers, and host module data after loading.
* **Streaming Scope**: Full-condition bounded-memory streaming remains deferred to [#352](https://github.com/cawalch/go-yara/issues/352). Existing streaming reports literal matches only; `ScanReader` still buffers its input.

### Features

* **Numeric Min/Max Overloads**: Add float and mixed integer/float overloads with float results while retaining YARA's unsigned integer comparison semantics and existing integer external-variable calls ([#350](https://github.com/cawalch/go-yara/issues/350)).
* **Structured Host Modules**: Add schema-checked nested fields, scalar constants, arrays, string-keyed dictionaries, and collection loops ([#351](https://github.com/cawalch/go-yara/issues/351)). Bind owned Go struct/map snapshots with `WithModuleData` or `Scanner.SetModuleData`; collection loops short-circuit once their quantifier is decided. Host data remains runtime-only.
* **Expanded Built-in Modules**: Added `hash.crc32`, `hash.checksum32`, math helpers and statistical functions, `string.to_int`, `string.length`, and `time.now()` ([#350](https://github.com/cawalch/go-yara/issues/350)). Added `hash.sha512` as a go-yara extension. Added YARA-compatible mean absolute deviation overloads while retaining the existing two-argument standard-deviation extension.
* **Standard YARA CLI Tooling Parity**: Added standard YARA positional syntax (`go-yara [OPTIONS] RULES_FILE TARGET`), recursive directory scanning (`-r`, `--recursive`) with multi-threaded worker pools (`-p`, `--threads`), match string and offset reporting (`-s`, `--print-strings`), metadata reporting (`-m`, `--print-meta`), tag printing (`-g`, `--print-tags`), match count reporting (`-c`, `--count`), tag/identifier filtering (`-t`, `-i`), unsatisfied rule negation (`-n`, `--negate`), zero-match fast scan (`--fast-scan`, `--no-matches`), and structured JSON output (`--json`) for SIEM/pipeline ingestion.
* **Integer Enumeration For-Loops**: Added support for integer enumeration iteration in rule conditions (e.g., `for any i in (1, 2, 3) : (...)`), implementing `OpIterStartIntEnum`, semantic tuple type checking, and libyara 4.5.8 differential parity proofs.

### Performance

* **File and Compilation Paths**: Add zero-copy memory-mapped file scanning, dead-pattern pruning, condition constant folding, and reusable compilation scratch storage.
* **Stack-Free Conditions and Shared External Guards**: Fuse fixed-offset integer reads, filesize comparisons, string-at checks, and string counts. Evaluate complete assertion-only boolean conditions without operand-stack traffic, and share payload and integer/boolean/string external guards across rules ([#353](https://github.com/cawalch/go-yara/issues/353)). Safe mandatory guards reject rules before interpretation while preserving callbacks, dynamic type errors, undefined values, match reporting, and per-scan rebinding. Three paired Apple M3 Max runs against unfused compilation reduced median condition dispatch from 172.3 to 68.7 ns (60.1%) and passing 200-rule scans from 86.8 to 62.4 microseconds (28.0%); these are synthetic guard-heavy measurements.
* **Per-Scan Module Call Cache**: Reuse deterministic numeric/range call results across rules with a bounded 16-entry cache that resets between scans. Cache hits allocate no memory; custom callbacks remain uncached unless they opt in with `ModuleFunction.Cacheable`. On an Apple M3 Max, the 100-rule duplicate SHA-256/entropy benchmark over 10 MiB improved from approximately 654 ms to 6.7 ms per scan, with allocations reduced from 401 to 5; these measurements apply to repeated identical calls.
* **Reverse-Prefix & First-Byte Set Regex Candidate Pruning**: Added static AST analysis in `regex` ([`FirstByteSet`](regex/first_bytes.go), [`ReversePrefixAnalysis`](regex/first_bytes.go)) to extract restrictive leading byte sets, exact literal prefix suffixes, and preceding character-class repetitions ($C_{min} \le N \le C_{max}$). Prunes false atom occurrences in $O(1)$ byte checks and collapses variable-repeat search windows before forward Thompson VM dispatch in [`regexAtomCandidateStarts`](compiler/regex_match.go) and [`appendRegexPrefilterMatches`](compiler/atom_prefilter.go), achieving **1.4 GB/s throughput** on dense false-positive atom workloads without invoking the VM.
* **Multi-Byte Hex Atom Extraction & Bounded Offset Windowing**: Expanded [`selectHexAtom`](compiler/atom_selection.go) to extract high-information literal atoms across variable jumps (`[min-max]`), alternatives, and single-key XOR patterns. Integrated bounded candidate window expansion ([`collectRegexCandidateStartsInto`](compiler/regex_byte_set.go)) into the shared prefilter pass ([`SharedPatternAutomaton`](compiler/shared_pattern_automaton.go)), allowing complex hex-heavy rules to be rejected early in the global prefilter pass without per-rule execution.
* **XOR-Invariant 1st-Order Differential Matching (`findHexMatchesXorDiffEach`)**: Added adjacent XOR-differential skip matching ($b_i \oplus b_{i+1}$) for multi-key XOR patterns. Replaced repetitive $O(K \cdot N)$ anchor iterations with a vectorized 64-bit word differential buffer scan and branchless bitmask key validation, delivering a **53.4x throughput speedup** on 256-key XOR patterns (1,123 µs $\to$ 21 µs) with zero heap allocations after warm-up.
* **Zero-Allocation & Match-Free Scan Modes (`WithoutMatches`, `WithoutRuleResults`)**: Added `WithoutMatches()` / `WithIncludeMatches(bool)` and `WithoutRuleResults()` / `WithIncludeRuleResults(bool)` scanner options. Skipping detailed match map materialization and rule result allocation drops production scan memory by **91.6%** (9,360 B/op $\to$ 784 B/op) and reduces allocations from 41 down to 2 allocs/op (and 0 allocs on clean rejections).

### Fixes

* **Concurrent Regex Scanning**: Synchronize memoized AST atom analysis and clone exported results to prevent shared-cache races.
* **Diagnostic Columns**: Correct lexer column tracking after newlines so member/index type errors identify the exact source character.
* **Integer Read Signedness**: Correct the inverted signed/unsigned flag in ordinary little-endian reads, with high-bit differential coverage against libyara.
* **Block Scan Result Options**: Avoid writing to an omitted rule-results map when a block rule is rejected before interpretation.
* **Module and Interpreter Compatibility**: Support zero-argument module calls, propagate undefined module values, accept `string.length` member syntax, and align range truncation, undefined boolean operands, and floating-point equality/NaN comparisons with libyara. Preserve caller-owned block data when assembling contiguous module ranges.

### Testing & Quality

* **Module Compatibility Boundaries**: Classify native signed/unsigned `char` string-statistics variants separately while keeping go-yara results consistent across targets. Add SHA-512 known-answer coverage, float overload serialization, a 100-rule/10 MiB single-digest check, and a regression showing duplicate digest rules add no allocations beyond the first digest.
* **Assertion Dataflow Validation**: Add stack-free execution/allocation checks, optimized-versus-unfused external-guard tests and fuzzing, callback/error preservation, cache reset/rebinding, malformed programs, and legacy format 4–6 fixtures.
* **Security Scan False Positive**: Scope a G101 annotation to the fixed opcode mnemonic table; retain the hardcoded-credential check elsewhere.
* **Portable Integer-Parsing Oracle**: Separate host-dependent libyara binary-prefix behavior from portable module parity tests, fixing the Ubuntu CI failure for `string.to_int("0b10")`. Keep go-yara decimal/octal/hex autodetection deterministic and cover explicit base-2 conversion and rejected prefixes independently.
* **Condition Equivalence**: Add optimized-versus-unfused comparisons, a targeted fuzz harness, 62 libyara cases across four scan paths, malformed operand checks, and coverage for shared-cache isolation, scanner reuse, absolute block offsets, and serialization.
* **Module Differential Coverage**: Added 58 libyara 4.5.8 cases across buffer and file scan paths, plus regression coverage for serialization, block offsets, scanner reuse, concurrent scanners, bounded cache storage, signed-zero cache keys, and zero-allocation cache hits.
* **Differential Fuzzing Expansion & Libyara Oracle Parity**: Expanded `TestLibyaraDifferentialCorpus` and `FuzzLibyaraDifferential` with anonymous string normalization (`$_anon_N` translation enabling libyara CLI match span reporting), string count `#` condition support, and seed corpus coverage for integer enumeration, proximity loops, bitwise operator precedence, integer division, and anonymous string sets.

### Documentation

* Clarify streaming and allocation limits, correct the SHA-256 example, replace machine-local links, and consolidate serialization and benchmark guidance. Simplify the README and remove outdated AST visitor references.

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
