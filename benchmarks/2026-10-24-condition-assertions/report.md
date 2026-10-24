# Condition assertions (#353)

Measured on an Apple M3 Max, macOS arm64, Go 1.27.2. The compiler emits five fused instructions for fixed-offset unsigned 16/32-bit equality, integer filesize comparisons, string-at offsets, and string counts. Each instruction pushes its boolean result once; it does not push or pop intermediate operands. The representative condition uses 10 instructions instead of 23.

Input-only predicates are interned across rules and cached in scanner-owned state. Header prefilters and interpreter instructions consume the same entries. Safe mandatory filesize guards also reject rules before interpretation in modes that do not require matches from rejected rules. Cache entries reset before every scan, including early rejections and block finalization. Strings remain rule-local. External-variable predicates are not cached; optional read errors and callbacks retain ordinary evaluation.

## Measurements

Command:

```sh
go test ./compiler -run '^$' -bench 'BenchmarkConditionAssertions|BenchmarkConditionDispatch' -count=5
```

The benchmark compiles identical source with fusion enabled and disabled in the same binary. The disabled variant also removes shared header caching. Both use the corrected integer-read signedness. Medians of five runs are below; [paired.txt](paired.txt) retains every sample.

| Scenario | Unfused | Fused/shared | Time reduction |
| --- | ---: | ---: | ---: |
| Passing scan, 200 rules | 75.584 us | 63.868 us | 15.5% |
| Header rejection, 200 rules | 5.678 us | 5.343 us | 5.9% |
| Filesize rejection, 200 rules | 80.091 us | 11.847 us | 85.2% |
| One condition, populated match context/cache | 131.5 ns | 80.15 ns | 39.0% |

The scan benchmark uses `WithoutMatches` and `WithoutRuleResults`. Each rule checks a 16-bit header, a 32-bit header, filesize, count, and string offset. Passing/header-rejected scans use a 13-byte buffer. Filesize rejection uses the same bytes as a memory block with a logical size of 30 MiB. The dispatch benchmark excludes pattern matching and cache initialization, representing subsequent rules reusing payload guards. It includes interpreter preparation and produces no allocations. Passing scans retain two allocations; header rejections retain ten; filesize rejection allocates zero.

These are synthetic guard-heavy results, not a throughput claim for production corpora. The small header-rejection difference should not be treated as a general improvement; the original cheap-read path was already fast. The scan gain is smaller than the isolated dispatch gain because pattern processing and result handling remain.

## Validation and compatibility

- `make check`: formatting, module tidiness, vet, repository analyzers, lint, vulnerability checking, and all tests.
- `go test -race -count=1 ./...`.
- Optimized/unfused equivalence across scanner options, scan APIs, integer boundaries, and observable failures.
- 62 new libyara 4.5.8 cases across four buffer/file paths, comparing matched rule identities and spans.
- `FuzzConditionAssertionEquivalence`: 15 seconds, four workers, 192,487 executions without a divergence.
- Shared guards across 120 rules, concurrent scanners, reuse after early rejection, rule-local strings, malformed operands, and absolute block offsets.
- Format version 5 stores assertion operands; version 4 artifacts remain loadable. Older binaries require recompilation to consume new artifacts.

The boundary checks also exposed and fixed the reversed signed/unsigned argument in ordinary little-endian reads. Fused and unfused compilation now agree with libyara on high-bit 8/16/32-bit values.
