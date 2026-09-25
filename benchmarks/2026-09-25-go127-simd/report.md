# Go 1.27 SIMD scanner prototype

Decision: keep the character-range and ASCII nocase prototype **opt-in**.
There is a major gain on the affected sparse-search workloads, but no meaningful
gain in the existing mixed production benchmarks. Native amd64 performance is
still unverified. Reject the separate fused-root experiment in its current form.

## What changed

`GOEXPERIMENT=simd` with Go 1.27 enables vectorized `indexASCIIFoldByte` and
non-wide contiguous regex byte-range searches. These paths previously scanned
one byte at a time. Short inputs remain scalar, and the first 16 bytes of longer
searches are checked before SIMD dispatch to protect dense/early-match cases.

The matching operations use the portable `simd` API. Small ARM64 and amd64
`archsimd` helpers extract the first matching lane because Go 1.27 does not expose
that operation portably. Unsupported architectures and forced emulation fall
back to scalar search. The default build retains its existing paths and Go 1.26
compatibility. Public APIs, occurrence handling, and compiled formats are unchanged.

This does not replace all nocase searches: the regex literal cursor already uses
platform byte-search functions, and its existing benchmarks remain essentially
unchanged. Existing ordinary literal searches and general AC traversal are also
unchanged.

## Measurements

- CPU: Apple M3 Max, native darwin/arm64.
- Toolchain: Go 1.27.1 for **both** baseline and candidate. These measurements
  isolate the implementation change, not a Go-version upgrade.
- Baseline: `bf6c3e4af2ae8d7df70a305513caee32a6fecfbc`, with only the new scan
  benchmark file copied in. Candidate: this prototype, built with `GOEXPERIMENT=simd`.
- 55 cases, six samples per variant/case, 200 ms per sample, sequential runs with
  original/candidate order reversed on alternate pairs.
- Complete scans exclude compilation and scanner construction. The existing
  `NoCaseRegexLiteralSearchDensity` cases are search-only controls; they are not
  presented as complete scan improvements.
- Compare each case separately; the workload mix is deliberately diagnostic and
  its aggregate geometric mean is not a production speedup estimate.

| Complete scan | Baseline median | SIMD median | Speedup |
|---|---:|---:|---:|
| Nocase literal, 16 KiB, absent | 6.994 us | 1.316 us | 5.32x |
| Character range, 16 KiB, absent | 7.131 us | 1.236 us | 5.77x |
| Nocase literal, 16 KiB, one match at end | 7.656 us | 1.961 us | 3.90x |
| Character range, 16 KiB, one match at end | 7.943 us | 2.002 us | 3.97x |
| Existing atomless regex, leading class, 1 MiB | 433.617 us | 57.560 us | 7.53x |
| Existing production scanner | 47.861 us | 47.588 us | 1.01x, not significant |
| Existing unique-pattern production scanner | 145.597 us | 144.281 us | 1.01x, not significant |

The large targeted gains have p=0.002 in benchstat. These are favorable synthetic
negative/sparse inputs, not evidence of a universal scanner speedup. Short,
dense, AC, literal, and mixed production controls remain close to baseline.
No case has a median slowdown above 5%; the largest is 2.89% on the 64-byte dense
literal control (not significant). One unchanged 16 KiB dense literal control
has a statistically significant 0.79% slowdown. Allocation counts are unchanged;
allocated-byte figures have only small run-to-run variation in three existing
benchmarks.

Full results: [paired/benchstat.txt](paired/benchstat.txt),
[paired/original.txt](paired/original.txt), [paired/simd.txt](paired/simd.txt),
and [paired/summary.json](paired/summary.json).

## Rejected fused-root trial

A separate temporary checkout added a single SIMD pass comparing two to four
root bytes, using the same portable operations and first-lane helpers. The
retained implementation does not contain this change.

Six alternating pairs at 150 ms/sample showed 16 KiB no-match scans becoming
**135.6% slower for two roots** and **37.2% slower for four roots** than the
nocase/range-only candidate. Dense candidate inputs improved by 13-40%, but the
sparse regressions defeat the intended benefit. Go's existing `bytes.IndexByte`
is a strong baseline; fewer logical passes alone did not make this kernel faster.
The trial passes the existing sparse-root and cursor tests, but is not a
production-ready implementation (for example, cancellation uses the old path).

Evidence: [fused-root/benchstat.txt](fused-root/benchstat.txt),
[fused-kernel.go.txt](fused-kernel.go.txt),
[fused-root-integration.patch](fused-root-integration.patch).

## Correctness and portability

- Exhaustive single-byte placement over all 256 values, eight alignments, and
  sizes spanning scalar prefixes, vector boundaries, and tails.
- 20,000 deterministic randomized comparisons with independent scalar oracles.
- End-to-end count/offset/length-sensitive rules, overlapping nocase occurrences,
  and ordinary/fast scanning across vector boundaries.
- Native ARM64 and forced scalar-emulation tests.
- amd64 correctness under Rosetta, including explicitly selected 128-bit and
  256-bit SIMD modes; **no native amd64 performance claim**. AVX-512 execution
  has not been tested.
- Linux/amd64, Linux/386, and js/wasm cross-compilation. The latter two exercise
  fallback build compatibility; they are not runtime performance measurements.
- Go 1.26 compiler-package tests pass with the ordinary build.
- Clean candidate snapshots run `make check` and `go test -race ./...` in both
  ordinary and SIMD configurations; see the `clean-check-*` and `clean-race-*`
  logs alongside this report.

The original clean snapshot passes `make check`. In the working checkout,
pre-existing **ignored** files under `benchmarks/2026-09-19-bounded-routing` break
the broad formatting and package checks (copied research tests reference absent
types). They are not tracked source and were preserved. Clean snapshots include
all tracked project files plus the candidate files, without that archived material.

## Reproduction

Build the original revision in a separate checkout, copy
`compiler/simd_scan_benchmark_test.go` into it, and build its test binary:

```sh
go test -c -o /tmp/go-yara-original.test ./compiler
```

In the candidate checkout:

```sh
GOEXPERIMENT=simd go test -c -o /tmp/go-yara-simd.test ./compiler
python3 benchmarks/2026-09-25-go127-simd/run_pairs.py \
  --baseline /tmp/go-yara-original.test \
  --candidate /tmp/go-yara-simd.test \
  --output /tmp/go-yara-simd-results \
  --bench '^Benchmark(SIMDScan|SIMDRootScan|AtomlessRegexScanner|LeadingClassRegexAtoms|NoCaseRegexLiteralSearchDensity|RegexMatchDensity|SparseRootTextSet|ACScanLargeInput|ProductionScanner|ProductionScannerUniquePatterns|MultiRuleScanner)$'
```

Keep the same toolchain and environment for both builds, run them on the same
otherwise-idle machine, and do not pool results across CPU architectures.
Native x86 measurements on at least AVX2, plus real deployment rules/corpora,
are the next acceptance requirement before broad adoption.
