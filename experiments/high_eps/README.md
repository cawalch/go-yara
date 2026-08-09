# High-EPS scanning tournament

This directory preserves the external-engine and GPU experiments used to test
10,000-rule scanning of independent 256-byte JSON events. None of these files
or dependencies are part of the production scanner path.

## Workload

- 100, 1,000, 10,000, and 50,000 rule portfolios
- literal, regex, mixed regex/hex/count, duplicate, suffix-heavy, and bounded-repeat shapes
- clean, about 1% matching, 100% matching, common-root miss, and near-match traffic
- one block scan per event so record boundaries remain exact
- reusable scanner/scratch state and allocation reporting

The production Go benchmark lives in
`compiler/high_eps_tournament_test.go`. This directory contains the external
challengers:

- `hyperscan_tournament.cc`: block-mode Hyperscan/Vectorscan ceiling test
- `hyperscan_cgo`: one cgo call per event with the callback kept in C
- `cuda_batch_floor.cu`: pinned-copy plus full-buffer GPU-touch lower bound

## Results

### Exact Go candidate execution

Corrected baseline versus the final sparse-candidate path on an Apple M3 Max,
10,000 rules, 256-byte events, about 1% positives:

| Portfolio | Baseline | Sparse candidates | Improvement |
| --- | ---: | ---: | ---: |
| literal | 105-107 us/event | 656-662 ns/event | about 161x |
| regex | 218-219 us/event | 356-359 ns/event | about 610x |
| mixed | 143-157 us/event | 673-689 ns/event | about 218x |

On a Ryzen 9 9950X, the final single-core path reached about 2.05M literal
EPS, 3.14M regex EPS, and 2.03M mixed EPS. Fully matching traffic remained
above 1.25M EPS for each portfolio. At 32 goroutines, sparse regex reached
about 48.5M EPS and sparse mixed rules about 36M EPS.

This path keeps the existing regex and hex verifiers. Mandatory atoms prove
absence and route exact candidate starts; they do not replace regex semantics.
Atomless, negated, stringless, or incompletely covered rules remain on the
always-evaluate path.

### Hyperscan and Vectorscan

On the Ryzen host, 10,000 presence-only regexes in block mode:

| Engine | Sparse | Dense | Common miss | Near miss |
| --- | ---: | ---: | ---: | ---: |
| Hyperscan 5.4.2 | 64.8M EPS | 14.3M EPS | 33.7M EPS | 11.3M EPS |
| Vectorscan 5.4.11 distro | 23.6M EPS | 9.8M EPS | 17.8M EPS | 8.8M EPS |
| Vectorscan 5.4.12 `znver5` static | 48.6M EPS | 13.8M EPS | 32.1M EPS | 10.9M EPS |

The Hyperscan cgo path measured about 27-30M EPS; distro Vectorscan measured
about 19M EPS. Start-of-match reporting cost roughly 17% in the tested
Hyperscan portfolio. A mandatory 16-repeat regex increased compilation to
about 11 seconds for 10,000 expressions but still scanned at about 61M EPS.

These results establish a useful optional-backend ceiling, not an automatic
drop-in implementation. Direct execution is safe only for a proven compatible
presence-only subset. Counts, offsets, captures/evidence, unsupported syntax,
and occurrence-sensitive rules require exact verification. Hyperscan vectored
mode treats vectors as one logical concatenated stream, so it does not preserve
independent event boundaries by itself.

### GPU floor

The RTX 5090 experiment measured only pinned host-to-device copy, launch, and a
full-buffer touch; real regex work can only be slower.

| Events/batch | Batch latency | Ceiling |
| ---: | ---: | ---: |
| 1 | 4.09 us | 244k EPS |
| 64 | 4.19 us | 15.3M EPS |
| 1,024 | 15.1 us | 67.8M EPS |
| 16,384 | 157 us | 104M EPS |
| 65,536 | 570 us | 115M EPS |

GPU regex remains plausible only for large buffered batches where at least
hundreds of microseconds of latency are acceptable. It is not the first choice
for per-event inline scanning after the CPU candidate path.

## Primary research basis

- [Hyperscan: A Fast Multi-pattern Regex Matcher for Modern CPUs](https://www.usenix.org/conference/nsdi19/presentation/wang-xiang)
- [Hyperscan compilation modes and flags](https://intel.github.io/hyperscan/dev-reference/compilation.html)
- [Hyperscan performance guidance](https://intel.github.io/hyperscan/dev-reference/performance.html)
- [Vectorscan](https://github.com/VectorCamp/vectorscan)
- [Rust regex-automata one-pass DFA](https://docs.rs/regex-automata/latest/regex_automata/dfa/onepass/struct.DFA.html)
- [XAV anchor DFA and XOR filter](https://arxiv.org/abs/2403.16533)
- [DFC cache-friendly multi-pattern matching](https://www.usenix.org/conference/nsdi16/technical-sessions/presentation/choi)
- [GASPP GPU stateful packet processing](https://www.usenix.org/conference/atc14/technical-sessions/presentation/vasiliadis)
- [Nonbacktracking bounded-repeat denial of service](https://www.usenix.org/conference/usenixsecurity22/presentation/turonova)

## Reproduction notes

The Ryzen host used Go 1.26.0, GCC 15.2, CUDA 13.3, an RTX 5090, Hyperscan
5.4.2, Ubuntu Vectorscan 5.4.11, and a native Vectorscan 5.4.12 build configured
with `FAT_RUNTIME=OFF` and `USE_CPU_NATIVE=ON`.

Compile the standalone challengers with:

```sh
g++ -std=c++20 -O3 -march=native hyperscan_tournament.cc -lhs -o hyperscan_tournament
nvcc -std=c++20 -O3 -arch=native cuda_batch_floor.cu -o cuda_batch_floor
```

Run the cgo benchmark only where libhs is installed:

```sh
go test -tags hyperscan ./experiments/high_eps/hyperscan_cgo \
  -run no_tests -bench BenchmarkCGOBlockScan10KRegex -benchmem
```
