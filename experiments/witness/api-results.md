# Boolean routing through the public API

**Pass for opt-in integration.** Two independent Linux amd64 runs of `Scanner.Matches` reduced the nine primary cases' geometric-mean latency by 79.72% and 79.65%. Both runners were AMD EPYC 7763; this does not establish Intel performance.

Production revision: `3b670330c587c9577b55d8dab67879f2c962ba49`. Measured study revision: `955a0dc8ac3c96ccbddb66c58e9a7a23c49e2c7c`; its compiler and internal matcher are identical to the production revision. Go 1.26.0, GOAMD64=v1, GOMAXPROCS=2. [Run 1](https://github.com/cawalch/go-yara/actions/runs/35474862943), [run 2](https://github.com/cawalch/go-yara/actions/runs/35474876219), [frozen protocol](https://github.com/cawalch/go-yara/blob/955a0dc8ac3c96ccbddb66c58e9a7a23c49e2c7c/experiments/witness/api-protocol.md).

| Primary family | Run 1 latency change | Run 2 latency change |
|---|---:|---:|
| Literal | -70.12% | -70.20% |
| Conjunction | -86.60% | -86.49% |
| Bounded regex alternatives | -79.18% | -79.07% |
| All nine | -79.72% | -79.65% |

Primary inputs are 256-byte generated logs, 1% positive, with 24/256/2,048 rules. All 44 cases passed expected-result parity. All nine primaries and 12 all-positive controls improved individually (benchstat p=.002, six samples per variant per run). No selected-case regression exceeded 10%, including primaries; no declined/size-bypassed case exceeded 5%. No case added scan allocations. The 12 positive controls improved by at least 88% on each run. Results and CPUs were not pooled.

Of the original 32 cases, 19 exercised routing, seven declined, and six bypassed it because records exceeded 1,024 bytes. The seven declines were short/mixed-short portfolios and an irreducible variable-gap portfolio. All 12 additional positive controls exercised routing. API timings include Unknown fallback; no internal fallback-rate counter was available. Conversion coalesces singleton/case-pair classes into literals, so this treatment differs from the research-only matcher.

Startup remains the tradeoff. At 2,048 rules, first opted-in scanner construction took about 61–62 ms for complex patterns, 558–561 ms for shared contexts, and 1.65 s for shared tails. Those builds allocated roughly 66.6, 70.4 and 125.7 MB total respectively, excluding ordinary source compilation. These are cumulative allocations, not retained heap or RSS. Subsequent scanners share the plan and add 96 bytes/two allocations over the normal constructor. Scanner construction is not the per-event path.

The default evaluator, detailed scans, unsupported conditions/modifiers, tags, globals, and serialized programs retain the ordinary path. The strict eligibility proof is positive pattern conjunctions; this is not a universal regex replacement. Synthetic generated inputs are not production traffic, the 256-rule tables remain slower than some larger tables, and the same-new-compiler comparison does not measure default compilation overhead versus an older release.

Validation: repository tests/race/vet/analyzers/lint/security, 82.7% local coverage, independent review, internal matcher fuzzing, and 161,491 final public-adapter fuzz executions without mismatch. The review fixed a 599 MB regex-translation amplification before measurement, reducing that reproduction to 1.1 MB and covering an empty-group bypass.

Reproduce the study using `.github/workflows/boolean-routing-study.yml` at the measured revision. Run `python3 experiments/witness/analyze_api.py RESULTS_DIRECTORY` separately for each downloaded artifact. Raw logs, hashes, binaries, parity, startup samples and benchstat output are also preserved locally in `/Users/cawalch/go-yara/benchmarks/2026-09-19-boolean-routing-api/`.
