# Two-stage compact filter study

Study-only fixtures; baseline is main `fcd4e78`. All files require `perfstudy`.
Run the identical files on every candidate. No rule or corpus tuning after freezing.
`event_study_test.go` and `event_guard_study_test.go` are unchanged prior controls.

New scan matrix: 24/256/2048 rules, exactly 256-byte records, six realistic message
families. Conjunction rules require the common `status=200` marker and a unique
mandatory token. Mixed portfolios alternate conjunction, single literal, regex,
and occurrence-count conditions. Traffic contains:

- `clean`: common marker only; all rules false.
- `partial_near`: common marker plus a token with its last byte invalid.
- `sparse`: exactly one positive in every 100 records.
- `dense`: every record positive.
- `anchor_only`: valid unique token with `status=201`; conjunctions remain false.
  Independent literal/regex/count rules can match in the mixed portfolio.
- `late_positive`: the final rule matches, with its token at the record's end.
- `no_markers`: neither common nor unique markers occur.

Parity checks use the existing disabled-prefilter reference path. Reuse coverage
alternates Matches, complete Scan, MatchingRules, and reported-only Scan on one
scanner, including partial candidates, count conditions, modifiers and wide text.
`BenchmarkTwoStageLatePositive` separately exercises 4096-byte and 64-KiB
records with exactly one common marker at the beginning and one last-rule
anchor at the end. Its filler never repeats the common marker; this exposes
the additional pass cost when the first stage admits a late match.

From each candidate checkout containing the three frozen test files:

```sh
GOTOOLCHAIN=go1.26.0 go test -tags perfstudy ./compiler \
  -run 'Test(TwoStageStudy(Parity|Reuse|LateParity)|EventStudyParity|ACEventGuardParity)$' -count=1

GOTOOLCHAIN=go1.26.0 GOMAXPROCS=2 go test -tags perfstudy ./compiler -run '^$' \
  -bench '^Benchmark(TwoStageStudy|TwoStageLatePositive|EventStudy|ACEventGuard)$' -benchtime=250ms -count=6

GOTOOLCHAIN=go1.26.0 GOMAXPROCS=2 go test -tags perfstudy ./compiler -run '^$' \
  -bench '^BenchmarkTwoStageCompile$' -benchtime=1x -count=6

GOTOOLCHAIN=go1.26.0 GOMAXPROCS=2 go test -tags perfstudy ./compiler \
  -run '^TestTwoStageStudyMemory$' -count=3 -v
```

Compile benchmarks report time, allocation bytes and allocation count. Memory
checks report retained heap deltas after GC for a program and a warmed scanner,
plus total compile allocations. These deltas include runtime/compiler caches;
compare repeated measurements in fresh processes, not exact byte equality.
