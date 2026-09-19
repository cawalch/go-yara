# Restricted word-witness study

Research harness for a candidate that uses neither Aho–Corasick nor a regex VM.
The baseline is main `39ee778` (#245), compiling equivalent YARA rules and calling
`Scanner.Matches` with `WithFastScan`. No full YARA feature is silently treated as
supported: the candidate grammar is AND of patterns, OR of concatenations, with
literal terms and bounded byte-class runs. Unsupported compilation is reported.

Freeze this file and `study_test.go` before timings. Training and held-out corpora
use disjoint deterministic marker seeds. Do not tune on held-out timings or drop
failed cases. Record the fixture hashes, implementation revisions, Go version,
CPU, and raw results. Linux amd64 is the decision platform.

The 76 scan cases cover 24/256/2048-rule literal, common-plus-rare conjunction,
and complex patterns at 256 bytes; clean, 1% positive, dense, and near traffic;
short-anchor controls; low-entropy/common-prefix, common-suffix, binary, and
shuffled-component negatives; and separate 4 KiB/64 KiB sparse/dense controls.
Complex patterns have two distinct alternatives, digit and uppercase runs,
a bounded any-byte gap, and a suffix. The rotating corpus uses eight byte
alignments and exact end placement; dense/parity cases exercise positive matches
at each alignment. The short-anchor and no-anchor coverage is reported separately.

Each supported case measures the baseline, standalone candidate, and complete
hybrid (`Unknown` calls the baseline). Plain literals also have a `bytes.Contains`
control. Standalone `Unknown` is **not** successful rejection or a complete scan;
`unknown/op` reports its corpus fraction. Only hybrid results justify end-to-end
speed claims. The frozen parity test checks explicit fixture truth, candidate
soundness against the baseline, and scanner reuse. NoCase/no-anchor coverage is
also checked outside timing. Compilation failures remain visible coverage gaps.

Compilation and retained program heap are measured separately. Candidate compile
starts from prebuilt restricted IR; baseline compile includes YARA parsing, so
those timings are different frontend costs. Hybrid deployments retain both
programs; report their combined memory, not the candidate alone. Scan allocation
metrics describe warmed reusable scanners.

Suggested frozen decision gate: zero incorrect definitive decisions; at least
10% lower held-out hybrid latency geomean across the nine 256-byte sparse primary
cases; improvement in each rule family; and no held-out guardrail above 10%
regression or individual primary above 5% regression. Report every per-case
result and coverage fraction; a workload-specific exception requires an explicit
accept/reject decision, not a changed gate. Marginal but repeatable gains qualify.

Run parity with `go test -tags=witnessstudy ./experiments/witness -run
'TestWitnessStudy(Parity|Coverage)$' -v`. Run scan benchmarks with
`-run '^$' -bench '^BenchmarkWitnessStudy$' -benchtime=100ms -count=1` in six
independent rounds, alternating `WITNESS_REVERSE=0` and `WITNESS_REVERSE=1`
to reverse sub-benchmark variant order. Keep compile/heap measurements out of scan rounds.
Use six compile samples and three fresh-process heap samples. The two datasets
are labeled in benchmark names; do not aggregate training into the primary score.
