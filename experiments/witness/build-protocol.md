# Bounded Boolean-routing construction study

Frozen before inspecting candidate timing results. This protocol compares the shipped opt-in API at `bf6c3e4` with a candidate that reduces and bounds construction work. It does not replace the previous ordinary-versus-routed study or retune its fixtures.

## Treatments and immutable inputs

Build two independent test binaries with Go 1.26.0 from baseline `bf6c3e4` and the final candidate SHA. Run both on the same otherwise idle Linux amd64 host, GOAMD64=v1, GOMAXPROCS=2, with the same environment and CPU affinity if used. Record OS, CPU, Go version, source SHAs, fixture SHA256s, binary SHA256s, exact commands, validation logs and all raw samples. Local Apple measurements are a preliminary screen only.

Reuse `/tmp/boolean-routing-api-study-files/experiments/witness/` without editing fixture generation or events. Frozen hashes:

- `routing_study_test.go`: `0e0ecd3a4bef34bebd29725644f803da6910c51ef35d5747b9533401c9e00cbc`
- `study_test.go`: `29f63a0e615c861cf48f2d62d8c7a35aa6f96a38b7c4fc8a74a29a9994420bfc`
- `api_study_test.go`: `bdef76e0b5b4db06c9ab6e234fbec428a5fa15090271c82af3df8f8c854cbc85`

The original 32 cases and separately named 12 all-positive cases remain separate in reports. Verify every case's static event truth and reuse behavior under ordinary and opted-in scanners. Compare the complete 44-case plan-activation and size-bypass vectors between revisions; preserve each bit, including declined and >1024-byte bypass cases. Equal aggregate activation counts alone are insufficient.

## Primary startup endpoint

The nine first-scanner cases are complex, shared-tail and shared-context portfolios at 24, 256 and 2048 rules. Measure `BenchmarkBooleanRoutingAPIFirstScanner` with `-benchtime=1x` in six fresh-process paired rounds. Within each round run both revision binaries sequentially; alternate baseline/candidate order on odd/even rounds. Also alternate `BOOLEAN_API_REVERSE` to balance ordinary/routed sub-benchmark order. No concurrent benchmark or build jobs on that host.

Time only the first `NewScanner(WithFastScan(), WithBooleanRouting())` on a fresh normally compiled program. Source compilation and scanner Close remain outside timing. Each sample must report successful plan activation. Do not reuse an already initialized program for this endpoint. Keep ordinary first-scanner results as an attribution control, not as the primary comparator.

For each case take the median of six samples, then calculate candidate/baseline ratios. The primary endpoint is the geometric mean of these nine latency ratios: acceptance requires <=0.50, a reduction of at least 50%. Material allocation improvement is predefined as a geometric mean first-scanner B/op ratio <=0.70 across the same nine cases. Report allocs/op separately and every per-case value; do not let a geometric mean hide a startup regression. Run paired benchstat as uncertainty context; incomplete samples or unresolved noisy boundary results are inconclusive, not a pass.

Cached-plan constructor cost is a secondary endpoint: `BenchmarkBooleanRoutingAPIReusedScanner`, `-benchtime=100x`, same six paired rounds. Warm plan initialization and backing scanner-slice allocation stay outside timing; scanner allocations remain measured. Report both ordinary and opted-in cases. This endpoint cannot substitute for first-scanner improvement.

## Scan guards and retained benefit

Run the unchanged `BenchmarkBooleanRoutingAPI` and `BenchmarkBooleanRoutingAPIPositive` matrices with six fresh-process paired rounds, `-benchtime=100ms`, alternating revision and variant order as above. Warm and validate all 100 events before each measured variant; measure the direct scanner.Matches call in both binaries, with fixture truth checks unchanged. Keep all 32+12 cases, even if expensive or unfavorable.

The construction candidate must have no per-case opted-in median scan latency regression greater than 5% relative to opted-in `bf6c3e4`, for any of the 44 cases. Report allocation counts and investigate newly introduced scan allocations. Any case over 1.05 fails this guard; do not exclude cases after seeing results.

Also retain the prior benefit versus ordinary scanning on the candidate binary: at least 10% primary aggregate improvement on the original nine 256-byte, 1%-positive literal/conjunction/complex cases, improvement in each primary family, no active-plan guard more than 10% slower than ordinary, and no declined or size-bypassed guard more than 5% slower. Apply those guard budgets to the 12 positive supplements too. Existing historical results are context only, not substituted for same-run comparisons.

## Correctness and resource-limit interpretation

Before timing, require repository checks, focused race validation, independent adapter/wordmatch parity, integration fallback/error tests, and exact 44-case eligibility parity. Resource limits must be exercised at/above their boundaries with deterministic logical accounting. Resource exhaustion means route construction declines and existing scanner behavior continues; it must not become a false result or new public scan error.

Document each counter's unit and charge point: input/source bytes, expanded alternatives/terms/literal bytes, posting/table capacity, feature cells, partition member work, retained routing nodes and duplicated references. Check before allocation or iteration and use overflow-safe subtraction/comparison. A program-wide budget must not reset per rule or regex. Counters bound specified logical resources; they are not hard wall-clock, total heap/RSS, allocator-overhead or context-cancellation guarantees. Normal YARA compilation precedes this opt-in constructor and is outside these additional construction limits.

No threshold, corpus, activation-policy or sample exclusion changes after timing. Any changed candidate is a new labeled revision; preserve failed or inconclusive results. Synthetic fixed-format events do not establish universal production-log performance. No automatic merge or publication is implied by acceptance.
