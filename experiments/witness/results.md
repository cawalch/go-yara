# Word-witness spike, 2026-09-19

**Verdict: reject a general replacement; continue research on a selectively
compiled long-anchor path.** Both Linux runs fail the frozen overall gate despite
large primary-workload gains. The implementation was not tuned to repair the
failed held-out cases. The research branch remains unmerged.

## Measured result

Primary workloads are 256-byte records, 1% positive, at 24/256/2,048 rules.
Values below are geometric means of hybrid/baseline latency ratios, using the
median of six independent samples per case. Negative percentages are faster.

| Primary family | Intel Xeon 8573C | AMD EPYC 7763 |
|---|---:|---:|
| Literal | -86.56% | -85.06% |
| Conjunction | -92.24% | -91.86% |
| Bounded complex | -60.78% | -65.52% |
| All nine cases | **-84.01%** | **-83.88%** |

For example, at 2,048 rules on AMD, median baseline → hybrid times were
915 → 146 ns for literals, 4,509 → 147 ns for conjunctions, and 439 → 151 ns for
complex patterns. These are complete Boolean results for the restricted grammar.

Both runs fail the same five original guardrails: four short-pattern cases and
one low-entropy case. Short-pattern latency is 3.9–19.6× baseline across these
cases/runners. Low entropy takes 11.9–14.4× baseline and returns 100% `Unknown`
before fallback. All nine primary wins and all five failures have benchstat
`p=0.002, n=6` within each runner. This does not establish performance on unseen
production logs.

The separate AMD stress suite confirms that pure one/two-byte negative portfolios
are 10.5×/26.7× slower, and mixed-width negatives are 2.38× slower. Repeated-anchor
near misses return 100% `Unknown` and are 28% slower including fallback. Conversely,
non-space 4/64 KiB negatives and exact-end positives improve 86–90%; repeated
positive payloads improve 99.89% for this Boolean-only fixture. None of those
supplemental wins changes the failed original gate.

No scan allocation increases were observed. At 2,048 rules the candidate adds
1.41 MiB (literal), 1.71 MiB (conjunction), or 4.12 MiB (complex) of program heap.
Estimated combined hybrid program heap is respectively 588.16, 597.21, and
575.11 MiB; retaining the fallback prevents claiming a production memory saving.

## Method and scope

This prototype samples aligned 1/2/4/8-byte words, looks up exact projected keys,
and verifies the associated literal. Complex patterns propagate reachable byte
positions through literal, byte-class and bounded-gap constraints using bitsets.
There is no AC automaton or regex VM in the candidate. AND rules and alternatives
are supported; spans, counts, modules, unbounded repetitions and branches without
a mandatory literal are outside this experiment. Unsupported compilation is not
a negative result. Exhausting the verification budget returns `Unknown`; the
measured hybrid then invokes the existing scanner.

The alignment coverage construction has direct prior art. This is a new
implementation experiment for this repository, not a claim of an invented search
principle or superiority over Hyperscan/Teddy. See [the research notes](references.md).

## Protocol and interpretation

The [protocol](README.md) and original 76-case fixture were frozen at `4579825`
before timings; implementation logic was frozen at `2f75596`. The baseline is
main `39ee778` with `WithFastScan().Matches`. Training was screened on Apple M3
Max; Linux amd64 is the decision platform. No implementation tuning followed
held-out results. Supplemental stress fixtures were added separately after a
review of coverage and frozen at `9cd7d11` before their timings, without modifying
the original cases or acceptance gate.

Measurements use Go 1.26.0, GOAMD64=v1, GOMAXPROCS=2, six fresh scan processes
with alternating variant order, six compilation samples, and three heap
processes. Each timed scanner is reused and warmed. These are synthetic,
cache-resident microbenchmarks, not a measured service EPS rate.

The original held-out set changes marker seeds, not log structure. Its dense
cases contain one positive payload per event. Its larger records mostly contain
spaces, and binary inputs are tested against ASCII patterns. The supplemental
suite covers true short-only portfolios, mixed lengths, repeated candidates and
matches, non-space large records, and exact-end positives.

Retained heap means incremental compiled-program heap; it excludes scanner
scratch, input IR/source and total process memory. A hybrid retains both programs.
Candidate compilation consumes prebuilt IR while the baseline also parses YARA,
so compile speed comparisons do not have equivalent frontend work.

## Correctness and limits

Independent alignment/boundary, binary, folding, alternatives, conjunction,
bounded-run and reuse checks passed. A recursive reference oracle found no
mismatch in 9,670,281 fuzz executions over 60 seconds; race tests passed. Repository
tests and prototype vet passed. This is evidence, not a formal proof of the
implementation. The work budget does not strictly bound CPU time: hash probes
and parts of library/no-case searches are not byte-budgeted. Four prototype style
lint findings remain; no production integration or merge is proposed.

## What to test next

Local ARM profiles restricted to candidate call stacks attribute 69% of the
low-entropy samples to anchor verification. Short-pattern near misses divide
roughly 51% into the scan loop and 45% into verification. This supports addressing
candidate fanout and short-lane selection before optimizing the hash function;
the percentages are diagnostic ARM observations, not Linux measurements.

A falsifiable next composition is to compile shared-word buckets into additional
offset-based byte tests before enumerating rule IDs, and statically select which
portfolios use this engine. Every alternative, alignment and folded-key collision
must retain a valid path. Rare words selected per alignment phase alone may not
exist for repetitive literals. These proposals are unimplemented; require fresh
rule/event distributions and direct packed-matcher comparisons before promotion.

## Reproduction and evidence

- [Intel run, revision 1a6ccb5](https://github.com/cawalch/go-yara/actions/runs/35471887026)
- [AMD run and supplemental stress, revision 15336be](https://github.com/cawalch/go-yara/actions/runs/35472157554)
- Each run uploads raw timings, parity output, source/binary hashes, environment,
  compilation samples and retained-heap samples. Artifact retention is 30 days.
- A durable local copy, paired benchstat results, supplemental tables and profiles
  lives at `benchmarks/2026-09-19-word-witness/` in the main checkout (ignored by Git).
- [Workflow](../../.github/workflows/witness-study.yml), [summarizer](summarize.py),
  [frozen protocol](README.md), and [supplemental fixtures](stress_test.go).
