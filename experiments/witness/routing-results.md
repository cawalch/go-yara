# Shared-word routing experiment, 2026-09-19

**PASS on both tested Linux amd64 hosts under the frozen experimental gate.**
The router removes the targeted shared-word fanout bottleneck while static
selection avoids v1's short-pattern regressions. This supports a narrowly scoped
integration study; it does not establish full YARA compatibility or justify
enabling the prototype in production. The research branch remains unmerged.

## Results

Six fresh-process samples per case and host, alternating variant order, Go 1.26.0,
GOAMD64=v1, GOMAXPROCS=2. All ratios use median latency and include exact fallback.
Primary entries below are geometric means over three rule counts: 24/256/2,048,
256-byte records, 1% positive.

| Primary family, routed versus production baseline | AMD EPYC 7763 | AMD EPYC 9V74 |
|---|---:|---:|
| Literal | -72.64% | -73.97% |
| Conjunction | -86.75% | -87.83% |
| Bounded complex | -81.36% | -82.08% |
| All nine | **-81.10%** | **-82.16%** |

| Shared-word target, routed versus v1 hybrid | AMD EPYC 7763 | AMD EPYC 9V74 |
|---|---:|---:|
| Shared tail, 24 rules | -59.30% | -59.05% |
| Shared tail, 256 rules | -92.73% | -93.21% |
| Shared tail, 2,048 rules | -93.91% | -94.19% |
| Shared context, 24 rules | -63.51% | -65.32% |
| Shared context, 256 rules | -94.48% | -94.72% |
| Shared context, 2,048 rules | -99.89% | -99.92% |

All six targets activate real routing trees; none earns its gain by declining to
baseline. All primary and fanout gains have paired benchstat p=0.002, n=6 within
each host. No scan allocation increases were observed. The prior 17 regression
controls also stay within about 1% of baseline or improve; the small regressions
there are not statistically significant.

## Selection and costs

The router accepts 25/32 fresh portfolios. Six short/mixed-short portfolios and
one shared variable-gap portfolio go directly to baseline. This selection avoids
large negative-event regressions but also forgoes v1's wins on some positive
short-pattern traffic. It is not a universally faster replacement.

Repeated 4 KiB near-matches still return 99% `Unknown`. Including fallback, their
latency is 3.07–3.17% above baseline, within the frozen 10% selected-case limit.
The verifier budget limits counted work, not wall time or all hash probes.

Retained routed-program heap is 1.032–1.590 times v1 across nine resource cases,
below the frozen 2x limit. At 2,048 rules, routed programs retain about 4.23 MiB
for complex patterns, 2.19 MiB for shared contexts, and 1.52 MiB for shared tails.
The hybrid still retains the production program too; these are incremental
program heaps, not scanner memory or process RSS.

Compilation is expensive for shared buckets: 2,048-rule shared contexts take
0.55–0.83 seconds and shared tails 1.14–1.72 seconds, versus roughly 1.6–2.6 ms
for v1. Total compilation allocations are about 70/119 MiB respectively. This
tradeoff favors long-lived rule sets. These candidate-to-candidate comparisons
use identical prebuilt IR; baseline compilation additionally parses YARA.

## What changed and what was validated

Large witness buckets now compile into bounded binary byte-test trees. A probe
position must be required by every surviving posting; allowed-byte unions reject
impossible bytes, overlapping classes retain both feasible branches, and signed
bounds are checked before reading. Each leaf retains at most eight postings for
the unchanged exact verifier. Unsupported widths and unresolved/resource-limited
plans decline the entire portfolio. Fixed-context extraction stops at variable
runs after collecting only their mandatory adjacent bytes.

The scan loop is also specialized for eight-byte witnesses. Primary gains over
v1 include that specialization; they cannot all be attributed to the routing
tree. Throughput is not flat with rule count: the 256-rule marker tables are
slower than the 24/2,048-rule tables on several primary cases in both versions.

Independent unit/race tests and 618,986 fuzz executions passed. Every fuzz trial
required active routing and checked a separate recursive oracle. An additional
2,048-rule test checks every code at every alignment: 16,384 positives and 16,384
invalid-checksum negatives, all correct under unit and race checks. This bounded
grammar testing is evidence, not a formal implementation proof.

Fresh 32-case and historical 88-case parity passed on both hosts. The new corpus
uses different markers, eight log layouts and correlated contexts, but remains
synthetic. Large-event guards are space-padded. No real customer corpus, Intel
replication for this version, or direct Hyperscan/Teddy comparison was performed.
Full YARA conditions, errors, spans and module behavior remain outside the
candidate API. No novel search-principle or SOTA claim is made.

## Reproduction

The fixture/protocol were frozen at `ed298cd`, with a documentation correction
at `9938a8e`, before timing. Both measured runs use exact revision `6ec25be` and
identical binaries. Production and v1 control sources are unchanged. The later
deep-tree test and this report do not change the measured implementation.

- [AMD EPYC 7763 run](https://github.com/cawalch/go-yara/actions/runs/35473295906)
- [AMD EPYC 9V74 run](https://github.com/cawalch/go-yara/actions/runs/35473381630)
- [Frozen protocol](routing-protocol.md), [fixtures](routing_study_test.go),
  [workflow](../../.github/workflows/routing-study.yml), [summarizer](summarize_routing.py).
- Raw samples, hashes, parity, all per-case tables, paired statistics and local
  test logs are preserved in the main checkout's ignored
  `benchmarks/2026-09-19-witness-routing/` directory. Hosted artifacts expire after 30 days.

Next: an opt-in integration restricted to supported Boolean scans, retaining
existing behavior for unsupported/errorful conditions and full span reporting.
Validate that integration on real rule/event corpora before proposing a default.
