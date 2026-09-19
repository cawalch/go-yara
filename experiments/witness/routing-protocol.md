# Frozen witness-routing follow-up

This is a fresh study of restricted-grammar routing, compared with the current
YARA baseline (#245) and frozen v1 witness hybrid. Candidate paths use neither AC
nor regex execution; the YARA baseline provides exact fallback. The prior 76-case
matrix and 12 stress cases remain historical regressions, not fresh holdouts.
No performance results may influence these fixtures or acceptance thresholds.

`CompileRouted` either accepts the whole portfolio or returns `ErrIneligible`.
Declined portfolios execute the baseline directly; they do not run v1 first.
Other compilation errors fail validation. Eligible portfolios use the routed
scanner, falling back to YARA for `Unknown`. Report `eligible/op`, `unknown/op`,
and routing `nodes/op`; a declined portfolio is not an optimized rejection.
Both v1 and routed timed variants are complete hybrids, including fallback.

Before any timings, the fixed construction bounds are depth 12, cumulative child
reference membership 12N per bucket, scoring work 128 million, a global node
limit proportional to twice total postings,
at most eight references per leaf, offsets within ±256 bytes, and width-eight
witnesses only. Depth eight would require perfect partitions to reduce 2,048
references to eight; depth twelve provides capacity slack. This is a structural
capacity choice, not a response to benchmark results.

The independent generator creates 24-byte non-hex mixed-case markers, eight
actual log layouts (JSON, syslog, key/value, CSV, tabular, access, alternate JSON,
and plain health records), rotating placement, and late/end records. Its seeds,
marker alphabet, formats and contextual constraints differ from v1. This remains
a deterministic synthetic corpus, not representative customer traffic. Large
controls are predominantly space-padded synthetic guards, not representative
large-event payloads.

The 32 fresh cases are fixed as follows:

- Nine primary cases: literal, common-plus-selective AND, and bounded complex OR
  patterns, each at 24/256/2048 rules, 256-byte records, exactly 1% positive.
- Six fanout targets: shared literal tails and a shared full literal followed by
  correlated fixed-byte context, each at 24/256/2048 rules. Context near misses
  change the final code byte; distinguishing byte combinations matters.
- Seventeen guardrails: shared prefixes; repeated near/positive records; true
  one-byte, two-byte and mixed-short portfolios (negative/positive); 4 KiB/64 KiB
  clean/late records; binary; NoCase; variable-gap shared contexts; and reordered
  AND components (intentionally positive because AND does not impose order).

Freeze the file hashes and implementation revision before timings. Require zero
incorrect definitive decisions and correct explicit baseline truth for every
fixture, with scanner reuse. The frozen performance decision requires:

1. All nine primaries eligible; at least 10% lower fresh primary routed-hybrid
   latency geomean versus baseline, with improvement in every primary family.
2. At least 50% lower routed-hybrid latency versus v1 in **each** of the six
   prespecified shared-tail/shared-context fanout targets; all six must be eligible
   and have nonzero routing nodes.
3. No eligible fresh case more than 10% slower than baseline.
4. No statically declined fresh case more than 5% slower than baseline.
5. Eligible routed retained-program heap no greater than twice v1 at any resource case.

Use six alternating variant-order rounds (`WITNESS_REVERSE=0/1`), 100 ms per
benchmark, Linux amd64, Go 1.26.0, GOMAXPROCS=2. Report all medians, sample counts,
paired benchstat comparisons, coverage and failed gates. An exception is an
explicit changed decision, never a silently narrowed corpus. Historical controls
are reported separately and cannot replace a fresh failure.

The routed scan is specialized for width-eight witnesses while v1 scans generic
width lanes. Therefore primary gains over v1 cannot all be attributed to the
routing tree; fanout cases and `nodes/op` provide the more relevant evidence.
The historical benchmark contains the previous five failed controls plus all
12 stress cases; historical parity covers all original 76+12 fixtures unchanged.

Compile and incremental retained-program heap are separate measurements for the
complex, shared-tail and shared-context families at all three rule counts. Baseline compilation includes YARA parsing; candidates
receive prebuilt IR. Hybrid memory retains baseline plus its candidate program;
heap deltas exclude input IR, warmed scanners, and total process RSS. Declined
routed programs report eligible=false and zero retained program bytes; their
compile allocations remain measured, and their hybrid retains only baseline. Run six
compile samples and three fresh-process heap samples, outside scan rounds.
