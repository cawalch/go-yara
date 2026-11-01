# Evidence allocation and ownership

`WithEvidence` returns owned capture bytes and owned result containers. Mutating
the input, scanning again, resetting a block scanner or closing a scanner does
not invalidate a retained result. Captures and findings within one result can
refer to the same capture bytes, as before. This change preserves that contract
and the existing API, capture ordering, correlation, truncation and serialized
program format.

## Storage

Each rule materialization uses fresh capture and byte chunks. The first
allocation is exact-sized. Later allocations batch up to 64 capture slots or
4,096 bytes, subject to the remaining match count; a larger individual request
gets its required size. Empty and unmatched captures keep their existing
representations. Full slice expressions prevent an append from writing into a
neighbor's storage. Public storage is never returned to a pool or reused by a
scanner. Retaining a small sub-slice can keep its enclosing chunk alive.

Only temporary occurrence records are reused. Small cases use a local 16-record
buffer. A scanner can retain up to 1,024 records, approximately 120 KiB of payload
on the measured 64-bit platform, plus allocator overhead. Larger scans use
transient overflow storage. All used records, including the retained prefix
when overflow occurs, are cleared on success, cancellation or error so they do
not retain capture bytes or result references. `Close` releases the scratch.

Correlation collects integer indices into occurrences instead of copying full
occurrence records for every anchor. Capture-only rules skip occurrence
collection and sorting because they have no correlation plan. Capture VM scratch,
streaming input, output bytes and caller-retained results retain their separate
lifetimes; the scratch limit is not a bound on total scan memory.

## Measurements

[Raw samples](evidence_ownership_samples.json) compare main `43eacc3` with this
change: Go 1.27.3, darwin/arm64 Apple M3 Max, `GOMAXPROCS=1`, six alternating
process pairs. No task tests ran during timing; the machine was shared. These
are complete scans with public result materialization, not helper-only timings.

| Workload | Bytes/scan, before → after | Allocations, before → after | Median time, before → after |
|---|---:|---:|---:|
| Original match-heavy evidence benchmark | 700,677 → 449,198 | 2,075 → 1,053 | 665 → 606 µs |
| Three captures with correlation, 512 matches | 1,396,912 → 981,232 | 2,078 → 1,073 | 1,002 → 1,001 µs |
| Three captures without correlation, 512 matches | 865,312 → 238,688 | 1,041 → 40 | 795 → 608 µs |
| Reader, 128 matches | 448,856 → 292,152 | 700 → 446 | 858 → 838 µs |
| Block, 128 matches | 393,376 → 236,672 | 552 → 298 | 247 → 237 µs |

Small, sparse-optional and large-single-capture cases kept their allocation
counts and bytes. Truncated/empty correlated cases used about 30% fewer bytes
and 48% fewer allocations, with 0.9–1.3% higher median times. Unchanged
without-evidence controls also timed faster, so the timing differences should
not all be attributed to this change. The main evidence result is a 36% byte and
49% allocation reduction, not the broader issue's proposed 80% reduction.
Per-finding mutable maps remain result-owned allocations.

A separate cold/retention measurement held six result sets while reusing one
scanner. At 512 matches, cold allocation fell from 728,832 to 604,016 bytes;
retained heap before `Close` increased by about 66 KiB from reusable scratch,
then was essentially equal after `Close` (2.865 MB). At 2,048 matches the analogous
scratch increase was about 125 KiB. These measurements include process/runtime
state; they are not isolated verifier-memory figures. Raw heap and RSS values
are included in the receipt.

Reproduce the scan measurements on both revisions using the same benchmark
source, alternating execution order:

```sh
GOMAXPROCS=1 go test ./compiler -run '^$' -bench '^BenchmarkEvidence(ScanPaths|Ownership)$' -benchmem -benchtime=200ms -count=6
```

Ownership tests retain results through buffer, reader, file and block lifetimes,
input mutation, reload, reset, close and concurrent result reads during scanner
reuse. They also exercise appends at chunk boundaries, empty/truncated captures,
bounded scratch and error cleanup. Seeded external comparisons matched the full
public baseline output for 1,000 cases / 4,000 scans per build; these compare the
existing Go evidence extension, not a libyara capture API. Existing correlation
and serialization fuzzers supplement that comparison.
