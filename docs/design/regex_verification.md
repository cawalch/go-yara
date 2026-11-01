# Regex occurrence selection and verification reuse

Occurrence selection is a compatibility contract, separate from candidate
acceleration. `regex_verification_plan.go` selects canonical atoms and splits
forward/backward programs. Literal and byte-set prefilters can reduce candidate
work, but cannot replace canonical atom identity or event order.

## Selection contract

- Forward programs preserve the emitted entries of optional repeats. Atomless
  and proven match-start programs use `CompileForward`; consuming backward
  prefixes retain their existing lowering. Capture replay uses the corresponding
  tagged compiler and the selected outer span.
- `verificationAtomOrder` orders canonical events by atom end, width, identity,
  case variant and encoding. `addBoundedRegexVerifications` retains the winning
  accepted occurrence for each start, then emits starts in ascending order.
  Fullword and explicit span caps are applied before an occurrence can win.
- `ExecVerifyBatchWithCancel` has a 4,096-byte directional budget measured from
  the atom. Assertions still see physical input boundaries. Backward verification
  collects starts; forward verification selects its priority endpoint. This is
  not a universal whole-match or streaming-retention bound.
- Format 18 persists match-start alternative dispatch. Historical artifacts keep
  their compiled entries and policy flags. The reuse changes below do not alter
  bytecode, serialized policy, streaming horizons or historical results.

## Bounded reuse of failed states

Ordinary batched matching can opt into `VMBatch.EnableFailureReuse`. The compiler
uses this only for unbounded programs of at most 64 bytecode bytes without a
bounded-alternation specialization or an explicit match-span cap. Candidate
selection and all existing specialized paths remain in place.

One expensive unsuccessful attempt (at least 128 VM steps) arms recording. The
next attempt records a 64-bit consuming-state mask at each visited byte position.
Only a completed unsuccessful attempt publishes this trace. Successful or
canceled recording is discarded. A later attempt can stop its remaining threads
only when **every** live consuming state belongs to the failed mask at that
position; any already accepted endpoint is retained by the ordinary VM.

This is a reachability proof, not endpoint memoization: no state in a wholly
unsuccessful attempt can reach an accepting state under the same code, flags and
remaining input. There is no acceptance-driven priority pruning in that failed
attempt. Recording only consuming states also permits removing an input prefix:
after consuming, future assertions see the same bytes and physical end. Different
input ends, code identities or flags invalidate the trace. Code and input must
remain immutable within the opt-in scope; `Prepare` and `Release` reset it.

Recording starts only on inputs of 128–4,096 bytes. A ready trace can serve a
shorter suffix. Scratch is at most 4,096 masks (32 KiB) for the one VM batch owned
by a match context, and is lazily allocated and pooled. There is no per-candidate
or per-atom cache. Larger programs/inputs use the existing VM; budgeted forward
and backward verification never consult these masks because their limits move
with the atom. Cancellation checks remain ahead of cache queries and partial
recording cannot become a proof.

The cache's scratch bound excludes existing VM thread buffers, retained streaming
input, result/evidence storage and concurrent scanners. Those retain their
existing lifetimes and may grow independently. No constant-total-memory claim is
made.

## Skipping already outranked atoms

For greedy format-18 match-start plans, the atom position is the match start.
Once a valid occurrence is retained there, a later atom whose canonical order
is strictly lower cannot replace it. It can be skipped before verification,
without allocating additional state. Equal priority is not skipped. Lazy plans
and consuming backward prefixes retain their existing execution order.

## Validation and reproduction

`TestFailureReuse*` checks ordinary-VM equivalence, cache identity/reset, scratch
bounds, canceled calls, and mixed failed/live frontiers. The libyara scan matrix
covers complete occurrences, rule counts and lengths, reload, scanner reuse,
ASCII/wide/fullword/nocase, buffer/file/block/readers and fast/compact modes.
Genuine historical fixtures remain in the serialization suite.

Run the complete-scan benchmark at each revision with the same Go version and
machine, alternating revision order and retaining raw samples:

```sh
GOMAXPROCS=1 go test ./compiler -run '^$' -bench '^BenchmarkRegexVerificationReuse$' -benchmem -count=6
```

It includes negative, successful, lazy and already-outranked-atom workloads at
128, 512, 4,096 and 4,097 repetitions. Compilation is outside scan timing; full
result materialization is included. Larger positive workloads can be expensive
for a libyara callback oracle and must not be called parity-verified if that
oracle times out.

## Measured decision (2026-11-01)

Adopt failed-state reuse on the eligible ordinary VM path and greedy
already-outranked-atom pruning. Reject applying that pruning to lazy plans in this
change: the screen showed 7–14% overhead on one cheap lazy alternative, with
inconsistent benefit elsewhere. Broad backward memoization, another interpreter
and global cache/dispatch replacement are not part of this adoption.

The [raw receipt](regex_verification_samples.json) contains
exact inputs, complete-scan samples, compile time, artifact size, allocations,
process heap/RSS, a larger literal-control audit and separate cold allocations.
Baseline is `cb6f34a` (merged #432), Go 1.27.3, darwin/arm64 Apple M3 Max,
`GOMAXPROCS=1`, six alternating pairs with a fresh process per case/variant.
No task test jobs ran during timing; other shared-host contention was uncontrolled.
Every measured case passed the pinned libyara 4.5.8 exact callback oracle.

| Complete scan | Baseline median | Candidate median | Change |
|---|---:|---:|---:|
| `a.*b`, `a` × 512, absent `b` | 2.718 ms | 0.075 ms | −97.2% |
| Same, 4,096 bytes | 170.641 ms | 0.643 ms | −99.6% |
| Same, 4,097 bytes | 170.631 ms | 2.044 ms | −98.8% |
| Same, 8,192 bytes | 521.112 ms | 352.904 ms | −32.3% |
| `(xy\|x)(a?.)+`, `xy` + `a!` × 512 | 35.849 µs | 17.822 µs | −50.3% |
| `a+b`, `a` × 512 + `b` | 2.705 ms | 2.736 ms | +1.1% |
| `(ab\|aba)+?`, `ab` × 512 | 154.580 µs | 154.528 µs | approximately unchanged |

The 8,192-byte case still performs ordinary distance-limited verification until
its remaining windows become eligible; it is not evidence for an unbounded
cache. Other successful controls were within about 2.2%, reflecting the small
cost of the reuse hooks; no universal speedup is claimed. Literal-only timings
were bimodal in both builds. A larger 100-sample-per-build audit reversed the
initial apparent slowdown (candidate mean −2.8%, median −0.9%); the cause of the
two timing bands was not established.

Warm allocations and serialized sizes were unchanged in all measured cases.
The first negative scan adds 4,112 bytes at input size 512, or 32,784 bytes at
size 4,096: one mask allocation plus 16 bytes of VM-state overhead. Successful
and unsupported controls added only that 16-byte cold overhead. At size 4,096,
process heap-in-use rose by 32 KiB; RSS high-water measurements fluctuated at
roughly 8.1 MB and do not isolate verifier memory. Compile samples are recorded,
but compilation code is unchanged and no compile-time improvement is claimed.

The earlier screen's large dense positive oracle request timed out and was
excluded. The final measured set uses bounded positive controls and separately
checks negative inputs across the dispatch boundary. The permanent Go benchmark
also exposes larger positive workloads for future measurement, without claiming
that those extra sizes were oracle-qualified here.
