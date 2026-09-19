# Construction study: candidate history

Baseline: bf6c3e4af2ae8d7df70a305513caee32a6fecfbc. Frozen protocol and corpus are on research/routing-build; neither changed after measurements.

## Candidate 1: 0a521f0 (study c584cb1)

Both EPYC 7763 Linux/amd64 Go 1.26.0 runs held (35476051944, 35476082667). Startup latency geomean ratios were 0.2550 and 0.2590; allocated-byte ratios were 0.4521 in both. All activation and correctness checks passed.

Complex/256/binary scan latency increased 17.39% and 18.57%, p=.002 in both; all twelve paired samples regressed. Literal/2048/positive increased 6.28% and 9.08%. Other cases crossed the 5% limit in one run. Ordinary binary controls increased only 1.58% and 1.04%; neither execution order nor broad host slowdown explains the repeatable routing penalty.

Archived binary inspection found the routed scan methods and exact verifier retain the same instruction structure; their addresses move by 4,064 bytes, rotating placement within 64-byte cache lines by 32 bytes. Alignment sensitivity is a hypothesis, not demonstrated causation. RoutedProgram grows from 88 to 96 bytes but remains within the same Go allocation size class, with hot field offsets unchanged.

Canonical runtime plan comparisons also match for complex/256/binary, literal/2048/positive, shared-tail/2048/near and shared-context/2048/near: rules, per-word postings, tree masks/offsets/leaf order, table occupancy and node/reference counts. The binary fixture has no routing nodes or candidate hits, and all 100 events have identical probe counts. This excludes increased logical scan work in that case. See bounded-plan-old.txt, bounded-plan-new.txt and the saved diagnostic source.

## Candidate 2: e51020d (study 27092ec)

Makes the existing hash-shift range explicit with shift & 63. Nonempty tables have a power-of-two size of at least two, so all constructed shifts are in 1..63. This removes redundant negative/overshift handling from the per-word lookup without changing valid results. Linux/amd64 disassembly confirms the checks disappear. No padding or function-order tuning was applied. Complete unchanged-protocol runs 35476620637 and 35476626537 both held. Run 1 reduced the binary penalty to 9.1%, but 11 cases exceeded the 5% scan guard. Run 2 used EPYC 9V45, rather than run 1 EPYC 7763. Within that paired run, routed literal/conjunction/nocase 256-rule sparse scans regressed 46–53% (all six pairs slower, p=.002), while ordinary controls stayed nearly flat overall. Other cases stayed flat or improved, so a general host slowdown does not explain the result. The mechanism remains unproven; it also held. No gates were waived.

## Candidate 3: 1a3189d (study 53468ee)

Snapshots immutable lane metadata by value before the scan loop. Linux/amd64 disassembly confirms table pointer, length and hash shift loads move outside the per-word loop. This trades additional live registers for fewer repeated loads. Both complete unchanged-protocol paired runs held. EPYC 7763 (35476991123) retains four scan regressions of 5.8–8.1%; startup latency improves 74.5%. EPYC 9V45 (35476990941) passes all 31 selected/non-bypassed scan guards (geomean -0.27%, worst +4.02%) but fails six fallback/bypass cases by 5.3–17.1%; these largely track changes in ordinary scanning. Startup latency improves 69.8%. Both reduce allocated bytes by 54.8%. No performance gates were waived; PR #247 remains a draft.
