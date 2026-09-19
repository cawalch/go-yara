# Bounded Boolean routing construction study

Baseline: `bf6c3e4`. Candidate 1: `0a521f0`; candidate 2: `e51020d`; candidate 3: `1a3189d`.

Each run pairs old/new binaries on one Linux x86-64 host using Go 1.26.0, GOAMD64=v1, six fresh-process rounds and alternating order. The frozen corpus, budgets and acceptance gates were unchanged throughout. Startup changes are geomeans over nine first-scanner cases. Allocated bytes are cumulative Go B/op, not peak RSS.

| Candidate | CPU | Startup latency | Startup bytes | Scan failures / 44 | Result | Run |
|---|---|---:|---:|---:|---|---|
| 1 | 7763 | -74.5% | -54.8% | 3 | HOLD | [35476051944](https://github.com/cawalch/go-yara/actions/runs/35476051944) |
| 1 | 7763 | -74.1% | -54.8% | 4 | HOLD | [35476082667](https://github.com/cawalch/go-yara/actions/runs/35476082667) |
| 2 | 7763 | -74.0% | -54.8% | 11 | HOLD | [35476620637](https://github.com/cawalch/go-yara/actions/runs/35476620637) |
| 2 | 9V45 | -70.5% | -54.8% | 11 | HOLD | [35476626537](https://github.com/cawalch/go-yara/actions/runs/35476626537) |
| 3 | 7763 | -74.5% | -54.8% | 4 | HOLD | [35476991123](https://github.com/cawalch/go-yara/actions/runs/35476991123) |
| 3 | 9V45 | -69.8% | -54.8% | 6 | HOLD | [35476990941](https://github.com/cawalch/go-yara/actions/runs/35476990941) |

Final decision: **HOLD; do not merge PR #247.** Startup gains are consistent, but neither final paired run passes the complete scan guard. On 9V45 all 31 selected/non-bypassed cases pass; the six failures largely track ordinary scanning. On 7763 four active cases still regress. Further evaluation must separate algorithmic cost from binary-layout sensitivity before claiming a portable improvement.

## Scan guards

- Candidate 1, 7763, run 35476051944: `complex/rules_256/bytes_256/binary` +17.4%; `literal/rules_2048/bytes_256/positive` +6.3%; `shared_tail/rules_2048/bytes_256/positive` +5.5%.
- Candidate 1, 7763, run 35476082667: `complex/rules_256/bytes_256/binary` +18.6%; `nocase/rules_256/bytes_256/sparse` +5.1%; `literal/rules_2048/bytes_256/positive` +9.1%; `shared_context/rules_2048/bytes_256/positive` +8.4%.
- Candidate 2, 7763, run 35476620637: `complex/rules_256/bytes_256/binary` +9.1%; `conjunction/rules_256/bytes_256/sparse` +8.1%; `literal/rules_256/bytes_256/sparse` +7.9%; `nocase/rules_256/bytes_256/sparse` +8.5%; `shared_context/rules_2048/bytes_256/near` +5.9%; `shared_prefix/rules_256/bytes_256/near` +6.0%; `shared_tail/rules_2048/bytes_256/near` +6.0%; `shared_tail/rules_24/bytes_256/near` +5.8%; `shared_tail/rules_256/bytes_256/near` +5.9%; `literal/rules_2048/bytes_256/positive` +6.5%; `shared_tail/rules_2048/bytes_256/positive` +5.4%.
- Candidate 2, 9V45, run 35476626537: `conjunction/rules_256/bytes_256/shuffled` +6.4%; `conjunction/rules_256/bytes_256/sparse` +46.1%; `literal/rules_256/bytes_256/sparse` +53.3%; `nocase/rules_256/bytes_256/sparse` +45.9%; `shared_prefix/rules_256/bytes_256/near` +45.7%; `shared_tail/rules_2048/bytes_256/near` +31.2%; `shared_tail/rules_24/bytes_256/near` +33.3%; `shared_tail/rules_256/bytes_256/near` +33.0%; `complex/rules_2048/bytes_256/positive` +7.0%; `literal/rules_256/bytes_256/positive` +12.8%; `shared_tail/rules_2048/bytes_256/positive` +9.1%.
- Candidate 3, 7763, run 35476991123: `complex/rules_256/bytes_256/binary` +8.1%; `literal/rules_2048/bytes_256/positive` +5.8%; `shared_context/rules_2048/bytes_256/positive` +8.1%; `shared_tail/rules_2048/bytes_256/positive` +6.8%.
- Candidate 3, 9V45, run 35476990941: `complex/rules_24/bytes_4096/clean` +15.7%; `complex/rules_24/bytes_65536/clean` +17.0%; `complex/rules_24/bytes_65536/late` +6.4%; `mixed_short/rules_24/bytes_256/clean` +17.1%; `short1/rules_24/bytes_256/clean` +11.7%; `short1/rules_24/bytes_256/positive` +5.3%.

## Diagnosis

The construction-only candidate produced identical canonical plans in four diagnostic fixtures. The strongest original regression (complex/256/binary) had identical probe counts and no candidate verification. Hot instructions were unchanged but relocated by 4,064 bytes. Layout sensitivity is plausible, not established causation. Ordinary controls and alternating order did not explain the regressions.

Candidate 2 exposes the invariant hash-shift range, removing redundant checks. Candidate 3 additionally snapshots immutable lane metadata, hoisting three loop loads. Both are functional source optimizations, without padding or function-order tuning.

Routing remains opt-in. Logical input, conversion, hash-probe, feature and tree-work caps fall back conservatively to the existing evaluator; they are not wall-clock or total-RSS guarantees.
