# go-yara vs yara-x benchmark tournament

This suite measures the same rules and deterministic payloads through go-yara
and yara-x. Its north-star metric is the per-cell throughput ratio:

```text
ratio = go-yara MB/s / yara-x MB/s
```

The matrix has 180 cells: 15 rule shapes, four punctuation/match-density
profiles, and 16 KiB, 256 KiB, and 1 MiB inputs. It includes permanent guards
for the performance failures from issues #160, #162, #164, #167, #169, #171,
and #173, plus a realistic combined skimmer ruleset and a literal-string
control.

## Methodology

- Rules are compiled once per rule case.
- One scanner is reused across all timed scans for that rule case.
- Each engine receives source and payload bytes from the same canonical matrix.
- go-yara is built with `CGO_ENABLED=0`.
- yara-x is built with `CGO_ENABLED=1` because its Go binding uses the C API.
- The runner reports MB/s, B/op, allocs/op, and matching public rules.
- The comparison rejects a cell when the engines disagree on matching rule
  count or the fingerprint of the actual public rule names.
- Three repetitions are reduced to the median for each engine and cell.

The two-engine runner design is deliberate: yara-x's Go binding is CGO-based,
so it cannot coexist in the `CGO_ENABLED=0` go-yara benchmark binary. The
yara-x binding and its dependencies live in a nested module and do not affect
the production go-yara module.

## Run locally

Install yara-x 1.19.0 and `pkg-config`. On macOS:

```bash
brew install pkgconf yara-x
```

The runner verifies that both the installed C API and pinned Go binding are
exactly version 1.19.0. This makes a Homebrew formula update fail explicitly
instead of silently changing the comparison engine and invalidating the
baseline.

Run the tournament:

```bash
make bench-vs-yarax
```

For a focused diagnostic run, use the standard Go benchmark name filter:

```bash
BENCH_REGEX='^BenchmarkTournament/combined_skimmer_regex/.*/1MiB$' \
  make bench-vs-yarax BENCHTIME=250ms BENCHCOUNT=5
```

Generated raw output, CSV, and Markdown reports are written under
`performance/tournament/results/` and ignored by Git.

## Baseline and policy

The suite keeps separate versioned baselines for the exact CPUs that run it:

- `baseline.csv` is the Apple M3 Max developer baseline;
- `baseline-ci.csv` is the GitHub `macos-15` Apple M1 virtual-runner baseline.

The reporter rejects a baseline unless its GOOS, architecture, and CPU metadata
exactly match both benchmark runs. Ratios remove much same-host noise, but they
are not invariant across CPU microarchitectures; comparing an M3 measurement to
an M1 baseline can otherwise create false regressions in individual cells.

The default policy:

- warns for every cell below 0.5x yara-x;
- fails if a cell's ratio regresses by more than 25% from its baseline;
- reports the geomean ratio across the full matrix as an informational trend.

The ratio is used for gating because both engines run back-to-back on the same
host. Absolute MB/s remains in the report for diagnosis. Update the baseline
only after reviewing the full report and confirming the change is intentional:

```bash
make bench-vs-yarax-update-baseline
```

To compare against or update another platform baseline, select it explicitly:

```bash
TOURNAMENT_BASELINE=performance/tournament/baseline-ci.csv \
  make bench-vs-yarax

TOURNAMENT_BASELINE=performance/tournament/baseline-ci.csv \
  make bench-vs-yarax-update-baseline
```

CI runs the tournament on the GitHub `macos-15` arm64 image, uploads all report
files, selects `baseline-ci.csv`, and includes its result in the repository
quality gate.
