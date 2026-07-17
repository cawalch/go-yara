# go-yara vs yara-x benchmark tournament

This suite measures the same rules and deterministic payloads through go-yara
and yara-x. Its north-star metric is the per-cell throughput ratio:

```text
ratio = go-yara MB/s / yara-x MB/s
```

The matrix has 180 cells: 15 rule shapes, four punctuation/match-density
profiles, and 16 KiB, 256 KiB, and 1 MiB inputs. It retains the rule shapes
from issues #160, #162, #164, #167, #169, #171, and #173, plus a realistic
combined skimmer ruleset and a literal-string control.

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

## Optional local baseline

Throughput measurements and baselines are intentionally not checked in or used
as a required CI gate. Repeated runs of unchanged code showed that shared CI
hosts introduce enough per-cell variance to make that gate misleading. The
tournament is a diagnostic tool for finding and validating actual performance
work. Every tournament run still rejects engine disagreements in matched-rule
count or identity, while normal Go tests cover the matrix and report logic.

The default run warns for every cell below 0.5x yara-x and reports the geomean
ratio. To create an ignored, machine-local baseline after reviewing a complete
run:

```bash
make bench-vs-yarax-update-baseline
```

Subsequent runs on that exact GOOS, architecture, and CPU compare against the
local baseline and fail when a ratio regresses by more than 25%. Use
`TOURNAMENT_BASELINE=/path/to/baseline.csv` to keep a baseline elsewhere. Both
the generated reports and default local baseline are ignored by Git.
