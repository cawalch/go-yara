# Parity Harness (official YARA vs go-yara)

This tool runs both the official `yara` binary and the go-yara CLI against the same rules and data, diffs the matched rule names, and produces a Markdown report.

## Location
- Command: `cmd/parity`
- Output: `docs/Parity_Report.md` (default)

## Usage
From the repo root:

```bash
# Basic run over a small default set of rules and sample data
go run ./cmd/parity

# Skip rules containing regex, include directives, or module imports (recommended early on)
go run ./cmd/parity -skip-regex -skip-includes -skip-modules

# Run curated regex parity suite (maps rules/data under testdata/regex)
go run ./cmd/parity -regex-suite

# Custom rule list and data
go run ./cmd/parity -rules tmp/always_true.yar,tmp/simple_string.yar -data yara/sample.file

# Specify alternate output report and timeouts
go run ./cmd/parity -out docs/Parity_Custom.md -timeout 20s

# Point to different binaries
go run ./cmd/parity -yara-bin ./yara/yara -go-yara-cmd "go run ./cmd/main.go"
```

## What it compares
- Official YARA: runs `yara <rules> <data>` and parses matched rule names from stdout
- go-yara: runs `go run ./cmd/main.go <rules> --execute --data <data>` and parses matched rule names from the "Executing rule:" / "Result: MATCH" lines

The report shows, for each rule file:
- YARA matches (set of rule names)
- go-yara matches (set of rule names)
- Status: parity_ok, mismatch, or error: ...

## Skipping known-unsupported features
Regex parity is now supported via the internal VM and integrated CLI reporting. The curated regex suite runs with zero mismatches (see [docs/Parity_Report.md](docs/Parity_Report.md:1)). You can still use:
- `-regex-suite`: run only the curated regex parity suite in `testdata/regex` (each rule is paired to matching data)
- `-skip-includes`: skip rule files that contain `include "..."`
- `-skip-modules`: skip rule files that contain `import "..."`

Optionally include `-skip-regex` if you want to focus strictly on non-regex parity.

These checks are intentionally simple and may occasionally over/under-match; they’re sufficient for early triage.

## Output examples
- `docs/Parity_Report.md`: full matrix including regex/includes/modules
- `docs/Parity_Report_Filtered.md`: using `-skip-regex -skip-includes -skip-modules` (parity signal on core features)

## Notes and caveats
- Regex parity: The go-yara regex VM mirrors libyara semantics (leftmost-longest, FlagsScan/DOT_ALL/NO_CASE/WIDE) and is integrated into CLI reporting. The curated suite shows parity_ok across all cases.
- Includes and modules (e.g., `import "pe"`) are not yet supported in go-yara and will show as errors unless skipped.
- The harness parses text outputs. If we later add a machine-readable mode to [cmd/main.go](cmd/main.go:1) (e.g., `--json`), the harness can be updated for even stronger parsing guarantees.

