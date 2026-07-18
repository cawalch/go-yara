# go-yara

`go-yara` is a Go implementation of core YARA rule processing. It can parse
YARA source, validate rules, compile them to bytecode, and scan byte slices,
readers, or files through a reusable scanner API.

This project is actively evolving. It supports a broad set of YARA rule syntax,
string modifiers, expressions, rule metadata, tags, includes, and execution
features, but it is not a complete drop-in replacement for upstream YARA.

## Features

- Parse YARA rules into an AST.
- Run semantic validation and collect compiler errors or warnings.
- Compile rules to executable bytecode.
- Scan data with public APIs in `github.com/cawalch/go-yara/compiler`.
- Reuse scanners across many inputs to reduce allocations.
- Compile valid rules from partially invalid rule sets with structured omitted-
  rule diagnostics.
- Use conservative fast-scan retention without changing count-, offset-, or
  range-sensitive rule results.
- Scan sparse or non-contiguous address spaces incrementally with a block
  scanner that still evaluates full rule conditions.
- Import built-in `hash` and `math` modules or register typed custom modules.
- Cache compiled programs in a versioned binary format while retaining regex,
  hex, and shared-prefilter optimizations.
- Inspect direct rule dependencies and dependents.
- Filter scans by tags and configure `itersmax` for loop-heavy rules.
- Evaluate text, hex, and regex strings, string modifiers, metadata, private and
  global rules, rule references, and common condition operators.
- Use the CLI to lex, parse, compile, or execute rules against data files.

## Compatibility

`go-yara` supports core YARA parsing, validation, compilation, and scanning.
The public API is focused on normal rules, strings, modifiers, metadata, tags,
includes, external variables, private and global rules, and common condition
expressions.

The built-in `hash` module provides `md5`, `sha1`, and `sha256`; the built-in
`math` module provides `entropy`, `mean`, and `deviation`. Each accepts the
YARA-compatible forms implemented by the typed module registry. Other upstream
module object models such as `pe`, `elf`, and `dotnet` are not yet implemented.

## Installation

```bash
go get github.com/cawalch/go-yara/compiler
```

The module currently declares Go `1.26.0` in [go.mod](go.mod).

## Library Usage

Use the exported `compiler` package for normal rule compilation and scanning.
Do not import packages under `internal/`; those are implementation details and
cannot be imported by external modules.

### Compile And Scan Bytes

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/cawalch/go-yara/compiler"
)

func main() {
	source := `rule MalwareString {
    strings:
        $a = "malware" nocase
    condition:
        $a
}`

	c := compiler.NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		log.Fatalf("compile failed: %v", err)
	}

	result, err := program.Scan([]byte("sample contains MALWARE marker"))
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}

	for _, match := range result.MatchedRules {
		fmt.Println(match.Rule)
	}
}
```

### Compile And Scan Files

```go
func scanFile(ctx context.Context, ruleFile, dataFile string) error {
	c := compiler.NewCompiler()
	program, err := c.CompileFileWithContext(ctx, ruleFile)
	if err != nil {
		return err
	}

	result, err := program.ScanFile(dataFile)
	if err != nil {
		return err
	}

	for _, rule := range result.MatchedRules {
		fmt.Printf("%s matched with tags %v\n", rule.Rule, rule.Tags)
	}

	return nil
}
```

### Reuse A Scanner

Create a scanner when you want to scan many inputs with the same compiled
program.

```go
func scanMany(program *compiler.CompiledProgram, samples ...[]byte) error {
	scanner := compiler.NewScanner(
		program,
		compiler.WithTagsFilter([]string{"malware", "triage"}),
		compiler.WithItersmax(100000),
	)
	defer scanner.Close()

	for _, sample := range samples {
		result, err := scanner.Scan(sample)
		if err != nil {
			return err
		}

		fmt.Println(len(result.MatchedRules))
	}

	return nil
}
```

### Set External Variables

Rules can declare runtime-provided values with `external`. Set those values on
the compiled program for one-shot scans, or on a reusable scanner.

```go
program, err := compiler.NewCompiler().CompileSourceWithContext(ctx, `
external gate
external marker
rule gated { condition: gate and marker == "needle" }
`)
if err != nil {
	return err
}

if err := program.SetExternalVariables(map[string]any{
	"gate":   true,
	"marker": "needle",
}); err != nil {
	return err
}

result, err := program.Scan(data)
```

For reusable scanners, pass `compiler.WithExternalVariables(...)` to
`compiler.NewScanner` or call `scanner.SetExternalVariables(...)` between
scans.

`ScanResult` includes:

- `MatchedRules`: public, matched rules with tags, metadata, and public string
  matches.
- `RuleResults`: boolean condition results for evaluated rules.
- `Matches`: per-rule string matches keyed by rule name and string identifier.

Pass `compiler.WithReportedMatchesOnly()` to a reusable scanner when only
public matching rules need entries in `Matches`; `RuleResults` is unaffected.

Pass `compiler.WithFastScan()` when only the first occurrence of each string is
needed. The compiler marks rules whose conditions inspect occurrence counts,
offsets, lengths, or constrained ranges as ineligible and automatically keeps
all of their matches, preserving condition results.

### Compile Around Invalid Rules

Strict compilation remains the default. For bulk rule feeds where one bad rule
should not reject unrelated valid rules, opt into resilient compilation:

```go
c := compiler.NewCompiler(compiler.WithIgnoreInvalidRules(true))
program, err := c.CompileSourceWithContext(ctx, source)
if err != nil {
	return err // program-level errors still fail compilation
}

for _, ignored := range c.GetIgnoredRules() {
	fmt.Printf("ignored %s during %s: %s\n",
		ignored.Rule, ignored.Phase, ignored.Message)
}
```

Rules that depend on an omitted rule are omitted transitively. An omitted
`global` rule also omits every remaining rule because silently dropping its
gate would change program semantics.

Compiler warnings have stable `Code`, `Phase`, `Rule`, `String`, `Line`, and
`Column` fields. Current warning codes include `unused-string`,
`missing-condition`, `trivial-condition`, `duplicate-pattern`, and
`slow-pattern`.

### Modules

Rules can import the built-in `hash` and `math` modules directly:

```go
program, err := compiler.NewCompiler().CompileSourceWithContext(ctx, `
import "hash"
import "math"
rule measured {
    condition:
        hash.sha256("abc") ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" and
        math.mean(0, filesize) >= 0.0
}
`)
```

Register an application module with `compiler.WithModule`. Each
`ModuleFunction` declares accepted typed signatures, its return type, and an
`Evaluate` callback. The callback receives immutable scan data, sparse blocks
when applicable, and the current rule name. Imported module functions execute
inside the scan call, so callbacks should be deterministic, bounded, and safe
for the caller's scanner concurrency model.

### Scan Non-Contiguous Blocks

`BlockScanner` accumulates matches at logical addresses and evaluates rule
conditions once `Finish` is called:

```go
scanner := program.NewBlockScanner(compiler.WithFastScan())
defer scanner.Close()

if err := scanner.SetFileSize(logicalSize); err != nil {
	return err
}
if err := scanner.Scan(0x1000, firstBlock); err != nil {
	return err
}
if err := scanner.Scan(0x8000, secondBlock); err != nil {
	return err
}
result, err := scanner.Finish()
```

Blocks may be sparse or overlapping. Overlapping bytes must be consistent.
Matches that cross a block boundary require the caller to provide overlapping
block data; the scanner does not invent bytes for address gaps. Match offsets
are absolute logical offsets, and `Match.Base` records the supplying block.

This differs from pattern-only streaming through `EnableStreaming`: streaming
reports chunked pattern matches, while `BlockScanner.Finish` evaluates complete
rule conditions.

### Cache Compiled Programs

Compiled programs can be stored and loaded without parsing and code generation:

```go
encoded, err := program.MarshalBinary()
if err != nil {
	return err
}

loaded, err := compiler.UnmarshalCompiledProgram(encoded)
```

Use `WriteTo` and `ReadCompiledProgram` for `io.Writer` and `io.Reader` flows.
The format has a magic header and explicit version and rejects incompatible or
truncated data. It preserves compiled pattern and prefilter plans. Runtime
external-variable values are intentionally not serialized and must be set on
the loaded program or scanner. When a compiler was configured with custom
modules, pass those modules again while loading so callbacks can be rebound:

```go
loaded, err := compiler.UnmarshalCompiledProgram(encoded, customModule)
```

Treat compiled blobs as trusted cache artifacts; the decoder is not an
authentication or sandbox boundary.

### Inspect Rule Dependencies

The compiled program exposes direct dependency data:

```go
dependencies := program.RuleDependencies("child")
dependents := program.RuleDependents("base")
graph := program.DependencyGraph()
```

Returned slices and maps are copies and can be modified by the caller.

Rules with mandatory fixed-offset checks such as `uint32(0) == 0x464c457f` or
`$magic at 0` are pruned before their general pattern search when the check is
false. `ScanResult.PrunedRules` exposes which rules took this path. Constraint
derivation is conservative across boolean expressions and does not change rule
semantics.

### Diagnostics And Heuristic Metrics

The compiler exposes diagnostic helpers such as `GetStats`,
`GetMemoryUsage`, `GetTotalMemoryUsage`, `EstimateComplexity`, and
`EstimatePatternComplexity`. These are deterministic project-level metrics for
debugging, relative sizing, and tests. They are not exact measurements of Go
heap usage or scan/runtime cost.

## Command-Line Usage

The CLI expects the YARA file as the first positional argument, followed by
options.

```bash
# Compile rules. This is the default mode.
go run ./cmd ./examples/demo_rule.yar --mode=compile

# Show lexer tokens.
go run ./cmd ./examples/demo_rule.yar --mode=lex

# Parse and summarize the AST.
go run ./cmd ./examples/demo_rule.yar --mode=parse

# Execute rules against a data file.
go run ./cmd ./testdata/rules/simple_strings.yar --mode=execute --data ./testdata/execution/test_1kb.dat
```

Advanced execute-mode streaming flags:

```bash
go run ./cmd ./testdata/rules/simple_strings.yar \
  --mode=execute \
  --data ./testdata/execution/test_1mb.dat \
  --streaming \
  --chunk-size 1048576 \
  --early-termination
```

Streaming mode is intended for chunked large-input pattern scanning. It reports
literal text-pattern matches only; regex and hex patterns are not included, and
rule conditions are not evaluated. The normal execute path is the primary path
for full rule condition results.

## Repository Layout

- `compiler/`: compilation pipeline, bytecode, scanner, interpreter, string
  matching, and streaming support.
- `parser/`: YARA parser.
- `semantic/`: semantic validation and type checks.
- `ast/`: AST nodes, builder, and visitors.
- `regex/`: in-repo YARA-compatible regex engine.
- `token/`: public token types.
- `internal/lexer/`: lexer implementation used by parser and compiler.
- `cmd/`: command-line entry point.
- `examples/`, `testdata/`, `test_regression/`: sample rules, data, and
  regression fixtures.

## Known Limitations

- Structured upstream module object models such as `pe`, `elf`, and `dotnet`
  are not implemented. The current module registry exposes typed functions.
- Block scanning requires caller-provided overlap for patterns that cross block
  boundaries.
- Some YARA data read function variants and advanced edge cases may differ from
  upstream YARA.

## Testing And Development

Run the complete local validation gate:

```bash
make check
```

Use `make test` or `go test ./...` when only the test suite is needed.

Run fuzz targets through the helper script:

```bash
make fuzz FUZZTIME=60s
```

Run benchmarks:

```bash
make bench
make bench PKG=./compiler
make bench-scan
make bench-prefilter-scale
make bench-single-rule-size
make profile-scan
make trace-scan
```

Generated output is written under ignored directories such as `benchmarks/`
and `profiles/`. The suites cover repeated and unique patterns, prefilter
scaling, and several input sizes.

## More Documentation

- [test_regression/README.md](test_regression/README.md): targeted regression
  fixture notes.
- [testdata/performance/README.md](testdata/performance/README.md): tracked and
  generated benchmark inputs.
- [testdata/regex/README.md](testdata/regex/README.md): regex parity fixture
  notes.

## Contributing

Contributions are welcome. Please keep changes focused, run the relevant tests,
and include regression coverage for behavior changes.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
