# go-yara

`go-yara` is a Go implementation of core YARA rule processing. It can parse
YARA source, validate rules, compile them to bytecode, and scan byte slices,
readers, or files through a reusable scanner API.

This project is actively evolving. It supports a broad set of YARA rule syntax,
string modifiers, expressions, rule metadata, tags, includes, and execution
features, but it is not a complete drop-in replacement for upstream YARA. In
particular, upstream YARA modules are not implemented for v1.0.

## Features

- Parse YARA rules into an AST.
- Run semantic validation and collect compiler errors or warnings.
- Compile rules to executable bytecode.
- Scan data with public APIs in `github.com/cawalch/go-yara/compiler`.
- Reuse scanners across many inputs to reduce allocations.
- Filter scans by tags and configure `itersmax` for loop-heavy rules.
- Evaluate text, hex, and regex strings, string modifiers, metadata, private and
  global rules, rule references, and common condition operators.
- Use the CLI to lex, parse, compile, or execute rules against data files.

## Compatibility

`go-yara` supports core YARA parsing, validation, compilation, and scanning for
v1.0. The public API is focused on normal rules, strings, modifiers, metadata,
tags, includes, external variables, private and global rules, and common
condition expressions.

Upstream YARA modules such as `pe`, `hash`, `math`, `elf`, and `dotnet` are
unsupported for v1.0. Rules that import modules or call module functions should
be treated as outside the supported compatibility surface.

Future JavaScript or QuickJS support may be added as an optional external
integration. QuickJS is not bundled with `go-yara` for v1.0.

## Installation

```bash
go get github.com/cawalch/go-yara
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

Legacy shorthand flags are also available:

```bash
go run ./cmd ./examples/demo_rule.yar --lex
go run ./cmd ./examples/demo_rule.yar --parse
go run ./cmd ./examples/demo_rule.yar --compile
go run ./cmd ./testdata/rules/simple_strings.yar --execute --data ./testdata/execution/test_1kb.dat
```

Advanced execute-mode streaming flags:

```bash
go run ./cmd ./testdata/rules/simple_strings.yar \
  --mode=execute \
  --data ./testdata/execution/test_1mb.dat \
  --streaming \
  --chunk-size 1048576 \
  --max-concurrency 4 \
  --early-termination
```

Streaming mode is intended for chunked large-input pattern scanning. It reports
string pattern matches only and does not evaluate rule conditions. The normal
execute path is the primary path for full rule condition results.

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

- YARA modules are not implemented; imports such as `import "pe"` and module
  function calls are outside the v1.0 compatibility target.
- Some YARA data read function variants and advanced edge cases may differ from
  upstream YARA.
- The project has explicit known-gap tests in parser and integration suites.
- The `yara/` directory is ignored by git and is not part of the public Go API.

## Testing And Development

Run the full test suite:

```bash
go test ./...
```

Run fuzz targets through the helper script:

```bash
make fuzz FUZZTIME=60s
```

Run benchmarks:

```bash
make bench
make bench PKG=./compiler
```

Useful generated benchmark and profile output is written under ignored
directories such as `benchmarks/` and `profiles/`.

## More Documentation

- [test_regression/README.md](test_regression/README.md): targeted regression
  fixture notes.
- [testdata/regex/README.md](testdata/regex/README.md): staged regex parity
  suite notes.

## Contributing

Contributions are welcome. Please keep changes focused, run the relevant tests,
and include regression coverage for behavior changes.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
