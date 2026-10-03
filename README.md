# go-yara

`go-yara` is a native Go implementation of YARA rule parsing, compilation, and scanning. It converts YARA source rules into executable bytecode and evaluates them against byte slices, streams, and files through an allocation-conscious scanner API.

`go-yara` supports core YARA rule syntax, string modifiers, expressions, metadata, tags, includes, and external variables. It provides high-performance scanning through conservative literal prefiltering, rule pruning, and compiled program serialization.

## Features

- **AST and parsing**: Parse YARA source into a structured abstract syntax tree (AST).
- **Semantic analysis**: Validate rule semantics and emit structured errors and warnings.
- **Bytecode compilation**: Compile valid rules to executable bytecode.
- **Resilient compilation**: Optionally compile valid rules from rule sets containing syntax or semantic errors, while collecting omitted-rule diagnostics.
- **Prefiltering and fast rejection**: Reject clean inputs using a conservative mandatory-literal prefilter before executing rule bytecode, achieving zero heap allocations on clean inputs after warm-up.
- **Rule pruning**: Prune rules with failing fixed-offset assertions (such as `$magic at 0` or `uint32(0) == 0x464c457f`) before scanning strings.
- **Optimized scanning modes**:
  - Reusable scanners with pooled state across repeated evaluations.
  - Boolean evaluation (`Matches`) for clean-input short-circuiting.
  - Compact matching (`MatchingRules`) to return matched rules without allocating full per-rule condition tables.
  - First-occurrence matching (`WithFastScan`) with automatic retention for rules that depend on counts or offsets.
- **Non-contiguous block scanning**: Incrementally scan sparse or overlapping memory blocks with absolute logical offsets and evaluate full rule conditions.
- **Extensible modules**: Import built-in `hash` and `math` modules or register typed custom Go modules.
- **Cache serialization**: Save and load compiled programs using a versioned binary format that preserves prefilter plans and regex state.
- **Dependency analysis**: Inspect direct rule dependencies, dependents, and full dependency graphs.
- **Secret extraction**: Extract structured capture spans and correlate credential candidates using the `capture(...)` and `evidence:` syntax extensions.
- **Command-line tool**: Lex, parse, compile, or execute rules against data files with optional streaming.

## Compatibility

`go-yara` supports core YARA parsing, validation, compilation, and scanning features:

- Text, hexadecimal, and regular expression pattern strings.
- String modifiers: `nocase`, `wide`, `ascii`, `fullword`, `xor`, `base64`, `base64wide`, and `private`.
- Rule metadata, tags, include directives, and external variables.
- Private rules, global rules, and inter-rule condition references.
- Arithmetic, bitwise, comparison, logical, and range operators.
- String count (`#`), length (`!`), offset (`@`), and occurrence (`at`, `in`) operators.
- For-loop iteration expressions over integer ranges and string sets (`them`, `$*`, `$a*`).
- Built-in modules:
  - `hash`: provides `md5`, `sha1`, and `sha256`.
  - `math`: provides `entropy`, `mean`, and `deviation`.

> [!NOTE]
> Structured upstream module object models such as `pe`, `elf`, and `dotnet` are not yet implemented. If your rules require custom functions, you can register typed Go callbacks using the module API.

## Requirements and installation

`go-yara` requires **Go 1.26.0** or later.

To add `go-yara` to your Go module, run:

```bash
go get github.com/cawalch/go-yara/compiler
```

> [!IMPORTANT]
> Import only the public packages (such as `compiler`, `parser`, `ast`, and `token`). Do not import packages under `internal/`, as their APIs are unstable and subject to change without notice.

## Quickstart

The following example compiles a YARA rule from a string and scans a byte slice:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/cawalch/go-yara/compiler"
)

func main() {
	source := `
rule DetectMalware {
    strings:
        $text = "malware-sample" nocase
    condition:
        $text
}`

	// 1. Create a compiler and compile the rule source.
	c := compiler.NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		log.Fatalf("Compilation failed: %v", err)
	}

	// 2. Scan an input byte slice.
	result, err := program.Scan([]byte("Payload contains MALWARE-SAMPLE signature."))
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// 3. Inspect matching rules.
	for _, match := range result.MatchedRules {
		fmt.Printf("Matched rule: %s\n", match.Rule)
	}
}
```

## Library usage

The primary entry point for rule compilation and execution is the `compiler` package.

### Compile and scan byte slices

Use `CompileSourceWithContext` or `CompileSource` to compile rules from an in-memory string:

```go
c := compiler.NewCompiler()
program, err := c.CompileSourceWithContext(ctx, ruleSource)
if err != nil {
	return err
}

result, err := program.Scan(data)
if err != nil {
	return err
}

for _, match := range result.MatchedRules {
	fmt.Printf("Rule %s matched\n", match.Rule)
}
```

### Compile and scan files

Use `CompileFileWithContext` to compile a rule file from disk, resolving any relative `include` directives against the parent directory:

```go
c := compiler.NewCompiler()
program, err := c.CompileFileWithContext(ctx, "rules/index.yar")
if err != nil {
	return err
}

result, err := program.ScanFile("samples/target.bin")
if err != nil {
	return err
}

for _, match := range result.MatchedRules {
	fmt.Printf("Rule: %s, Tags: %v\n", match.Rule, match.Tags)
}
```

### Reuse a scanner across multiple inputs

Creating a new scanner for each input incurs unnecessary allocations. When scanning multiple inputs against the same ruleset, create a reusable `Scanner`:

```go
func scanBatch(program *compiler.CompiledProgram, samples [][]byte) error {
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
		fmt.Printf("Matched rules count: %d\n", len(result.MatchedRules))
	}
	return nil
}
```

### Scan result types and evaluation modes

The `Scan` method returns a `ScanResult` struct containing:

- `MatchedRules`: Public rules that matched the input, including tags, metadata, and matched string details.
- `RuleResults`: A boolean lookup map containing condition evaluation results for all evaluated rules.
- `Matches`: Per-rule string matches keyed by rule name and string identifier.
- `PrunedRules`: Names of rules skipped early due to failing fixed-offset checks.

You can customize scanner evaluation behavior using functional options:

- **Compact matches (`WithReportedMatchesOnly`)**: Omits string match details for non-matching rules, reducing allocation overhead.
- **Fast scan (`WithFastScan`)**: Halts pattern matching after finding the first occurrence of each string. The compiler automatically disables fast-scan for rules whose conditions depend on match counts, offsets, or ranges, preserving exact condition semantics.

#### Boolean-only matching

If you only need to determine whether any rule in the program matched, use `scanner.Matches(data)`:

```go
hasMatch, err := scanner.Matches(data)
if err != nil {
	return err
}
if hasMatch {
	fmt.Println("At least one rule matched the input.")
}
```

When all evaluated rules require at least one string match and the shared prefilter finds no candidates, `Matches` returns `false` before running any bytecode. After scanner warm-up, this clean-input path performs zero heap allocations.

#### Matched-rules filtering

If you need details for matching rules without allocating complete condition tables for non-matching rules, use `scanner.MatchingRules(data)`:

```go
matches, err := scanner.MatchingRules(data)
if err != nil {
	return err
}
for _, match := range matches {
	fmt.Printf("Matched: %s (Tags: %v)\n", match.Rule, match.Tags)
}
```

`MatchingRules` evaluates rules using the same prefilter candidate path as `Matches`, returning caller-owned `RuleMatch` structs while avoiding `ScanResult.RuleResults` map allocations.

### Configure external variables

Rules can reference runtime values defined with the `external` keyword:

```yara
external is_production
external environment_name

rule EnvironmentGate {
    condition:
        is_production and environment_name == "staging"
}
```

You can set external variable values directly on the compiled program or on a reusable scanner:

```go
// Set variables on a compiled program:
err := program.SetExternalVariables(map[string]any{
	"is_production":    true,
	"environment_name": "staging",
})
if err != nil {
	return err
}

// Or configure them when constructing a reusable scanner:
scanner := compiler.NewScanner(
	program,
	compiler.WithExternalVariables(map[string]any{
		"is_production":    true,
		"environment_name": "staging",
	}),
)
defer scanner.Close()

// You can also update external variables between scans:
err = scanner.SetExternalVariables(map[string]any{
	"environment_name": "production",
})
```

### Extract structured secret evidence

`go-yara` extends standard YARA with `capture(...)` and `evidence:` declarations. This extension extracts structured submatch spans (such as credentials, API keys, or endpoints) without altering the rule's boolean condition:

```yara
rule DatabaseConnectionSecret {
    strings:
        $uri = /postgres:\/\/([^: ]+):([^@ ]+)@([^\/ ]+)/
            capture(username = 1, secret = 2, endpoint = 3)
    evidence:
        credential = (endpoint, username, secret) within 4KB of secret
    condition:
        $uri
}
```

To extract evidence, enable it on a scanner by providing an explicit per-capture byte limit:

```go
scanner := program.NewScanner(compiler.WithEvidence(4096))
defer scanner.Close()

result, err := scanner.Scan(data)
if err != nil {
	return err
}

findings := result.Evidence["DatabaseConnectionSecret"]["credential"]
for _, finding := range findings {
	if finding.Status == compiler.EvidenceStatusReady {
		fmt.Printf("Endpoint: %s, User: %s, Secret: %s\n",
			finding.Fields["endpoint"].Data,
			finding.Fields["username"].Data,
			finding.Fields["secret"].Data,
		)
	}
}
```

- Capture group `0` represents the full pattern match. Positive numbers correspond to parenthesized regex groups numbered from left to right.
- `Capture.Data` contains copied raw bytes from the source. The application remains responsible for unescaping, URL decoding, and credential verification.
- Capture extraction retains all candidate occurrences even when using `WithFastScan`.

### Tolerate invalid rules during compilation

By default, compilation fails if any rule contains a syntax or semantic error. For large rule feeds where invalid rules should not prevent valid rules from compiling, enable resilient compilation:

```go
c := compiler.NewCompiler(compiler.WithIgnoreInvalidRules(true))
program, err := c.CompileSourceWithContext(ctx, ruleSet)
if err != nil {
	// Program-level errors (such as fatal parser failures) still return an error.
	return err
}

// Inspect omitted rules and diagnostics:
for _, ignored := range c.GetIgnoredRules() {
	fmt.Printf("Omitted rule %s in phase %s: %s\n",
		ignored.Rule, ignored.Phase, ignored.Message)
}
```

> [!NOTE]
> Rules that reference an omitted rule are transitively omitted. If an omitted rule is declared `global`, all subsequent rules are also omitted to prevent unintended matching behavior.

### Use built-in and custom modules

Rules can import the built-in `hash` and `math` modules:

```yara
import "hash"
import "math"

rule ModuleDemo {
    condition:
        hash.sha256("test-input") == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" and
        math.mean(0, filesize) >= 0.0
}
```

To register custom modules, use `compiler.WithModule`:

```go
customModule := compiler.NewModule("custom")
customModule.RegisterFunction(compiler.ModuleFunction{
	Name:       "is_authorized",
	ParamTypes: []compiler.Type{compiler.TypeString},
	ReturnType: compiler.TypeBool,
	Evaluate: func(ctx *compiler.ModuleContext, args []any) (any, error) {
		token, _ := args[0].(string)
		return token == "valid-auth-token", nil
	},
})

c := compiler.NewCompiler(compiler.WithModule(customModule))
program, err := c.CompileSourceWithContext(ctx, source)
```

Module callback functions execute during scan evaluation. Callbacks must be deterministic, bounded, and safe for concurrent execution across multiple scanners.

### Scan non-contiguous memory blocks

Use `BlockScanner` to scan sparse, segmented, or out-of-order memory regions (such as process memory dumps or fragmented files) and evaluate complete rule conditions once all blocks are loaded:

```go
scanner := program.NewBlockScanner(compiler.WithFastScan())
defer scanner.Close()

// Set total logical file size for conditions referencing 'filesize':
if err := scanner.SetFileSize(totalLogicalSize); err != nil {
	return err
}

// Ingest memory blocks at specific logical base offsets:
if err := scanner.Scan(0x1000, headerBlock); err != nil {
	return err
}
if err := scanner.Scan(0x8000, payloadBlock); err != nil {
	return err
}

// Evaluate complete rule conditions across all accumulated blocks:
result, err := scanner.Finish()
if err != nil {
	return err
}

for _, match := range result.MatchedRules {
	fmt.Printf("Matched: %s\n", match.Rule)
}
```

> [!IMPORTANT]
> The caller must supply overlapping bytes if a pattern crosses a block boundary. The scanner does not synthesize bytes across unprovided address gaps.

### Serialize and cache compiled programs

You can serialize compiled programs to disk or storage to eliminate parsing and bytecode generation overhead on startup:

```go
// Serialize the compiled program:
encodedBytes, err := program.MarshalBinary()
if err != nil {
	return err
}

// Restore the compiled program:
loadedProgram, err := compiler.UnmarshalCompiledProgram(encodedBytes)
if err != nil {
	return err
}
```

For stream-based serialization, use `program.WriteTo(writer)` and `compiler.ReadCompiledProgram(reader)`.

- The binary format uses format version 3 and rejects incompatible or truncated payloads.
- Serialized programs preserve compiled regex automatons, hex tables, and prefilter structures.
- External variable values are not serialized; you must re-apply them on the restored program or scanner.
- If you use custom modules, provide them to `UnmarshalCompiledProgram` or `ReadCompiledProgram` to rebind function handlers.

### Inspect rule dependencies and pruning

Inspect rule relationships and dependency graphs directly on the compiled program:

```go
dependencies := program.RuleDependencies("child_rule")
dependents := program.RuleDependents("base_rule")
graph := program.DependencyGraph()
```

Rules with mandatory fixed-offset checks (such as `uint16(0) == 0x5a4d`) are automatically evaluated early against target data. If the assertion fails, the rule is pruned before its strings are scanned. You can inspect pruned rules via `result.PrunedRules`.

### Diagnostic and heuristic metrics

The compiler provides inspection methods for debugging, static sizing, and testing:

- `GetStats()`: Returns counts of compiled rules, strings, opcodes, and memory usage.
- `GetMemoryUsage()`: Returns estimated bytecode and metadata footprint.
- `EstimateComplexity()`: Computes relative condition evaluation complexity.
- `EstimatePatternComplexity()`: Computes relative string pattern matching complexity.

## Command-line interface

The repository includes a command-line interface under `cmd/`.

### Basic CLI usage

The CLI accepts the rule file path as its first argument:

```bash
# Compile and validate rules (default mode):
go run ./cmd ./examples/demo_rule.yar --mode=compile

# Print lexer token stream:
go run ./cmd ./examples/demo_rule.yar --mode=lex

# Parse rules and display the AST summary:
go run ./cmd ./examples/demo_rule.yar --mode=parse

# Scan a data file with compiled rules:
go run ./cmd ./examples/demo_rule.yar --mode=execute --data ./target_sample.dat
```

### Streaming mode

For large files, you can use streaming execution to scan text patterns in chunks:

```bash
go run ./cmd ./examples/demo_rule.yar \
  --mode=execute \
  --data ./large_sample.dat \
  --streaming \
  --chunk-size 1048576 \
  --early-termination
```

> [!NOTE]
> Streaming execution reports literal text pattern occurrences only. It does not evaluate regex or hex patterns, and does not evaluate full rule conditions. For complete condition evaluation, use the default execute mode or the `BlockScanner` Go API.

## Repository layout

The project is structured into the following packages:

- [`compiler/`](compiler/): Core compilation pipeline, scanner engine, bytecode interpreter, prefilter indexing, and serialization.
- [`parser/`](parser/): YARA grammar parser and recursive-descent syntax tree builder.
- [`semantic/`](semantic/): Semantic analyzer, type checker, and validation rules.
- [`ast/`](ast/): AST definitions, node types, and visitor patterns.
- [`regex/`](regex/): Embedded regular expression compiler and matching engine.
- [`token/`](token/): Token definitions and lexical constants.
- [`internal/lexer/`](internal/lexer/): Lexer implementation used by the parser and compiler.
- [`internal/wordmatch/`](internal/wordmatch/): Word-based fast pattern routing algorithms.
- [`cmd/`](cmd/): Command-line tool.
- [`examples/`](examples/): Example rules and integration demonstrations.
- [`testdata/`](testdata/): Test suites, benchmarks, and regression fixtures.

## Known limitations

- **Upstream module parity**: Structured module object models such as `pe`, `elf`, `cuckoo`, and `dotnet` are not implemented.
- **Pattern overlap in block scanning**: When scanning non-contiguous blocks, patterns spanning across block boundaries require overlapping block input from the caller.
- **Data read edge cases**: Certain boundary conditions in low-level integer read functions (such as reading past buffer bounds) may differ from native C-based YARA behavior.

## Testing and development

### Run validation checks

To run the complete verification suite (formatting, module tidiness, static analysis, linters, and unit tests):

```bash
make check
```

To run individual test stages:

```bash
# Run unit and integration tests:
make test

# Run tests with the race detector enabled:
make test-race

# Run custom static analyzers:
make analyze

# Check code formatting and module tidy state:
make fmt-check
make tidy-check
```

### Run fuzz testing

Run fuzz targets using the bundled script:

```bash
make fuzz FUZZTIME=30s
```

### Run benchmarks and profiling

Run performance benchmark suites:

```bash
# Run compiler benchmarks:
make bench PKG=./compiler

# Run scanner performance benchmarks:
make bench-scan

# Benchmark prefilter scaling:
make bench-prefilter-scale

# Benchmark single rule scaling across input sizes:
make bench-single-rule-size

# Generate CPU and memory profiles:
make profile-scan

# Generate execution trace:
make trace-scan
```

Benchmark output and profiling artifacts are generated under the ignored `benchmarks/` and `profiles/` directories.

## Additional documentation

- [Targeted regression fixture notes](test_regression/README.md)
- [Performance benchmark test data and inputs](testdata/performance/README.md)
- [Regular expression parity test notes](testdata/regex/README.md)

## Contributing

Contributions are welcome. When submitting changes:

1. Keep pull requests focused on a single bug fix or feature.
2. Ensure all checks pass by running `make check`.
3. Add unit or regression tests covering any new behavior.
4. Adhere to standard Go idioms and the existing code style.

## License

This project is licensed under the [MIT License](LICENSE).
