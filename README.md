# go-yara

`go-yara` is a pure Go implementation of YARA rule parsing, compilation, and scanning. It compiles standard YARA rules into bytecode and executes them against in-memory buffers, data streams, and files without CGO or external C library dependencies.

The engine is designed for high-throughput scanning pipelines. It uses literal prefiltering (Aho-Corasick and SIMD-accelerated multi-pattern search), early header-based rule pruning, and pooled execution state to minimize memory overhead and eliminate heap allocations on non-matching inputs after warm-up.

## Key Capabilities

- **Pure Go**: Zero CGO dependencies. Produces static binaries and cross-compiles cleanly to all Go-supported architectures.
- **YARA Parity**: Strict parser and compiler supporting text strings, hex patterns with wildcards and jumps, regular expressions, condition operators, and built-in `hash` and `math` modules.
- **High-Throughput Prefiltering**: Aho-Corasick literal indexing and early header-based rule pruning skip non-matching rules before condition evaluation.
- **Low Memory Overhead**: Reusable scanner instances and internal pooling eliminate heap allocations on clean inputs after warm-up.
- **Thread Safety**: Immutable compiled programs support safe, concurrent scanning across multiple goroutines.
- **Extensibility**: Support for custom Go module functions, runtime external variables, binary rule serialization, structured evidence extraction, and a standalone CLI.

## Requirements and Installation

`go-yara` requires **Go 1.26.0** or later.

Install the compiler package:

```bash
go get github.com/cawalch/go-yara/compiler
```

Install the command-line tool:

```bash
go install github.com/cawalch/go-yara/cmd/...@latest
```

### Hardware Acceleration (Optional)

When compiled with Go 1.27 or later using `GOEXPERIMENT=simd`, `go-yara` uses hardware vector instructions (ARM NEON, x86 AVX2, and AVX-512) for multi-literal prefiltering and case-folding:

```bash
GOEXPERIMENT=simd go build ./cmd
```

Scalar fallback routines are automatically used on unsupported platforms or when SIMD is disabled at runtime (`GODEBUG=simd=0`).

## Quickstart

The following example compiles a YARA rule and scans an in-memory byte slice:

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
rule DetectSample {
    strings:
        $text = "suspicious-payload" nocase
    condition:
        $text
}`

	c := compiler.NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	if err != nil {
		log.Fatalf("Compilation failed: %v", err)
	}

	result, err := program.Scan([]byte("Data containing SUSPICIOUS-PAYLOAD string."))
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	for _, match := range result.MatchedRules {
		fmt.Printf("Matched rule: %s (tags: %v)\n", match.Rule, match.Tags)
	}
}
```

## Library Usage

The primary entry point is the [`compiler`](compiler/) package.

### Compiling Rules

You can compile rules from strings or files on disk. When compiling files, relative `include` directives are automatically resolved against the file's parent directory:

```go
c := compiler.NewCompiler()

// Compile from a string:
program, err := c.CompileSourceWithContext(ctx, sourceString)

// Compile from a file:
program, err = c.CompileFileWithContext(ctx, "rules/index.yar")
```

To compile valid rules from rule sets that may contain syntax or semantic errors, enable `WithIgnoreInvalidRules`:

```go
c := compiler.NewCompiler(compiler.WithIgnoreInvalidRules(true))
program, err := c.CompileFileWithContext(ctx, "rules/third_party.yar")
if err != nil {
	return err // Fatal parser failures still return an error.
}

// Inspect omitted rules and diagnostics:
for _, ignored := range c.GetIgnoredRules() {
	fmt.Printf("Omitted rule %s at %d:%d: %s\n",
		ignored.Rule, ignored.Line, ignored.Column, ignored.Message)
}
```

### Scanning Inputs

`CompiledProgram` provides methods to scan byte slices, readers, and files:

```go
// Scan an in-memory byte slice:
result, err := program.Scan(data)

// Scan an io.Reader stream:
result, err = program.ScanReader(reader)

// Scan a file directly:
result, err = program.ScanFile("sample.bin")
```

The returned `ScanResult` contains:
- `MatchedRules`: Slice of `RuleMatch` structs for rules evaluating to `true`.
- `RuleResults`: Map of boolean outcomes for all evaluated rules (`map[string]bool`).
- `Matches`: Map of matched pattern occurrences by rule and string identifier.
- `PrunedRules`: Names of rules skipped early by header-based assertions (such as `$magic at 0`).
- `Evidence`: Structured findings when evidence extraction is enabled.

### Reusable Scanners and Concurrency

A `CompiledProgram` is immutable and safe for concurrent use across multiple goroutines. Convenience methods on `CompiledProgram` (`Scan`, `Matches`, `MatchingRules`) automatically manage an internal `sync.Pool` of scanners.

When you need custom scanning configurations (such as tag filters, match limits, hooks, or fast-scan flags), instantiate a dedicated `Scanner`:

```go
scanner := program.NewScanner(
	compiler.WithTagsFilter([]string{"malware", "triage"}),
	compiler.WithFastScan(),
)
defer scanner.Close()

result, err := scanner.Scan(sampleData)
```

#### Evaluation Modes

`Scanner` supports specialized evaluation modes to reduce latency and memory allocations:

- **Boolean matching (`Matches`)**: Checks whether any rule matched without populating match details or rule metadata. Returns `false` immediately on prefilter rejection, performing zero allocations after warm-up:
  ```go
  matched, err := scanner.Matches(data)
  ```
- **Matching rules only (`MatchingRules`)**: Returns matched rules and tags while omitting the evaluation map for non-matching rules:
  ```go
  matches, err := scanner.MatchingRules(data)
  ```
- **Fast scan (`WithFastScan()`)**: Stops pattern evaluation after finding the first occurrence of each string, unless the rule's condition depends on match counts (`#`), offsets (`@`), or ranges (`in`).

### External Variables

Rules can reference runtime values declared with the `external` keyword:

```yara
external is_production
external environment_name

rule ProductionGate {
    condition:
        is_production and environment_name == "staging"
}
```

Bind external variables globally on a compiled program or scope them to a specific scanner:

```go
// Set globally on the program:
err := program.SetExternalVariables(map[string]any{
	"is_production":    true,
	"environment_name": "staging",
})

// Or configure on a specific scanner instance:
scanner := program.NewScanner(
	compiler.WithExternalVariables(map[string]any{
		"is_production":    true,
		"environment_name": "staging",
	}),
)
defer scanner.Close()
```

### Built-in and Custom Modules

Rules can import the built-in `hash` and `math` modules:

```yara
import "hash"
import "math"

rule CheckPayload {
    condition:
        hash.sha256("test-input") == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" and
        math.mean(0, filesize) >= 0.0
}
```

You can register custom modules with Go callback functions:

```go
customModule := compiler.Module{
	Name: "auth",
	Functions: map[string]compiler.ModuleFunction{
		"is_authorized": {
			Signatures: []compiler.ModuleSignature{
				{Arguments: []compiler.ModuleValueType{compiler.ModuleString}},
			},
			ReturnType: compiler.ModuleBoolean,
			Evaluate: func(ctx compiler.ModuleContext, args []compiler.ModuleValue) (compiler.ModuleValue, error) {
				token := args[0].String
				return compiler.BooleanValue(token == "valid-auth-token"), nil
			},
		},
	},
}

c := compiler.NewCompiler(compiler.WithModule(customModule))
program, err := c.CompileSourceWithContext(ctx, source)
```

Module callback functions must be deterministic and safe for concurrent execution across goroutines.

### Program Serialization and Caching

To avoid recompiling rules on service startup, serialize compiled programs to binary format:

```go
// Serialize the compiled program:
data, err := program.MarshalBinary()
if err != nil {
	return err
}

// Restore from bytes:
loadedProgram, err := compiler.UnmarshalCompiledProgram(data)
if err != nil {
	return err
}
```

Stream-based serialization is also supported via `program.WriteTo(w)` and `compiler.ReadCompiledProgram(r)`. Serialized programs preserve compiled automatons, hex tables, and prefilter structures. External variables and custom module handlers must be rebound after deserialization.

### Sparse Block Scanning

Use `BlockScanner` to scan non-contiguous or fragmented memory blocks (such as virtual memory dumps or chunked transfers) and evaluate complete rule conditions across all blocks:

```go
scanner := program.NewBlockScanner()
defer scanner.Close()

// Set total logical file size for rules referencing 'filesize':
_ = scanner.SetFileSize(totalSize)

// Ingest blocks at specific logical offsets:
_ = scanner.Scan(0x1000, headerBlock)
_ = scanner.Scan(0x8000, payloadBlock)

// Evaluate conditions across all accumulated blocks:
result, err := scanner.Finish()
```

> [!NOTE]
> If a pattern spans a block boundary, you must supply overlapping bytes in the adjoining blocks. The scanner does not infer data across unprovided address ranges.

### Structured Evidence and Secret Extraction

`go-yara` includes an opt-in syntactic extension for credential scanning and DLP workflows. The `capture(...)` modifier extracts named match groups, and the `evidence:` section correlates fields that appear within a spatial byte window without changing the rule's boolean condition:

```yara
rule DatabaseConnectionSecret {
    strings:
        $uri = /(postgres|mysql):\/\/([^: ]+):([^@ ]+)@([^\/ ]+)/
            capture(username = 2, secret = 3, endpoint = 4)
    evidence:
        credential = (endpoint, username, secret) within 0 of secret
    condition:
        $uri
}
```

To extract evidence, enable `WithEvidence(maxBytes)` on the scanner:

```go
scanner := program.NewScanner(compiler.WithEvidence(4096))
defer scanner.Close()

result, err := scanner.Scan(payload)
if err != nil {
	return err
}

for ruleName, decls := range result.Evidence {
	for declName, findings := range decls {
		for _, f := range findings {
			if f.Status == compiler.EvidenceStatusReady {
				fmt.Printf("Rule %s found %s: %+v\n", ruleName, declName, f.Fields)
			}
		}
	}
}
```

When evidence extraction is disabled (the default), capture parsing and correlation are bypassed with zero runtime overhead.

### Telemetry and Hooks

You can monitor scanning execution, track latency, or throttle CPU usage in background workers:

| Option | Purpose |
| :--- | :--- |
| `WithTelemetry(sink *ScanTelemetry)` | Updates counters (scans, rejects, rules evaluated, candidate hits) in-place without heap allocations. |
| `WithTelemetryLatency(sink *ScanTelemetry)` | Measures execution phase durations and total scan duration. |
| `WithPollHook(hook PollHook, byteStride int)` | Cooperative callback for progress reporting, CPU yielding (`PollYield`), throttling (`PollThrottle`), or early cancellation (`PollAbort`). |
| `WithRuleProfiling(hook RuleEfficiencyHook)` | Emits per-rule latency, VM steps, candidate hits, and verification outcomes for metrics pipelines. |
| `WithMatchHook(hook MatchHook)` | Streaming callback invoked immediately upon rule match; can abort the scan early with `MatchActionStopScan`. |
| `WithMaxMatches(limit int, onExceeded func)` | Enforces a safety limit on matched strings per rule to prevent memory exhaustion on repetitive inputs. |
| `WithHooks(hooks ScanHooks)` | Bundles lifecycle callbacks (`OnScanStart`, `OnScanComplete`, `OnChunk`). |

Example:

```go
var telemetry compiler.ScanTelemetry

scanner := program.NewScanner(
	compiler.WithTelemetryLatency(&telemetry),
	compiler.WithMatchHook(func(rule *compiler.CompiledRule, match compiler.RuleMatch) compiler.MatchAction {
		fmt.Printf("Matched: %s\n", match.Rule)
		return compiler.MatchActionContinue
	}),
)
defer scanner.Close()

_, _ = scanner.Scan(sampleData)
fmt.Printf("Scanned %d bytes in %d ns; prefilter rejected %d scans\n",
	telemetry.BytesScanned, telemetry.TotalScanDurationNs, telemetry.PrefilterRejects)
```

## Performance and Benchmarks

The scanning engine uses several architectural techniques to maintain high throughput:
- **Zero Allocations on Non-Matches**: Prefilter rejections require zero heap allocations after scanner warm-up, avoiding garbage collector pauses.
- **Early Rule Pruning**: Rules with failing fixed-offset assertions (such as `$magic at 0` or `uint32(0) == 0x464c457f`) are pruned before scanning string tables.
- **Linear Proximity Checks**: String distance and ordering constraints evaluate in $O(N + M)$ two-pointer traversal instead of nested interpreter loops.
- **Prefilter Routing**: Mandatory literal tables index candidate rules, allowing inputs lacking required tokens to skip bytecode evaluation entirely.

### Representative Benchmarks

Measured on an Apple M3 Max (14 cores):

| Scenario | Payload Size | Throughput | Latency | Allocations |
| :--- | :--- | :--- | :--- | :--- |
| **Literal (Clean Reject)** | 256 B | 2.84 GB/s | 84 ns | 0 B, 0 alloc |
| **Literal (Clean Reject)** | 4 KB | 6.69 GB/s | 570 ns | 0 B, 0 alloc |
| **Literal (Clean Reject)** | 1 MB | 8.88 GB/s | 110 µs | 0 B, 0 alloc |
| **Literal (Match)** | 4 KB | 3.52 GB/s | 1.08 µs | 608 B, 4 alloc |
| **Hex Mask (Clean Reject)** | 4 KB | 6.31 GB/s | 605 ns | 0 B, 0 alloc |
| **Regex (Clean Reject)** | 4 KB | 6.51 GB/s | 586 ns | 0 B, 0 alloc |
| **10 Rules (Clean Reject)** | 4 KB | 1.87 GB/s | 2.04 µs | 0 B, 0 alloc |
| **10 Rules (Match)** | 4 KB | 1.47 GB/s | 2.60 µs | 608 B, 4 alloc |
| **Parallel High EPS** | 4 KB | 49.74 GB/s | 76.6 ns | 0 B, 0 alloc |
| **Corpus Sweep** | 59,047 files (2.7 GB) | 750 MB/s | 3.6 s | 0 B VM loop alloc |

Run benchmarks locally:

```bash
make bench-scan
```

## Command-Line Interface

The repository includes a standalone CLI tool for validating rules and scanning files:

```bash
# Compile and validate a rule file:
go-yara rules.yar --mode=compile

# Scan a file against compiled rules:
go-yara rules.yar --mode=execute --data sample.bin

# Inspect tokens or parsed abstract syntax tree:
go-yara rules.yar --mode=lex
go-yara rules.yar --mode=parse

# Scan large files using chunked streaming:
go-yara rules.yar --mode=execute --data large_sample.bin --streaming --chunk-size 1048576
```

## Compatibility and Limitations

`go-yara` supports the standard YARA grammar and semantics:
- **Strings**: Text, hex byte sequences (with wildcards `??`, `?F`, and jumps `[1-4]`), and regular expressions.
- **Modifiers**: `nocase`, `wide`, `ascii`, `fullword`, `xor`, `base64`, `base64wide`, and `private`.
- **Expressions**: Arithmetic, bitwise, comparison, logical, range, string count (`#`), length (`!`), offset (`@`), occurrence (`at`, `in`), and quantifiers (`for ... of them`).
- **Modules**: Built-in `hash` (md5, sha1, sha256) and `math` (entropy, mean, deviation).

### Limitations

- **C-Based Modules**: Upstream C-based module object models (`pe`, `elf`, `cuckoo`, `dotnet`) are not bundled. Applications can implement custom logic by registering Go callback functions with `compiler.WithModule`.
- **Block Boundary Spanning**: In `BlockScanner`, patterns crossing segmented block boundaries require overlapping bytes in the caller-provided buffers.

## Repository Layout

- [`compiler/`](compiler/): Rule compilation, bytecode VM, scanner engine, prefiltering, and serialization.
- [`parser/`](parser/): Recursive-descent grammar parser and AST construction.
- [`semantic/`](semantic/): Semantic analysis, type validation, symbol tables, and diagnostic reporting.
- [`ast/`](ast/): Typed AST node definitions and expression interfaces.
- [`regex/`](regex/): Embedded regular expression compiler and matching engine.
- [`token/`](token/): Token definitions and lexical constants.
- [`cmd/`](cmd/): Command-line tool.
- [`examples/`](examples/): Example rules and integration demonstrations.

## Development and Testing

Run the full verification suite (formatting, module tidiness, static analysis, linters, and tests):

```bash
make check
```

Common development targets:

```bash
make test        # Run unit and integration tests
make test-race   # Run tests with the Go race detector enabled
make test-simd   # Run SIMD acceleration tests (Go 1.27+)
make bench-scan  # Run scanner throughput benchmarks
make fmt         # Format Go sources with gofmt and goimports
make fix         # Run formatters, linters with autofix, and module tidy
make build       # Build the go-yara CLI binary under bin/
```

## License

This project is licensed under the [MIT License](LICENSE).
