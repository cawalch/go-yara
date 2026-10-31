# go-yara

[Documentation](https://cawalch.github.io/go-yara/) · [Quickstart](https://cawalch.github.io/go-yara/quickstart/) · [YARA compatibility](https://cawalch.github.io/go-yara/compatibility/) · [Go API](https://pkg.go.dev/github.com/cawalch/go-yara/compiler)

`go-yara` is a pure Go implementation of YARA rule parsing, compilation, and scanning. It compiles standard YARA rules into bytecode and executes them against in-memory buffers, data streams, and files without CGO or external C library dependencies.

The engine is designed for high-throughput scanning pipelines. It uses literal prefiltering (Aho-Corasick and SIMD-accelerated multi-pattern search), early header-based rule pruning, and pooled execution state to minimize memory overhead and avoid heap allocations on prefilter-rejected inputs after warm-up.

## Key Capabilities

- **Pure Go**: Zero CGO dependencies. Produces static binaries and cross-compiles cleanly to all Go-supported architectures.
- **YARA Parity**: Strict parser and compiler supporting text strings, hex patterns with wildcards and jumps, regular expressions, condition operators, and built-in `hash`, `math`, `string`, and `time` modules.
- **High-Throughput Prefiltering**: Aho-Corasick literal indexing and early header-based rule pruning skip non-matching rules before condition evaluation.
- **Low Memory Overhead**: Reusable scanner instances and internal pooling avoid heap allocations on prefilter-rejected inputs after warm-up. Other scan paths may allocate for results or module computations.
- **Thread Safety**: Immutable compiled programs support safe, concurrent scanning across multiple goroutines.
- **Extensibility**: Support for structured host modules, custom Go module functions, runtime external variables, binary rule serialization, structured evidence extraction, and a standalone CLI.

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

// Scan an io.Reader sequentially with constant bounded memory:
result, err = program.ScanReader(reader)

// Check if an io.Reader matches any rule with early termination:
matched, err := program.MatchesReader(reader)

// Scan a file directly:
result, err = program.ScanFile("sample.bin")
```

`ScanReader` scans sequentially using a constant-memory sliding-window buffer ($C + W$, default 1 MB + automatic rule overlap), evaluating text, regex, and hex patterns without buffering the full stream. `MatchesReader` performs early-exit boolean match checks as soon as a monotonic rule condition is satisfied.

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

Rules can import the built-in `hash`, `math`, `string`, and `time` modules:

```yara
import "hash"
import "math"

rule CheckPayload {
    condition:
        hash.sha256("test-input") == "ae1608896372720b6ebb58261e0c0092c608324b0804bc99267c1753990faaa8" and
        math.mean(0, filesize) >= 0.0
}
```

| Module | Functions |
| --- | --- |
| `hash` | `md5`, `sha1`, `sha256`, `crc32`, `checksum32`, `sha512` |
| `math` | `entropy`, `mean`, `deviation`, `in_range`, `min`, `max`, `abs`, `count`, `percentage`, `mode`, `serial_correlation`, `monte_carlo_pi`, `to_number`, `to_string` |
| `string` | `to_int`, `length` |
| `time` | `now` |

Hash functions accept a string or `(offset, size)`. Statistical functions accept
strings or ranges; `count` and `percentage` accept a byte value with an optional
range, and `mode` accepts an optional range. Invalid ranges and conversions yield
YARA's undefined value. Ranges beginning inside the input are truncated at EOF.
`math.min` and `math.max` compare integers as unsigned values, as YARA does.
Float and mixed integer/float overloads are go-yara extensions: they return a
float and use signed numeric ordering. Calls with untyped external arguments
retain the declared integer result contract unless a float argument is statically
known; supply a float literal or typed module field to select the float overload.
`math.in_range` takes three floats. `math.to_string` supports bases 8, 10, and 16.
`string.to_int` autodetects decimal, octal, and hexadecimal consistently on all
platforms. Binary prefixes such as `"0b10"` are undefined; use
`string.to_int("10", 2)` for binary input. Native libyara may accept binary
prefixes depending on its host C library and build.

`hash.sha512` is a go-yara extension, not a libyara 4.5.x function. The original
`math.deviation(offset, size)` standard-deviation extension remains supported.
YARA-compatible mean absolute deviation uses `math.deviation(offset, size, mean)`
or `math.deviation(string, mean)`, with a floating-point mean.
String statistics consistently interpret high bytes as signed characters;
range statistics use unsigned bytes. Native libyara string results can differ
on targets where C `char` is unsigned. Differential tests classify these known
native variants separately from strict portable parity.

Deterministic built-in numeric/range calls share a bounded 16-entry cache across
rules in each scan. Entries are discarded before the next scan, including block
scans. Once the cache is full, additional distinct calls execute normally;
string arguments and `time.now()` are not cached. Cache hits allocate no memory.
The cache adds no per-scan allocations after warm-up; a cache miss may still
allocate for the underlying operation, such as constructing a digest string.
Repeating the same digest across 100 rules incurs the same allocations as one rule.
Custom callbacks are uncached unless they explicitly set `ModuleFunction.Cacheable`
and meet its purity contract. Custom modules supplied when loading a serialized
program determine their own caching policy.

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

### Structured Host Modules

Declare nested fields, constants, arrays, and string-keyed dictionaries with
`Module.Schema`. The compiler checks member names and index types before scanning:

```go
telemetry := compiler.Module{
    Name: "telemetry",
    Schema: &compiler.ModuleSchema{Fields: map[string]compiler.ModuleField{
        "items": {Kind: compiler.ModuleArray, Element: &compiler.ModuleField{
            Kind: compiler.ModuleStruct,
            Struct: &compiler.ModuleStructDef{Fields: map[string]compiler.ModuleField{
                "metric": {Kind: compiler.ModuleFloat},
            }},
        }},
        "env": {Kind: compiler.ModuleDictionary, Element: &compiler.ModuleField{
            Kind: compiler.ModuleString,
        }},
    }},
}
c := compiler.NewCompiler(compiler.WithModule(telemetry))
program, err := c.CompileSourceWithContext(ctx, `
import "telemetry"
rule elevated {
    condition:
        telemetry.env["USER"] == "analyst" and
        for any item in telemetry.items : (item.metric > 0.9)
}`)
if err != nil {
    return err
}
scanner := program.NewScanner(compiler.WithModuleData("telemetry", map[string]any{
    "items": []map[string]any{{"metric": 0.95}},
    "env": map[string]string{"USER": "analyst"},
}))
defer scanner.Close()
result, err := scanner.Scan(data)
```

Access arrays with integer indices (`telemetry.items[0].metric`) and dictionaries
with string keys. Dictionary loops bind a key and value:
`for any key,value in telemetry.env : (key == "USER" and value == "analyst")`.
Collection loops stop once `any`, `all`, `none`, or a numeric threshold is decided.
Missing fields, missing keys, and out-of-range indices evaluate as undefined.
Missing collections iterate as empty collections; `all` and `none` are true for
an empty collection, while `any` is false. Use `defined` to require a value.

Binding copies data into a scanner-owned snapshot. It accepts Go structs with
exported fields (case-insensitive names or exact `yara:"name"` tags), string-keyed
maps, slices, and arrays. Scalar types must match the schema; integer fields accept
signed integers and unsigned values through `math.MaxInt64`. Binding errors from
`WithModuleData` are returned by scan methods. Use `scanner.SetModuleData(name,
data)` between scans to replace a snapshot and receive errors immediately.
Setters must not run concurrently with scans. Separate scanners can bind different
data to the same compiled program.

A scalar field can set `Constant` to a matching `ModuleValue`; direct references
to constants work without runtime data. Schemas are copied at registration, must
be finite, and support up to 32 levels. Schema fields can coexist with the existing
scalar callback API in `Module.Functions`. Native `pe`/`elf` parsers are not bundled.

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

Stream-based serialization is also supported via `program.WriteTo(w)` and `compiler.ReadCompiledProgram(r)`. Serialized programs preserve compiled automatons, hex tables, and prefilter structures. External variables and custom module handlers must be rebound after deserialization. New artifacts use format version 14, including symbolic finite-prefix verification, unbounded atom-verification plans, bounded-alternation verification plans, atomless-regex forward branch priority, the fullword boundary policy, and fixed-offset literal restrictions for text, regex, and hex declarations; versions 4–13 remain readable. Format 8 preserves text-only fixed-offset restrictions. Older artifacts retain their compiled match policies; recompile them to apply these corrections. Older binaries cannot load version 14 artifacts. Structured module schemas are preserved; host data must be rebound on each scanner.

The compiler fuses fixed-offset `uint16`/`uint32` equality, integer filesize bounds,
string-at checks, string-count comparisons, and external comparisons with integer,
boolean, or string constants. A complete condition composed of these predicates
and `and`/`or`/`not` runs as a dataflow program with no operand-stack pushes or
pops. Mixed conditions retain the stack-based fused instructions. Payload and
external guards share scan-local results across rules. Safe mandatory guards can
reject rules before interpretation; default scans still preserve string matches
for rules rejected by a filesize or external condition. Conditions with callbacks
or potentially observable errors retain normal evaluation. When using `Interpreter` directly with compiled bytecode, bind its rules with `SetCompiledRules` and select the rule with `SetCurrentRule` so assertion operands are available.

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
				fmt.Printf("Rule %s found %s at byte %d (ready for validation)\n", ruleName, declName, f.Anchor.Offset)
			}
		}
	}
}
```

A ready finding has complete, unambiguous capture data; it does not prove that a credential is active. The [credential evidence guide](https://cawalch.github.io/go-yara/scanning/#credential-evidence-and-validation) includes executable validator-handoff and offline private-key parsing examples, plus handling for partial and ambiguous findings. Avoid logging captured secret values.

When evidence extraction is disabled (the default), capture parsing and correlation are bypassed with zero runtime overhead.

### Telemetry and Hooks

Phase timings, pattern callbacks, and consistent lifecycle accounting are available starting in **v0.8.1**. See the [metrics guide](https://cawalch.github.io/go-yara/performance/#hooks-and-scan-metrics) for examples and measurement limits.

You can monitor scanning execution, track latency, or throttle CPU usage in background workers:

| Option | Purpose |
| :--- | :--- |
| `WithTelemetry(sink *ScanTelemetry)` | Updates counters (scans, rejects, rules evaluated, candidate hits) in-place without heap allocations. |
| `WithTelemetryLatency(sink *ScanTelemetry)` | Measures execution phase durations and total scan duration. |
| `WithPollHook(hook PollHook, byteStride int)` | Cooperative callback for progress reporting, CPU yielding (`PollYield`), throttling (`PollThrottle`), or early cancellation (`PollAbort`). |
| `WithRuleProfiling(hook RuleEfficiencyHook)` | Emits per-rule duration, loop-iteration deltas, candidate hits, and retained occurrence counts. |
| `WithMatchHook(hook MatchHook)` | Callback during public match delivery; `MatchActionStopScan` returns the current match and stops later delivery without an error. |
| `WithMaxMatches(limit int, onExceeded func)` | Enforces a safety limit on matched strings per rule to prevent memory exhaustion on repetitive inputs. |
| `WithHooks(hooks ScanHooks)` | Bundles lifecycle, prefilter, pattern-profile (`OnPatternProfile`), and chunk callbacks. |

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

if _, err := scanner.Scan(sampleData); err != nil {
	return err
}
fmt.Printf("Scanned %d bytes in %d ns; prefilter rejected %d scans\n",
	telemetry.BytesScanned, telemetry.TotalScanDurationNs, telemetry.PrefilterRejects)
```


Keep one telemetry sink per scanner and export its snapshot after the scan returns. Fields are not atomic. `TotalMatches` counts returned public rules; boolean `Matches` counts a positive result as one. Already-cancelled contexts and invalid bindings fail before counters advance. Later errors contribute elapsed time but no successful matches. `OnScanComplete` runs after final telemetry updates only on successful returns, including deliberate early stops. For boolean scans its result argument is nil; rule-list scans supply only `MatchedRules`.

With latency enabled, phase timers record exclusive time: compact/word routing and mandatory assertions in `PrefilterDurationNs`, candidate generation and verification in `PatternSearchNs`, and interpreter setup/execution in `ConditionEvalNs`. Speculative conditions inside pattern search suspend the pattern timer. Shared automaton search, including regex/hex verification, belongs to pattern time. Result construction and callbacks can leave total time above the phase sum. Counters-only mode leaves all timing fields untouched.

`OnPatternProfile` runs once for each live pattern in an evaluated rule context, without captured values. `VerifiedMatches` counts retained occurrences; boolean and fast scans may stop collecting early. `CandidateHitsKnown` distinguishes available automaton hit counts from fallback searches that do not expose them. `Selectivity` is the occurrence-to-candidate ratio when known and nonzero, and zero otherwise. A shared cached search can contribute to several logical rule profiles, so these counts are not a measure of physical verifier invocations. Skipped rules and failed contexts do not emit pattern profiles. Rule `ConditionSteps` counts that rule's loop iterations, including speculative evaluations.

For `BlockScanner`, pattern profiles and search timing occur during each `Scan`; lifecycle events, scan/byte counters, condition timing, and returned-match counts occur at `Finish`. Bytes count supplied blocks, including overlaps, rather than the logical address-space size. Total time sums active calls and excludes idle time between them. Each `Finish` is another condition-evaluation attempt. Reset the sink between logical block scans, alongside `BlockScanner.Reset`.

`OnPrefilter` provides stage durations even without telemetry latency. Its shared-automaton duration includes exact verification, so it is not interchangeable with `PrefilterDurationNs`. Header checks may occur more than once. Keep callbacks bounded and avoid blocking I/O. The executable [instrumentation example](compiler/example_instrumentation_test.go) shows pattern events and timing without printing input data; the [regression tests](compiler/hooks_instrumentation_test.go) cover all scan result APIs, failures, reuse, block input, and disabled-timer behavior.

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

# Report literal text-pattern matches using chunked I/O (no rule conditions):
go-yara rules.yar --mode=execute --data large_sample.bin --streaming --chunk-size 1048576
```

## Compatibility and Limitations

`go-yara` supports the standard YARA grammar and semantics:
- **Strings**: Text, hex byte sequences (with wildcards `??`, `?F`, and jumps `[1-4]`), and regular expressions.
- **Modifiers**: `nocase`, `wide`, `ascii`, `fullword`, `xor`, `base64`, `base64wide`, and `private`.
- **Expressions**: Arithmetic, bitwise, comparison, logical, range, string count (`#`), length (`!`), offset (`@`), occurrence (`at`, `in`), and quantifiers (`for ... of them`).
- **Modules**: Built-in `hash`, `math`, `string`, and `time` functions (see the module table above).

### Limitations

- **C-Based Modules**: Upstream C-based module object models (`pe`, `elf`, `cuckoo`, `dotnet`) are not bundled. Applications can supply structured schemas and host data or Go callback functions with `compiler.WithModule`.
- **Streaming**: Full rule conditions, regex, and hex patterns are evaluated with constant-memory streaming via `ScanReader` and `MatchesReader` (#352). The legacy `StreamingProcessor` and CLI `--streaming` utility remain available for literal text-pattern occurrences.
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
