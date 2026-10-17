# go-yara

`go-yara` is a high-performance, 100% pure Go implementation of YARA rule parsing, compilation, and scanning. It compiles standard YARA rules into optimized bytecode and evaluates them against in-memory buffers, data streams, and files—without any CGO dependencies or external C libraries.

Architected for high-concurrency cloud environments and high-throughput security pipelines, `go-yara` combines multi-gigabyte-per-second literal prefiltering (Aho-Corasick and Teddy SIMD), early header-based rule pruning, and a thread-safe, pooled execution engine that achieves zero heap allocations on clean inputs after warm-up.

## Features

- **Pure Go Architecture**: Zero CGO dependencies, easy cross-compilation, static binary generation, and safe concurrent evaluation across goroutines.
- **Full Grammar & AST Support**: Strict, recursive-descent parsing into a typed abstract syntax tree (AST) with comprehensive support for text, hex, and regex patterns.
- **Deep Semantic Analysis**: Compile-time type checking, symbol resolution, machine-readable diagnostic codes, and "did you mean...?" suggestions for misspelled identifiers and functions.
- **Resilient Compilation**: Optionally compile valid rules from rule sets containing syntax or semantic errors, while collecting detailed omitted-rule diagnostics and dependency cascades.
- **High-Throughput Prefiltering & Fast Rejection**: Conservative mandatory-literal routing bypasses bytecode execution on non-matching inputs, achieving zero heap allocations on clean inputs after warm-up.
- **Early Rule Pruning**: Rules with failing fixed-offset assertions (such as `$magic at 0` or `uint32(0) == 0x464c457f`) are pruned before scanning string tables.
- **Allocation-Conscious Evaluation Modes**:
  - Reusable scanner instances with pooled internal state.
  - Zero-allocation convenience forwarders on `CompiledProgram` via an internal `sync.Pool`.
  - Boolean evaluation (`Matches`) for immediate short-circuiting on clean inputs.
  - Compact matching (`MatchingRules`) returning matched rules without allocating full condition result maps.
  - First-occurrence matching (`WithFastScan`) with automatic full-match retention for rules dependent on match counts, offsets, or ranges.
  - Match span bounds (`WithMaxMatchSpan`) to defend against catastrophic regex backtracking.
- **Sparse & Non-Contiguous Block Scanning**: Segmented or out-of-order memory scanning (`BlockScanner`) with absolute logical offsets for virtual memory dumps and fragmented files.
- **Extensible Module System**: Built-in `hash` (MD5, SHA-1, SHA-256) and `math` (entropy, mean, deviation) modules, plus registration of custom typed Go functions.
- **Versioned Cache Serialization**: Fast binary serialization (`MarshalBinary` / `UnmarshalCompiledProgram`) preserving compiled automata, literal tables, and prefilter plans across processes.
- **Rule Dependency Graphing**: Inspect direct dependencies, reverse dependents, and full cyclic or acyclic rule dependency graphs.
- **Structured Evidence & Secret Extraction**: Syntactic extensions (`capture(...)` and `evidence:`) for credential harvesting and DLP workflows with deterministic spatial proximity windows (e.g. `within 4KB of secret`).
- **Production Observability & Telemetry**: Zero-allocation in-place counters, phase-level latency tracking, cooperative CPU throttling (`WithPollHook`), and streaming match callbacks (`WithMatchHook`).
- **Experimental SIMD Acceleration (Go 1.27+)**: Compile-time opt-in hardware-vectorized (`AVX2`, `AVX-512`, `ARM NEON`) case-folding, character range testing, Teddy multi-literal matching (7–11+ GB/s across 2–64 patterns), and multi-gigabyte root-miss skipping.
- **Feature-Rich CLI**: Standalone tool for lexing, parsing, compiling, and scanning files with optional chunked streaming.

## Compatibility

`go-yara` provides comprehensive compatibility with standard YARA syntax and semantics:

- **String Types**: Text strings, hexadecimal byte patterns with wildcards and jumps, and PCRE-compatible regular expressions.
- **String Modifiers**: `nocase`, `wide`, `ascii`, `fullword`, `xor`, `base64`, `base64wide`, and `private`.
- **Rule Declarations**: Metadata (`meta:`), tags, file includes (`include "..."`), and external variables (`external`).
- **Rule Visibility & Ordering**: `private` rules, `global` rules, and inter-rule condition references.
- **Expressions & Operators**:
  - Arithmetic, bitwise, comparison, logical, and range (`..`) operators.
  - String count (`#`), length (`!`), offset (`@`), and occurrence (`at`, `in`) operators.
  - Quantifiers and set loops: `for ... of them`, `for any of ($a*)`, `for all i in (1..5)`.
- **Standard Modules**:
  - `hash`: `md5`, `sha1`, `sha256`.
  - `math`: `entropy`, `mean`, `deviation`.

> [!NOTE]
> Structured C-based upstream module object models such as `pe`, `elf`, `cuckoo`, and `dotnet` are not currently bundled. If your rules require custom parsing logic, you can register typed Go callback functions using the extensible module API.

## Requirements and Installation

`go-yara` requires **Go 1.26.0** or later.

To add `go-yara` to your Go module, run:

```bash
go get github.com/cawalch/go-yara/compiler
```

> [!IMPORTANT]
> Import only the public packages (`compiler`, `parser`, `ast`, `semantic`, and `token`). Do not import packages under `internal/`, as their internal APIs are subject to change.

### Experimental SIMD Acceleration (Go 1.27+)

When compiled with **Go 1.27** or later using the standard vector experiment flag (`GOEXPERIMENT=simd`), `go-yara` unlocks hardware-vectorized byte scanning loops:

- **ASCII Case-Folding (`nocase`)**: `indexASCIIFoldByte` broadcasts and case-folds byte comparisons across 16-byte (NEON/SSE), 32-byte (AVX2), or 64-byte (AVX-512) vector lanes, accelerating case-insensitive string matching.
- **Character Range Scanning**: `indexByteRange` evaluates character sets (e.g. `[a-z]`, `[0-9]`) using parallel vector subtraction and unsigned span comparisons.
- **Teddy Multi-Literal Prefiltering**: Vectorized multi-pattern prefilter inspired by Hyperscan's Teddy algorithm. Uses 16-byte parallel nibble lookups (`archsimd.Uint8x16.LookupOrZero` on ARM NEON) or broadcast equality vectors (AVX2/SSE on AMD64) across 1-byte, 2-byte, or 3-byte prefixes (including case-folded variants), scanning clean and sparse data at 7–11+ GB/s across 2–64 patterns before invoking Aho-Corasick state traversal. Runtime support can be verified with `compiler.TeddySIMDSupported()`.
- **Aho-Corasick Root-Miss Skipping**: Scans input for matching automaton root transitions at up to 30+ GB/s, rapidly skipping clean or non-matching regions before bytecode evaluation.

#### Enabling SIMD at Build Time

Set `GOEXPERIMENT=simd` when building your application or running tests:

```bash
# Build binary with SIMD acceleration enabled:
make build-simd
# or:
GOEXPERIMENT=simd go build ./cmd

# Run tests with SIMD:
make test-simd
# or:
GOEXPERIMENT=simd go test ./compiler -run TestByteSearch -count=1
```

#### Runtime Vector Width Controls

You can inspect, constrain, or disable vectorization at runtime using `GODEBUG=simd`:

```bash
# Force 128-bit vector width (e.g. ARM NEON or SSE):
GODEBUG=simd=+128 ./my-scanner

# Disable vectorization at runtime (forces scalar fallback):
GODEBUG=simd=0 ./my-scanner
```

#### Platform Support

| Architecture | Vector Extension | Width | Fallback |
| :--- | :--- | :--- | :--- |
| `amd64` | AVX-512 / AVX2 / SSE | 64 / 32 / 16 bytes | Automatic scalar fallback |
| `arm64` | ARM NEON | 16 bytes | Automatic scalar fallback |
| Other / Non-SIMD | — | — | Highly optimized scalar loops |

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

## Library Usage

The primary entry point for rule compilation and execution is the [`compiler`](file:///Users/cawalch/go-yara/compiler) package.

### Compile and Scan Byte Slices

Use `CompileSourceWithContext` (or `CompileSource`) to compile rules from an in-memory string:

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

### Compile and Scan Files

Use `CompileFileWithContext` to compile a rule file from disk. Relative `include` directives are resolved automatically against the file's parent directory:

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

### Reusable Scanners and Convenience Pooling

For high-throughput concurrent workloads (such as web services, message consumer workers, or stream processors), convenience scanning methods directly on `CompiledProgram` (`program.Scan`, `program.Matches`, `program.MatchingRules`) manage an internal, thread-safe `sync.Pool` of reusable scanners. They require no manual cleanup and achieve zero heap allocations on repeated scans under default options.

When custom scanning configurations are required (such as tag filtering, match threshold caps, telemetry, execution hooks, or fast-scan flags), or when binding worker-local external variables, instantiate an explicit reusable `Scanner` with functional options:

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

### Scan Result Types and Evaluation Modes

The `Scan` method returns a `ScanResult` struct containing comprehensive execution details:

- `MatchedRules`: Public rules that evaluated to `true`, including their tags, metadata, and matched string details.
- `RuleResults`: A fast boolean lookup map keyed by rule name containing evaluation outcomes for all evaluated rules.
- `Matches`: Verified string matches grouped by rule name and string identifier.
- `PrunedRules`: Names of rules skipped early due to failing fixed-offset assertions.
- `Evidence`: Structured findings and correlated field tuples extracted when `WithEvidence` is configured.

You can customize scanner evaluation behavior using functional options:

- **Compact matches (`WithReportedMatchesOnly`)**: Omits string match details for non-matching rules, minimizing allocation overhead.
- **Fast scan (`WithFastScan`)**: Halts pattern matching after finding the first occurrence of each string. The compiler automatically preserves full occurrences for rules whose conditions depend on match counts (`#`), offsets (`@`), or ranges (`in`), ensuring exact condition semantics are never compromised.
- **Match span windowing (`WithMaxMatchSpan`)**: Bounds the maximum byte length evaluated forward from candidate regex starts (e.g. `compiler.WithMaxMatchSpan(1024)`). Defaults to unlimited (`0`) for strict YARA specification compliance.

#### Boolean-Only Matching

If you only need to determine whether any rule in the program matches without inspecting rule names or string offsets, use `scanner.Matches(data)`:

```go
hasMatch, err := scanner.Matches(data)
if err != nil {
	return err
}
if hasMatch {
	fmt.Println("At least one rule matched the input.")
}
```

When all rules require string matches and the prefilter detects no candidate literals, `Matches` returns `false` before executing any bytecode VM instructions. After scanner warm-up, this clean-input path performs **zero heap allocations**.

#### Matched-Rules Filtering

If you need the list of matched rules and tags without paying the memory cost of allocating full condition result maps for non-matching rules, use `scanner.MatchingRules(data)`:

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

### Configure External Variables

Rules can reference runtime values defined with the `external` keyword:

```yara
external is_production
external environment_name

rule EnvironmentGate {
    condition:
        is_production and environment_name == "staging"
}
```

External variables can be bound globally on a compiled program or scoped to a reusable scanner:

```go
// Set variables globally on a compiled program:
err := program.SetExternalVariables(map[string]any{
	"is_production":    true,
	"environment_name": "staging",
})
if err != nil {
	return err
}

// Or configure them locally when constructing a reusable scanner:
scanner := compiler.NewScanner(
	program,
	compiler.WithExternalVariables(map[string]any{
		"is_production":    true,
		"environment_name": "staging",
	}),
)
defer scanner.Close()

// Update external variables between scans on the same scanner:
err = scanner.SetExternalVariables(map[string]any{
	"environment_name": "production",
})
```

### Extract Structured Secret Evidence

`go-yara` extends standard YARA with an opt-in `capture(...)` string modifier and `evidence:` rule section. This extension enables secret detection, credential extraction, and DLP workflows to extract structured submatch fields (such as usernames, API keys, and endpoints) and correlate fields appearing in close spatial proximity, without altering the rule's boolean condition evaluation.

#### Syntax and Grammar

##### 1. `capture(...)` String Modifier

The `capture(...)` modifier assigns names to pattern match spans or regex capture groups:

```yara
strings:
    // Regex pattern with 1-indexed parenthesized sub-groups:
    $uri = /postgres:\/\/([^: ]+):([^@ ]+)@([^\/ ]+)/
        capture(username = 1, secret = 2, endpoint = 3)

    // Full match (group 0) on text and hex strings:
    $key = "AKIAIOSFODNN7EXAMPLE" capture(access_key = 0)
    $hex = { 4D 5A 90 00 } capture(dos_magic = 0)
```

- **Group numbers**:
  - `0`: Denotes the entire matched pattern span. Allowed on text (`"..."`), hexadecimal (`{ ... }`), and regular expression patterns (`/.../`).
  - `1..N`: Denotes the 1-indexed parenthesized capture group in a regular expression pattern.
- **Grammar constraints**:
  - Anonymous strings (`$ = "..."`) cannot declare captures.
  - Private strings (`private`) cannot declare captures.
  - At most 32 capture bindings per pattern string.
  - Capture names must be unique within a given string pattern.
  - Trailing commas in the capture binding list are disallowed.

##### 2. `evidence:` Section

The `evidence:` section appears after `strings:` (or `meta:`) and before `condition:`. It defines deterministic spatial correlation rules between captured fields:

```yara
evidence:
    <declaration_name> = (<field1>, <field2>, ...) within <distance> of <anchor>
```

- `<declaration_name>`: Identifier for the correlated finding tuple.
- `(<field1>, <field2>, ...)`: Comma-separated list of capture names defined across strings in the rule.
- `<distance>`: Maximum byte window between any candidate field span and the anchor span:
  - Byte count: Non-negative integer literal (e.g., `0`, `512`, `4096`).
  - Sized units: Case-insensitive size suffix (`KB`, `MB`, `GB`, `TB`), such as `4KB` (4,096 bytes) or `1MB` (1,048,576 bytes).
- `of <anchor>`: Designates the reference capture field that serves as the spatial center. The anchor must be included in the field list `(<field1>, <field2>, ...)`.
- **Co-located matches (`within 0 of <anchor>`)**: A distance of `0` requires all fields to originate from the exact same pattern match span (ideal when a single regex extracts multiple sub-groups).

#### Rule Examples

See [`examples/structured_secrets.yar`](examples/structured_secrets.yar) for full runnable rule examples.

##### Example 1: Single Regex Extraction (Co-located Fields)

Extract database credentials from a single connection string:

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

##### Example 2: Multi-String Spatial Proximity Correlation

Correlate credentials declared across distinct lines or JSON fields in a configuration file or log:

```yara
rule AWSConfigCredentials {
    strings:
        $endpoint = /endpoint[ ]*[:=][ ]*["']?([^"' \n]+)/i capture(endpoint = 1)
        $access   = /aws_access_key_id[ ]*[:=][ ]*["']?([A-Z0-9]{20})/i capture(access_key = 1)
        $secret   = /aws_secret_access_key[ ]*[:=][ ]*["']?([A-Za-z0-9\/+=]{40})/i capture(secret = 1)
    evidence:
        credential = (endpoint, access_key, secret) within 4KB of secret
    condition:
        $access and $secret
}
```

##### Example 3: Text and Hex Pattern Captures (Group 0)

Extract full text tokens and binary signatures:

```yara
rule APIKeyAndSalt {
    strings:
        $key    = "AIzaSy" capture(key_prefix = 0)
        $header = { 89 50 4E 47 0D 0A 1A 0A } capture(png_magic = 0)
    evidence:
        asset = (key_prefix, png_magic) within 1KB of key_prefix
    condition:
        $key and $header
}
```

#### Go Scanning and Results API

To extract evidence, pass `compiler.WithEvidence(maxCaptureBytes)` when constructing a scanner:

```go
// 1. Create a scanner with evidence extraction enabled (max 4096 bytes per capture span).
scanner := compiler.NewScanner(program, compiler.WithEvidence(4096))
defer scanner.Close()

// 2. Scan target input.
result, err := scanner.Scan(data)
if err != nil {
	log.Fatal(err)
}

// 3. Inspect structured evidence findings:
// Result is keyed by rule name, then evidence declaration name.
for ruleName, declarations := range result.Evidence {
	for declName, findings := range declarations {
		for _, finding := range findings {
			fmt.Printf("Rule %s | Finding: %s | Status: %s\n", ruleName, declName, finding.Status)
			fmt.Printf("  Anchor: offset=%d len=%d\n", finding.Anchor.Offset, finding.Anchor.Length)

			switch finding.Status {
			case compiler.EvidenceStatusReady:
				// Exactly one unambiguous capture per field; ready for validation.
				for fieldName, captures := range finding.Fields {
					fmt.Printf("  %s: %s (offset %d)\n", fieldName, captures[0].Data, captures[0].Offset)
				}
			case compiler.EvidenceStatusPartial:
				// A field was not found within the proximity window, or data was truncated.
				fmt.Println("  (Partial finding: missing fields or truncated data)")
			case compiler.EvidenceStatusAmbiguous:
				// Multiple candidate captures fell within the window at equal or competing distance.
				fmt.Println("  (Ambiguous finding: multiple competing candidates preserved)")
			}
		}
	}
}

// 4. Inspect individual pattern captures directly on matches:
for _, match := range result.Matches["AWSConfigCredentials"]["$access"] {
	for _, cap := range match.Captures {
		fmt.Printf("Capture: %s = %s (group %d, offset %d)\n", cap.Name, cap.Data, cap.Group, cap.Offset)
	}
}
```

#### Status Classifications and Operational Notes

- **`EvidenceStatusReady` ("ready")**: Every declared field has exactly one unambiguous candidate capture within the proximity window, and none were truncated. Safe for automated downstream validation.
- **`EvidenceStatusPartial` ("partial")**: One or more declared fields were missing within the proximity window, or captured data exceeded `maxCaptureBytes` (`Capture.DataTruncated == true`).
- **`EvidenceStatusAmbiguous` ("ambiguous")**: Multiple candidate captures for a field were located within the window (such as equidistant occurrences). Rather than guessing, all candidates are preserved in `Fields`.
- **Fast-scan safety**: When `WithEvidence` is active, patterns with capture bindings automatically retain all occurrences across the input, even if `WithFastScan` is enabled, ensuring proximity correlation is never distorted.
- **Zero overhead when disabled**: When `WithEvidence` is omitted or set to `<= 0` (the default), capture replay and correlation logic is completely skipped with zero allocations.

### Tolerate Invalid Rules During Compilation

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
	fmt.Printf("Omitted rule %s at %d:%d (code %s): %s\n",
		ignored.Rule, ignored.Line, ignored.Column, ignored.Code, ignored.Message)
}
```

> [!NOTE]
> Rules that reference an omitted rule are transitively omitted. If an omitted rule is declared `global`, all subsequent rules are also omitted to prevent unintended matching behavior.

### Observability, Hooks, and Telemetry

`go-yara` provides an allocation-conscious hooks and telemetry system for long-running batch scans, large-file inspection, and high-throughput pipelines. When hooks are disabled (the default), internal bitmask dispatching incurs **zero allocations** and negligible CPU overhead (< 0.5%).

#### Public Scanner Options

| Option | Purpose | Incurred Cost |
| :--- | :--- | :--- |
| `WithTelemetry(sink *ScanTelemetry)` | Updates aggregate counters (scans, rejects, rules pruned/evaluated, candidate hits) in-place. | < 1.5 ns (zero heap allocs) |
| `WithTelemetryLatency(sink *ScanTelemetry)` | Measures phase durations and total scan latency in addition to counters. | ~25 ns (vDSO clock calls) |
| `WithPollHook(hook PollHook, byteStride int)` | Cooperative callback during rule loops for progress, CPU yielding, throttling, or early abort. | Invoked per byte-stride / rule |
| `WithRuleProfiling(hook RuleEfficiencyHook)` | Per-rule profiling (`RuleProfile`: duration, condition VM steps, candidate hits, verified matches, pass/reject). | Invoked per evaluated rule |
| `WithPrefilterHook(hook PrefilterHook)` | Observes prefilter decisions across literal routing, compact masks, shared automata, and header checks. | Invoked per prefilter stage |
| `WithRuleGate(gate RuleGateFunc)` | Dynamically gates/skips individual rules at runtime based on external conditions without recompiling. | Single boolean check per rule |
| `WithMatchHook(hook MatchHook)` | Invoked immediately upon a rule match, allowing streaming match ingestion or early termination (`MatchActionStopScan`). | Invoked per matched rule |
| `WithMaxMatches(limit int, onExceeded func)` | Safety threshold capping matches per rule, aborting when the limit is exceeded. | Counter check |
| `WithMaxMatchSpan(maxBytes int)` | Bounds regex search window forward from candidate starts (0 = unlimited). | Window limit per candidate |
| `WithChunkHook(hook ChunkHook)` | Boundary progress callback during streaming and `BlockScanner` execution. | Invoked per block/chunk |
| `WithHooks(hooks ScanHooks)` | Bundles any combination of the above callbacks plus `OnScanStart` and `OnScanComplete` lifecycle hooks. | Configured once on Scanner |

#### Telemetry and Latency Measurement

Aggregate scanner metrics and reject/prune counters in-place with zero heap allocations:

```go
var telemetry compiler.ScanTelemetry

// Use WithTelemetry for counter-only tracking (< 1.5 ns overhead)
// Or WithTelemetryLatency to also track scan durations
scanner := program.NewScanner(compiler.WithTelemetryLatency(&telemetry))
defer scanner.Close()

for _, sample := range samples {
	_, _ = scanner.Scan(sample)
}

fmt.Printf("Scans: %d, Prefilter Rejects: %d, Evaluated: %d, Matches: %d (Total time: %d ns)\n",
	telemetry.TotalScans, telemetry.PrefilterRejects, telemetry.RulesEvaluated,
	telemetry.TotalMatches, telemetry.TotalScanDurationNs)
```

#### Cooperative Polling and Throttling

For background scans or massive files, `WithPollHook` enables cooperative CPU throttling, yielding (`runtime.Gosched()`), and responsive cancellation:

```go
scanner := program.NewScanner(compiler.WithPollHook(func(ctx context.Context, p compiler.PollProgress) (compiler.PollAction, time.Duration) {
	fmt.Printf("Phase: %s | Scanned %d/%d bytes | Rule: %s (%d/%d)\n",
		p.Phase, p.BytesScanned, p.TotalBytes, p.CurrentRule, p.RulesEvaluated, p.TotalRules)

	// Cooperatively throttle CPU for background worker workloads
	if p.RulesEvaluated%100 == 0 {
		return compiler.PollThrottle, 50 * time.Microsecond
	}
	return compiler.PollContinue, 0
}, 64*1024))
```

#### Rule Efficiency Profiling (Metrics Ingestion)

Track single-rule performance, pass/reject rates, VM evaluation steps, and candidate false-positive ratios (ideal for emitting to Prometheus, Datadog, or OpenTelemetry):

```go
scanner := program.NewScanner(compiler.WithRuleProfiling(func(p compiler.RuleProfile) {
	// Log or aggregate per-rule execution metrics:
	// - p.RuleName: rule identifier
	// - p.Duration: exact evaluation latency
	// - p.Matched: whether rule fired (pass rate)
	// - p.Pruned: rejected by header constraints
	// - p.CandidateHits vs p.VerifiedMatches: pattern selectivity / noise ratio
	if p.Duration > 5*time.Millisecond {
		fmt.Printf("Slow rule: %s took %v (VM steps: %d, candidates: %d)\n",
			p.RuleName, p.Duration, p.ConditionSteps, p.CandidateHits)
	}
}))
```

#### Prefilter Observability and Dynamic Rule Gating

Inspect prefilter decisions or dynamically bypass rules at runtime without recompiling the ruleset:

```go
scanner := program.NewScanner(
	compiler.WithPrefilterHook(func(d compiler.PrefilterDecision) {
		if d.Rejected {
			fmt.Printf("Prefilter fast-rejected input at stage %s\n", d.Stage)
		}
	}),
	compiler.WithRuleGate(func(rule *compiler.CompiledRule) bool {
		// Dynamically evaluate only rules tagged for this environment
		return len(rule.Tags) == 0 || rule.Tags[0] == "production"
	}),
)
```

#### Streaming Match Alerts and Threshold Limits

Stream matches in real time and abort as soon as a target match threshold is reached:

```go
scanner := program.NewScanner(
	// Process matches immediately as they are verified
	compiler.WithMatchHook(func(rule *compiler.CompiledRule, match compiler.RuleMatch) compiler.MatchAction {
		fmt.Printf("Immediate match found: %s\n", match.Rule)
		return compiler.MatchActionStopScan // Abort scan immediately upon first match
	}),
	// Or enforce a safety cap on maximum matches per rule
	compiler.WithMaxMatches(100, func(rule string, count int) {
		fmt.Printf("Rule %s exceeded %d match limit\n", rule, count)
	}),
)
```

#### Bundled Configuration via `ScanHooks`

All callbacks can alternatively be passed as a single cohesive [`compiler.ScanHooks`](compiler/hooks.go) bundle:

```go
hooks := compiler.ScanHooks{
	OnScanStart: func(ctx context.Context, inputLen int64) {
		fmt.Printf("Starting scan on %d bytes\n", inputLen)
	},
	OnScanComplete: func(ctx context.Context, result *compiler.ScanResult, duration time.Duration) {
		fmt.Printf("Scan completed in %v with %d matching rules\n", duration, len(result.MatchedRules))
	},
	OnChunk: func(offset int64, chunkSize int, matchesFound int) {
		fmt.Printf("Chunk at %d (%d bytes): %d matches\n", offset, chunkSize, matchesFound)
	},
}
scanner := program.NewScanner(compiler.WithHooks(hooks))
```

### Inspect Semantic Diagnostics and Warnings

The compiler and semantic analysis layers emit rich diagnostic feedback:

- **Compiler Warnings**: Inspect non-fatal rule issues such as unreferenced strings (`unused-string`), trivial conditions (`trivial-condition`), duplicate patterns (`duplicate-pattern`), or slow patterns (`slow-pattern`):

```go
c := compiler.NewCompiler()
program, err := c.CompileSourceWithContext(ctx, source)
if err != nil {
	return err
}

for _, warn := range c.GetWarnings() {
	fmt.Printf("[%s] Rule %s: %s at %d:%d\n",
		warn.Code, warn.Rule, warn.Message, warn.Line, warn.Column)
}
```

- **Semantic Analysis Errors**: When building standalone linters or rule validators, the `semantic` package emits structured errors with machine-readable codes and "did you mean...?" suggestions for misspelled identifiers and functions:

```go
v := semantic.NewValidator()
errors := v.ValidateProgram(astProgram)
for _, err := range errors {
	if semErr, ok := err.(*semantic.Error); ok {
		fmt.Printf("[%s] %s at %d:%d\n",
			semErr.Code, semErr.Error(), semErr.Position.Line, semErr.Position.Column)
		if semErr.Suggestion != "" {
			fmt.Printf("  Suggestion: did you mean %s?\n", semErr.Suggestion)
		}
	}
}
```

### Use Built-in and Custom Modules

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

To register custom modules, supply a [`compiler.Module`](file:///Users/cawalch/go-yara/compiler/modules.go) definition via `compiler.WithModule`:

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

Module callback functions execute during scan evaluation. Callbacks must be deterministic, bounded, and safe for concurrent execution across multiple scanners.

### Scan Non-Contiguous Memory Blocks

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

### Serialize and Cache Compiled Programs

You can serialize compiled programs to disk or distributed cache to eliminate parsing and bytecode generation overhead on startup:

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

- The binary format uses format version 3 and validates headers, magic numbers, and checksums.
- Serialized programs preserve compiled regex automatons, hex tables, and prefilter structures.
- External variable values are not serialized; you must re-apply them on the restored program or scanner.
- When restoring programs with custom modules, pass them to `UnmarshalCompiledProgram` or `ReadCompiledProgram` to rebind function handlers.

### Inspect Rule Dependencies and Pruning

Inspect rule relationships and dependency graphs directly on the compiled program:

```go
dependencies := program.RuleDependencies("child_rule")
dependents := program.RuleDependents("base_rule")
graph := program.DependencyGraph()
```

Rules with mandatory fixed-offset checks (such as `uint16(0) == 0x5a4d`) are automatically evaluated early against target data. If the assertion fails, the rule is pruned before its strings are scanned. You can inspect pruned rules via `result.PrunedRules`.

### Diagnostic and Heuristic Metrics

The compiler provides inspection methods for debugging, static sizing, and testing:

- `GetStats()`: Returns counts of compiled rules, strings, opcodes, and memory usage.
- `GetMemoryUsage()`: Returns estimated bytecode and metadata footprint.
- `EstimateComplexity()`: Computes relative condition evaluation complexity.
- `EstimatePatternComplexity()`: Computes relative string pattern matching complexity.

## Command-Line Interface

The repository includes a command-line interface under `cmd/`.

### Basic CLI Usage

The CLI accepts a YARA rule file path as its first argument:

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

### Streaming Mode

For large files, streaming execution evaluates text patterns in sequential chunks:

```bash
go run ./cmd ./examples/demo_rule.yar \
  --mode=execute \
  --data ./large_sample.dat \
  --streaming \
  --chunk-size 1048576 \
  --early-termination
```

> [!NOTE]
> Streaming mode reports literal text pattern occurrences only. It does not evaluate regex or hex patterns, and does not evaluate full rule conditions. For full condition evaluation on partitioned or streamed data, use the default execute mode or the `BlockScanner` Go API.

## Repository Layout

The project is structured into the following packages:

- [`compiler/`](compiler/): Core compilation pipeline, scanner engine, bytecode VM, prefilter indexing, and binary serialization.
- [`parser/`](parser/): Recursive-descent YARA grammar parser and AST builder.
- [`semantic/`](semantic/): Semantic analyzer, type checker, symbol table, and validation rules.
- [`ast/`](ast/): AST node definitions, expression interfaces, and visitor patterns.
- [`regex/`](regex/): Embedded regular expression compiler and matching engine.
- [`token/`](token/): Token definitions and lexical constants.
- [`internal/lexer/`](internal/lexer/): Lexer implementation used by the parser and compiler.
- [`internal/wordmatch/`](internal/wordmatch/): Word-based fast pattern routing algorithms.
- [`cmd/`](cmd/): Command-line tool.
- [`examples/`](examples/): Example rules and integration demonstrations.
- [`testdata/`](testdata/): Test suites, benchmarks, and regression fixtures.

## Known Limitations

- **Upstream Module Parity**: Structured C-based module object models such as `pe`, `elf`, `cuckoo`, and `dotnet` are not implemented. Custom modules can be registered via the Go module API.
- **Pattern Overlap in Block Scanning**: When scanning non-contiguous blocks, patterns spanning across block boundaries require overlapping block input from the caller.
- **Data Read Edge Cases**: Boundary conditions in low-level integer read functions (such as reading past buffer bounds) may differ subtly from native C-based `libyara` behavior.

## Testing and Development

### Build Binaries

```bash
# Build the go-yara CLI binary under bin/:
make build

# Build with experimental SIMD acceleration enabled (Go 1.27+):
make build-simd

# Clean build outputs, coverage reports, and profiling dumps:
make clean
```

### Validation and Test Suites

To run the complete verification suite (formatting, module tidiness, static analysis, linters, and unit tests):

```bash
make check
```

To run individual test stages:

```bash
# Run unit and integration tests:
make test

# Run all unit tests plus the libyara 4.5.8 differential bugproof suite:
make test-all

# Run the libyara differential proof suite only:
make test-bugproof

# Run tests with the Go race detector enabled:
make test-race

# Run SIMD byte search tests (Go 1.27+):
make test-simd

# Run repository-specific static analyzers:
make analyze

# Generate HTML test coverage report (coverage.html):
make coverage
```

### Code Hygiene and Formatting

```bash
# Format Go source files with gofmt and goimports:
make fmt

# Verify code formatting and module tidy state:
make fmt-check
make tidy-check

# Run linters and apply automatic fixes:
make lint-fix

# Run fmt, tidy, and lint-fix in one step:
make fix
```

### Fuzz Testing

Run continuous fuzzing across all targets:

```bash
make fuzz FUZZTIME=30s
```

### Benchmarks and Profiling

Run performance benchmark suites:

```bash
# Run compiler benchmarks:
make bench PKG=./compiler

# Run core scanner throughput benchmarks:
make bench-scan

# Benchmark experimental SIMD acceleration (Go 1.27+):
make bench-simd

# Benchmark prefilter scaling:
make bench-prefilter-scale

# Benchmark single rule scaling across input sizes:
make bench-single-rule-size

# Save benchmark results for differential analysis:
make bench-save

# Compare benchmark runs using benchstat:
make benchstat BASE=benchmarks/old.txt NEW=benchmarks/new.txt

# Generate CPU and memory profiles:
make profile-scan

# Generate execution trace:
make trace-scan
```

Benchmark output and profiling artifacts are generated under the ignored `benchmarks/` and `profiles/` directories.

## Additional Documentation

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
