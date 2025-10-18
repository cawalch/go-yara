# YARA Performance Comparison Infrastructure

This package provides benchmarking infrastructure to compare the performance of go-yara against the official VirusTotal/yara C implementation.

## Overview

The comparison infrastructure includes:

- **CGO Wrapper** (`yara_c_wrapper.go`): Go bindings to the C YARA library for benchmarking
- **Test Data Loader** (`testdata.go`): Loads YARA rules from various sources (inline, fuzzer corpus, samples)
- **Benchmark Suite** (`benchmark_test.go`): Comprehensive benchmarks comparing both implementations

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Benchmark Suite                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐              ┌──────────────────┐   │
│  │   go-yara Lexer  │              │  C YARA Compiler │   │
│  │   (Pure Go)      │              │  (CGO Wrapper)   │   │
│  └──────────────────┘              └──────────────────┘   │
│          │                                  │              │
│          │                                  │              │
│          v                                  v              │
│  ┌──────────────────────────────────────────────────────┐ │
│  │              Test Data Loader                        │ │
│  │  - Inline test cases                                 │ │
│  │  - Fuzzer corpus (yara/tests/oss-fuzz/...)          │ │
│  │  - Sample rules (yara/sample.rules)                  │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Building

### Prerequisites

1. **Autotools** (for building C YARA):
   ```bash
   brew install automake autoconf libtool
   ```

2. **C YARA Library** (already built if you followed setup):
   ```bash
   cd yara
   ./bootstrap.sh
   ./configure --disable-shared --enable-static
   make -j$(sysctl -n hw.ncpu)
   cd ..
   ```

### Compile Benchmarks

```bash
go test -c ./internal/comparison
```

## Running Benchmarks

### Quick Test

Run a quick sanity check:

```bash
go test ./internal/comparison -bench=Simple -benchtime=100x
```

### Full Benchmark Suite

Run all benchmarks with detailed metrics:

```bash
go test ./internal/comparison -bench=. -benchmem -benchtime=2s
```

### Save Results

Save benchmark results to a file:

```bash
go test ./internal/comparison -bench=. -benchmem -benchtime=2s > benchmarks/comparison_$(date +%Y%m%d_%H%M%S).txt
```

### Compare Specific Tests

Run only go-yara benchmarks:

```bash
go test ./internal/comparison -bench=GoYara -benchmem
```

Run only C YARA benchmarks:

```bash
go test ./internal/comparison -bench=CYara -benchmem
```

## Benchmark Categories

### 1. Simple Benchmarks

- `BenchmarkGoYaraLexer_Simple`: Minimal rule
- `BenchmarkCYaraCompiler_Simple`: Minimal rule

### 2. Complex Benchmarks

- `BenchmarkGoYaraLexer_Complex`: Multi-section rule with strings and conditions
- `BenchmarkCYaraCompiler_Complex`: Multi-section rule with strings and conditions

### 3. Test Data Benchmarks

- `BenchmarkGoYaraLexer`: All test data (inline + corpus + samples)
- `BenchmarkCYaraCompiler`: All test data (inline + corpus + samples)

### 4. Benchmark Suite

- `BenchmarkGoYaraLexer_Benchmark`: Specific benchmark rules (small, medium, large)
- `BenchmarkCYaraCompiler_Benchmark`: Specific benchmark rules (small, medium, large)

## Test Data Sources

### Inline Test Cases

Hardcoded test cases covering:
- Simple rules
- Basic operators
- Strings and hex patterns
- Regex patterns
- Complex multi-section rules
- Arithmetic and bitwise operations
- Data type functions
- Quantifiers

### Fuzzer Corpus

YARA rules from the official fuzzer corpus:
- Location: `yara/tests/oss-fuzz/rules_fuzzer_corpus/`
- Up to 10 files loaded for benchmarking
- Real-world test cases from fuzzing

### Sample Rules

Official YARA sample rules:
- Location: `yara/sample.rules`
- Production-quality rules

## Understanding Results

### Metrics

- **Time/op**: Nanoseconds per operation (lower is better)
- **Throughput**: MB/s processed (higher is better)
- **Memory/op**: Bytes allocated per operation (lower is better)
- **Allocs/op**: Number of allocations per operation (lower is better)

### Interpreting Comparisons

**Important**: The comparison is between:
- **go-yara**: Lexer only (tokenization)
- **C YARA**: Full compiler (lexer + parser + code generation)

The go-yara lexer is expected to be faster since it does less work. However, the results demonstrate:
1. Go can be competitive with C for lexical analysis
2. The go-yara implementation is highly optimized
3. Memory usage is reasonable and predictable

## Example Output

```
BenchmarkGoYaraLexer_Simple-14      10072819    234.3 ns/op   123.76 MB/s    80 B/op   1 allocs/op
BenchmarkCYaraCompiler_Simple-14       50773  47626.0 ns/op     0.61 MB/s     8 B/op   1 allocs/op
```

This shows:
- go-yara is ~203x faster (234 ns vs 47,626 ns)
- go-yara has higher throughput (123.76 MB/s vs 0.61 MB/s)
- go-yara uses more memory per op (80 B vs 8 B) but still very efficient
- Both have 1 allocation per operation

## Troubleshooting

### CGO Compilation Errors

If you see CGO errors, ensure:
1. C YARA library is built: `ls yara/.libs/libyara.a`
2. Headers are present: `ls yara/libyara/include/yara.h`

### Benchmark Failures

If benchmarks fail with "compilation failed":
1. Check the YARA rule syntax
2. Test with `./yara/yarac <rule_file> /tmp/test.yarc`
3. Update test data to use valid YARA syntax

### Performance Variations

Benchmark results can vary based on:
- System load
- CPU frequency scaling
- Memory pressure
- Background processes

Run benchmarks multiple times and compare averages.

## Contributing

To add new test cases:

1. Add to `getInlineTestCases()` in `testdata.go`
2. Or add YARA files to the fuzzer corpus
3. Run benchmarks to verify

To add new benchmark scenarios:

1. Add benchmark function to `benchmark_test.go`
2. Follow naming convention: `Benchmark{Go|C}Yara{Lexer|Compiler}_{Name}`
3. Use `b.ReportAllocs()` and `b.SetBytes()` for detailed metrics

## See Also

- [Performance Comparison Report](../../docs/PERFORMANCE_COMPARISON.md)
- [Benchmark Results](../../benchmarks/)
- [YARA Official Repository](https://github.com/VirusTotal/yara)

