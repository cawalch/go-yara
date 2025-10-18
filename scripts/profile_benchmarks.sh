#!/bin/bash

# Profile Benchmarks Script
# This script provides comprehensive profiling for go-yara benchmarks

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "=== Go-YARA Benchmark Profiling Script ==="
echo

# Function to run CPU profiling
run_cpu_profile() {
    local bench_name="$1"
    local output_file="$2"

    echo "Running CPU profile for $bench_name..."
    go test -cpuprofile="$output_file" ./internal/comparison -bench="$bench_name" -benchtime=5s -run=^$

    echo "Analyzing CPU profile..."
    echo "Top 10 CPU consumers:"
    go tool pprof -top "$output_file" | head -15
    echo
}

# Function to run memory profiling
run_memory_profile() {
    local bench_name="$1"
    local output_file="$2"

    echo "Running memory profile for $bench_name..."
    go test -memprofile="$output_file" ./internal/comparison -bench="$bench_name" -benchtime=5s -run=^$

    echo "Analyzing memory profile..."
    echo "Top 10 memory allocators:"
    go tool pprof -alloc_space -top "$output_file" | head -15
    echo
}

# Function to run benchmark with detailed metrics
run_detailed_benchmark() {
    local bench_name="$1"

    echo "Running detailed benchmark for $bench_name..."
    go test ./internal/comparison -bench="$bench_name" -benchmem -benchtime=5s -run=^$
    echo
}

# Create profiles directory
mkdir -p profiles

# Profile key benchmarks
echo "=== Profiling Key Benchmarks ==="

# CPU profiling
run_cpu_profile "BenchmarkGoYaraCompiler_Benchmark/bench_large" "profiles/cpu_large.prof"
run_cpu_profile "BenchmarkGoYaraLexer_Benchmark/bench_large" "profiles/cpu_lexer.prof"

# Memory profiling
run_memory_profile "BenchmarkGoYaraCompiler_Benchmark/bench_large" "profiles/mem_large.prof"
run_memory_profile "BenchmarkGoYaraCompiler_Benchmark/bench_medium" "profiles/mem_medium.prof"

# Detailed benchmarks
echo "=== Detailed Benchmark Results ==="
run_detailed_benchmark "BenchmarkGoYaraCompiler_Benchmark"
run_detailed_benchmark "BenchmarkGoYaraLexer_Benchmark"
run_detailed_benchmark "BenchmarkCYaraCompiler_Benchmark"

# Component profiling
echo "=== Component Profiling ==="
run_cpu_profile "BenchmarkACAutomaton" "profiles/cpu_acautomaton.prof"
run_cpu_profile "BenchmarkStringCompiler" "profiles/cpu_stringcompiler.prof"
run_cpu_profile "BenchmarkEmitter" "profiles/cpu_emitter.prof"

echo "=== Profiling Complete ==="
echo "Profile files saved in profiles/ directory:"
ls -la profiles/
echo
echo "To analyze profiles interactively:"
echo "  go tool pprof profiles/cpu_large.prof"
echo "  go tool pprof profiles/mem_large.prof"
echo
echo "For web interface:"
echo "  go tool pprof -http=:8080 profiles/cpu_large.prof"