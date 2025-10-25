.PHONY: bench bench-save bench-profiles bench-detailed bench-memory bench-cpu bench-trace \
        pprof-cpu pprof-mem pprof-alloc pprof-heap pprof-trace benchstat bench-compare \
        bench-string-modifiers bench-regression bench-hotspots profile-analysis

# Default package to benchmark/profile
PKG=./internal/lexer

# Basic benchmarking
bench:
	go test -bench . -benchmem -run ^$$ $(PKG)

# Enhanced benchmarking with detailed metrics
bench-detailed:
	@echo "Running detailed benchmarks with extended metrics..."
	go test -bench . -benchmem -benchtime=5s -count=3 -run ^$$ $(PKG)

# Memory-focused benchmarking
bench-memory:
	@echo "Running memory-focused benchmarks..."
	go test -bench . -benchmem -memprofilerate=1 -run ^$$ $(PKG)

# CPU-focused benchmarking
bench-cpu:
	@echo "Running CPU-focused benchmarks..."
	go test -bench . -benchtime=10s -cpu=1,2,4,8 -run ^$$ $(PKG)

# String modifier specific benchmarks
bench-string-modifiers:
	@echo "Running string modifier benchmarks..."
	go test -bench "BenchmarkLexer_.*Modifier.*|BenchmarkLexer_Phase2.*" -benchmem -run ^$$ $(PKG)

# Regression testing against saved benchmarks
bench-regression:
	@if [ ! -f benchmarks/baseline.txt ]; then \
		echo "No baseline found. Creating baseline..."; \
		make bench-save-baseline; \
	fi
	@echo "Running regression test against baseline..."
	@make bench-save
	@LATEST=$$(ls -t benchmarks/bench_*.txt | head -1); \
	make benchstat BASE=benchmarks/baseline.txt NEW=$$LATEST

# Save current benchmark as baseline
bench-save-baseline:
	@mkdir -p benchmarks
	@echo "Saving current benchmark as baseline..."
	go test -bench . -benchmem -run ^$$ $(PKG) > benchmarks/baseline.txt
	@echo "Baseline saved to benchmarks/baseline.txt"

bench-save:
	@mkdir -p benchmarks
	@OUT=benchmarks/bench_$$(date +%Y%m%d_%H%M%S).txt; \
	echo "Writing $$OUT"; \
	go test -bench . -benchmem -run ^$$ $(PKG) > $$OUT; \
	echo "Saved benchmark output to $$OUT"

# Generate comprehensive profiles
bench-profiles:
	@mkdir -p profiles
	@echo "Generating comprehensive profiles..."
	go test -bench BenchmarkLexer_.* -run ^$$ \
		-cpuprofile profiles/cpu.out \
		-memprofile profiles/mem.out \
		-blockprofile profiles/block.out \
		-mutexprofile profiles/mutex.out \
		$(PKG)
	@echo "Profiles generated:"
	@echo "  CPU:   profiles/cpu.out"
	@echo "  Memory: profiles/mem.out"
	@echo "  Block:  profiles/block.out"
	@echo "  Mutex:  profiles/mutex.out"

# Generate execution trace
bench-trace:
	@mkdir -p profiles
	@echo "Generating execution trace..."
	go test -bench BenchmarkLexer_MixedRule -run ^$$ -trace profiles/trace.out $(PKG)
	@echo "Trace generated: profiles/trace.out"
	@echo "View with: go tool trace profiles/trace.out"

# Profile analysis shortcuts
pprof-cpu:
	@echo "Launching pprof for CPU profile (ctrl+c to stop)..."
	go tool pprof -http=:0 profiles/cpu.out

pprof-mem:
	@echo "Launching pprof for MEM profile (ctrl+c to stop)..."
	go tool pprof -http=:0 profiles/mem.out

pprof-alloc:
	@echo "Launching pprof for allocation profile (ctrl+c to stop)..."
	go tool pprof -alloc_space -http=:0 profiles/mem.out

pprof-heap:
	@echo "Launching pprof for heap profile (ctrl+c to stop)..."
	go tool pprof -inuse_space -http=:0 profiles/mem.out

pprof-trace:
	@echo "Launching trace viewer (ctrl+c to stop)..."
	go tool trace profiles/trace.out

# Hotspot analysis
bench-hotspots:
	@mkdir -p profiles
	@echo "Analyzing performance hotspots..."
	go test -bench BenchmarkLexer_Phase1AllFeatures -run ^$$ -cpuprofile profiles/hotspot_cpu.out $(PKG)
	@echo "Top CPU hotspots:"
	@go tool pprof -top -cum profiles/hotspot_cpu.out

# Memory leak detection
bench-memory-leaks:
	@mkdir -p profiles
	@echo "Checking for memory leaks..."
	go test -bench BenchmarkLexer_ManyIdentifiers -run ^$$ -memprofile profiles/leak_check.out $(PKG)
	@echo "Memory allocation analysis:"
	@go tool pprof -alloc_space -top profiles/leak_check.out

# Comprehensive profile analysis
profile-analysis:
	@echo "=== COMPREHENSIVE PROFILE ANALYSIS ==="
	@echo ""
	@echo "1. CPU Profile Top Functions:"
	@go tool pprof -top -cum profiles/cpu.out | head -20
	@echo ""
	@echo "2. Memory Allocation Top Functions:"
	@go tool pprof -alloc_space -top profiles/mem.out | head -20
	@echo ""
	@echo "3. Memory Usage Top Functions:"
	@go tool pprof -inuse_space -top profiles/mem.out | head -20

benchstat:
	@if ! command -v benchstat >/dev/null 2>&1; then \
		echo "benchstat not found. Install with:"; \
		echo "  go install golang.org/x/perf/cmd/benchstat@latest"; \
		exit 1; \
	fi
	@test -n "$(BASE)" -a -n "$(NEW)" || (echo "usage: make benchstat BASE=benchmarks/old.txt NEW=benchmarks/new.txt" && exit 2)
	benchstat $(BASE) $(NEW)

# Compare two benchmark runs
bench-compare:
	@if [ -z "$(OLD)" ] || [ -z "$(NEW)" ]; then \
		echo "Usage: make bench-compare OLD=path/to/old.txt NEW=path/to/new.txt"; \
		exit 1; \
	fi
	@echo "Comparing $(OLD) vs $(NEW):"
	@make benchstat BASE=$(OLD) NEW=$(NEW)

# Performance regression detection
bench-check-regression:
	@echo "Checking for performance regressions..."
	@if [ ! -f benchmarks/baseline.txt ]; then \
		echo "No baseline found. Run 'make bench-save-baseline' first."; \
		exit 1; \
	fi
	@TEMP_BENCH=$$(mktemp); \
	go test -bench . -benchmem -run ^$$ $(PKG) > $$TEMP_BENCH; \
	DIFF=$$(mktemp); \
	if ! make benchstat BASE=benchmarks/baseline.txt NEW=$$TEMP_BENCH > $$DIFF; then true; fi; \
	echo "Benchmark comparison written to $$DIFF"; \
	FAIL=0; \
	if grep -E '\+([5-9]\.[0-9]|[1-9][0-9]+\.[0-9])%.*ns/op' $$DIFF >/dev/null; then echo "ns/op regression exceeds 5%"; FAIL=1; fi; \
	if grep -E '\+([5-9]\.[0-9]|[1-9][0-9]+\.[0-9])%.*B/op' $$DIFF >/dev/null; then echo "B/op regression exceeds 5%"; FAIL=1; fi; \
	if grep -E '\+[1-9][0-9]*\.[0-9]%.*allocs/op' $$DIFF >/dev/null; then echo "allocs/op increased"; FAIL=1; fi; \
	rm $$TEMP_BENCH; \
	if [ $$FAIL -ne 0 ]; then echo "❌ Performance budget failed"; exit 1; else echo "✅ Performance within budget"; fi

# Help target
help:
	@echo "Available performance analysis targets:"
	@echo ""
	@echo "Basic Benchmarking:"
	@echo "  bench              - Run basic benchmarks"
	@echo "  bench-detailed     - Run detailed benchmarks with extended metrics"
	@echo "  bench-memory       - Run memory-focused benchmarks"
	@echo "  bench-cpu          - Run CPU-focused benchmarks"
	@echo "  bench-string-modifiers - Run string modifier benchmarks"
	@echo ""
	@echo "Profiling:"
	@echo "  bench-profiles     - Generate comprehensive profiles"
	@echo "  bench-trace        - Generate execution trace"
	@echo "  bench-hotspots     - Analyze performance hotspots"
	@echo "  profile-analysis   - Comprehensive profile analysis"
	@echo ""
	@echo "Analysis:"
	@echo "  pprof-cpu          - Launch CPU profile viewer"
	@echo "  pprof-mem          - Launch memory profile viewer"
	@echo "  pprof-alloc        - Launch allocation profile viewer"
	@echo "  pprof-heap         - Launch heap profile viewer"
	@echo "  pprof-trace        - Launch trace viewer"
	@echo ""
	@echo "Regression Testing:"
	@echo "  bench-save-baseline    - Save current benchmark as baseline"
	@echo "  bench-regression       - Test against baseline"
	@echo "  bench-check-regression - Check for performance regressions"
	@echo ""
	@echo "Comparison:"
	@echo "  benchstat BASE=old.txt NEW=new.txt - Compare two benchmark files"
	@echo "  bench-compare OLD=old.txt NEW=new.txt - Compare with automatic benchstat"

