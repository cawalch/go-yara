.PHONY: bench bench-save bench-profiles bench-detailed bench-memory bench-cpu bench-trace \
        bench-scan bench-prefilter-scale bench-single-rule-size profile-scan trace-scan \
        pprof-cpu pprof-mem pprof-alloc pprof-heap pprof-trace benchstat bench-compare \
        bench-string-modifiers bench-regression bench-hotspots profile-analysis \
        compare-yara compare-yara-quick compare-yara-deep compare-yara-report \
        performance-suite performance-monitor performance-baseline performance-compare \
        performance-dashboard performance-cleanup perf-automaton perf-e2e perf-scaling \
        bench-greentea perf-greentea-compare bench-greentea-memory bench-greentea-cpu \
        bench-vs-yarax bench-vs-yarax-update-baseline fuzz

# Default package to benchmark/profile
PKG=./internal/lexer

# Fuzzing duration per target
FUZZTIME=30s
BENCHTIME?=100ms
BENCHCOUNT?=3

# Run all fuzz targets sequentially
fuzz:
	@./scripts/fuzz_all.sh $(FUZZTIME)

# Run the same matrix through go-yara and the pinned yara-x Go binding.
bench-vs-yarax:
	@BENCHTIME="$(BENCHTIME)" BENCHCOUNT="$(BENCHCOUNT)" ./scripts/bench_vs_yarax.sh

# Regenerate the ignored, machine-local ratio baseline after reviewing a run.
bench-vs-yarax-update-baseline:
	@BENCHTIME="$(BENCHTIME)" BENCHCOUNT="$(BENCHCOUNT)" \
		TOURNAMENT_CHECK=0 TOURNAMENT_UPDATE_BASELINE=1 ./scripts/bench_vs_yarax.sh


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

# Scanner-focused end-to-end benchmarks and profiles.
bench-scan:
	go test ./compiler -run '^$$' -bench '^Benchmark(ProductionScanner|ProductionScannerUniquePatterns|MultiRuleScanner)$$' -benchmem -count=5

bench-prefilter-scale:
	go test ./compiler -run '^$$' -bench '^BenchmarkSharedNonTextPrefilterScale$$' -benchmem -count=5

bench-single-rule-size:
	go test ./compiler -run '^$$' -bench '^BenchmarkSingleRuleScanSize$$' -benchmem -count=5

profile-scan:
	@mkdir -p profiles
	go test ./compiler -run '^$$' -bench '^BenchmarkProductionScanner$$' -benchtime=5s \
		-cpuprofile profiles/scanner_cpu.out -memprofile profiles/scanner_mem.out

trace-scan:
	@mkdir -p profiles
	go test ./compiler -run '^$$' -bench '^BenchmarkProductionScanner$$' -benchtime=2s \
		-trace profiles/scanner_trace.out

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

# === GreenTea GC Benchmarks (Go 1.25 Optimization) ===

# GreenTea GC basic benchmarks
bench-greentea:
	@echo "=== GreenTea GC Benchmarks ==="
	@mkdir -p profiles/greentea
	@echo "Running benchmarks with GreenTea GC (small-object optimization)..."
	GOEXPERIMENT=greenteagc go test -bench . -benchmem -benchtime=5s -count=3 -run ^$$ $(PKG) > profiles/greentea/bench_greentea_$(date +%Y%m%d_%H%M%S).txt
	@echo "GreenTea GC benchmarks completed!"
	@echo "Results saved to profiles/greentea/"

# GreenTea GC memory-focused benchmarks
bench-greentea-memory:
	@echo "=== GreenTea GC Memory Analysis ==="
	@mkdir -p profiles/greentea
	@echo "Running memory benchmarks with GreenTea GC..."
	GOEXPERIMENT=greenteagc go test -bench . -benchmem -memprofilerate=1 -run ^$$ $(PKG) \
		-memprofile profiles/greentea/greentea_mem_$(date +%Y%m%d_%H%M%S).out
	@echo "GreenTea GC memory profile generated: profiles/greentea/greentea_mem_*.out"
	@echo "Compare with standard GC using: make pprof-alloc and make pprof-alloc-greentea"

# GreenTea GC CPU-focused benchmarks
bench-greentea-cpu:
	@echo "=== GreenTea GC CPU Analysis ==="
	@mkdir -p profiles/greentea
	@echo "Running CPU benchmarks with GreenTea GC..."
	GOEXPERIMENT=greenteagc go test -bench . -benchtime=10s -cpuprofile profiles/greentea/greentea_cpu_$(date +%Y%m%d_%H%M%S).out -run ^$$ $(PKG)
	@echo "GreenTea GC CPU profile generated: profiles/greentea/greentea_cpu_*.out"
	@echo "Compare with standard GC using: make pprof-cpu and make pprof-cpu-greentea"

# Compare GreenTea GC vs standard GC
perf-greentea-compare:
	@echo "=== GreenTea GC vs Standard GC Comparison ==="
	@mkdir -p comparison-results
	@echo "Running benchmarks with standard GC..."
	go test -bench . -benchmem -count=3 -run ^$$ $(PKG) > comparison-results/standard_gc_$(date +%Y%m%d_%H%M%S).txt
	@echo "Running benchmarks with GreenTea GC..."
	GOEXPERIMENT=greenteagc go test -bench . -benchmem -count=3 -run ^$$ $(PKG) > comparison-results/greentea_gc_$(date +%Y%m%d_%H%M%S).txt
	@echo "Generating comparison..."
	@STANDARD=$$(ls -t comparison-results/standard_gc_*.txt | head -1); \
	GREEN=$$(ls -t comparison-results/greentea_gc_*.txt | head -1); \
	benchstat $$STANDARD $$GREEN > comparison-results/greentea_comparison_$(date +%Y%m%d_%H%M%S).txt
	@echo "✅ GreenTea GC comparison completed!"
	@echo "Results saved to comparison-results/greentea_comparison_*.txt"
	@echo "View comparison: cat comparison-results/greentea_comparison_*.txt"

# GreenTea GC profile viewers
pprof-cpu-greentea:
	@echo "Launching GreenTea GC CPU profile viewer..."
	@greentea_profile=$$(ls -t profiles/greentea/greentea_cpu_*.out | head -1); \
	if [ -z "$$greentea_profile" ]; then echo "No GreenTea CPU profile found. Run 'make bench-greentea-cpu' first."; exit 1; fi; \
	go tool pprof -http=:0 $$greentea_profile

pprof-alloc-greentea:
	@echo "Launching GreenTea GC allocation profile viewer..."
	@greentea_profile=$$(ls -t profiles/greentea/greentea_mem_*.out | head -1); \
	if [ -z "$$greentea_profile" ]; then echo "No GreenTea memory profile found. Run 'make bench-greentea-memory' first."; exit 1; fi; \
	go tool pprof -alloc_space -http=:0 $$greentea_profile

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

# === Enhanced Performance Monitoring ===

# Run comprehensive performance suite
performance-suite:
	@echo "=== Running Comprehensive Performance Suite ==="
	@./scripts/performance_monitor.sh run

# Performance monitoring with comparison
performance-monitor:
	@echo "=== Performance Monitoring with Regression Detection ==="
	@./scripts/performance_monitor.sh run
	@echo ""
	@echo "=== Checking for Regressions ==="
	@./scripts/performance_monitor.sh compare

# Update performance baseline
performance-baseline:
	@echo "=== Updating Performance Baseline ==="
	@./scripts/performance_monitor.sh run
	@./scripts/performance_monitor.sh baseline
	@echo ""
	@echo "✅ Performance baseline updated successfully"

# Compare with existing baseline
performance-compare:
	@echo "=== Performance Comparison ==="
	@./scripts/performance_monitor.sh compare

# Generate performance dashboard
performance-dashboard:
	@echo "=== Generating Performance Dashboard ==="
	@./scripts/performance_monitor.sh dashboard

# Clean up old performance data
performance-cleanup:
	@echo "=== Cleaning Performance Data ==="
	@./scripts/performance_monitor.sh cleanup 30

# === Component-Specific Benchmarks ===

# ACAutomaton performance benchmarks (CRITICAL COMPONENT)
perf-automaton:
	@echo "=== ACAutomaton Performance Benchmarks ==="
	@mkdir -p performance-results
	@echo "Testing ACAutomaton core performance..."
	@go test -bench=BenchmarkMicro.* -benchmem -benchtime=5s -count=3 -run=^$ ./compiler > performance-results/automaton_$(date +%Y%m%d_%H%M%S).txt
	@echo "Running memory profiling..."
	@go test -bench=BenchmarkMicro_StringMatching_PerformanceRegression -memprofile=performance-results/automaton_mem_$(date +%Y%m%d_%H%M%S).out -run=^$ ./compiler
	@echo "ACAutomaton benchmarks completed!"
	@echo "Results saved to performance-results/"

# End-to-end performance benchmarks
perf-e2e:
	@echo "=== End-to-End Performance Benchmarks ==="
	@mkdir -p performance-results
	@echo "Testing end-to-end performance..."
	@go run simple_benchmark.go -iterations 1000 -verbose > performance-results/e2e_$(date +%Y%m%d_%H%M%S).txt
	@echo "E2E benchmarks completed!"
	@echo "Results saved to performance-results/"

# Scaling analysis benchmarks
perf-scaling:
	@echo "=== Scaling Performance Analysis ==="
	@mkdir -p performance-results
	@echo "Testing scaling performance..."
	@go run scaling_analysis.go > performance-results/scaling_$(date +%Y%m%d_%H%M%S).txt
	@echo "Scaling analysis completed!"
	@echo "Results saved to performance-results/"

# Quick performance check (CI-friendly)
perf-quick:
	@echo "=== Quick Performance Check ==="
	@echo "ACAutomaton performance:"
	@go test -bench=BenchmarkMicro_StringMatching_PerformanceRegression -benchmem -run=^$$ ./compiler
	@echo ""
	@echo "E2E performance:"
	@cd cmd/performance && go run simple_benchmark.go -iterations 100

# Performance regression check (stricter than CI)
perf-regression:
	@echo "=== Performance Regression Check ==="
	@echo "Checking for performance regressions against stored baseline..."
	@if [ ! -f performance-data/baselines/latest_baseline.txt ]; then \
		echo "No baseline found. Running performance-suite first..."; \
		$(MAKE) performance-suite; \
	fi
	@./scripts/performance_monitor.sh compare
	@echo ""
	@echo "✅ No performance regressions detected"

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
	@echo "  bench-vs-yarax       - Run the go-yara/yara-x matrix tournament"
	@echo "  bench-vs-yarax-update-baseline - Review and replace the tournament baseline"
	@echo ""
	@echo "Enhanced Performance Monitoring:"
	@echo "  performance-suite     - Run comprehensive performance suite"
	@echo "  performance-monitor    - Run suite with regression detection"
	@echo "  performance-baseline   - Update performance baseline"
	@echo "  performance-compare   - Compare with baseline"
	@echo "  performance-dashboard  - Generate HTML dashboard"
	@echo "  performance-cleanup   - Clean old data (30 days)"
	@echo ""
	@echo "Component-Specific Benchmarks:"
	@echo "  perf-automaton       - ACAutomaton performance (CRITICAL)"
	@echo "  perf-e2e            - End-to-end performance"
	@echo "  perf-scaling        - Scaling analysis"
	@echo "  perf-quick          - Quick performance check"
	@echo "  perf-regression     - Strict regression check"
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
	@echo "Go 1.25 GreenTea GC Optimizations:"
	@echo "  bench-greentea     - Run benchmarks with GreenTea GC"
	@echo "  bench-greentea-memory - GreenTea GC memory profiling"
	@echo "  bench-greentea-cpu - GreenTea GC CPU profiling"
	@echo "  perf-greentea-compare - Compare GreenTea GC vs standard GC"
	@echo "  pprof-cpu-greentea - View GreenTea GC CPU profiles"
	@echo "  pprof-alloc-greentea - View GreenTea GC allocation profiles"
	@echo ""
	@echo "Regression Testing:"
	@echo "  bench-save-baseline    - Save current benchmark as baseline"
	@echo "  bench-regression       - Test against baseline"
	@echo "  bench-check-regression - Check for performance regressions"
	@echo ""
	@echo "Comparison:"
	@echo "  benchstat BASE=old.txt NEW=new.txt - Compare two benchmark files"
	@echo "  bench-compare OLD=old.txt NEW=new.txt - Compare with automatic benchstat"
	@echo ""
	@echo "Go-YARA vs Reference YARA:"
	@echo "  compare-yara       - Run comprehensive go-yara vs yara comparison"
	@echo "  compare-yara-quick - Quick comparison with reduced test set"
	@echo "  compare-yara-deep  - Deep comparison with comprehensive testing"
	@echo "  compare-yara-report - Generate detailed comparison report"

# Go-YARA vs Reference YARA comparison
compare-yara:
	@echo "Running comprehensive go-yara vs reference YARA comparison..."
	@mkdir -p comparison-results
	@go run ./cmd/compare -rules "internal/profiling/comparison/testdata,examples" -data "internal/profiling/comparison/testdata" -verbose -output comparison-results/results.json -report comparison-results/report.txt
	@echo "Comparison complete. Results saved to comparison-results/"
	@echo "View detailed report: cat comparison-results/report.txt"

# Quick comparison for rapid testing
compare-yara-quick:
	@echo "Running quick go-yara vs reference YARA comparison..."
	@mkdir -p comparison-results
	@go run ./cmd/compare -rules "internal/profiling/comparison/testdata" -data "internal/profiling/comparison/testdata" -quick -output comparison-results/quick-results.json -report comparison-results/quick-report.txt
	@echo "Quick comparison complete. Results saved to comparison-results/"

# Deep comparison for comprehensive analysis
compare-yara-deep:
	@echo "Running deep go-yara vs reference YARA comparison..."
	@mkdir -p comparison-results
	@go run ./cmd/compare -rules "examples,testdata" -data "testdata" -deep -verbose -output comparison-results/deep-results.json -report comparison-results/deep-report.txt
	@echo "Deep comparison complete. Results saved to comparison-results/"

# Generate detailed comparison report with profiling
compare-yara-report:
	@echo "Generating detailed go-yara vs reference YARA comparison report with profiling..."
	@mkdir -p comparison-results
	@go run ./cmd/compare -rules "internal/profiling/comparison/testdata,examples" -data "internal/profiling/comparison/testdata" -verbose -profile-cpu -profile-mem -profile-allocs -output comparison-results/detailed-results.json -report comparison-results/detailed-report.txt
	@echo "Detailed comparison complete. Results saved to comparison-results/"
	@echo "Files generated:"
	@echo "  - JSON data: comparison-results/detailed-results.json"
	@echo "  - Human report: comparison-results/detailed-report.txt"
	@echo ""
	@echo "Key findings:"
	@if [ -f comparison-results/detailed-report.txt ]; then \
		grep -E "(Speedup|Reduction|Score|Accuracy)" comparison-results/detailed-report.txt | head -10; \
	fi
