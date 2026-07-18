.PHONY: check test test-race vet lint fmt-check tidy-check fuzz \
	bench bench-save benchstat bench-scan bench-prefilter-scale \
	bench-single-rule-size profile-scan trace-scan help

PKG ?= ./compiler
BENCH ?= .
BENCHTIME ?= 1s
COUNT ?= 1
FUZZTIME ?= 30s

check: fmt-check tidy-check vet lint test

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run --config=.golangci.yml

fmt-check:
	@files="$$(gofmt -s -l .)"; \
	if [ -n "$$files" ]; then \
		echo "The following files need gofmt:"; \
		echo "$$files"; \
		exit 1; \
	fi
	@if command -v goimports >/dev/null 2>&1; then \
		files="$$(goimports -l .)"; \
		if [ -n "$$files" ]; then \
			echo "The following files need goimports:"; \
			echo "$$files"; \
			exit 1; \
		fi; \
	else \
		echo "goimports not found; install golang.org/x/tools/cmd/goimports"; \
		exit 1; \
	fi

tidy-check:
	@diff="$$(go mod tidy -diff)"; \
	if [ -n "$$diff" ]; then \
		echo "go.mod or go.sum is not tidy:"; \
		echo "$$diff"; \
		exit 1; \
	fi

fuzz:
	./scripts/fuzz_all.sh --time "$(FUZZTIME)"

bench:
	go test "$(PKG)" -run '^$$' -bench '$(BENCH)' -benchmem \
		-benchtime="$(BENCHTIME)" -count="$(COUNT)"

bench-save:
	@mkdir -p benchmarks
	@out="benchmarks/bench_$$(date +%Y%m%d_%H%M%S).txt"; \
	echo "Writing $$out"; \
	go test "$(PKG)" -run '^$$' -bench '$(BENCH)' -benchmem \
		-benchtime="$(BENCHTIME)" -count="$(COUNT)" > "$$out"

benchstat:
	@if ! command -v benchstat >/dev/null 2>&1; then \
		echo "benchstat not found; install golang.org/x/perf/cmd/benchstat"; \
		exit 1; \
	fi
	@test -n "$(BASE)" -a -n "$(NEW)" || \
		(echo "usage: make benchstat BASE=old.txt NEW=new.txt"; exit 2)
	benchstat "$(BASE)" "$(NEW)"

bench-scan:
	go test ./compiler -run '^$$' \
		-bench '^Benchmark(ProductionScanner|ProductionScannerUniquePatterns|MultiRuleScanner)$$' \
		-benchmem -count=5

bench-prefilter-scale:
	go test ./compiler -run '^$$' -bench '^BenchmarkSharedNonTextPrefilterScale$$' \
		-benchmem -count=5

bench-single-rule-size:
	go test ./compiler -run '^$$' -bench '^BenchmarkSingleRuleScanSize$$' \
		-benchmem -count=5

profile-scan:
	@mkdir -p profiles
	go test ./compiler -run '^$$' -bench '^BenchmarkProductionScanner$$' \
		-benchtime=5s -cpuprofile profiles/scanner_cpu.out \
		-memprofile profiles/scanner_mem.out

trace-scan:
	@mkdir -p profiles
	go test ./compiler -run '^$$' -bench '^BenchmarkProductionScanner$$' \
		-benchtime=2s -trace profiles/scanner_trace.out

help:
	@echo "Validation targets:"
	@echo "  check                  Run formatting, tidy, vet, lint, and tests"
	@echo "  test                   Run the full test suite"
	@echo "  test-race              Run the full test suite with the race detector"
	@echo "  fuzz FUZZTIME=30s      Run every fuzz target sequentially"
	@echo ""
	@echo "Benchmark targets:"
	@echo "  bench                  Run benchmarks (PKG=./compiler BENCH=. by default)"
	@echo "  bench-save             Save benchmark output under benchmarks/"
	@echo "  benchstat BASE=... NEW=..."
	@echo "  bench-scan"
	@echo "  bench-prefilter-scale"
	@echo "  bench-single-rule-size"
	@echo "  profile-scan"
	@echo "  trace-scan"
