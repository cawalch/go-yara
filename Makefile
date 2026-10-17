.PHONY: build build-simd clean check test test-all test-race test-simd test-bugproof coverage \
	vet analyze lint lint-fix fmt fmt-check tidy tidy-check fix fuzz \
	bench bench-save benchstat bench-scan bench-simd bench-prefilter-scale \
	bench-single-rule-size profile-scan trace-scan help

PKG ?= ./compiler
BENCH ?= .
BENCHTIME ?= 1s
COUNT ?= 1
FUZZTIME ?= 30s
BIN_DIR ?= ./bin

build:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -o $(BIN_DIR)/go-yara ./cmd

build-simd:
	@mkdir -p $(BIN_DIR)
	GOEXPERIMENT=simd go build -trimpath -o $(BIN_DIR)/go-yara ./cmd

clean:
	rm -rf $(BIN_DIR) profiles/*.out benchmarks/*.txt coverage.out coverage.html *.test go-yara-diff-findings.jsonl

check: fmt-check tidy-check vet analyze lint vulncheck test

test:
	go test ./...

test-all: test test-bugproof

test-race:
	go test -race ./...

test-simd:
	GOEXPERIMENT=simd go test ./compiler -run TestByteSearch -count=1

test-bugproof:
	go test -tags bugproof -race ./tests/integration/ -run TestBug

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

vet:
	go vet ./...

analyze:
	go run ./cmd/go-yara-analyzers ./...

lint:
	golangci-lint run --config=.golangci.yml

lint-fix:
	golangci-lint run --config=.golangci.yml --fix

fmt:
	@gofmt -s -w .
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w -local github.com/cawalch/go-yara .; \
	else \
		echo "goimports not found; install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi

tidy:
	go mod tidy

fix: fmt tidy lint-fix

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

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

bench-simd:
	GOEXPERIMENT=simd go test ./compiler -run '^$$' \
		-bench '^BenchmarkSIMD' \
		-benchmem -count=3

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
	@echo "Build targets:"
	@echo "  build                  Build the go-yara CLI binary under bin/"
	@echo "  build-simd             Build the go-yara CLI binary with SIMD enabled (Go 1.27+)"
	@echo "  clean                  Remove build outputs, test coverage, and profiling dumps"
	@echo ""
	@echo "Validation & testing targets:"
	@echo "  check                  Run formatting, tidy, vet, analyzers, lint, vulncheck, and tests"
	@echo "  test                   Run the full unit test suite"
	@echo "  test-all               Run the unit tests and libyara bugproof differential suite"
	@echo "  test-race              Run the full test suite with the race detector"
	@echo "  test-simd              Run SIMD byte search tests (Go 1.27+)"
	@echo "  test-bugproof          Run the libyara 4.5.8 differential proof test suite"
	@echo "  coverage               Generate HTML test coverage report (coverage.html)"
	@echo "  analyze                Run repository-specific static analyzers"
	@echo "  fuzz FUZZTIME=30s      Run every fuzz target sequentially"
	@echo ""
	@echo "Formatting & code hygiene targets:"
	@echo "  fmt                    Format Go source files with gofmt and goimports"
	@echo "  fmt-check              Verify code is properly formatted"
	@echo "  tidy                   Run go mod tidy"
	@echo "  tidy-check             Verify go.mod and go.sum are tidy"
	@echo "  lint-fix               Run linters and apply automatic fixes"
	@echo "  fix                    Run fmt, tidy, and lint-fix in one step"
	@echo ""
	@echo "Benchmark targets:"
	@echo "  bench                  Run benchmarks (PKG=./compiler BENCH=. by default)"
	@echo "  bench-save             Save benchmark output under benchmarks/"
	@echo "  benchstat BASE=... NEW=..."
	@echo "  bench-scan             Run core scanner benchmarks"
	@echo "  bench-simd             Run experimental SIMD benchmarks (Go 1.27+)"
	@echo "  bench-prefilter-scale"
	@echo "  bench-single-rule-size"
	@echo "  profile-scan           Generate scanner CPU and memory profiles"
	@echo "  trace-scan             Generate scanner execution trace"
