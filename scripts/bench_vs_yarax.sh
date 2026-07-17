#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BENCHTIME=${BENCHTIME:-100ms}
BENCHCOUNT=${BENCHCOUNT:-3}
BENCH_REGEX=${BENCH_REGEX:-^BenchmarkTournament$}
YARAX_VERSION=${YARAX_VERSION:-1.19.0}
TOURNAMENT_MIN_RATIO=${TOURNAMENT_MIN_RATIO:-0.5}
TOURNAMENT_MAX_REGRESSION=${TOURNAMENT_MAX_REGRESSION:-0.25}
TOURNAMENT_CHECK=${TOURNAMENT_CHECK:-1}
TOURNAMENT_CONFIRM_COUNT=${TOURNAMENT_CONFIRM_COUNT:-5}
TOURNAMENT_UPDATE_BASELINE=${TOURNAMENT_UPDATE_BASELINE:-0}
TOURNAMENT_OUT_DIR=${TOURNAMENT_OUT_DIR:-$ROOT_DIR/performance/tournament/results}
TOURNAMENT_BASELINE=${TOURNAMENT_BASELINE:-$ROOT_DIR/performance/tournament/baseline.csv}

mkdir -p "$TOURNAMENT_OUT_DIR"
GOYARA_OUTPUT="$TOURNAMENT_OUT_DIR/goyara.txt"
YARAX_OUTPUT="$TOURNAMENT_OUT_DIR/yarax.txt"
CSV_OUTPUT="$TOURNAMENT_OUT_DIR/current.csv"
MARKDOWN_OUTPUT="$TOURNAMENT_OUT_DIR/current.md"
FAILURE_CELLS_OUTPUT="$TOURNAMENT_OUT_DIR/failure-cells.txt"
CONFIRM_GOYARA_OUTPUT="$TOURNAMENT_OUT_DIR/confirmation-goyara.txt"
CONFIRM_YARAX_OUTPUT="$TOURNAMENT_OUT_DIR/confirmation-yarax.txt"
CONFIRM_CSV_OUTPUT="$TOURNAMENT_OUT_DIR/confirmation.csv"
CONFIRM_MARKDOWN_OUTPUT="$TOURNAMENT_OUT_DIR/confirmation.md"

if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists yara_x_capi; then
	echo "yara_x_capi is required. On macOS: brew install pkgconf yara-x" >&2
	exit 1
fi
CAPI_VERSION=$(pkg-config --modversion yara_x_capi)
BINDING_VERSION=$(cd "$ROOT_DIR/performance/tournament/yarax" && \
	go list -m -f '{{.Version}}' github.com/VirusTotal/yara-x/go)
if [[ "$CAPI_VERSION" != "$YARAX_VERSION" || "$BINDING_VERSION" != "v$YARAX_VERSION" ]]; then
	echo "yara-x version mismatch: want $YARAX_VERSION, C API=$CAPI_VERSION, Go binding=$BINDING_VERSION" >&2
	exit 1
fi
if [[ "$TOURNAMENT_UPDATE_BASELINE" == "1" && "$BENCH_REGEX" != '^BenchmarkTournament$' ]]; then
	echo "refusing to replace the baseline from a filtered benchmark run" >&2
	exit 1
fi

run_goyara() {
	local regex=$1
	local benchtime=$2
	local count=$3
	local output=$4
	echo "Running go-yara tournament with CGO_ENABLED=0"
	(
		cd "$ROOT_DIR"
		CGO_ENABLED=0 go test ./performance/tournament/goyara \
			-run '^$' \
			-bench "$regex" \
			-benchmem \
			-benchtime "$benchtime" \
			-count "$count" \
			-timeout 30m
	) | tee "$output"
}

run_yarax() {
	local regex=$1
	local benchtime=$2
	local count=$3
	local output=$4
	echo "Running yara-x tournament with CGO_ENABLED=1"
	(
		cd "$ROOT_DIR/performance/tournament/yarax"
		CGO_ENABLED=1 go test . \
			-run '^$' \
			-bench "$regex" \
			-benchmem \
			-benchtime "$benchtime" \
			-count "$count" \
			-timeout 30m
	) | tee "$output"
}

run_goyara "$BENCH_REGEX" "$BENCHTIME" "$BENCHCOUNT" "$GOYARA_OUTPUT"
run_yarax "$BENCH_REGEX" "$BENCHTIME" "$BENCHCOUNT" "$YARAX_OUTPUT"

COMPARE_ARGS=(
	-goyara "$GOYARA_OUTPUT"
	-yarax "$YARAX_OUTPUT"
	-csv "$CSV_OUTPUT"
	-markdown "$MARKDOWN_OUTPUT"
	-failure-cells "$FAILURE_CELLS_OUTPUT"
	-min-ratio "$TOURNAMENT_MIN_RATIO"
	-max-regression "$TOURNAMENT_MAX_REGRESSION"
)
if [[ -f "$TOURNAMENT_BASELINE" ]]; then
	COMPARE_ARGS+=(-baseline "$TOURNAMENT_BASELINE")
else
	echo "No baseline found at $TOURNAMENT_BASELINE; producing an unbased report"
fi
(
	cd "$ROOT_DIR"
	go run ./performance/tournament/cmd/compare "${COMPARE_ARGS[@]}"
)

if [[ "$TOURNAMENT_CHECK" == "1" && -s "$FAILURE_CELLS_OUTPUT" ]]; then
	FAILURE_RULE_PATTERN=$(cut -d/ -f1 "$FAILURE_CELLS_OUTPUT" | sort -u | paste -sd '|' -)
	CONFIRM_REGEX="^BenchmarkTournament/(${FAILURE_RULE_PATTERN})$"
	echo "Potential regressions detected; confirming affected rule cases with count=$TOURNAMENT_CONFIRM_COUNT"
	# Reverse engine order in the confirmation pass so host drift cannot
	# consistently favor the same engine in both measurements.
	run_yarax "$CONFIRM_REGEX" "$BENCHTIME" "$TOURNAMENT_CONFIRM_COUNT" "$CONFIRM_YARAX_OUTPUT"
	run_goyara "$CONFIRM_REGEX" "$BENCHTIME" "$TOURNAMENT_CONFIRM_COUNT" "$CONFIRM_GOYARA_OUTPUT"

	CONFIRM_ARGS=(
		-goyara "$CONFIRM_GOYARA_OUTPUT"
		-yarax "$CONFIRM_YARAX_OUTPUT"
		-csv "$CONFIRM_CSV_OUTPUT"
		-markdown "$CONFIRM_MARKDOWN_OUTPUT"
		-check-cells "$FAILURE_CELLS_OUTPUT"
		-min-ratio "$TOURNAMENT_MIN_RATIO"
		-max-regression "$TOURNAMENT_MAX_REGRESSION"
		-check
	)
	if [[ -f "$TOURNAMENT_BASELINE" ]]; then
		CONFIRM_ARGS+=(-baseline "$TOURNAMENT_BASELINE")
	fi
	(
		cd "$ROOT_DIR"
		go run ./performance/tournament/cmd/compare "${CONFIRM_ARGS[@]}"
	)
	echo "Confirmation CSV report: $CONFIRM_CSV_OUTPUT"
	echo "Confirmation Markdown report: $CONFIRM_MARKDOWN_OUTPUT"
fi

if [[ "$TOURNAMENT_UPDATE_BASELINE" == "1" ]]; then
	cp "$CSV_OUTPUT" "$TOURNAMENT_BASELINE"
	echo "Updated baseline: $TOURNAMENT_BASELINE"
fi

echo "CSV report: $CSV_OUTPUT"
echo "Markdown report: $MARKDOWN_OUTPUT"
