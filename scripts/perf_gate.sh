#!/usr/bin/env bash
set -euo pipefail

BASE_REF="${PERF_BASE_REF:-}"
BENCHTIME="${PERF_BENCHTIME:-100ms}"
COUNT="${PERF_COUNT:-6}"
RUN_SIMD="${PERF_SIMD:-1}"
MAX_SEC_REGRESSION_PCT="${MAX_SEC_REGRESSION_PCT:-25}"
MAX_ALLOC_PCT="${MAX_ALLOC_PCT:-15}"

SCALAR_PATTERNS=(
    '^BenchmarkHexJumpLargeRange$'
    '^BenchmarkRegexMaxMatchSpan$'
    '^BenchmarkRegexAtomlessRecords$/^printable$/^(Matches|Scan)$/^bytes=65536$'
    '^BenchmarkHighEPSSelectivity$/^(literal|regex|mixed)$/^((clean|sparse|dense|near_miss))$'
    '^BenchmarkHighEPSMatchingRulesSelectivity$/^mixed$/^(sparse|dense)$'
    '^BenchmarkHighEPSParallel10K$/^mixed$/^(sparse|dense)$'
    '^BenchmarkHighEPSGateThenScan$/^mixed$/^(sparse|dense)$'
    '^BenchmarkPrefilterRejectScale$/^rules=64$/^strings=12$'
    '^BenchmarkEvidenceScanPaths$/^(normal|match_heavy_evidence_enabled|match_heavy_borrowed_evidence_enabled)$'
    '^BenchmarkCorpusPrefixAtoms$/^rules=512$/^(clean|shared_atom|match)$'
    '^(BenchmarkStreamingScan_1MB|BenchmarkMatchesReaderEarlyTermination_10MB)$'
)
SIMD_PATTERNS=(
    '^BenchmarkHighEPSSelectivity$/^(literal|regex|mixed)$/^clean$'
    '^BenchmarkHighEPSParallel10K$/^mixed$/^(sparse|dense)$'
)

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --base) BASE_REF="$2"; shift ;;
        --benchtime) BENCHTIME="$2"; shift ;;
        --count) COUNT="$2"; shift ;;
        --no-simd) RUN_SIMD=0 ;;
        *) echo "usage: $0 [--base <git-ref>] [--benchtime <dur>] [--count <n>] [--no-simd]" >&2; exit 2 ;;
    esac
    shift
done

REPO_ROOT=$(git rev-parse --show-toplevel)
TMP_DIR=$(mktemp -d)
BASE_WT=""

cleanup() {
    if [[ -n "$BASE_WT" ]]; then
        git -C "$REPO_ROOT" worktree remove --force "$BASE_WT" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ensure_benchstat() {
    if command -v benchstat >/dev/null 2>&1; then
        return 0
    fi
    echo "Installing benchstat..."
    go install golang.org/x/perf/cmd/benchstat@v0.0.0-20261117185222-4febdb082b2c
    export PATH="$(go env GOPATH)/bin:$PATH"
}

run_benches() {
    local dir="$1"
    local out_scalar="$2"
    local out_simd="$3"
    local bin_scalar="$TMP_DIR/compiler_scalar.test"
    local bin_simd="$TMP_DIR/compiler_simd.test"
    (
        cd "$dir"
        go test -c -o "$bin_scalar" ./compiler
        : > "$out_scalar"
        for pat in "${SCALAR_PATTERNS[@]}"; do
            "$bin_scalar" -test.run '^$' -test.bench "$pat" -test.benchmem -test.benchtime="$BENCHTIME" -test.count="$COUNT" >> "$out_scalar"
        done
        # A new or renamed benchmark must not silently disappear on either side
        # of the comparison (benchstat otherwise accepts unmatched rows).
        python3 - "$out_scalar" "$COUNT" <<'PY'
import collections
import re
import sys

expected = {
    "max_int32_no_match", "wildcard_then_missing_no_match",
    "repeated_prefix_then_missing_no_match", "unbounded_no_match",
    "max_int32_match_at_end",
}
samples = collections.Counter()
with open(sys.argv[1]) as source:
    for line in source:
        match = re.match(r'^BenchmarkHexJumpLargeRange/([^\s]+)-\d+\s+\d+\s+[\d.]+\s+ns/op\b', line)
        if match:
            samples[match[1]] += 1
if set(samples) != expected or any(n != int(sys.argv[2]) for n in samples.values()):
    sys.exit(f"Incomplete hex-jump benchmark samples in {sys.argv[1]}: {dict(samples)}")
PY
        if [[ "$dir" == "$REPO_ROOT" ]]; then
            python3 - "$out_scalar" "$COUNT" <<'PYGATE'
import collections
import re
import statistics
import sys

samples = collections.defaultdict(list)
with open(sys.argv[1]) as source:
    for line in source:
        match = re.match(r'^BenchmarkRegexMaxMatchSpan/span=(\d+)(?:-\d+)?\s+\d+\s+([\d.]+)\s+ns/op\b', line)
        if match:
            samples[int(match[1])].append(float(match[2]))
if set(samples) != {0, 256, 4096, 65536} or any(len(v) != int(sys.argv[2]) for v in samples.values()):
    sys.exit("Incomplete regex span benchmark samples")
ratio = statistics.median(samples[4096]) / statistics.median(samples[0])
print(f"Regex span=4096 / default time ratio: {ratio:.2f}")
if ratio > 2:
    sys.exit("Regex span=4096 exceeded twice the default scan time")
PYGATE
        fi
        if [[ "$RUN_SIMD" = "1" ]]; then
            GOEXPERIMENT=simd go test -c -o "$bin_simd" ./compiler
            : > "$out_simd"
            for pat in "${SIMD_PATTERNS[@]}"; do
                "$bin_simd" -test.run '^$' -test.bench "$pat" -test.benchmem -test.benchtime="$BENCHTIME" -test.count="$COUNT" >> "$out_simd"
            done
        fi
    )
}

check_benchstat_regression() {
    local label="$1"
    local base_file="$2"
    local head_file="$3"
    local csv_file="$TMP_DIR/${label}.csv"
    local txt_file="$TMP_DIR/${label}.txt"

    benchstat -alpha 0.05 "$base_file" "$head_file" > "$txt_file"
    benchstat -alpha 0.05 -format csv "$base_file" "$head_file" > "$csv_file"

    echo ""
    echo "=== Performance Gate ($label) ==="
    cat "$txt_file"

    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        {
            echo "### Performance Gate ($label)"
            echo '```text'
            cat "$txt_file"
            echo '```'
        } >> "$GITHUB_STEP_SUMMARY"
    fi

    python3 - "$csv_file" "$MAX_SEC_REGRESSION_PCT" "$MAX_ALLOC_PCT" <<'PY'
import csv
import re
import sys

csv_path = sys.argv[1]
max_sec_pct = float(sys.argv[2])
max_alloc_pct = float(sys.argv[3])

def parse_pct(s):
    s = s.strip()
    if not s or s == "~" or s == "?":
        return None
    m = re.match(r'^([+-]?\d+(?:\.\d+)?)%$', s)
    return float(m.group(1)) if m else None

def parse_p(s):
    m = re.search(r'p=(\d+(?:\.\d+)?)', s)
    return float(m.group(1)) if m else 1.0

def parse_num(s):
    token = s.strip().split()[0] if s.strip() else ""
    if not token:
        return None
    multipliers = [
        ("Gi", 1024**3), ("Mi", 1024**2), ("Ki", 1024),
        ("ns", 1e-9), ("us", 1e-6), ("µs", 1e-6), ("ms", 1e-3),
        ("G", 1e9), ("M", 1e6), ("k", 1e3),
        ("n", 1e-9), ("µ", 1e-6), ("u", 1e-6), ("m", 1e-3), ("s", 1.0),
    ]
    for suffix, mult in multipliers:
        if token.endswith(suffix):
            try:
                return float(token[:-len(suffix)]) * mult
            except ValueError:
                return None
    try:
        return float(token)
    except ValueError:
        return None

section = ""
failures = []
with open(csv_path, newline="") as fh:
    reader = csv.reader(fh)
    for row in reader:
        if not row:
            continue
        if len(row) >= 2 and row[0] == "" and row[1] in ("sec/op", "B/op", "allocs/op", "B/s"):
            section = row[1]
            continue
        if row[0].startswith(("goos:", "goarch:", "pkg:", "cpu:", "geomean", "¹", "²", "³", "⁴")):
            continue
        if section not in ("sec/op", "B/op", "allocs/op") or len(row) < 6:
            continue
        name = row[0]
        base_val = parse_num(row[1])
        head_val = parse_num(row[3])
        delta_str = row[5]
        p_str = row[6] if len(row) > 6 else ""
        if base_val is None or head_val is None:
            continue
        pct = parse_pct(delta_str)
        p_val = parse_p(p_str)

        if section == "sec/op":
            if pct is not None and p_val < 0.05 and pct > max_sec_pct:
                failures.append(f"{name} [sec/op]: +{pct:.2f}% (p={p_val:.3f}) exceeds +{max_sec_pct:.1f}% limit ({base_val} -> {head_val})")
        elif section == "allocs/op":
            if base_val == 0 and head_val >= 1:
                failures.append(f"{name} [allocs/op]: broke zero-allocation invariant ({base_val:.0f} -> {head_val:.0f})")
            elif pct is not None and p_val < 0.05 and pct > max_alloc_pct and (head_val - base_val) >= 1:
                failures.append(f"{name} [allocs/op]: +{pct:.2f}% (p={p_val:.3f}) ({base_val:.1f} -> {head_val:.1f})")
        elif section == "B/op":
            if base_val <= 64 and head_val - base_val > 16 and (p_val < 0.05 or head_val >= 64):
                failures.append(f"{name} [B/op]: {base_val:.0f} -> {head_val:.0f} (+{head_val - base_val:.0f} B)")
            elif base_val > 64 and pct is not None and p_val < 0.05 and pct > max_alloc_pct:
                failures.append(f"{name} [B/op]: +{pct:.2f}% (p={p_val:.3f}) ({base_val:.0f} -> {head_val:.0f})")

if failures:
    print("\nPERFORMANCE REGRESSION DETECTED:", file=sys.stderr)
    for item in failures:
        print(f"  - {item}", file=sys.stderr)
    sys.exit(1)
print("No statistically significant performance or allocation regressions detected.")
PY
}

echo "Running deterministic zero-allocation contract tests..."
go test ./compiler -run '^TestHighEPSZeroAllocationContracts$' -count=1

ensure_benchstat

HEAD_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD)
RESOLVED_BASE=""
if [[ -n "$BASE_REF" ]]; then
    RESOLVED_BASE=$(git -C "$REPO_ROOT" rev-parse --verify "$BASE_REF" 2>/dev/null || true)
fi

if [[ -z "$RESOLVED_BASE" ]] || { [[ "$RESOLVED_BASE" = "$HEAD_SHA" ]] && [[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]]; }; then
    echo "No distinct base commit provided; running standalone benchmark snapshot."
    run_benches "$REPO_ROOT" "$TMP_DIR/head_scalar.txt" "$TMP_DIR/head_simd.txt"
    cat "$TMP_DIR/head_scalar.txt"
    if [[ "$RUN_SIMD" = "1" ]]; then
        cat "$TMP_DIR/head_simd.txt"
    fi
    exit 0
fi

echo "Comparing HEAD against base $RESOLVED_BASE..."
BASE_WT="$TMP_DIR/base_wt"
git -C "$REPO_ROOT" worktree add --detach "$BASE_WT" "$RESOLVED_BASE" >/dev/null

# Measure identical synthetic inputs even when the base predates this benchmark.
# Only the test harness is copied; the baseline scanner implementation is intact.
cp "$REPO_ROOT/compiler/hex_jump_bench_test.go" "$BASE_WT/compiler/hex_jump_bench_test.go"
cp "$REPO_ROOT/compiler/regex_span_bench_test.go" "$BASE_WT/compiler/regex_span_bench_test.go"

run_benches "$BASE_WT" "$TMP_DIR/base_scalar.txt" "$TMP_DIR/base_simd.txt"
run_benches "$REPO_ROOT" "$TMP_DIR/head_scalar.txt" "$TMP_DIR/head_simd.txt"

check_benchstat_regression "scalar" "$TMP_DIR/base_scalar.txt" "$TMP_DIR/head_scalar.txt"
if [[ "$RUN_SIMD" = "1" ]]; then
    check_benchstat_regression "simd" "$TMP_DIR/base_simd.txt" "$TMP_DIR/head_simd.txt"
fi
