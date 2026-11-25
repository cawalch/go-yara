#!/usr/bin/env bash
set -euo pipefail

# Default values
FUZZTIME="${FUZZTIME:-30s}"
PACKAGES="${FUZZ_PACKAGES:-}"
VERBOSE=false
SHARD_INDEX=0
SHARD_COUNT=1
LIST_ONLY=false
REQUIRE_ORACLE=false
TOTAL_TARGETS=0
FAILED_COUNT=0
if [ -n "${FUZZ_LOG_DIR:-}" ]; then
    LOG_DIR="$FUZZ_LOG_DIR"
    mkdir -p "$LOG_DIR"
else
    LOG_DIR=$(mktemp -d)
    trap 'rm -rf "$LOG_DIR"' EXIT
fi

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE=true ;;
        --shard-index) SHARD_INDEX="$2"; shift ;;
        --shard-count) SHARD_COUNT="$2"; shift ;;
        --list) LIST_ONLY=true ;;
        --require-oracle) REQUIRE_ORACLE=true ;;
        -t|--time) FUZZTIME="$2"; shift ;;
        -p|--packages) PACKAGES="$2"; shift ;;
        *) echo "usage: $0 [--time duration] [--packages pkg1,pkg2] [--verbose] [--shard-index n --shard-count n] [--list] [--require-oracle]" >&2; exit 2 ;;
    esac
    shift
done

if ! [[ "$SHARD_INDEX" =~ ^[0-9]+$ && "$SHARD_COUNT" =~ ^[0-9]+$ ]]; then
    echo "Shard index/count must be non-negative integers" >&2
    exit 2
fi
SHARD_INDEX=$((10#$SHARD_INDEX))
SHARD_COUNT=$((10#$SHARD_COUNT))
if (( SHARD_COUNT < 1 || SHARD_INDEX >= SHARD_COUNT )); then
    echo "Shard index must be smaller than the positive shard count" >&2
    exit 2
fi

if [ "$LIST_ONLY" = false ]; then
    echo "🔍 Finding fuzz targets in the repository..."
fi

# Find all packages with Fuzz functions
PACKAGE_FILE="$LOG_DIR/packages.txt"
TARGET_FILE="$LOG_DIR/targets.txt"
FAILED_FILE="$LOG_DIR/failed_list.txt"
rm -f "$FAILED_FILE"

is_fuzz_deadline_race() {
    local log_file="$1"

    # Go issue #75804 can turn the fuzz duration's normal shutdown into a
    # spurious failure. Real fuzz failures either write a crashing input or
    # report a different error, so retry only this exact coordinator error.
    ! grep -qi "failing input written to" "$log_file" &&
        grep -Eq '^[[:space:]]+context deadline exceeded$' "$log_file"
}

if [ -n "$PACKAGES" ] && [ "$PACKAGES" != "all" ]; then
    : > "$PACKAGE_FILE"
    for pkg in ${PACKAGES//,/ }; do
        pkg="${pkg#./}"
        if [ -d "$pkg" ] && grep -rq "func Fuzz" "$pkg"/*_test.go 2>/dev/null; then
            echo "./$pkg" >> "$PACKAGE_FILE"
        fi
    done
    sort -u -o "$PACKAGE_FILE" "$PACKAGE_FILE"
else
    while IFS= read -r -d '' file; do
        if grep -q "func Fuzz" "$file"; then
            dirname "$file"
        fi
    done < <(find . -name "*_test.go" -not -path "*/.*" -print0) | sort -u > "$PACKAGE_FILE"
fi

if [ ! -s "$PACKAGE_FILE" ]; then
    if [ -n "$PACKAGES" ] && [ "$PACKAGES" != "all" ]; then
        if [ "$LIST_ONLY" = false ]; then
            echo "ℹ️  No fuzz targets in requested packages ($PACKAGES); skipping."
        fi
        exit 0
    fi
    echo "❌ No fuzz targets found."
    exit 1
fi

# Pre-calculate all [package]:[target] pairs
: > "$TARGET_FILE"
while IFS= read -r pkg; do
    pkg_path=$(go list "$pkg")
    pkg_target_file="$LOG_DIR/$(echo "$pkg_path" | tr '/:' '__').targets"
    go test -list '^Fuzz' "$pkg_path" > "$pkg_target_file"
    while IFS= read -r target; do
        if [ -n "$target" ]; then
            echo "$pkg_path:$target" >> "$TARGET_FILE"
        fi
    done < <(grep '^Fuzz' "$pkg_target_file" || true)
done < "$PACKAGE_FILE"

if [ ! -s "$TARGET_FILE" ]; then
    echo "❌ No fuzz targets found."
    exit 1
fi

# Stable round-robin partition of the selected inventory, including small sets.
LC_ALL=C sort -u -o "$TARGET_FILE" "$TARGET_FILE"
SELECTED_COUNT=$(wc -l < "$TARGET_FILE" | xargs)
SHARD_FILE="$LOG_DIR/shard.txt"
awk -v shard="$SHARD_INDEX" -v count="$SHARD_COUNT" '(NR - 1) % count == shard' "$TARGET_FILE" > "$SHARD_FILE"
if [ "$LIST_ONLY" = true ]; then
    cat "$SHARD_FILE"
    exit 0
fi
TOTAL_TARGETS_COUNT=$(wc -l < "$SHARD_FILE" | xargs)
echo "Shard $SHARD_INDEX/$SHARD_COUNT: $TOTAL_TARGETS_COUNT of $SELECTED_COUNT selected targets"
if [ "$TOTAL_TARGETS_COUNT" -eq 0 ]; then
    echo "No targets assigned to this shard."
    exit 0
fi
if [ "$REQUIRE_ORACLE" = true ]; then
    oracle_version=$(yara --version)
    echo "libyara oracle: $oracle_version"
    test "$oracle_version" = "$(cat tests/integration/oracle-version.txt)"
fi

# Use while read to iterate over the lines
while IFS= read -r item; do
    pkg_path="${item%%:*}"
    target="${item#*:}"

    TOTAL_TARGETS=$((TOTAL_TARGETS + 1))
    printf "🏃 [%-2d/%-2d] Running %-35s ... " "$TOTAL_TARGETS" "$TOTAL_TARGETS_COUNT" "$target"

    LOG_FILE="$LOG_DIR/${TOTAL_TARGETS}-$(echo "$pkg_path:$target" | tr '/:' '__').log"

    # Run fuzz test
    TARGET_PASSED=false
    if go test -v "$pkg_path" -run=^$ -fuzz="^${target}$" -fuzztime="$FUZZTIME" > "$LOG_FILE" 2>&1; then
        TARGET_PASSED=true
    elif is_fuzz_deadline_race "$LOG_FILE"; then
        cp "$LOG_FILE" "$LOG_FILE.first-attempt"
        printf "⚠️  RETRY (Go fuzz deadline race)\n"
        printf "   Retrying %-35s ... " "$target"
        if go test -v "$pkg_path" -run=^$ -fuzz="^${target}$" -fuzztime="$FUZZTIME" > "$LOG_FILE" 2>&1; then
            TARGET_PASSED=true
        fi
    fi

    if [ "$REQUIRE_ORACLE" = true ] && [[ "$target" = FuzzLibyara* ]] &&
        grep -Eq "^--- SKIP: ${target}([[:space:]]|$)" "$LOG_FILE"; then
        echo "Oracle target skipped despite required libyara" >> "$LOG_FILE"
        TARGET_PASSED=false
    fi

    if [ "$TARGET_PASSED" = true ]; then
        printf "✅ PASS\n"
        if [ "$VERBOSE" = true ]; then
            cat "$LOG_FILE"
        fi
    else
        printf "❌ FAILED\n"
        echo "$pkg_path: $target" >> "$FAILED_FILE"

        echo "----------------------------------------------------------------"
        echo "🚨 FAILURE DETAILS: $target"

        CRASH_LINE=$(grep -i "failing input written to" "$LOG_FILE" || true)
        if [ -n "$CRASH_LINE" ]; then
            CRASH_FILE=${CRASH_LINE##*written to }
            echo "📁 Crashing input: $CRASH_FILE"
        fi

        echo "📝 Log output (filtered):"
        grep -vE "^(fuzz: elapsed:|    --- PASS:|=== RUN)" "$LOG_FILE" | grep -v "^$" | tail -n 20 || true
        echo "----------------------------------------------------------------"
    fi
done < "$SHARD_FILE"

if [ -f "$FAILED_FILE" ]; then
    FAILED_COUNT=$(wc -l < "$FAILED_FILE" | xargs)
else
    FAILED_COUNT=0
fi

echo ""
echo "================================================================"
echo "📊 FUZZING SUMMARY"
echo "================================================================"
echo "Total targets run: $TOTAL_TARGETS_COUNT"
echo "Total passed:     $((TOTAL_TARGETS_COUNT - FAILED_COUNT))"
echo "Total failed:     $FAILED_COUNT"

if [ "$FAILED_COUNT" -ne 0 ]; then
    echo ""
    echo "❌ FAILED TARGETS:"
    sed 's/^/  - /' "$FAILED_FILE"
    exit 1
fi

echo ""
echo "✨ All fuzz targets passed!"
exit 0
