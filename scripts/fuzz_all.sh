#!/usr/bin/env bash
set -euo pipefail

# Default values
FUZZTIME="30s"
VERBOSE=false
TOTAL_TARGETS=0
FAILED_COUNT=0
LOG_DIR=$(mktemp -d)
trap 'rm -rf "$LOG_DIR"' EXIT

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE=true ;;
        -t|--time) FUZZTIME="$2"; shift ;;
        *) echo "usage: $0 [--time duration] [--verbose]" >&2; exit 2 ;;
    esac
    shift
done

echo "🔍 Finding all fuzz targets in the repository..."

# Find all packages with Fuzz functions
PACKAGE_FILE="$LOG_DIR/packages.txt"
TARGET_FILE="$LOG_DIR/targets.txt"
FAILED_FILE="$LOG_DIR/failed_list.txt"

while IFS= read -r -d '' file; do
    if grep -q "func Fuzz" "$file"; then
        dirname "$file"
    fi
done < <(find . -name "*_test.go" -not -path "*/.*" -print0) | sort -u > "$PACKAGE_FILE"

if [ ! -s "$PACKAGE_FILE" ]; then
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

TOTAL_TARGETS_COUNT=$(wc -l < "$TARGET_FILE" | xargs)

# Use while read to iterate over the lines
while IFS= read -r item; do
    pkg_path="${item%%:*}"
    target="${item#*:}"

    TOTAL_TARGETS=$((TOTAL_TARGETS + 1))
    printf "🏃 [%-2d/%-2d] Running %-35s ... " "$TOTAL_TARGETS" "$TOTAL_TARGETS_COUNT" "$target"

    LOG_FILE="$LOG_DIR/${target}.log"

    # Run fuzz test
    if go test -v "$pkg_path" -run=^$ -fuzz="^${target}$" -fuzztime="$FUZZTIME" > "$LOG_FILE" 2>&1; then
        printf "✅ PASS\n"
        if [ "$VERBOSE" = true ]; then
            cat "$LOG_FILE"
        fi
    else
        printf "❌ FAILED\n"
        echo "$pkg_path: $target" >> "$FAILED_FILE"

        echo "----------------------------------------------------------------"
        echo "🚨 FAILURE DETAILS: $target"

        CRASH_LINE=$(grep "failing input written to" "$LOG_FILE" || true)
        if [ -n "$CRASH_LINE" ]; then
            CRASH_FILE=${CRASH_LINE##*failing input written to }
            echo "📁 Crashing input: $CRASH_FILE"
        fi

        echo "📝 Log output (filtered):"
        grep -vE "^(fuzz: elapsed:|    --- PASS:|=== RUN)" "$LOG_FILE" | grep -v "^$" | tail -n 20 || true
        echo "----------------------------------------------------------------"
    fi
done < "$TARGET_FILE"

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
