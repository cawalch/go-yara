#!/bin/bash

# Default values
FUZZTIME="30s"
VERBOSE=false
FAILED_TARGETS=()
TOTAL_TARGETS=0
FAILED_COUNT=0

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE=true ;;
        -t|--time) FUZZTIME="$2"; shift ;;
        *) FUZZTIME="$1" ;; # Support legacy positional argument
    esac
    shift
done

echo "🔍 Finding all fuzz targets in the repository..."

# Find all packages with Fuzz functions
packages=$(grep -l "func Fuzz" $(find . -name "*_test.go" -not -path "*/.*") | xargs dirname | sort | uniq)

if [ -z "$packages" ]; then
    echo "❌ No fuzz targets found."
    exit 1
fi

# Pre-calculate all [package]:[target] pairs
all_targets=$(for pkg in $packages; do
    pkg_path=$(go list "$pkg")
    pkg_targets=$(go test -list 'Fuzz' "$pkg_path" | grep '^Fuzz')
    for t in $pkg_targets; do
        echo "$pkg_path:$t"
    done
done)

TOTAL_TARGETS_COUNT=$(echo "$all_targets" | grep -v "^$" | wc -l | xargs)
LOG_DIR=$(mktemp -d)

# Use while read to iterate over the lines
echo "$all_targets" | grep -v "^$" | while read -r item; do
    pkg_path="${item%%:*}"
    target="${item#*:}"
    
    TOTAL_TARGETS=$((TOTAL_TARGETS + 1))
    # We use a temporary file to share state out of the while loop if needed, 
    # but for now we just want to print progress correctly.
    # Note: the pipe creates a subshell, so TOTAL_TARGETS incremented here 
    # won't be visible after the loop. We'll fix this.
    printf "🏃 [%-2d/%-2d] Running %-35s ... " "$TOTAL_TARGETS" "$TOTAL_TARGETS_COUNT" "$target"
    
    LOG_FILE="$LOG_DIR/${target}.log"
    
    # Run fuzz test
    go test -v "$pkg_path" -fuzz="$target" -fuzztime="$FUZZTIME" > "$LOG_FILE" 2>&1
    RESULT=$?
    
    if [ $RESULT -ne 0 ]; then
        printf "❌ FAILED\n"
        echo "$pkg_path: $target" >> "$LOG_DIR/failed_list.txt"
        
        echo "----------------------------------------------------------------"
        echo "🚨 FAILURE DETAILS: $target"
        
        CRASH_LINE=$(grep "failing input written to" "$LOG_FILE")
        if [ ! -z "$CRASH_LINE" ]; then
            CRASH_FILE=$(echo "$CRASH_LINE" | sed 's/.*failing input written to //')
            echo "📁 Crashing input: $CRASH_FILE"
        fi
        
        echo "📝 Log output (filtered):"
        grep -vE "^(fuzz: elapsed:|    --- PASS:|=== RUN)" "$LOG_FILE" | grep -v "^$" | tail -n 20
        echo "----------------------------------------------------------------"
    else
        printf "✅ PASS\n"
        if [ "$VERBOSE" = true ]; then
            cat "$LOG_FILE"
        fi
    fi
done

# The while pipe subshell issue: TOTAL_TARGETS and FAILED_COUNT 
# won't be correct here. Let's use a process substitution or just 
# read the failed_list.txt.

if [ -f "$LOG_DIR/failed_list.txt" ]; then
    FAILED_COUNT=$(wc -l < "$LOG_DIR/failed_list.txt" | xargs)
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

if [ $FAILED_COUNT -ne 0 ]; then
    echo ""
    echo "❌ FAILED TARGETS:"
    cat "$LOG_DIR/failed_list.txt" | sed 's/^/  - /'
    rm -rf "$LOG_DIR"
    exit 1
fi

echo ""
echo "✨ All fuzz targets passed!"
rm -rf "$LOG_DIR"
exit 0
