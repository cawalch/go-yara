#!/bin/bash

# Performance Monitoring Script for Go-YARA
# This script provides local performance monitoring and baseline management

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PERFORMANCE_DIR="$PROJECT_ROOT/performance-data"
BASELINE_DIR="$PERFORMANCE_DIR/baselines"
RESULTS_DIR="$PERFORMANCE_DIR/results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Ensure directories exist
ensure_directories() {
    mkdir -p "$BASELINE_DIR"
    mkdir -p "$RESULTS_DIR"
}

# Generate timestamp for filenames
timestamp() {
    date '+%Y%m%d_%H%M%S'
}

# Run comprehensive performance suite
run_performance_suite() {
    local results_file="$RESULTS_DIR/performance_$(timestamp).txt"
    local baseline_file="$BASELINE_DIR/latest_baseline.txt"

    log_info "Running comprehensive performance suite..."

    # Create results directory
    ensure_directories

    # Change to project root
    cd "$PROJECT_ROOT"

    # 1. Lexer Benchmarks
    log_info "1. Running Lexer Benchmarks..."
    go test -bench=. -benchmem -benchtime=5s -count=3 -run=^$ ./internal/lexer > "$RESULTS_DIR/lexer_$(timestamp).txt"

    # 2. ACAutomaton Benchmarks
    log_info "2. Running ACAutomaton Benchmarks..."
    go test -bench=BenchmarkMicro.* -benchmem -benchtime=5s -count=3 -run=^$ ./compiler > "$RESULTS_DIR/automaton_$(timestamp).txt"

    # 3. End-to-End Performance
    log_info "3. Running End-to-End Performance..."
    go run simple_benchmark.go -iterations 1000 -verbose > "$RESULTS_DIR/e2e_$(timestamp).txt"

    # 4. Scaling Analysis
    log_info "4. Running Scaling Analysis..."
    go run scaling_analysis.go > "$RESULTS_DIR/scaling_$(timestamp).txt"

    # 5. Memory Profiling
    log_info "5. Running Memory Analysis..."
    go test -bench=BenchmarkMicro_StringMatching_PerformanceRegression \
            -memprofile="$RESULTS_DIR/mem_profile_$(timestamp).out" \
            -run=^$ ./compiler

    # 6. CPU Profiling
    log_info "6. Running CPU Analysis..."
    go test -bench=BenchmarkMicro_StringMatching_PerformanceRegression \
            -cpuprofile="$RESULTS_DIR/cpu_profile_$(timestamp).out" \
            -run=^$ ./compiler

    # Generate combined results
    log_info "Generating combined performance report..."
    {
        echo "=== Go-YARA Performance Report ==="
        echo "Generated: $(date)"
        echo "Go Version: $(go version)"
        echo "System: $(uname -s) $(uname -r)"
        echo ""

        echo "## Current Results"
        echo ""

        # Extract key metrics from e2e benchmark
        if [ -f "$RESULTS_DIR/e2e_$(timestamp).txt" ]; then
            echo "### End-to-End Performance"
            cat "$RESULTS_DIR/e2e_$(timestamp).txt"
            echo ""
        fi

        # Extract key metrics from automaton benchmark
        if [ -f "$RESULTS_DIR/automaton_$(timestamp).txt" ]; then
            echo "### ACAutomaton Performance"
            tail -10 "$RESULTS_DIR/automaton_$(timestamp).txt"
            echo ""
        fi

        # Extract scaling analysis summary
        if [ -f "$RESULTS_DIR/scaling_$(timestamp).txt" ]; then
            echo "### Scaling Analysis Summary"
            grep -E "(Average Performance|Performance Summary|Recommendations)" "$RESULTS_DIR/scaling_$(timestamp).txt" || true
            echo ""
        fi

    } > "$results_file"

    log_success "Performance suite completed! Results saved to: $results_file"
    echo "$results_file"
}

# Compare current results with baseline
compare_with_baseline() {
    local current_file="$1"
    local baseline_file="$BASELINE_DIR/latest_baseline.txt"

    if [ ! -f "$baseline_file" ]; then
        log_warning "No baseline found. Creating new baseline..."
        cp "$current_file" "$baseline_file"
        log_success "New baseline created: $baseline_file"
        return 0
    fi

    log_info "Comparing with baseline..."

    # Install benchstat if not available
    if ! command -v benchstat &> /dev/null; then
        log_info "Installing benchstat..."
        go install golang.org/x/perf/cmd/benchstat@latest
    fi

    # Generate comparison report
    local comparison_file="$RESULTS_DIR/comparison_$(timestamp).txt"
    {
        echo "=== Performance Comparison Report ==="
        echo "Generated: $(date)"
        echo ""

        echo "## Current vs Baseline"
        echo ""

        # Extract comparable sections and run benchstat
        if [ -f "$RESULTS_DIR/lexer_$(timestamp).txt" ] && [ -f "$BASELINE_DIR/latest_lexer.txt" ]; then
            echo "### Lexer Performance Comparison"
            benchstat "$BASELINE_DIR/latest_lexer.txt" "$RESULTS_DIR/lexer_$(timestamp).txt"
            echo ""
        fi

        if [ -f "$RESULTS_DIR/automaton_$(timestamp).txt" ] && [ -f "$BASELINE_DIR/latest_automaton.txt" ]; then
            echo "### ACAutomaton Performance Comparison"
            benchstat "$BASELINE_DIR/latest_automaton.txt" "$RESULTS_DIR/automaton_$(timestamp).txt"
            echo ""
        fi

        # Check for regressions
        echo "## Regression Analysis"
        echo ""

        # Simple regression detection
        if [ -f "$RESULTS_DIR/lexer_$(timestamp).txt" ] && [ -f "$BASELINE_DIR/latest_lexer.txt" ]; then
            echo "Checking lexer regressions..."
            if benchstat "$BASELINE_DIR/latest_lexer.txt" "$RESULTS_DIR/lexer_$(timestamp).txt" | grep -E "\+([5-9]\.[0-9]|[1-9][0-9]+\.[0-9])%.*ns/op" > /dev/null; then
                log_error "Lexer performance regression detected!"
            else
                log_success "No lexer performance regressions detected"
            fi
        fi

        if [ -f "$RESULTS_DIR/automaton_$(timestamp).txt" ] && [ -f "$BASELINE_DIR/latest_automaton.txt" ]; then
            echo "Checking ACAutomaton regressions..."
            if benchstat "$BASELINE_DIR/latest_automaton.txt" "$RESULTS_DIR/automaton_$(timestamp).txt" | grep -E "\+([1-9]\.[0-9])%.*ns/op" > /dev/null; then
                log_error "ACAutomaton performance regression detected!"
            else
                log_success "No ACAutomaton performance regressions detected"
            fi
        fi

    } > "$comparison_file"

    cat "$comparison_file"
    log_success "Comparison report saved to: $comparison_file"
}

# Update baseline with current results
update_baseline() {
    local current_file="$1"

    log_info "Updating baseline with current results..."

    # Copy individual component baselines
    if [ -f "$RESULTS_DIR/lexer_$(timestamp).txt" ]; then
        cp "$RESULTS_DIR/lexer_$(timestamp).txt" "$BASELINE_DIR/latest_lexer.txt"
    fi

    if [ -f "$RESULTS_DIR/automaton_$(timestamp).txt" ]; then
        cp "$RESULTS_DIR/automaton_$(timestamp).txt" "$BASELINE_DIR/latest_automaton.txt"
    fi

    if [ -f "$RESULTS_DIR/e2e_$(timestamp).txt" ]; then
        cp "$RESULTS_DIR/e2e_$(timestamp).txt" "$BASELINE_DIR/latest_e2e.txt"
    fi

    # Copy combined results
    cp "$current_file" "$baseline_file"

    # Create timestamped backup
    local backup_file="$BASELINE_DIR/baseline_$(timestamp).txt"
    cp "$current_file" "$backup_file"

    log_success "Baseline updated: $baseline_file"
    log_success "Backup created: $backup_file"
}

# Run memory leak detection
run_memory_analysis() {
    local mem_profile="$RESULTS_DIR/mem_profile_$(timestamp).out"

    if [ ! -f "$mem_profile" ]; then
        log_error "Memory profile not found. Run performance suite first."
        return 1
    fi

    log_info "Running memory leak analysis..."

    local analysis_file="$RESULTS_DIR/memory_analysis_$(timestamp).txt"
    {
        echo "=== Memory Analysis Report ==="
        echo "Generated: $(date)"
        echo ""

        echo "## Memory Allocation Hotspots"
        go tool pprof -alloc_space -top "$mem_profile" | head -20
        echo ""

        echo "## Memory Allocation Details"
        go tool pprof -alloc_space -text "$mem_profile" | head -30
        echo ""

        # Check for potential issues
        echo "## Memory Health Check"

        TOTAL_ALLOCS=$(go tool pprof -alloc_space -text "$mem_profile" | grep "Total allocations" | grep -o "[0-9]*" || echo "0")
        echo "Total allocations: $TOTAL_ALLOCS"

        if [ "$TOTAL_ALLOCS" -gt 10000000 ]; then
            echo "⚠️ WARNING: Very high allocation count detected"
        elif [ "$TOTAL_ALLOCS" -gt 1000000 ]; then
            echo "⚠️ WARNING: High allocation count detected"
        else
            echo "✅ Allocation count is reasonable"
        fi

    } > "$analysis_file"

    cat "$analysis_file"
    log_success "Memory analysis saved to: $analysis_file"
}

# Show performance history
show_history() {
    log_info "Performance Baseline History:"
    echo ""

    if [ ! -d "$BASELINE_DIR" ]; then
        log_warning "No performance history found."
        return 1
    fi

    # List all baselines with dates
    ls -la "$BASELINE_DIR"/baseline_*.txt 2>/dev/null | while read -r line; do
        local file=$(echo "$line" | awk '{print $9}')
        local date=$(echo "$file" | grep -o '[0-9]\{8\}_[0-9]\{6\}' | sed 's/_/ /')
        local size=$(echo "$line" | awk '{print $5}')

        echo "  $date ($size)"
    done

    echo ""
    log_info "Current baseline: $BASELINE_DIR/latest_baseline.txt"
}

# Clean up old performance data
cleanup() {
    local days_to_keep=${1:-30}

    log_info "Cleaning up performance data older than $days_to_keep days..."

    # Find and remove old files
    find "$RESULTS_DIR" -name "*.txt" -mtime +$days_to_keep -delete 2>/dev/null || true
    find "$RESULTS_DIR" -name "*.out" -mtime +$days_to_keep -delete 2>/dev/null || true
    find "$BASELINE_DIR" -name "baseline_*.txt" -mtime +$days_to_keep -delete 2>/dev/null || true

    log_success "Cleanup completed"
}

# Generate performance dashboard
generate_dashboard() {
    local dashboard_file="$RESULTS_DIR/dashboard_$(timestamp).html"

    log_info "Generating performance dashboard..."

    # Get latest results
    local latest_lexer=$(ls -t "$RESULTS_DIR"/lexer_*.txt 2>/dev/null | head -1)
    local latest_automaton=$(ls -t "$RESULTS_DIR"/automaton_*.txt 2>/dev/null | head -1)
    local latest_e2e=$(ls -t "$RESULTS_DIR"/e2e_*.txt 2>/dev/null | head -1)
    local latest_scaling=$(ls -t "$RESULTS_DIR"/scaling_*.txt 2>/dev/null | head -1)

    cat > "$dashboard_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Go-YARA Performance Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
        .header { background: #f0f0f0; padding: 10px; margin-bottom: 20px; }
        pre { background: #f8f8f8; padding: 10px; overflow-x: auto; }
        .warning { color: #ff6600; }
        .success { color: #006600; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Go-YARA Performance Dashboard</h1>
        <p>Generated: $(date)</p>
    </div>

    <div class="metric">
        <h2>End-to-End Performance</h2>
        <pre>$(cat "$latest_e2e" 2>/dev/null || echo "No data available")</pre>
    </div>

    <div class="metric">
        <h2>ACAutomaton Performance</h2>
        <pre>$(tail -20 "$latest_automaton" 2>/dev/null || echo "No data available")</pre>
    </div>

    <div class="metric">
        <h2>Scaling Analysis</h2>
        <pre>$(grep -A 20 "Performance Summary" "$latest_scaling" 2>/dev/null || echo "No data available")</pre>
    </div>

    <div class="metric">
        <h2>Lexer Performance</h2>
        <pre>$(tail -10 "$latest_lexer" 2>/dev/null || echo "No data available")</pre>
    </div>

    <div class="footer">
        <p><em>Dashboard generated by Go-YARA Performance Monitor</em></p>
    </div>
</body>
</html>
EOF

    log_success "Dashboard generated: $dashboard_file"

    # Try to open in browser (optional)
    if command -v open &> /dev/null; then
        echo "Opening dashboard in browser..."
        open "$dashboard_file"
    fi
}

# Show help
show_help() {
    cat << EOF
Go-YARA Performance Monitor

Usage: $0 <command> [options]

Commands:
    run             Run comprehensive performance suite
    compare         Compare current results with baseline
    baseline        Update baseline with current results
    memory          Run memory leak analysis
    history         Show performance history
    dashboard       Generate HTML performance dashboard
    cleanup [days]  Clean up old data (default: 30 days)
    help            Show this help message

Examples:
    $0 run                    # Run performance suite
    $0 compare                 # Compare with baseline
    $0 baseline                # Update baseline
    $0 memory                  # Memory analysis
    $0 dashboard               # Generate dashboard
    $0 cleanup 7               # Clean data older than 7 days

Environment:
    PERFORMANCE_DIR: $PERFORMANCE_DIR
    BASELINE_DIR: $BASELINE_DIR
    RESULTS_DIR: $RESULTS_DIR

EOF
}

# Main execution
main() {
    cd "$PROJECT_ROOT"
    ensure_directories

    case "${1:-}" in
        "run")
            log_info "Running performance suite..."
            results_file=$(run_performance_suite)
            compare_with_baseline "$results_file"
            ;;
        "compare")
            latest_results=$(ls -t "$RESULTS_DIR"/performance_*.txt 2>/dev/null | head -1)
            if [ -z "$latest_results" ]; then
                log_error "No performance results found. Run 'run' command first."
                exit 1
            fi
            compare_with_baseline "$latest_results"
            ;;
        "baseline")
            latest_results=$(ls -t "$RESULTS_DIR"/performance_*.txt 2>/dev/null | head -1)
            if [ -z "$latest_results" ]; then
                log_error "No performance results found. Run 'run' command first."
                exit 1
            fi
            update_baseline "$latest_results"
            ;;
        "memory")
            run_memory_analysis
            ;;
        "history")
            show_history
            ;;
        "dashboard")
            generate_dashboard
            ;;
        "cleanup")
            cleanup "${2:-30}"
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "Unknown command: ${1:-}"
            show_help
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"