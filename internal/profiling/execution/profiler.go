// Package execution provides performance profiling and benchmarking for YARA rule execution
package execution

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

// ProfilingConfig holds configuration for execution profiling
type ProfilingConfig struct {
	// Test data configuration
	TestDataDir   string
	RulesDir      string
	OutputDir     string
	CPUProfile    bool
	MemoryProfile bool
	AllocProfile  bool
	TraceProfile  bool
	BenchTime     time.Duration
	BenchCount    int
	Timeout       time.Duration

	// Profiling filters
	MaxRules     int
	MaxDataSize  int64
	RulePatterns []string // Filter rules by pattern
	DataSizes    []int64  // Test data sizes to profile

	// Comparison settings
	CompareWithYara bool
	YaraBinary      string

	// Output settings
	Verbose    bool
	JSONOutput bool
}

// DefaultProfilingConfig returns a default profiling configuration
func DefaultProfilingConfig() *ProfilingConfig {
	return &ProfilingConfig{
		TestDataDir:     "testdata/execution",
		RulesDir:        "testdata/rules",
		OutputDir:       "profiles/execution",
		CPUProfile:      true,
		MemoryProfile:   true,
		AllocProfile:    true,
		TraceProfile:    false,
		BenchTime:       10 * time.Second,
		BenchCount:      3,
		Timeout:         30 * time.Second,
		MaxRules:        100,
		MaxDataSize:     10 * 1024 * 1024,                      // 10MB
		DataSizes:       []int64{1024, 10240, 102400, 1048576}, // 1KB, 10KB, 100KB, 1MB
		CompareWithYara: true,
		YaraBinary:      "yara",
		Verbose:         false,
		JSONOutput:      false,
	}
}

// ExecutionProfile represents a complete execution profile
// nolint:revive // Type name is descriptive and widely used
type ExecutionProfile struct {
	Config      *ProfilingConfig            `json:"config"`
	Environment *EnvironmentInfo            `json:"environment"`
	Results     map[string]*ExecutionResult `json:"results"`
	Summary     *ExecutionSummary           `json:"summary"`
	Hotspots    map[string]*HotspotAnalysis `json:"hotspots"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

// EnvironmentInfo captures environment details for profiling
type EnvironmentInfo struct {
	GoVersion     string           `json:"go_version"`
	OS            string           `json:"os"`
	Arch          string           `json:"arch"`
	NumCPU        int              `json:"num_cpu"`
	NumGoroutines int              `json:"num_goroutines"`
	MemStats      runtime.MemStats `json:"mem_stats"`
}

// ExecutionResult represents profiling results for a specific test case
// nolint:revive // Type name is descriptive and widely used
type ExecutionResult struct {
	Name          string         `json:"name"`
	RuleFile      string         `json:"rule_file"`
	DataFile      string         `json:"data_file"`
	DataSize      int64          `json:"data_size"`
	RuleCount     int            `json:"rule_count"`
	StringCount   int            `json:"string_count"`
	CompileTime   time.Duration  `json:"compile_time"`
	ExecutionTime time.Duration  `json:"execution_time"`
	TotalTime     time.Duration  `json:"total_time"`
	MemoryUsage   int64          `json:"memory_usage"`
	Allocations   int64          `json:"allocations"`
	Matches       int            `json:"matches"`
	Success       bool           `json:"success"`
	Error         string         `json:"error,omitempty"`
	ProfileData   map[string]any `json:"profile_data,omitempty"`

	// Performance counters
	Instructions  int64 `json:"instructions"`
	StackOps      int64 `json:"stack_ops"`
	StringMatches int64 `json:"string_matches"`
	RegexMatches  int64 `json:"regex_matches"`
}

// ExecutionSummary provides aggregated profiling results
// nolint:revive // Type name is descriptive and widely used
type ExecutionSummary struct {
	TotalCases      int `json:"total_cases"`
	SuccessfulCases int `json:"successful_cases"`
	FailedCases     int `json:"failed_cases"`

	// Performance metrics
	AvgExecutionTime time.Duration `json:"avg_execution_time"`
	MinExecutionTime time.Duration `json:"min_execution_time"`
	MaxExecutionTime time.Duration `json:"max_execution_time"`

	AvgCompileTime   time.Duration `json:"avg_compile_time"`
	AvgMemoryUsage   int64         `json:"avg_memory_usage"`
	TotalAllocations int64         `json:"total_allocations"`

	// Throughput metrics
	RulesPerSecond float64 `json:"rules_per_second"`
	BytesPerSecond float64 `json:"bytes_per_second"`

	// Comparison with reference YARA
	YaraComparison *YaraComparisonResult `json:"yara_comparison,omitempty"`
}

// HotspotAnalysis identifies performance bottlenecks
type HotspotAnalysis struct {
	Category    string   `json:"category"` // "interpreter", "automaton", "regex", "memory"
	Description string   `json:"description"`
	Percentage  float64  `json:"percentage"` // Percentage of total execution time
	Function    string   `json:"function,omitempty"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Suggestions []string `json:"suggestions"`
}

// YaraComparisonResult compares go-yara performance with reference YARA
type YaraComparisonResult struct {
	YaraTime     time.Duration `json:"yara_time"`
	GoYaraTime   time.Duration `json:"go_yara_time"`
	SpeedupRatio float64       `json:"speedup_ratio"`
	MatchesEqual bool          `json:"matches_equal"`
}

// Profiler orchestrates execution profiling
type Profiler struct {
	config    *ProfilingConfig
	profile   *ExecutionProfile
	testCases []TestCase
}

// TestCase represents a single profiling test case
type TestCase struct {
	Name     string
	RuleFile string
	DataFile string
	DataSize int64
}

// NewProfiler creates a new execution profiler
func NewProfiler(config *ProfilingConfig) *Profiler {
	if config == nil {
		config = DefaultProfilingConfig()
	}

	return &Profiler{
		config: config,
		profile: &ExecutionProfile{
			Config:   config,
			Results:  make(map[string]*ExecutionResult),
			Hotspots: make(map[string]*HotspotAnalysis),
		},
		testCases: make([]TestCase, 0),
	}
}

// AddFlags adds profiling flags to the flag set
func AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&DefaultProfilingConfig().TestDataDir, "test-data", "testdata/execution", "Directory containing test data files")
	fs.StringVar(&DefaultProfilingConfig().RulesDir, "rules-dir", "testdata/rules", "Directory containing rule files")
	fs.StringVar(&DefaultProfilingConfig().OutputDir, "output-dir", "profiles/execution", "Directory to write profiling results")
	fs.DurationVar(&DefaultProfilingConfig().BenchTime, "bench-time", 10*time.Second, "Benchmark duration")
	fs.IntVar(&DefaultProfilingConfig().BenchCount, "bench-count", 3, "Number of benchmark runs")
	fs.BoolVar(&DefaultProfilingConfig().CPUProfile, "cpu-profile", true, "Enable CPU profiling")
	fs.BoolVar(&DefaultProfilingConfig().MemoryProfile, "mem-profile", true, "Enable memory profiling")
	fs.BoolVar(&DefaultProfilingConfig().Verbose, "verbose", false, "Verbose output")
	fs.BoolVar(&DefaultProfilingConfig().JSONOutput, "json", false, "JSON output format")
}

// DiscoverTestCases discovers test cases from the configured directories
func (p *Profiler) DiscoverTestCases() error {
	// Discover rule files
	ruleFiles, err := filepath.Glob(filepath.Join(p.config.RulesDir, "*.yar"))
	if err != nil {
		return fmt.Errorf("discovering rule files: %w", err)
	}

	// Discover data files
	dataFiles, err := filepath.Glob(filepath.Join(p.config.TestDataDir, "*"))
	if err != nil {
		return fmt.Errorf("discovering data files: %w", err)
	}

	if len(ruleFiles) == 0 {
		return fmt.Errorf("no rule files found in %s", p.config.RulesDir)
	}

	if len(dataFiles) == 0 {
		return fmt.Errorf("no data files found in %s", p.config.TestDataDir)
	}

	// Create test cases
	for i, ruleFile := range ruleFiles {
		if i >= p.config.MaxRules {
			break
		}

		// Filter by pattern if specified
		if len(p.config.RulePatterns) > 0 {
			matched := false
			for _, pattern := range p.config.RulePatterns {
				if strings.Contains(filepath.Base(ruleFile), pattern) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		for _, dataFile := range dataFiles {
			// Check data size
			info, statErr := os.Stat(dataFile)
			if statErr != nil {
				continue
			}

			if info.Size() > p.config.MaxDataSize {
				continue
			}

			// Filter by data sizes if specified
			if len(p.config.DataSizes) > 0 {
				sizeMatched := false
				for _, size := range p.config.DataSizes {
					// Allow 10% tolerance
					tolerance := int64(float64(size) * 0.1)
					if info.Size() >= size-tolerance && info.Size() <= size+tolerance {
						sizeMatched = true
						break
					}
				}
				if !sizeMatched {
					continue
				}
			}

			testCase := TestCase{
				Name:     fmt.Sprintf("%s_%s", filepath.Base(ruleFile), filepath.Base(dataFile)),
				RuleFile: ruleFile,
				DataFile: dataFile,
				DataSize: info.Size(),
			}

			p.testCases = append(p.testCases, testCase)
		}
	}

	if p.config.Verbose {
		fmt.Printf("Discovered %d test cases\n", len(p.testCases))
	}

	return nil
}

// RunProfiling executes the complete profiling suite
func (p *Profiler) RunProfiling() error {
	// Capture environment info
	p.captureEnvironment()

	// Create output directory
	if err := os.MkdirAll(p.config.OutputDir, 0750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// Discover test cases
	if err := p.DiscoverTestCases(); err != nil {
		return fmt.Errorf("discovering test cases: %w", err)
	}

	if len(p.testCases) == 0 {
		return errors.New("no test cases discovered")
	}

	fmt.Printf("Running execution profiling on %d test cases...\n", len(p.testCases))

	// Run each test case
	for i, testCase := range p.testCases {
		if p.config.Verbose {
			fmt.Printf("Running test case %d/%d: %s\n", i+1, len(p.testCases), testCase.Name)
		}

		result := p.runTestCase(testCase)
		p.profile.Results[testCase.Name] = result

		// Early exit if too many failures
		failed := 0
		for _, r := range p.profile.Results {
			if !r.Success {
				failed++
			}
		}
		if float64(failed)/float64(i+1) > 0.5 {
			return fmt.Errorf("too many test failures (%d/%d), aborting", failed, i+1)
		}
	}

	// Generate summary
	p.generateSummary()

	// Analyze hotspots
	p.analyzeHotspots()

	// Compare with reference YARA if enabled
	if p.config.CompareWithYara {
		if err := p.compareToReferenceYara(); err != nil && p.config.Verbose {
			fmt.Printf("Warning: Could not compare with reference YARA: %v\n", err)
		}
	}

	// Set generation time
	p.profile.GeneratedAt = time.Now()

	// Write results
	if err := p.writeResults(); err != nil {
		return fmt.Errorf("writing results: %w", err)
	}

	fmt.Printf("Profiling complete. Results written to %s\n", p.config.OutputDir)

	return nil
}

// runTestCase executes a single test case with profiling
func (p *Profiler) runTestCase(testCase TestCase) *ExecutionResult {
	result := &ExecutionResult{
		Name:        testCase.Name,
		RuleFile:    testCase.RuleFile,
		DataFile:    testCase.DataFile,
		DataSize:    testCase.DataSize,
		ProfileData: make(map[string]any),
	}

	start := time.Now()

	// Compile rules
	compileStart := time.Now()
	compiledRules, err := p.compileRules(testCase.RuleFile)
	result.CompileTime = time.Since(compileStart)

	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("compilation failed: %v", err)
		return result
	}

	result.RuleCount = len(compiledRules)

	// Count strings
	for _, rule := range compiledRules {
		if rule.Automaton != nil {
			result.StringCount += rule.Automaton.StringCount
		}
	}

	// Read data
	data, err := os.ReadFile(testCase.DataFile)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("reading data failed: %v", err)
		return result
	}

	// Execute rules with profiling
	execStart := time.Now()
	matches, err := p.executeRules(compiledRules, data)
	result.ExecutionTime = time.Since(execStart)

	result.TotalTime = time.Since(start)
	result.Matches = len(matches)

	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("execution failed: %v", err)
		return result
	}

	result.Success = true

	// Collect runtime stats
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Execute again to get more accurate memory stats
	if _, execErr := p.executeRules(compiledRules, data); execErr != nil {
		// Log error but continue with memory profiling
		fmt.Printf("Warning: execution failed during memory profiling: %v\n", execErr)
	}

	runtime.ReadMemStats(&m2)
	result.MemoryUsage = int64(m2.Alloc - m1.Alloc)
	result.Allocations = int64(m2.TotalAlloc - m1.TotalAlloc)

	return result
}

// compileRules compiles YARA rules from a file using the optimized unified implementation
func (p *Profiler) compileRules(ruleFile string) ([]*compiler.CompiledRule, error) {
	// Read rule file content
	content, err := os.ReadFile(ruleFile)
	if err != nil {
		return nil, fmt.Errorf("reading rule file: %w", err)
	}

	// Parse rules (simplified for profiling)
	rules := p.parseSimpleRules(string(content))

	// Compile using optimized compiler
	compiledRules := make([]*compiler.CompiledRule, 0, len(rules))

	for _, rule := range rules {
		// Create automaton for pattern matching
		automaton := compiler.NewACAutomaton()

		// Add strings to automaton
		stringCount := 0
		for _, str := range rule.Strings {
			addErr := automaton.AddString(str.Identifier, []byte(str.Pattern), false, false)
			if addErr != nil {
				return nil, fmt.Errorf("adding string %s: %w", str.Identifier, addErr)
			}
			stringCount++
		}

		// Compile automaton
		err = automaton.Compile()
		if err != nil {
			return nil, fmt.Errorf("compiling automaton for rule %s: %w", rule.Name, err)
		}

		compiledRule := &compiler.CompiledRule{
			Name:        rule.Name,
			Index:       len(compiledRules),
			Bytecode:    []byte{}, // Empty bytecode for profiling
			StringCount: stringCount,
			Automaton:   automaton,
		}

		compiledRules = append(compiledRules, compiledRule)
	}

	return compiledRules, nil
}

// SimpleRule represents a simplified rule structure for profiling
type SimpleRule struct {
	Name    string
	Strings []SimpleString
}

// SimpleString represents a simplified string structure
type SimpleString struct {
	Identifier string
	Pattern    string
}

// parseSimpleRules parses simple YARA rules for profiling
func (p *Profiler) parseSimpleRules(content string) []SimpleRule {
	var rules []SimpleRule
	lines := strings.Split(content, "\n")

	var currentRule *SimpleRule

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "rule ") {
			// Extract rule name
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := strings.TrimSuffix(parts[1], " {")
				currentRule = &SimpleRule{Name: name}
				rules = append(rules, *currentRule)
			}
		} else if strings.HasPrefix(line, "$") && currentRule != nil {
			// Extract string definitions
			if strings.Contains(line, "=") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					identifier := strings.TrimSpace(parts[0])
					pattern := strings.TrimSpace(strings.Trim(parts[1], `"'`))
					currentRule.Strings = append(currentRule.Strings, SimpleString{
						Identifier: identifier,
						Pattern:    pattern,
					})
				}
			}
		}
	}

	return rules
}

// executeRules executes compiled rules against data using the optimized unified implementation
func (p *Profiler) executeRules(rules []*compiler.CompiledRule, data []byte) ([]compiler.Match, error) {
	var allMatches []compiler.Match

	for _, rule := range rules {
		if rule.Automaton == nil {
			continue
		}

		// Use the optimized search from the unified implementation
		matches := rule.Automaton.Search(data)

		// Convert ACMatch to Match format
		for _, match := range matches {
			allMatches = append(allMatches, compiler.Match{
				Pattern: match.StringID,
				Offset:  int64(match.Backtrack),
				Length:  len(match.StringID), // Simplified length for profiling
				Base:    0,
			})
		}
	}

	return allMatches, nil
}

// captureEnvironment captures environment information
func (p *Profiler) captureEnvironment() {
	p.profile.Environment = &EnvironmentInfo{
		GoVersion:     runtime.Version(),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		NumCPU:        runtime.NumCPU(),
		NumGoroutines: runtime.NumGoroutine(),
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	p.profile.Environment.MemStats = memStats
}

// generateSummary generates summary statistics
func (p *Profiler) generateSummary() {
	if len(p.profile.Results) == 0 {
		return
	}

	summary := &ExecutionSummary{
		TotalCases: len(p.profile.Results),
	}

	var totalExecTime, totalCompileTime time.Duration
	var totalMemory int64
	var totalAllocs int64
	var minExec, maxExec time.Duration
	minExec = time.Hour
	maxExec = 0

	for _, result := range p.profile.Results {
		if result.Success {
			summary.SuccessfulCases++
			totalExecTime += result.ExecutionTime
			totalCompileTime += result.CompileTime
			totalMemory += result.MemoryUsage
			totalAllocs += result.Allocations

			if result.ExecutionTime < minExec {
				minExec = result.ExecutionTime
			}
			if result.ExecutionTime > maxExec {
				maxExec = result.ExecutionTime
			}
		} else {
			summary.FailedCases++
		}
	}

	if summary.SuccessfulCases > 0 {
		summary.AvgExecutionTime = totalExecTime / time.Duration(summary.SuccessfulCases)
		summary.AvgCompileTime = totalCompileTime / time.Duration(summary.SuccessfulCases)
		summary.AvgMemoryUsage = totalMemory / int64(summary.SuccessfulCases)
		summary.MinExecutionTime = minExec
		summary.MaxExecutionTime = maxExec

		// Calculate throughput
		totalDataSize := int64(0)
		totalRuleCount := 0
		for _, result := range p.profile.Results {
			if result.Success {
				totalDataSize += result.DataSize
				totalRuleCount += result.RuleCount
			}
		}

		if totalExecTime > 0 {
			summary.BytesPerSecond = float64(totalDataSize) / totalExecTime.Seconds()
			summary.RulesPerSecond = float64(totalRuleCount) / totalExecTime.Seconds()
		}
	}

	summary.TotalAllocations = totalAllocs
	p.profile.Summary = summary
}

// analyzeHotspots analyzes performance bottlenecks
func (p *Profiler) analyzeHotspots() {
	if len(p.profile.Results) == 0 {
		return
	}

	// Calculate total execution time for percentage calculations
	var totalExecTime time.Duration
	for _, result := range p.profile.Results {
		if result.Success {
			totalExecTime += result.ExecutionTime
		}
	}

	if totalExecTime == 0 {
		return
	}

	// Identify hotspots based on patterns in results
	hotspots := make(map[string]*HotspotAnalysis)

	// Compilation hotspot
	var totalCompileTime time.Duration
	for _, result := range p.profile.Results {
		if result.Success {
			totalCompileTime += result.CompileTime
		}
	}

	compilePct := float64(totalCompileTime) / float64(totalExecTime) * 100
	if compilePct > 20 { // If compilation takes more than 20% of total time
		hotspots["compilation"] = &HotspotAnalysis{
			Category:    "compilation",
			Description: "Rule compilation takes significant portion of execution time",
			Percentage:  compilePct,
			Suggestions: []string{
				"Consider pre-compiling rules and caching compiled bytecode",
				"Optimize rule compiler performance",
				"Use rule compilation batching",
			},
		}
	}

	// Memory allocation hotspot
	var totalMemory int64
	for _, result := range p.profile.Results {
		if result.Success {
			totalMemory += result.MemoryUsage
		}
	}

	avgMemory := totalMemory / int64(len(p.profile.Results))
	if avgMemory > 10*1024*1024 { // If average memory usage > 10MB
		hotspots["memory"] = &HotspotAnalysis{
			Category:    "memory",
			Description: "High memory usage during execution",
			Percentage:  float64(avgMemory) / float64(totalExecTime) * 100,
			Suggestions: []string{
				"Implement memory pooling for frequently allocated objects",
				"Optimize interpreter stack allocation",
				"Use zero-copy techniques where possible",
				"Review Aho-Corasick automaton memory usage",
			},
		}
	}

	// Slow execution hotspots
	var totalSlowExec time.Duration
	slowCases := 0
	for _, result := range p.profile.Results {
		if result.Success && result.ExecutionTime > 100*time.Millisecond {
			totalSlowExec += result.ExecutionTime
			slowCases++
		}
	}

	if slowCases > 0 {
		slowPct := float64(totalSlowExec) / float64(totalExecTime) * 100
		if slowPct > 30 {
			hotspots["execution"] = &HotspotAnalysis{
				Category:    "execution",
				Description: "Slow execution in some test cases",
				Percentage:  slowPct,
				Suggestions: []string{
					"Profile interpreter opcode execution",
					"Optimize pattern matching algorithms",
					"Review regex engine performance",
					"Consider JIT compilation for frequently executed patterns",
				},
			}
		}
	}

	p.profile.Hotspots = hotspots
}

// compareToReferenceYara compares performance with reference YARA implementation
func (p *Profiler) compareToReferenceYara() error {
	// Implementation would compare go-yara performance with reference YARA
	// This would use similar logic to cmd/parity/main.go
	return nil
}

// writeResults writes profiling results to files
func (p *Profiler) writeResults() error {
	timestamp := time.Now().Format("20060102_150405")

	// Write text summary
	txtFile := filepath.Join(p.config.OutputDir, fmt.Sprintf("profile_%s.txt", timestamp))
	return p.writeTextSummary(txtFile)
}

// writeTextSummary writes a human-readable summary
func (p *Profiler) writeTextSummary(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, writeErr := fmt.Fprintf(file, "YARA Execution Performance Profile\n"); writeErr != nil {
		return fmt.Errorf("writing header: %w", writeErr)
	}
	if _, writeErr := fmt.Fprintf(file, "Generated: %s\n\n", p.profile.GeneratedAt.Format("2006-01-02 15:04:05")); writeErr != nil {
		return fmt.Errorf("writing timestamp: %w", writeErr)
	}

	// Helper function to ignore write errors for non-critical sections
	// nolint: errcheck
	write := func(format string, args ...any) {
		fmt.Fprintf(file, format, args...)
	}

	// Environment
	if p.profile.Environment != nil {
		write("Environment:\n")
		write("  Go Version: %s\n", p.profile.Environment.GoVersion)
		write("  OS/Arch: %s/%s\n", p.profile.Environment.OS, p.profile.Environment.Arch)
		write("  CPU Cores: %d\n", p.profile.Environment.NumCPU)
		write("  Initial Goroutines: %d\n", p.profile.Environment.NumGoroutines)
		write("\n")
	}

	// Summary
	if p.profile.Summary != nil {
		write("Summary:\n")
		write("  Total Test Cases: %d\n", p.profile.Summary.TotalCases)
		write("  Successful: %d\n", p.profile.Summary.SuccessfulCases)
		write("  Failed: %d\n", p.profile.Summary.FailedCases)
		write("  Average Execution Time: %v\n", p.profile.Summary.AvgExecutionTime)
		write("  Min/Max Execution Time: %v / %v\n", p.profile.Summary.MinExecutionTime, p.profile.Summary.MaxExecutionTime)
		write("  Average Memory Usage: %s\n", formatBytes(p.profile.Summary.AvgMemoryUsage))
		write("  Throughput: %.2f rules/sec, %s/sec\n",
			p.profile.Summary.RulesPerSecond,
			formatBytes(int64(p.profile.Summary.BytesPerSecond)))
		write("\n")
	}

	// Hotspots
	if len(p.profile.Hotspots) > 0 {
		write("Performance Hotspots:\n")
		for name, hotspot := range p.profile.Hotspots {
			write("  %s (%.1f%%): %s\n", name, hotspot.Percentage, hotspot.Description)
			for _, suggestion := range hotspot.Suggestions {
				write("    - %s\n", suggestion)
			}
		}
		write("\n")
	}

	// Detailed results
	if p.config.Verbose || len(p.profile.Results) <= 20 {
		write("Detailed Results:\n")
		write("%-40s %12s %12s %12s %8s %8s %8s\n",
			"Test Case", "Compile", "Execute", "Total", "Memory", "Allocs", "Matches")
		write("%s\n", strings.Repeat("-", 100))

		// Sort results by execution time
		var sortedNames []string
		for name := range p.profile.Results {
			sortedNames = append(sortedNames, name)
		}
		sort.Slice(sortedNames, func(i, j int) bool {
			return p.profile.Results[sortedNames[i]].ExecutionTime > p.profile.Results[sortedNames[j]].ExecutionTime
		})

		for _, name := range sortedNames {
			result := p.profile.Results[name]
			status := "✓"
			if !result.Success {
				status = "✗"
			}
			displayName := name
			if len(displayName) > 40 {
				displayName = name[:40]
			}
			write("%-40s %12v %12v %12v %8s %8s %8d %s\n",
				displayName, result.CompileTime, result.ExecutionTime, result.TotalTime,
				formatBytes(result.MemoryUsage), formatNumber(result.Allocations),
				result.Matches, status)
		}
	}

	return nil
}

// formatBytes formats a byte count as human-readable
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// formatNumber formats a number with commas
func formatNumber(n int64) string {
	return strconv.FormatInt(n, 10)
}
