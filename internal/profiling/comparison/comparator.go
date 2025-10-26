// Package comparison provides comprehensive performance comparison between go-yara and reference YARA
package comparison

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Comparator provides comprehensive comparison between go-yara and reference YARA
type Comparator struct {
	config     *ComparisonConfig
	results    *ComparisonResults
	profiler   *Profiler
	tempDir    string
	yaraBinary string
}

// ComparisonConfig defines comparison parameters
// nolint:revive // Type name is descriptive and widely used
type ComparisonConfig struct {
	RuleDirectories    []string      // Directories containing .yar files
	DataDirectories    []string      // Directories containing test data
	TestFilePattern    string        // Pattern for test files (e.g., "*.yar", "*.txt")
	MaxRuleFiles       int           // Maximum number of rule files to test
	MaxDataFiles       int           // Maximum number of data files to test
	MaxRulesPerFile    int           // Maximum rules per file to process
	MaxDataSize        int64         // Maximum data file size to process
	TimeoutCompilation time.Duration // Timeout for compilation
	TimeoutExecution   time.Duration // Timeout for execution
	ProfileCPU         bool          // Enable CPU profiling
	ProfileMemory      bool          // Enable memory profiling
	ProfileAllocs      bool          // Enable allocation profiling
	Verbose            bool          // Enable verbose output
	Parallelism        int           // Number of parallel workers (0 = auto)
}

// ComparisonResults holds all comparison results
// nolint:revive // Type name is descriptive and widely used
type ComparisonResults struct {
	StartTime            time.Time              `json:"start_time"`
	EndTime              time.Time              `json:"end_time"`
	Duration             time.Duration          `json:"duration"`
	Environment          *EnvironmentInfo       `json:"environment"`
	GoYaraResults        *GoYaraResults         `json:"go_yara_results"`
	ReferenceYaraResults *ReferenceYaraResults  `json:"reference_yara_results"`
	PerformanceGaps      *PerformanceGaps       `json:"performance_gaps"`
	CorrectnessResults   *CorrectnessResults    `json:"correctness_results"`
	ProfileData          map[string]interface{} `json:"profile_data"`
	TestCases            []*TestCaseResult      `json:"test_cases"`
}

// EnvironmentInfo captures environment details
type EnvironmentInfo struct {
	GoVersion   string    `json:"go_version"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	NumCPU      int       `json:"num_cpu"`
	RAMGB       float64   `json:"ram_gb"`
	YaraVersion string    `json:"yara_version"`
	YaraPath    string    `json:"yara_path"`
	Timestamp   time.Time `json:"timestamp"`
}

// GoYaraResults captures go-yara performance metrics
type GoYaraResults struct {
	CompilationMetrics *CompilationMetrics `json:"compilation"`
	ExecutionMetrics   *ExecutionMetrics   `json:"execution"`
	MemoryMetrics      *MemoryMetrics      `json:"memory"`
	ErrorMetrics       *ErrorMetrics       `json:"errors"`
}

// ReferenceYaraResults captures reference YARA performance metrics
type ReferenceYaraResults struct {
	CompilationMetrics *CompilationMetrics `json:"compilation"`
	ExecutionMetrics   *ExecutionMetrics   `json:"execution"`
	MemoryMetrics      *MemoryMetrics      `json:"memory"`
	ErrorMetrics       *ErrorMetrics       `json:"errors"`
}

// CompilationMetrics captures compilation performance
type CompilationMetrics struct {
	TotalFiles   int           `json:"total_files"`
	SuccessCount int           `json:"success_count"`
	ErrorCount   int           `json:"error_count"`
	TotalTime    time.Duration `json:"total_time"`
	MinTime      time.Duration `json:"min_time"`
	MaxTime      time.Duration `json:"max_time"`
	AvgTime      time.Duration `json:"avg_time"`
	TotalRules   int           `json:"total_rules"`
	RulesPerSec  float64       `json:"rules_per_sec"`
	BytesPerSec  float64       `json:"bytes_per_sec"`
}

// ExecutionMetrics captures execution performance
type ExecutionMetrics struct {
	TotalExecutions int           `json:"total_executions"`
	SuccessCount    int           `json:"success_count"`
	ErrorCount      int           `json:"error_count"`
	TotalTime       time.Duration `json:"total_time"`
	MinTime         time.Duration `json:"min_time"`
	MaxTime         time.Duration `json:"max_time"`
	AvgTime         time.Duration `json:"avg_time"`
	TotalMatches    int64         `json:"total_matches"`
	MBPerSec        float64       `json:"mb_per_sec"`
	FilesPerSec     float64       `json:"files_per_sec"`
}

// MemoryMetrics captures memory usage
type MemoryMetrics struct {
	PeakRSS      uint64          `json:"peak_rss_bytes"`
	AvgRSS       uint64          `json:"avg_rss_bytes"`
	TotalAllocs  uint64          `json:"total_allocs"`
	TotalBytes   uint64          `json:"total_bytes"`
	AvgAllocs    uint64          `json:"avg_allocs"`
	AllocsPerSec float64         `json:"allocs_per_sec"`
	BytesPerSec  float64         `json:"bytes_per_sec"`
	GCPauses     []time.Duration `json:"gc_pauses"`
}

// ErrorMetrics captures error statistics
type ErrorMetrics struct {
	CompilationErrors []string `json:"compilation_errors"`
	ExecutionErrors   []string `json:"execution_errors"`
	Timeouts          int      `json:"timeouts"`
	ParseErrors       int      `json:"parse_errors"`
	OtherErrors       int      `json:"other_errors"`
}

// PerformanceGaps compares performance between implementations
type PerformanceGaps struct {
	CompilationSpeedup  float64 `json:"compilation_speedup"`
	ExecutionSpeedup    float64 `json:"execution_speedup"`
	MemoryReduction     float64 `json:"memory_reduction"`
	AllocationReduction float64 `json:"allocation_reduction"`
	EnergyEfficiency    float64 `json:"energy_efficiency"`
	OverallScore        float64 `json:"overall_score"`
}

// CorrectnessResults compares correctness between implementations
type CorrectnessResults struct {
	TotalTestCases     int            `json:"total_test_cases"`
	MatchingResults    int            `json:"matching_results"`
	DifferentResults   int            `json:"different_results"`
	GoYaraOnlyMatches  int            `json:"go_yara_only_matches"`
	RefYaraOnlyMatches int            `json:"ref_yara_only_matches"`
	MatchAccuracy      float64        `json:"match_accuracy"`
	FalsePositives     int            `json:"false_positives"`
	FalseNegatives     int            `json:"false_negatives"`
	Discrepancies      []*Discrepancy `json:"discrepancies"`
}

// Discrepancy captures differences in results
type Discrepancy struct {
	RuleFile       string   `json:"rule_file"`
	DataFile       string   `json:"data_file"`
	GoYaraMatches  []string `json:"go_yara_matches"`
	RefYaraMatches []string `json:"ref_yara_matches"`
	MatchType      string   `json:"match_type"` // "extra_go", "extra_ref", "different_count"
}

// TestCaseResult represents a single test case comparison
type TestCaseResult struct {
	Name                string                 `json:"name"`
	RuleFile            string                 `json:"rule_file"`
	DataFile            string                 `json:"data_file"`
	RuleCount           int                    `json:"rule_count"`
	DataSize            int64                  `json:"data_size"`
	GoYaraResult        *SingleExecutionResult `json:"go_yara_result"`
	ReferenceYaraResult *SingleExecutionResult `json:"reference_yara_result"`
	MatchCorrectness    *CorrectnessCheck      `json:"match_correctness"`
	PerformanceGap      *PerformanceGap        `json:"performance_gap"`
}

// SingleExecutionResult captures result from single execution
type SingleExecutionResult struct {
	CompilationTime time.Duration `json:"compilation_time"`
	ExecutionTime   time.Duration `json:"execution_time"`
	MatchCount      int           `json:"match_count"`
	Matches         []string      `json:"matches"`
	MemoryUsage     uint64        `json:"memory_usage"`
	Allocations     uint64        `json:"allocations"`
	Success         bool          `json:"success"`
	Error           string        `json:"error"`
}

// CorrectnessCheck compares matches between implementations
type CorrectnessCheck struct {
	MatchesIdentical bool     `json:"matches_identical"`
	GoYaraOnly       []string `json:"go_yara_only"`
	RefYaraOnly      []string `json:"ref_yara_only"`
	CountDifference  int      `json:"count_difference"`
	Accuracy         float64  `json:"accuracy"`
}

// PerformanceGap compares performance for a single test case
type PerformanceGap struct {
	CompilationSpeedup float64 `json:"compilation_speedup"`
	ExecutionSpeedup   float64 `json:"execution_speedup"`
	MemoryReduction    float64 `json:"memory_reduction"`
	OverallFaster      bool    `json:"overall_faster"`
}

// Profiler provides detailed profiling capabilities
type Profiler struct {
	cpuProfileFile   *os.File
	memProfileFile   *os.File
	allocProfileFile *os.File
	enabled          bool // nolint:unused // Reserved for future use
}

// NewComparator creates a new comparison instance
func NewComparator(config *ComparisonConfig) (*Comparator, error) {
	if config == nil {
		config = DefaultComparisonConfig()
	}

	// Find YARA binary
	yaraPath, err := findYaraBinary()
	if err != nil {
		return nil, fmt.Errorf("finding YARA binary: %w", err)
	}

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "go-yara-comparison-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp directory: %w", err)
	}

	comparator := &Comparator{
		config:     config,
		results:    &ComparisonResults{},
		profiler:   &Profiler{},
		tempDir:    tempDir,
		yaraBinary: yaraPath,
	}

	// Initialize results
	comparator.results.Environment = comparator.captureEnvironmentInfo()
	comparator.results.GoYaraResults = &GoYaraResults{}
	comparator.results.ReferenceYaraResults = &ReferenceYaraResults{}
	comparator.results.PerformanceGaps = &PerformanceGaps{}
	comparator.results.CorrectnessResults = &CorrectnessResults{}
	comparator.results.ProfileData = make(map[string]interface{})
	comparator.results.TestCases = []*TestCaseResult{}

	return comparator, nil
}

// DefaultComparisonConfig returns sensible default comparison settings
func DefaultComparisonConfig() *ComparisonConfig {
	return &ComparisonConfig{
		RuleDirectories:    []string{"examples", "testdata", "rules"},
		DataDirectories:    []string{"testdata", "examples/data"},
		TestFilePattern:    "*.yar",
		MaxRuleFiles:       50,
		MaxDataFiles:       100,
		MaxRulesPerFile:    20,
		MaxDataSize:        10 * 1024 * 1024, // 10MB
		TimeoutCompilation: 30 * time.Second,
		TimeoutExecution:   60 * time.Second,
		ProfileCPU:         true,
		ProfileMemory:      true,
		ProfileAllocs:      true,
		Verbose:            false,
		Parallelism:        runtime.NumCPU(),
	}
}

// RunComparison executes comprehensive comparison
func (c *Comparator) RunComparison() error {
	c.results.StartTime = time.Now()
	defer func() {
		c.results.EndTime = time.Now()
		c.results.Duration = c.results.EndTime.Sub(c.results.StartTime)
	}()

	if c.config.Verbose {
		fmt.Printf("Starting comprehensive comparison between go-yara and reference YARA\n")
		fmt.Printf("YARA binary: %s\n", c.yaraBinary)
		fmt.Printf("Temp directory: %s\n", c.tempDir)
	}

	// Discover test cases
	testCases, err := c.discoverTestCases()
	if err != nil {
		return fmt.Errorf("discovering test cases: %w", err)
	}

	if len(testCases) == 0 {
		return fmt.Errorf("no test cases found")
	}

	if c.config.Verbose {
		fmt.Printf("Found %d test cases\n", len(testCases))
	}

	// Setup profiling
	if setupErr := c.setupProfiling(); setupErr != nil {
		return fmt.Errorf("setting up profiling: %w", setupErr)
	}
	defer c.cleanupProfiling()

	// Run comparisons
	c.runComparisons(testCases)

	// Calculate performance gaps
	c.calculatePerformanceGaps()

	// Calculate correctness results
	c.calculateCorrectnessResults()

	return nil
}

// captureEnvironmentInfo captures environment details
func (c *Comparator) captureEnvironmentInfo() *EnvironmentInfo {
	// Get memory info
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Get YARA version
	yaraVersion := "unknown"
	if cmd := exec.Command(c.yaraBinary, "--version"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			yaraVersion = strings.TrimSpace(string(output))
		}
	}

	return &EnvironmentInfo{
		GoVersion:   runtime.Version(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		NumCPU:      runtime.NumCPU(),
		RAMGB:       float64(memStats.Sys) / 1024 / 1024 / 1024,
		YaraVersion: yaraVersion,
		YaraPath:    c.yaraBinary,
		Timestamp:   time.Now(),
	}
}

// discoverTestCases finds all rule and data file combinations
func (c *Comparator) discoverTestCases() ([]*TestCaseResult, error) {
	var testCases []*TestCaseResult

	// Find rule files
	ruleFiles, err := c.findFiles(c.config.RuleDirectories, c.config.TestFilePattern, c.config.MaxRuleFiles)
	if err != nil {
		return nil, fmt.Errorf("finding rule files: %w", err)
	}

	// Find data files
	dataFiles, err := c.findFiles(c.config.DataDirectories, "*", c.config.MaxDataFiles)
	if err != nil {
		return nil, fmt.Errorf("finding data files: %w", err)
	}

	if c.config.Verbose {
		fmt.Printf("Found %d rule files and %d data files\n", len(ruleFiles), len(dataFiles))
	}

	// Create test cases (cross product, but limited)
	testCaseCount := 0
	maxTestCases := c.config.MaxRuleFiles * c.config.MaxDataFiles

	for _, ruleFile := range ruleFiles {
		for _, dataFile := range dataFiles {
			if testCaseCount >= maxTestCases {
				break
			}

			// Check data file size
			info, statErr := os.Stat(dataFile)
			if statErr == nil {
				if info.Size() > c.config.MaxDataSize {
					continue
				}
			}

			testCase := &TestCaseResult{
				Name:     fmt.Sprintf("%s_vs_%s", filepath.Base(ruleFile), filepath.Base(dataFile)),
				RuleFile: ruleFile,
				DataFile: dataFile,
			}

			testCases = append(testCases, testCase)
			testCaseCount++
		}

		if testCaseCount >= maxTestCases {
			break
		}
	}

	return testCases, nil
}

// findFiles finds files matching pattern in directories
func (c *Comparator) findFiles(directories []string, pattern string, maxFiles int) ([]string, error) {
	var files []string

	for _, dir := range directories {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Continue walking
			}

			if info.IsDir() {
				return nil
			}

			if len(files) >= maxFiles {
				return filepath.SkipDir
			}

			matched, err := filepath.Match(pattern, filepath.Base(path))
			if err != nil {
				return nil
			}

			if matched {
				files = append(files, path)
			}

			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	return files, nil
}

// setupProfiling sets up profiling
func (c *Comparator) setupProfiling() error {
	if !c.config.ProfileCPU && !c.config.ProfileMemory && !c.config.ProfileAllocs {
		return nil
	}

	if c.config.ProfileCPU {
		cpuFile, err := os.Create(filepath.Join(c.tempDir, "cpu.prof"))
		if err != nil {
			return fmt.Errorf("creating CPU profile: %w", err)
		}
		c.profiler.cpuProfileFile = cpuFile
		runtime.SetCPUProfileRate(100) // 100Hz sampling
	}

	if c.config.ProfileMemory {
		memFile, err := os.Create(filepath.Join(c.tempDir, "mem.prof"))
		if err != nil {
			return fmt.Errorf("creating memory profile: %w", err)
		}
		c.profiler.memProfileFile = memFile
	}

	if c.config.ProfileAllocs {
		allocFile, err := os.Create(filepath.Join(c.tempDir, "alloc.prof"))
		if err != nil {
			return fmt.Errorf("creating alloc profile: %w", err)
		}
		c.profiler.allocProfileFile = allocFile
	}

	c.profiler.enabled = true
	return nil
}

// cleanupProfiling cleans up profiling resources
func (c *Comparator) cleanupProfiling() {
	if c.profiler.cpuProfileFile != nil {
		c.profiler.cpuProfileFile.Close()
	}
	if c.profiler.memProfileFile != nil {
		c.profiler.memProfileFile.Close()
	}
	if c.profiler.allocProfileFile != nil {
		c.profiler.allocProfileFile.Close()
	}
}

// findYaraBinary finds the YARA binary in system PATH
func findYaraBinary() (string, error) {
	paths := []string{"yara", "/usr/bin/yara", "/usr/local/bin/yara"}

	for _, path := range paths {
		if _, err := exec.LookPath(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("YARA binary not found in PATH")
}

// SaveResults saves comparison results to file
func (c *Comparator) SaveResults(filename string) error {
	data, err := json.MarshalIndent(c.results, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}

	return os.WriteFile(filename, data, 0600)
}

// GenerateReport generates a human-readable report
func (c *Comparator) GenerateReport() string {
	var report strings.Builder

	report.WriteString("# Go-YARA vs Reference YARA Comparison Report\n\n")

	// Environment info
	report.WriteString("## Environment\n\n")
	report.WriteString(fmt.Sprintf("- **Go Version**: %s\n", c.results.Environment.GoVersion))
	report.WriteString(fmt.Sprintf("- **OS/Arch**: %s/%s\n", c.results.Environment.OS, c.results.Environment.Arch))
	report.WriteString(fmt.Sprintf("- **CPU Cores**: %d\n", c.results.Environment.NumCPU))
	report.WriteString(fmt.Sprintf("- **RAM**: %.2f GB\n", c.results.Environment.RAMGB))
	report.WriteString(fmt.Sprintf("- **YARA Version**: %s\n", c.results.Environment.YaraVersion))
	report.WriteString(fmt.Sprintf("- **Test Duration**: %s\n\n", c.results.Duration))

	// Performance gaps
	if c.results.PerformanceGaps != nil {
		report.WriteString("## Performance Gaps\n\n")
		report.WriteString(fmt.Sprintf("- **Compilation Speedup**: %.2fx\n", c.results.PerformanceGaps.CompilationSpeedup))
		report.WriteString(fmt.Sprintf("- **Execution Speedup**: %.2fx\n", c.results.PerformanceGaps.ExecutionSpeedup))
		report.WriteString(fmt.Sprintf("- **Memory Reduction**: %.2f%%\n", c.results.PerformanceGaps.MemoryReduction*100))
		report.WriteString(fmt.Sprintf("- **Overall Score**: %.2f\n\n", c.results.PerformanceGaps.OverallScore))
	}

	// Correctness
	if c.results.CorrectnessResults != nil {
		report.WriteString("## Correctness\n\n")
		report.WriteString(fmt.Sprintf("- **Total Test Cases**: %d\n", c.results.CorrectnessResults.TotalTestCases))
		report.WriteString(fmt.Sprintf("- **Matching Results**: %d\n", c.results.CorrectnessResults.MatchingResults))
		report.WriteString(fmt.Sprintf("- **Different Results**: %d\n", c.results.CorrectnessResults.DifferentResults))
		report.WriteString(fmt.Sprintf("- **Match Accuracy**: %.2f%%\n\n", c.results.CorrectnessResults.MatchAccuracy*100))
	}

	return report.String()
}

// GetResults returns the comparison results
func (c *Comparator) GetResults() *ComparisonResults {
	return c.results
}

// PrintSummary prints a concise summary to stdout
func (c *Comparator) PrintSummary() {
	fmt.Printf("\n=== Go-YARA vs Reference YARA Comparison Summary ===\n")
	fmt.Printf("Test Duration: %s\n", c.results.Duration)
	fmt.Printf("Test Cases: %d\n", len(c.results.TestCases))

	if c.results.PerformanceGaps != nil {
		fmt.Printf("Compilation Speedup: %.2fx\n", c.results.PerformanceGaps.CompilationSpeedup)
		fmt.Printf("Execution Speedup: %.2fx\n", c.results.PerformanceGaps.ExecutionSpeedup)
		if c.results.PerformanceGaps.MemoryReduction > 0 {
			fmt.Printf("Memory Reduction: %.2f%%\n", c.results.PerformanceGaps.MemoryReduction*100)
		}
	}

	if c.results.CorrectnessResults != nil {
		fmt.Printf("Match Accuracy: %.2f%%\n", c.results.CorrectnessResults.MatchAccuracy*100)
		if c.results.CorrectnessResults.DifferentResults > 0 {
			fmt.Printf("Warning: %d test cases with different results\n", c.results.CorrectnessResults.DifferentResults)
		}
	}

	fmt.Printf("======================================================\n")
}
