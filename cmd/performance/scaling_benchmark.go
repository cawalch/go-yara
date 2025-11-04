//go:build scaling_bench

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

// ScalingBenchmark tests performance across different scaling dimensions
type ScalingBenchmark struct {
	config   *ScalingConfig
	results  map[string]*ScalingResult
	yaraPath string
}

// ScalingConfig defines scaling test parameters
type ScalingConfig struct {
	// Test dimensions
	FileCounts  []int // Numbers of files to test
	FileSizesKB []int // File sizes in KB to test
	RuleCounts  []int // Numbers of rules to test

	// Test parameters
	OutputDir string // Output directory
	Verbose   bool   // Verbose output
	QuickMode bool   // Quick mode for faster testing
}

// ScalingResult represents results for a specific scaling configuration
type ScalingResult struct {
	Scenario       string        `json:"scenario"`
	Files          int           `json:"files"`
	FileSizeKB     int           `json:"file_size_kb"`
	Rules          int           `json:"rules"`
	GoYARATime     time.Duration `json:"go_yara_time"`
	LibYARATime    time.Duration `json:"libyara_time"`
	Speedup        float64       `json:"speedup"`
	GoYARAMemory   int64         `json:"go_yara_memory_mb"`
	LibYARAMemory  int64         `json:"libyara_memory_mb"`
	GoYARAMatches  int           `json:"go_yara_matches"`
	LibYARAMatches int           `json:"libyara_matches"`
	Accuracy       float64       `json:"accuracy"`
}

func main() {
	config := parseScalingFlags()
	benchmark := NewScalingBenchmark(config)

	if err := benchmark.Run(); err != nil {
		log.Fatalf("Benchmark failed: %v", err)
	}

	benchmark.AnalyzeResults()
}

func parseScalingFlags() *ScalingConfig {
	config := &ScalingConfig{
		FileCounts:  []int{10, 100, 1000, 5000},
		FileSizesKB: []int{1, 10, 100, 1000},
		RuleCounts:  []int{10, 50, 100, 500},
	}

	flag.Var((*IntSlice)(&config.FileCounts), "file-counts", "File counts to test (comma-separated)")
	flag.Var((*IntSlice)(&config.FileSizesKB), "file-sizes", "File sizes in KB to test (comma-separated)")
	flag.Var((*IntSlice)(&config.RuleCounts), "rule-counts", "Rule counts to test (comma-separated)")

	flag.StringVar(&config.OutputDir, "output", "scaling-results", "Output directory")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&config.QuickMode, "quick", false, "Quick mode (reduced test set)")

	flag.Parse()

	if config.QuickMode {
		config.FileCounts = []int{10, 100, 1000}
		config.FileSizesKB = []int{1, 10, 100}
		config.RuleCounts = []int{10, 50, 100}
	}

	return config
}

// IntSlice implements flag.Value for comma-separated integer slices
type IntSlice []int

func (i *IntSlice) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *IntSlice) Set(value string) error {
	parts := strings.Split(value, ",")
	*i = make(IntSlice, len(parts))
	for j, part := range parts {
		var val int
		_, err := fmt.Sscanf(strings.TrimSpace(part), "%d", &val)
		if err != nil {
			return err
		}
		(*i)[j] = val
	}
	return nil
}

func NewScalingBenchmark(config *ScalingConfig) *ScalingBenchmark {
	yaraPath, err := findYARABinary()
	if err != nil {
		log.Fatalf("Could not find yara binary: %v", err)
	}

	return &ScalingBenchmark{
		config:   config,
		results:  make(map[string]*ScalingResult),
		yaraPath: yaraPath,
	}
}

func findYARABinary() (string, error) {
	if path, err := exec.LookPath("yara"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("yara binary not found in PATH")
}

func (sb *ScalingBenchmark) Run() error {
	if sb.config.Verbose {
		fmt.Printf("=== Scaling Performance Benchmark ===\n")
		fmt.Printf("Test Configuration:\n")
		fmt.Printf("  File counts: %v\n", sb.config.FileCounts)
		fmt.Printf("  File sizes (KB): %v\n", sb.config.FileSizesKB)
		fmt.Printf("  Rule counts: %v\n", sb.config.RuleCounts)
		fmt.Printf("  Quick mode: %v\n", sb.config.QuickMode)
		fmt.Printf("\n")
	}

	// Create output directory
	if err := os.MkdirAll(sb.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate test data
	testDataDir := filepath.Join(sb.config.OutputDir, "test_data")
	if err := sb.generateTestData(testDataDir); err != nil {
		return fmt.Errorf("failed to generate test data: %w", err)
	}

	// Run scaling tests
	scenarios := sb.generateScenarios()
	total := len(scenarios)

	for i, scenario := range scenarios {
		if sb.config.Verbose {
			fmt.Printf("Running scenario %d/%d: %s\n", i+1, total, scenario.Name)
		}

		result, err := sb.runScenario(scenario, testDataDir)
		if err != nil {
			log.Printf("Failed to run scenario %s: %v", scenario.Name, err)
			continue
		}

		sb.results[scenario.Name] = result
	}

	return nil
}

type TestScenario struct {
	Name     string
	Files    int
	FileSize int
	Rules    int
}

func (sb *ScalingBenchmark) generateScenarios() []TestScenario {
	var scenarios []TestScenario

	// Generate combinations
	for _, fileCount := range sb.config.FileCounts {
		for _, fileSize := range sb.config.FileSizesKB {
			for _, ruleCount := range sb.config.RuleCounts {
				name := fmt.Sprintf("files_%d_size_%dKB_rules_%d", fileCount, fileSize, ruleCount)
				scenarios = append(scenarios, TestScenario{
					Name:     name,
					Files:    fileCount,
					FileSize: fileSize,
					Rules:    ruleCount,
				})
			}
		}
	}

	return scenarios
}

func (sb *ScalingBenchmark) generateTestData(baseDir string) error {
	filesDir := filepath.Join(baseDir, "files")
	rulesDir := filepath.Join(baseDir, "rules")

	if err := os.MkdirAll(filesDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return err
	}

	// Generate maximum needed files and rules
	maxFiles := 0
	for _, count := range sb.config.FileCounts {
		if count > maxFiles {
			maxFiles = count
		}
	}

	maxRules := 0
	for _, count := range sb.config.RuleCounts {
		if count > maxRules {
			maxRules = count
		}
	}

	maxSize := 0
	for _, size := range sb.config.FileSizesKB {
		if size > maxSize {
			maxSize = size
		}
	}

	// Generate files
	if err := sb.generateFiles(filesDir, maxFiles, maxSize); err != nil {
		return err
	}

	// Generate rules
	if err := sb.generateRules(rulesDir, maxRules); err != nil {
		return err
	}

	return nil
}

func (sb *ScalingBenchmark) generateFiles(dir string, count, maxSizeKB int) error {
	fileTypes := []struct {
		prefix    string
		generator func(int) []byte
	}{
		{"pe", generatePEFile},
		{"elf", generateELFFile},
		{"txt", generateTextFile},
		{"bin", generateBinaryFile},
	}

	filesPerType := count / len(fileTypes)

	for _, fileType := range fileTypes {
		for i := 0; i < filesPerType; i++ {
			// Generate different sizes
			for _, size := range sb.config.FileSizesKB {
				filename := fmt.Sprintf("%s_%d_%dkb.dat", fileType.prefix, i, size)
				filepath := filepath.Join(dir, filename)

				content := fileType.generator(size * 1024)
				if err := os.WriteFile(filepath, content, 0644); err != nil {
					return fmt.Errorf("failed to write file %s: %w", filename, err)
				}
			}
		}
	}

	return nil
}

func (sb *ScalingBenchmark) generateRules(dir string, count int) error {
	ruleTemplates := []string{
		`rule pe_header_%d {
    meta:
        description = "PE file header detection"
        author = "benchmark"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 }
    condition:
        $mz at 0 and $pe at
}`,

		`rule elf_header_%d {
    meta:
        description = "ELF file header detection"
        author = "benchmark"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0
}`,

		`rule malware_strings_%d {
    meta:
        description = "Common malware strings"
        author = "benchmark"
    strings:
        $s1 = "malware"
        $s2 = "virus"
        $s3 = "trojan"
        $s4 = /backdoor/i
    condition:
        any of them
}`,

		`rule api_calls_%d {
    meta:
        description = "Suspicious API calls"
        author = "benchmark"
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAllocEx"
    condition:
        any of them
}`,
	}

	rulesPerTemplate := count / len(ruleTemplates)

	for i, template := range ruleTemplates {
		for j := 0; j < rulesPerTemplate; j++ {
			ruleContent := fmt.Sprintf(template, i*rulesPerTemplate+j)
			filename := fmt.Sprintf("rule_%d_%d.yar", i, j)
			filepath := filepath.Join(dir, filename)

			if err := os.WriteFile(filepath, []byte(ruleContent), 0644); err != nil {
				return fmt.Errorf("failed to write rule file %s: %w", filename, err)
			}
		}
	}

	return nil
}

// File generation functions
func generatePEFile(size int) []byte {
	if size < 132 {
		size = 132
	}
	data := make([]byte, size)

	// PE header
	copy(data[0:2], []byte{0x4D, 0x5A}) // MZ
	if size > 64 {
		copy(data[60:64], []byte{0x80, 0x00, 0x00, 0x00}) // PE header offset
	}
	if size > 132 {
		copy(data[128:132], []byte{0x50, 0x45, 0x00, 0x00}) // PE
	}

	// Add some pattern strings for testing
	if size > 200 {
		copy(data[200:207], []byte("malware"))
	}
	if size > 300 {
		copy(data[300:316], []byte("CreateRemoteThread"))
	}

	// Fill rest with pattern
	for i := 132; i < size; i++ {
		data[i] = byte(i % 256)
	}

	return data
}

func generateELFFile(size int) []byte {
	if size < 16 {
		size = 16
	}
	data := make([]byte, size)

	// ELF header
	copy(data[0:4], []byte{0x7F, 0x45, 0x4C, 0x46}) // ELF
	if size > 8 {
		data[4] = 0x01 // 32-bit
		data[5] = 0x01 // little endian
		data[6] = 0x01 // ELF version
	}

	// Add some pattern strings
	if size > 100 {
		copy(data[100:106], []byte("virus"))
	}
	if size > 200 {
		copy(data[200:215], []byte("WriteProcessMemory"))
	}

	// Fill rest with pattern
	for i := 16; i < size; i++ {
		data[i] = byte(i % 256)
	}

	return data
}

func generateTextFile(size int) []byte {
	words := []string{
		"malware", "virus", "trojan", "backdoor", "exploit",
		"CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
		"encryption", "obfuscation", "packing", "anti-analysis",
	}

	data := make([]byte, 0, size)
	wordLen := len(words)

	for len(data) < size {
		word := words[len(data)/10%wordLen]
		if len(data)+len(word) <= size {
			data = append(data, []byte(word)...)
			if len(data) < size {
				data = append(data, ' ')
			}
		} else {
			break
		}
	}

	// Pad to exact size
	for len(data) < size {
		data = append(data, ' ')
	}

	return data[:size]
}

func generateBinaryFile(size int) []byte {
	data := make([]byte, size)

	// Add pattern strings at regular intervals
	patterns := [][]byte{
		[]byte("trojan"),
		[]byte("backdoor"),
		[]byte("VirtualAllocEx"),
	}

	patternInterval := size / (len(patterns) + 1)
	for i, pattern := range patterns {
		pos := (i + 1) * patternInterval
		if pos+len(pattern) < size {
			copy(data[pos:pos+len(pattern)], pattern)
		}
	}

	// Fill with pattern
	for i := 0; i < size; i++ {
		data[i] = byte(i % 256)
	}

	return data
}

func (sb *ScalingBenchmark) runScenario(scenario TestScenario, testDataDir string) (*ScalingResult, error) {
	// Select files and rules for this scenario
	files, err := sb.selectFiles(filepath.Join(testDataDir, "files"), scenario.Files, scenario.FileSize)
	if err != nil {
		return nil, fmt.Errorf("failed to select files: %w", err)
	}

	rules, err := sb.selectRules(filepath.Join(testDataDir, "rules"), scenario.Rules)
	if err != nil {
		return nil, fmt.Errorf("failed to select rules: %w", err)
	}

	if sb.config.Verbose {
		fmt.Printf("  Testing %d files (%dKB each) with %d rules\n", len(files), scenario.FileSize, len(rules))
	}

	// Test go-yara
	goYARAStart := time.Now()
	goYARAMatches, goYARAMemory, err := sb.testGoYARA(files, rules)
	if err != nil {
		return nil, fmt.Errorf("go-yara test failed: %w", err)
	}
	goYARATime := time.Since(goYARAStart)

	// Test libyara
	libYARAStart := time.Now()
	libYARAMatches, libYARAMemory, err := sb.testLibYARA(files, rules)
	if err != nil {
		return nil, fmt.Errorf("libyara test failed: %w", err)
	}
	libYARATime := time.Since(libYARAStart)

	// Calculate metrics
	speedup := float64(libYARATime) / float64(goYARATime)
	accuracy := sb.calculateAccuracy(goYARAMatches, libYARAMatches)

	return &ScalingResult{
		Scenario:       scenario.Name,
		Files:          scenario.Files,
		FileSizeKB:     scenario.FileSize,
		Rules:          scenario.Rules,
		GoYARATime:     goYARATime,
		LibYARATime:    libYARATime,
		Speedup:        speedup,
		GoYARAMemory:   goYARAMemory / 1024 / 1024, // Convert to MB
		LibYARAMemory:  libYARAMemory / 1024 / 1024,
		GoYARAMatches:  goYARAMatches,
		LibYARAMatches: libYARAMatches,
		Accuracy:       accuracy,
	}, nil
}

func (sb *ScalingBenchmark) selectFiles(dir string, count, sizeKB int) ([]string, error) {
	pattern := fmt.Sprintf("*_%dkb.dat", sizeKB)
	files, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil, err
	}

	if len(files) < count {
		return files, nil
	}

	sort.Strings(files)
	return files[:count], nil
}

func (sb *ScalingBenchmark) selectRules(dir string, count int) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yar"))
	if err != nil {
		return nil, err
	}

	if len(files) < count {
		return files, nil
	}

	sort.Strings(files)
	return files[:count], nil
}

func (sb *ScalingBenchmark) testGoYARA(files, rules []string) (matches int, memory int64, err error) {
	// Create rule compiler
	compiler := &compiler.RuleCompiler{}

	// Get initial memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	initialMemory := memStats.Alloc

	// Compile rules
	program, err := compiler.CompileFiles(rules)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to compile rules: %w", err)
	}

	// Scan files
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		// Execute compiled rules
		matches += len(program.Execute(data))
	}

	// Get final memory stats
	runtime.ReadMemStats(&memStats)
	finalMemory := memStats.Alloc

	return matches, int64(finalMemory - initialMemory), nil
}

func (sb *ScalingBenchmark) testLibYARA(files, rules []string) (matches int, memory int64, err error) {
	// Create temporary rule file
	tempRuleFile := filepath.Join(sb.config.OutputDir, "temp_rules.yar")
	if err := sb.combineRuleFiles(rules, tempRuleFile); err != nil {
		return 0, 0, fmt.Errorf("failed to combine rule files: %w", err)
	}
	defer os.Remove(tempRuleFile)

	// Run yara command
	args := []string{tempRuleFile}
	args = append(args, files...)

	cmd := exec.Command(sb.yaraPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Errorf("yara command failed: %w, output: %s", err, string(output))
	}

	// Count matches (each line in output represents a match)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			matches++
		}
	}

	// Estimate memory usage (simplified)
	memory = int64(len(files) * len(rules) * 2048) // Rough estimate

	return matches, memory, nil
}

func (sb *ScalingBenchmark) combineRuleFiles(ruleFiles []string, outputFile string) error {
	combined := strings.Builder{}

	for _, ruleFile := range ruleFiles {
		content, err := os.ReadFile(ruleFile)
		if err != nil {
			return err
		}
		combined.Write(content)
		combined.WriteString("\n")
	}

	return os.WriteFile(outputFile, []byte(combined.String()), 0644)
}

func (sb *ScalingBenchmark) calculateAccuracy(goMatches, libMatches int) float64 {
	if libMatches == 0 && goMatches == 0 {
		return 100.0
	}

	if libMatches == 0 {
		return 0.0
	}

	diff := abs(libMatches - goMatches)
	accuracy := 100.0 - (float64(diff)/float64(libMatches))*100.0

	if accuracy < 0 {
		return 0.0
	}

	return accuracy
}

func (sb *ScalingBenchmark) AnalyzeResults() {
	fmt.Printf("\n=== Scaling Performance Analysis ===\n")

	if len(sb.results) == 0 {
		fmt.Printf("No results to analyze\n")
		return
	}

	// Analyze by dimension
	sb.analyzeFileScaling()
	sb.analyzeRuleScaling()
	sb.analyzeSizeScaling()
	sb.identifyBottlenecks()
	sb.generateRecommendations()
}

func (sb *ScalingBenchmark) analyzeFileScaling() {
	fmt.Printf("\nFile Count Scaling Analysis:\n")

	// Group results by rule count and file size, analyze file count scaling
	for _, ruleCount := range sb.config.RuleCounts {
		for _, fileSize := range sb.config.FileSizesKB {
			fmt.Printf("  Rules: %d, File Size: %dKB\n", ruleCount, fileSize)

			var fileCounts []int
			var speedups []float64
			var goTimes []time.Duration
			var libTimes []time.Duration

			for _, fileCount := range sb.config.FileCounts {
				scenarioName := fmt.Sprintf("files_%d_size_%dKB_rules_%d", fileCount, fileSize, ruleCount)
				if result, exists := sb.results[scenarioName]; exists {
					fileCounts = append(fileCounts, fileCount)
					speedups = append(speedups, result.Speedup)
					goTimes = append(goTimes, result.GoYARATime)
					libTimes = append(libTimes, result.LibYARATime)
				}
			}

			if len(fileCounts) > 1 {
				sb.printScalingTrend("Files", fileCounts, speedups, goTimes, libTimes)
			}
		}
	}
}

func (sb *ScalingBenchmark) analyzeRuleScaling() {
	fmt.Printf("\nRule Count Scaling Analysis:\n")

	// Group results by file count and file size, analyze rule count scaling
	for _, fileCount := range sb.config.FileCounts {
		for _, fileSize := range sb.config.FileSizesKB {
			fmt.Printf("  Files: %d, File Size: %dKB\n", fileCount, fileSize)

			var ruleCounts []int
			var speedups []float64
			var goTimes []time.Duration
			var libTimes []time.Duration

			for _, ruleCount := range sb.config.RuleCounts {
				scenarioName := fmt.Sprintf("files_%d_size_%dKB_rules_%d", fileCount, fileSize, ruleCount)
				if result, exists := sb.results[scenarioName]; exists {
					ruleCounts = append(ruleCounts, ruleCount)
					speedups = append(speedups, result.Speedup)
					goTimes = append(goTimes, result.GoYARATime)
					libTimes = append(libTimes, result.LibYARATime)
				}
			}

			if len(ruleCounts) > 1 {
				sb.printScalingTrend("Rules", ruleCounts, speedups, goTimes, libTimes)
			}
		}
	}
}

func (sb *ScalingBenchmark) analyzeSizeScaling() {
	fmt.Printf("\nFile Size Scaling Analysis:\n")

	// Group results by file count and rule count, analyze file size scaling
	for _, fileCount := range sb.config.FileCounts {
		for _, ruleCount := range sb.config.RuleCounts {
			fmt.Printf("  Files: %d, Rules: %d\n", fileCount, ruleCount)

			var fileSizes []int
			var speedups []float64
			var goTimes []time.Duration
			var libTimes []time.Duration

			for _, fileSize := range sb.config.FileSizesKB {
				scenarioName := fmt.Sprintf("files_%d_size_%dKB_rules_%d", fileCount, fileSize, ruleCount)
				if result, exists := sb.results[scenarioName]; exists {
					fileSizes = append(fileSizes, fileSize)
					speedups = append(speedups, result.Speedup)
					goTimes = append(goTimes, result.GoYARATime)
					libTimes = append(libTimes, result.LibYARATime)
				}
			}

			if len(fileSizes) > 1 {
				sb.printScalingTrend("File Size (KB)", fileSizes, speedups, goTimes, libTimes)
			}
		}
	}
}

func (sb *ScalingBenchmark) printScalingTrend(dimension string, values []int, speedups []float64, goTimes []time.Duration, libTimes []time.Duration) {
	fmt.Printf("    %-15s | Speedup | Go-YARA | LibYARA\n", dimension)
	fmt.Printf("    %-15s-+---------+---------+--------\n", strings.Repeat("-", 15))

	for i, value := range values {
		fmt.Printf("    %-15d | %7.2fx | %7.3fs | %6.3fs\n",
			value, speedups[i], goTimes[i].Seconds(), libTimes[i].Seconds())
	}

	// Analyze scaling behavior
	if len(speedups) >= 2 {
		firstSpeedup := speedups[0]
		lastSpeedup := speedups[len(speedups)-1]
		trend := "stable"
		if lastSpeedup > firstSpeedup*1.2 {
			trend = "improving"
		} else if lastSpeedup < firstSpeedup*0.8 {
			trend = "degrading"
		}
		fmt.Printf("    Scaling trend: %s (%.2fx -> %.2fx)\n", trend, firstSpeedup, lastSpeedup)
	}
}

func (sb *ScalingBenchmark) identifyBottlenecks() {
	fmt.Printf("\nBottleneck Analysis:\n")

	// Find worst performing scenarios
	var worstSpeedup *ScalingResult
	var bestSpeedup *ScalingResult
	var worstAccuracy *ScalingResult
	var highestMemory *ScalingResult

	for _, result := range sb.results {
		if worstSpeedup == nil || result.Speedup < worstSpeedup.Speedup {
			worstSpeedup = result
		}
		if bestSpeedup == nil || result.Speedup > bestSpeedup.Speedup {
			bestSpeedup = result
		}
		if worstAccuracy == nil || result.Accuracy < worstAccuracy.Accuracy {
			worstAccuracy = result
		}
		if highestMemory == nil || result.GoYARAMemory > highestMemory.GoYARAMemory {
			highestMemory = result
		}
	}

	fmt.Printf("  Best Performance: %s (%.2fx speedup)\n", bestSpeedup.Scenario, bestSpeedup.Speedup)
	fmt.Printf("  Worst Performance: %s (%.2fx speedup)\n", worstSpeedup.Scenario, worstSpeedup.Speedup)
	fmt.Printf("  Worst Accuracy: %s (%.1f%%)\n", worstAccuracy.Scenario, worstAccuracy.Accuracy)
	fmt.Printf("  Highest Memory: %s (%d MB)\n", highestMemory.Scenario, highestMemory.GoYARAMemory)
}

func (sb *ScalingBenchmark) generateRecommendations() {
	fmt.Printf("\nRecommendations:\n")

	recommendations := []string{}

	// Analyze speedup patterns
	avgSpeedup := 0.0
	speedupCount := 0
	degradingCount := 0

	for _, result := range sb.results {
		avgSpeedup += result.Speedup
		speedupCount++

		// Check if performance degrades with scale
		if result.Files > 100 && result.Speedup < 2.0 {
			degradingCount++
		}
	}

	if speedupCount > 0 {
		avgSpeedup /= float64(speedupCount)

		if avgSpeedup < 5.0 {
			recommendations = append(recommendations, "Average speedup is below 5x - consider performance optimizations")
		}

		if degradingCount > speedupCount/3 {
			recommendations = append(recommendations, "Performance degrades significantly at scale - investigate scaling bottlenecks")
		}
	}

	// Memory recommendations
	var avgMemory int64
	memoryCount := 0
	for _, result := range sb.results {
		avgMemory += result.GoYARAMemory
		memoryCount++
		if result.GoYARAMemory > 1000 { // > 1GB
			recommendations = append(recommendations, fmt.Sprintf("High memory usage in %s - optimize memory management", result.Scenario))
		}
	}

	if memoryCount > 0 {
		avgMemory /= int64(memoryCount)
		if avgMemory > 500 { // > 500MB average
			recommendations = append(recommendations, "High average memory usage - consider memory pooling and allocation optimization")
		}
	}

	// Accuracy recommendations
	for _, result := range sb.results {
		if result.Accuracy < 95.0 {
			recommendations = append(recommendations, fmt.Sprintf("Low accuracy (%.1f%%) in %s - verify implementation correctness", result.Accuracy, result.Scenario))
		}
	}

	// Rule compilation recommendations
	if avgSpeedup > 10.0 {
		recommendations = append(recommendations, "Excellent performance achieved - focus on maintaining performance while adding features")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Performance looks good across all tested scenarios")
	}

	for _, rec := range recommendations {
		fmt.Printf("  - %s\n", rec)
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
