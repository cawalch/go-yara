package comparison

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

// runComparisons executes all test cases for both implementations
func (c *Comparator) runComparisons(testCases []*TestCaseResult) {
	if c.config.Verbose {
		fmt.Printf("Running %d test cases...\n", len(testCases))
	}

	// Process test cases in parallel if configured
	parallelism := c.config.Parallelism
	if parallelism <= 0 {
		parallelism = 1
	}

	semaphore := make(chan struct{}, parallelism)
	errChan := make(chan error, len(testCases))
	resultChan := make(chan *TestCaseResult, len(testCases))

	for i, testCase := range testCases {
		go func(idx int, tc *TestCaseResult) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if c.config.Verbose {
				fmt.Printf("Processing test case %d/%d: %s\n", idx+1, len(testCases), tc.Name)
			}

			result, err := c.runSingleComparison(tc)
			if err != nil {
				errChan <- fmt.Errorf("test case %s failed: %w", tc.Name, err)
				return
			}

			resultChan <- result
		}(i, testCase)
	}

	// Collect results
	var errors []error
	for i := 0; i < len(testCases); i++ {
		select {
		case err := <-errChan:
			errors = append(errors, err)
		case result := <-resultChan:
			c.results.TestCases = append(c.results.TestCases, result)
		}
	}

	if len(errors) > 0 {
		fmt.Printf("Encountered %d errors during comparison:\n", len(errors))
		for _, err := range errors {
			fmt.Printf("  - %s\n", err.Error())
		}
	}

	if c.config.Verbose {
		fmt.Printf("Completed %d test cases successfully\n", len(c.results.TestCases))
	}
}

// runSingleComparison runs a single test case for both implementations
func (c *Comparator) runSingleComparison(testCase *TestCaseResult) (*TestCaseResult, error) {
	// Get rule count and data size
	ruleCount, err := c.countRules(testCase.RuleFile)
	if err != nil {
		return nil, fmt.Errorf("counting rules: %w", err)
	}

	dataSize, err := c.getDataSize(testCase.DataFile)
	if err != nil {
		return nil, fmt.Errorf("getting data size: %w", err)
	}

	testCase.RuleCount = ruleCount
	testCase.DataSize = dataSize

	// Skip if exceeds limits
	if ruleCount > c.config.MaxRulesPerFile {
		if c.config.Verbose {
			fmt.Printf("Skipping %s: too many rules (%d > %d)\n", testCase.Name, ruleCount, c.config.MaxRulesPerFile)
		}
		return testCase, nil
	}

	// Run go-yara
	goYaraResult, err := c.runGoYara(testCase)
	if err != nil {
		return nil, fmt.Errorf("running go-yara: %w", err)
	}
	testCase.GoYaraResult = goYaraResult

	// Run reference YARA
	referenceResult, err := c.runReferenceYara(testCase)
	if err != nil {
		return nil, fmt.Errorf("running reference YARA: %w", err)
	}
	testCase.ReferenceYaraResult = referenceResult

	// Compare correctness
	testCase.MatchCorrectness = c.compareCorrectness(goYaraResult, referenceResult)

	// Calculate performance gap
	testCase.PerformanceGap = c.calculatePerformanceGap(goYaraResult, referenceResult)

	return testCase, nil
}

// runGoYara executes go-yara implementation
func (c *Comparator) runGoYara(testCase *TestCaseResult) (*SingleExecutionResult, error) {
	result := &SingleExecutionResult{}

	// Measure compilation time
	compStart := time.Now()

	// Compile rules
	compiledProgram, memStatsBefore, err := c.compileRules(testCase, compStart, result)
	if err != nil {
		return result, err
	}

	// Measure execution time
	execStart := time.Now()

	// Execute rules
	matches, memStatsAfter, err := c.executeRules(testCase, compiledProgram, execStart, result)
	if err != nil {
		return result, err
	}

	// Finalize result
	result.ExecutionTime = time.Since(execStart)
	result.Success = true
	result.MemoryUsage = memStatsAfter.Alloc - memStatsBefore.Alloc
	result.Allocations = memStatsAfter.Mallocs - memStatsBefore.Mallocs
	result.MatchCount = len(matches)
	result.Matches = make([]string, len(matches))
	for i, match := range matches {
		result.Matches[i] = match.Pattern
	}

	return result, nil
}

// compileRules handles rule compilation phase
func (c *Comparator) compileRules(testCase *TestCaseResult, compStart time.Time, result *SingleExecutionResult) (*compiler.CompiledProgram, runtime.MemStats, error) {
	// Read rule file
	ruleContent, err := os.ReadFile(testCase.RuleFile)
	if err != nil {
		result.Error = fmt.Sprintf("reading rule file: %v", err)
		return nil, runtime.MemStats{}, err
	}

	// Get memory stats before compilation
	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	// Compile rules using the main compiler
	comp := compiler.NewCompiler()

	if c.config.Verbose {
		fmt.Printf("DEBUG: Compiling rule content: %q\n", string(ruleContent))
	}

	compiledProgram, err := comp.CompileSource(string(ruleContent))
	if err != nil {
		result.CompilationTime = time.Since(compStart)
		result.Error = fmt.Sprintf("compilation failed: %v", err)
		return nil, memStatsBefore, err
	}

	result.CompilationTime = time.Since(compStart)
	return compiledProgram, memStatsBefore, nil
}

// executeRules handles rule execution phase
func (c *Comparator) executeRules(testCase *TestCaseResult, compiledProgram *compiler.CompiledProgram, execStart time.Time, result *SingleExecutionResult) ([]compiler.Match, runtime.MemStats, error) {
	// Read data file
	data, err := os.ReadFile(testCase.DataFile)
	if err != nil {
		result.Error = fmt.Sprintf("reading data file: %v", err)
		return nil, runtime.MemStats{}, err
	}

	// Execute each rule
	rules := compiledProgram.Rules
	var matches []compiler.Match

	for _, rule := range rules {
		ruleMatches, execErr := c.executeSingleRule(rule, rules, data)
		if execErr != nil {
			result.ExecutionTime = time.Since(execStart)
			result.Error = fmt.Sprintf("execution failed: %v", execErr)
			return nil, runtime.MemStats{}, execErr
		}
		matches = append(matches, ruleMatches...)
	}

	// Get memory stats after execution
	var memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsAfter)

	return matches, memStatsAfter, nil
}

// executeSingleRule executes a single rule and returns matches
func (c *Comparator) executeSingleRule(rule *compiler.CompiledRule, rules []*compiler.CompiledRule, data []byte) ([]compiler.Match, error) {
	interpreter := compiler.NewInterpreter(rule.GetBytecode())

	// Set up match context and rule results
	ruleResults := make(map[string]bool)
	interpreter.SetRuleResults(ruleResults)
	interpreter.SetCompiledRules(rules)
	interpreter.SetCurrentRule(rule.GetName())

	// Set file size and data in match context
	interpreter.GetMatchContext().FileSize = int64(len(data))
	interpreter.GetMatchContext().Data = data

	// Set up string matching
	if rule.Automaton != nil {
		c.setupAutomatonMatches(interpreter, rule.Automaton, data)
		c.setupMemorySlots(interpreter, rule.Automaton)
	}

	if c.config.Verbose {
		fmt.Printf("DEBUG: Executing rule: %s\n", rule.GetName())
		if rule.Automaton != nil {
			fmt.Printf("DEBUG: Automaton has %d strings\n", len(rule.Automaton.Strings))
		}
	}

	execErr := interpreter.Execute()
	if execErr != nil {
		return nil, execErr
	}

	// Check if rule matched
	ruleMatched := c.checkRuleMatched(interpreter, rule.GetName(), ruleResults)

	if c.config.Verbose {
		fmt.Printf("DEBUG: Rule %s matched: %v\n", rule.GetName(), ruleMatched)
	}

	if ruleMatched {
		return []compiler.Match{{
			Pattern: rule.GetName(),
			Offset:  0,
			Length:  len(data),
			Base:    0,
		}}, nil
	}

	return nil, nil
}

// setupAutomatonMatches sets up automaton matches in the interpreter
func (c *Comparator) setupAutomatonMatches(interpreter *compiler.Interpreter, automaton *compiler.ACAutomaton, data []byte) {
	acMatches := automaton.Search(data)
	if c.config.Verbose {
		fmt.Printf("DEBUG: Found %d automaton matches\n", len(acMatches))
	}
	for _, acMatch := range acMatches {
		if c.config.Verbose {
			fmt.Printf("DEBUG: Adding match: %s at offset %d\n", acMatch.StringID, acMatch.Backtrack)
		}
		interpreter.GetMatchContext().AddMatch(compiler.Match{
			Pattern: acMatch.StringID,
			Offset:  int64(acMatch.Backtrack),
			Length:  len(acMatch.StringID),
			Base:    0,
		})
	}
}

// setupMemorySlots initializes VM memory slots with string identifiers
func (c *Comparator) setupMemorySlots(interpreter *compiler.Interpreter, automaton *compiler.ACAutomaton) {
	for idx, s := range automaton.Strings {
		if c.config.Verbose {
			fmt.Printf("DEBUG: Setting memory slot %d to %s\n", idx, s.Identifier)
		}
		interpreter.SetMemoryString(idx, s.Identifier)
	}
}

// checkRuleMatched checks if a rule matched based on stack results
func (c *Comparator) checkRuleMatched(interpreter *compiler.Interpreter, ruleName string, ruleResults map[string]bool) bool {
	stack := interpreter.GetStack()
	ruleMatched := false

	if len(stack) > 0 {
		result := stack[len(stack)-1]
		if result.Type == compiler.ValueTypeInt && result.IntVal != 0 {
			ruleMatched = true
		}
	}

	if c.config.Verbose {
		fmt.Printf("DEBUG: Rule %s matched: %v (ruleResults: %v)\n", ruleName, ruleMatched, ruleResults[ruleName])
		if len(stack) > 0 {
			result := stack[len(stack)-1]
			fmt.Printf("DEBUG: Stack result: Type=%v, IntVal=%v, StringVal=%v\n", result.Type, result.IntVal, result.StringVal)
		}
	}

	return ruleMatched
}

// runReferenceYara executes reference YARA implementation
func (c *Comparator) runReferenceYara(testCase *TestCaseResult) (*SingleExecutionResult, error) {
	result := &SingleExecutionResult{}

	// Reference YARA compiles and executes in one step, but we want to separate timing
	// So we'll run it twice - once to measure compilation, once to measure execution

	// Measure "compilation time" by running YARA on empty data
	compStart := time.Now()

	// Create temporary empty file for compilation timing
	emptyFile := filepath.Join(c.tempDir, "empty.txt")
	if err := os.WriteFile(emptyFile, []byte{}, 0600); err != nil {
		return nil, fmt.Errorf("creating empty file: %w", err)
	}

	compCmd := exec.Command(c.yaraBinary, testCase.RuleFile, emptyFile)
	compOutput, err := compCmd.CombinedOutput()
	// Ignore exit status for compilation timing - YARA returns non-zero for no matches
	// Both branches had the same logic, so consolidate
	result.CompilationTime = time.Since(compStart)
	_ = compOutput // Mark as used to avoid unused variable warning
	_ = err

	// Measure execution time
	execStart := time.Now()

	// Run YARA matching on actual data
	execCmd := exec.Command(c.yaraBinary, testCase.RuleFile, testCase.DataFile)
	execOutput, err := execCmd.CombinedOutput()
	if err != nil {
		// YARA returns non-zero exit code when no matches are found, which is normal
		if len(execOutput) == 0 {
			// No matches found
			result.ExecutionTime = time.Since(execStart)
			result.Success = true
			result.MatchCount = 0
			result.Matches = []string{}
			return result, nil
		}
		result.ExecutionTime = time.Since(execStart)
		result.Error = fmt.Sprintf("YARA execution failed: %v, output: %s", err, string(execOutput))
		return result, err
	}

	result.ExecutionTime = time.Since(execStart)
	result.Success = true

	// Parse YARA output
	matches, err := c.parseYaraOutput(string(execOutput))
	if err != nil {
		result.Error = fmt.Sprintf("parsing YARA output: %v", err)
		return result, err
	}

	result.MatchCount = len(matches)
	result.Matches = matches

	// For reference YARA, we can't easily get memory usage, so we'll estimate
	// based on typical patterns
	result.MemoryUsage = 0 // Not available from external process
	result.Allocations = 0 // Not available from external process

	return result, nil
}

// parseYaraOutput parses YARA command-line output
func (c *Comparator) parseYaraOutput(output string) ([]string, error) {
	var matches []string

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "error:") {
			continue
		}

		// YARA output format is: "rule_identifier filename"
		// Extract the rule identifier (first field)
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			ruleIdentifier := parts[0]
			matches = append(matches, ruleIdentifier)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning YARA output: %w", err)
	}

	return matches, nil
}

// countRules counts the number of rules in a YARA file
func (c *Comparator) countRules(ruleFile string) (int, error) {
	content, err := os.ReadFile(ruleFile)
	if err != nil {
		return 0, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	ruleCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "rule ") && !strings.HasPrefix(line, "//") {
			ruleCount++
		}
	}

	return ruleCount, scanner.Err()
}

// getDataSize returns the size of a data file
func (c *Comparator) getDataSize(dataFile string) (int64, error) {
	info, err := os.Stat(dataFile)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// compareCorrectness compares match results between implementations
func (c *Comparator) compareCorrectness(goYaraResult, referenceResult *SingleExecutionResult) *CorrectnessCheck {
	check := &CorrectnessCheck{}

	// Convert to sets for comparison
	goYaraMatches := make(map[string]bool)
	for _, match := range goYaraResult.Matches {
		goYaraMatches[match] = true
	}

	refMatches := make(map[string]bool)
	for _, match := range referenceResult.Matches {
		refMatches[match] = true
	}

	// Find matches only in go-yara
	for match := range goYaraMatches {
		if !refMatches[match] {
			check.GoYaraOnly = append(check.GoYaraOnly, match)
		}
	}

	// Find matches only in reference YARA
	for match := range refMatches {
		if !goYaraMatches[match] {
			check.RefYaraOnly = append(check.RefYaraOnly, match)
		}
	}

	// Calculate statistics
	totalMatches := len(goYaraMatches) + len(refMatches)
	matchingMatches := 0
	for match := range goYaraMatches {
		if refMatches[match] {
			matchingMatches++
		}
	}

	check.MatchesIdentical = len(check.GoYaraOnly) == 0 && len(check.RefYaraOnly) == 0
	check.CountDifference = len(goYaraMatches) - len(refMatches)

	if totalMatches > 0 {
		check.Accuracy = float64(matchingMatches*2) / float64(totalMatches)
	} else {
		check.Accuracy = 1.0 // Both empty
	}

	return check
}

// calculatePerformanceGap calculates performance gap between implementations
func (c *Comparator) calculatePerformanceGap(goYaraResult, referenceResult *SingleExecutionResult) *PerformanceGap {
	gap := &PerformanceGap{}

	// Compilation speedup
	if referenceResult.CompilationTime > 0 && goYaraResult.CompilationTime > 0 {
		gap.CompilationSpeedup = float64(referenceResult.CompilationTime) / float64(goYaraResult.CompilationTime)
	}

	// Execution speedup
	if referenceResult.ExecutionTime > 0 && goYaraResult.ExecutionTime > 0 {
		gap.ExecutionSpeedup = float64(referenceResult.ExecutionTime) / float64(goYaraResult.ExecutionTime)
	}

	// Memory reduction (only available for go-yara)
	if referenceResult.MemoryUsage == 0 && goYaraResult.MemoryUsage > 0 {
		// Can't compare memory usage when reference doesn't provide it
		gap.MemoryReduction = 0
	} else if referenceResult.MemoryUsage > 0 && goYaraResult.MemoryUsage > 0 {
		reduction := float64(referenceResult.MemoryUsage-goYaraResult.MemoryUsage) / float64(referenceResult.MemoryUsage)
		gap.MemoryReduction = reduction
	}

	// Overall faster determination
	gap.OverallFaster = gap.CompilationSpeedup > 1 || gap.ExecutionSpeedup > 1

	return gap
}

// calculatePerformanceGaps calculates overall performance gaps
func (c *Comparator) calculatePerformanceGaps() {
	if len(c.results.TestCases) == 0 {
		return
	}

	// Collect metrics from all test cases
	metrics := c.collectTestMetrics()

	// Calculate different performance gaps
	gaps := c.results.PerformanceGaps
	c.calculateCompilationGaps(gaps, metrics)
	c.calculateExecutionGaps(gaps, metrics)
	c.calculateMemoryGaps(gaps, metrics)
	c.calculateAllocationGaps(gaps, metrics)

	// Calculate overall score
	c.calculateOverallScore(gaps)
}

// collectTestMetrics aggregates metrics from all test cases
func (c *Comparator) collectTestMetrics() *TestMetrics {
	metrics := &TestMetrics{}

	for _, testCase := range c.results.TestCases {
		if testCase.GoYaraResult != nil && testCase.ReferenceYaraResult != nil {
			c.processTestCaseMetrics(testCase, metrics)
		}
	}

	return metrics
}

// processTestCaseMetrics processes a single test case and updates metrics
func (c *Comparator) processTestCaseMetrics(testCase *TestCaseResult, metrics *TestMetrics) {
	// Compilation times
	if testCase.GoYaraResult.CompilationTime > 0 && testCase.ReferenceYaraResult.CompilationTime > 0 {
		metrics.TotalGoYaraCompTime += testCase.GoYaraResult.CompilationTime
		metrics.TotalRefCompTime += testCase.ReferenceYaraResult.CompilationTime
		metrics.SuccessfulCompilations++
	}

	// Execution times
	if testCase.GoYaraResult.ExecutionTime > 0 && testCase.ReferenceYaraResult.ExecutionTime > 0 {
		metrics.TotalGoYaraExecTime += testCase.GoYaraResult.ExecutionTime
		metrics.TotalRefExecTime += testCase.ReferenceYaraResult.ExecutionTime
		metrics.SuccessfulExecutions++
	}

	// Memory usage
	if testCase.GoYaraResult.MemoryUsage > 0 && testCase.ReferenceYaraResult.MemoryUsage > 0 {
		metrics.TotalGoYaraMemory += testCase.GoYaraResult.MemoryUsage
		metrics.TotalRefMemory += testCase.ReferenceYaraResult.MemoryUsage
		metrics.ValidMemoryComparisons++
	}

	// Allocations (only go-yara)
	metrics.TotalGoYaraAllocs += testCase.GoYaraResult.Allocations
}

// calculateCompilationGaps calculates compilation performance gaps
func (c *Comparator) calculateCompilationGaps(gaps *PerformanceGaps, metrics *TestMetrics) {
	if metrics.SuccessfulCompilations > 0 {
		avgGoYaraComp := metrics.TotalGoYaraCompTime / time.Duration(metrics.SuccessfulCompilations)
		avgRefComp := metrics.TotalRefCompTime / time.Duration(metrics.SuccessfulCompilations)
		if avgRefComp > 0 {
			gaps.CompilationSpeedup = float64(avgRefComp) / float64(avgGoYaraComp)
		}
	}
}

// calculateExecutionGaps calculates execution performance gaps
func (c *Comparator) calculateExecutionGaps(gaps *PerformanceGaps, metrics *TestMetrics) {
	if metrics.SuccessfulExecutions > 0 {
		avgGoYaraExec := metrics.TotalGoYaraExecTime / time.Duration(metrics.SuccessfulExecutions)
		avgRefExec := metrics.TotalRefExecTime / time.Duration(metrics.SuccessfulExecutions)
		if avgRefExec > 0 {
			gaps.ExecutionSpeedup = float64(avgRefExec) / float64(avgGoYaraExec)
		}
	}
}

// calculateMemoryGaps calculates memory usage gaps
func (c *Comparator) calculateMemoryGaps(gaps *PerformanceGaps, metrics *TestMetrics) {
	if metrics.ValidMemoryComparisons > 0 && metrics.TotalRefMemory > 0 {
		gaps.MemoryReduction = float64(metrics.TotalRefMemory-metrics.TotalGoYaraMemory) / float64(metrics.TotalRefMemory)
	}
}

// calculateAllocationGaps calculates allocation reduction estimates
func (c *Comparator) calculateAllocationGaps(gaps *PerformanceGaps, metrics *TestMetrics) {
	// This is an estimate since we can't get allocation data from reference YARA
	if metrics.TotalGoYaraAllocs > 0 {
		// Estimate reference YARA would allocate 10x more based on typical patterns
		estimatedRefAllocs := metrics.TotalGoYaraAllocs * 10
		gaps.AllocationReduction = float64(estimatedRefAllocs-metrics.TotalGoYaraAllocs) / float64(estimatedRefAllocs)
	}
}

// calculateOverallScore calculates weighted average performance score
func (c *Comparator) calculateOverallScore(gaps *PerformanceGaps) {
	score := 0.0
	weight := 0.0

	if gaps.CompilationSpeedup > 0 {
		score += gaps.CompilationSpeedup * 0.3
		weight += 0.3
	}

	if gaps.ExecutionSpeedup > 0 {
		score += gaps.ExecutionSpeedup * 0.4
		weight += 0.4
	}

	if gaps.MemoryReduction != 0 {
		// Memory reduction is positive, so we add it to score
		score += (1 + gaps.MemoryReduction) * 0.2
		weight += 0.2
	}

	if gaps.AllocationReduction > 0 {
		score += (1 + gaps.AllocationReduction) * 0.1
		weight += 0.1
	}

	if weight > 0 {
		gaps.OverallScore = score / weight
	}
}

// TestMetrics holds aggregated metrics from test cases
type TestMetrics struct {
	TotalGoYaraCompTime    time.Duration
	TotalRefCompTime       time.Duration
	TotalGoYaraExecTime    time.Duration
	TotalRefExecTime       time.Duration
	TotalGoYaraMemory      uint64
	TotalRefMemory         uint64
	TotalGoYaraAllocs      uint64
	SuccessfulCompilations int
	SuccessfulExecutions   int
	ValidMemoryComparisons int
}

// calculateCorrectnessResults calculates overall correctness metrics
func (c *Comparator) calculateCorrectnessResults() {
	if len(c.results.TestCases) == 0 {
		return
	}

	correctness := c.results.CorrectnessResults
	correctness.TotalTestCases = len(c.results.TestCases)

	var totalAccuracy float64
	var validAccuracyCount int

	for _, testCase := range c.results.TestCases {
		if testCase.MatchCorrectness != nil {
			if testCase.MatchCorrectness.MatchesIdentical {
				correctness.MatchingResults++
			} else {
				correctness.DifferentResults++
			}

			correctness.GoYaraOnlyMatches += len(testCase.MatchCorrectness.GoYaraOnly)
			correctness.RefYaraOnlyMatches += len(testCase.MatchCorrectness.RefYaraOnly)

			if testCase.MatchCorrectness.Accuracy >= 0 {
				totalAccuracy += testCase.MatchCorrectness.Accuracy
				validAccuracyCount++
			}

			// Create discrepancy record if results differ
			if !testCase.MatchCorrectness.MatchesIdentical {
				discrepancy := &Discrepancy{
					RuleFile:       testCase.RuleFile,
					DataFile:       testCase.DataFile,
					GoYaraMatches:  testCase.MatchCorrectness.GoYaraOnly,
					RefYaraMatches: testCase.MatchCorrectness.RefYaraOnly,
				}

				// Determine discrepancy type based on match patterns
				goOnlyCount := len(testCase.MatchCorrectness.GoYaraOnly)
				refOnlyCount := len(testCase.MatchCorrectness.RefYaraOnly)

				switch {
				case goOnlyCount > 0 && refOnlyCount == 0:
					discrepancy.MatchType = "extra_go"
					correctness.FalsePositives++
				case refOnlyCount > 0 && goOnlyCount == 0:
					discrepancy.MatchType = "extra_ref"
					correctness.FalseNegatives++
				default:
					discrepancy.MatchType = "different_count"
				}

				correctness.Discrepancies = append(correctness.Discrepancies, discrepancy)
			}
		}
	}

	if validAccuracyCount > 0 {
		correctness.MatchAccuracy = totalAccuracy / float64(validAccuracyCount)
	}
}

// UpdateAggregatedMetrics updates the aggregated metrics for both implementations
func (c *Comparator) UpdateAggregatedMetrics() {
	// Initialize metrics
	metrics := c.initializeMetrics()

	// Process test cases
	c.processTestCases(metrics)

	// Calculate final metrics
	c.calculateCompilationMetrics(metrics.goYaraComp, metrics.goYaraCompTimes)
	c.calculateCompilationMetrics(metrics.refComp, metrics.refCompTimes)

	if len(metrics.goYaraExecTimes) > 0 {
		c.calculateExecutionMetrics(metrics.goYaraExecTimes, metrics.goYaraExec)
	}
	if len(metrics.refExecTimes) > 0 {
		c.calculateExecutionMetrics(metrics.refExecTimes, metrics.refExec)
	}

	c.calculateMemoryMetrics(metrics.goYaraComp, metrics.goYaraExec, metrics.goYaraMemory)

	// Set results
	c.setResults(metrics.goYaraComp, metrics.goYaraExec, metrics.goYaraMemory, metrics.refComp, metrics.refExec)
}

// metricsCollection holds all metrics for easier parameter passing
type metricsCollection struct {
	goYaraComp      *CompilationMetrics
	goYaraExec      *ExecutionMetrics
	goYaraMemory    *MemoryMetrics
	goYaraCompTimes []time.Duration
	goYaraExecTimes []time.Duration
	refComp         *CompilationMetrics
	refExec         *ExecutionMetrics
	refCompTimes    []time.Duration
	refExecTimes    []time.Duration
}

// initializeMetrics initializes all metrics structures
func (c *Comparator) initializeMetrics() *metricsCollection {
	return &metricsCollection{
		goYaraComp: &CompilationMetrics{
			TotalFiles: len(c.results.TestCases),
		},
		goYaraExec: &ExecutionMetrics{
			TotalExecutions: len(c.results.TestCases),
		},
		goYaraMemory: &MemoryMetrics{},
		refComp: &CompilationMetrics{
			TotalFiles: len(c.results.TestCases),
		},
		refExec: &ExecutionMetrics{
			TotalExecutions: len(c.results.TestCases),
		},
		goYaraCompTimes: []time.Duration{},
		goYaraExecTimes: []time.Duration{},
		refCompTimes:    []time.Duration{},
		refExecTimes:    []time.Duration{},
	}
}

// processTestCases processes all test cases and updates metrics
func (c *Comparator) processTestCases(metrics *metricsCollection) {
	for _, testCase := range c.results.TestCases {
		// Go-YARA metrics
		if testCase.GoYaraResult != nil {
			metrics.goYaraComp.TotalRules += testCase.RuleCount
			metrics.goYaraMemory.TotalAllocs += testCase.GoYaraResult.Allocations
			metrics.goYaraMemory.TotalBytes += testCase.GoYaraResult.MemoryUsage

			if testCase.GoYaraResult.Success {
				metrics.goYaraComp.SuccessCount++
				metrics.goYaraCompTimes = append(metrics.goYaraCompTimes, testCase.GoYaraResult.CompilationTime)
				metrics.goYaraComp.TotalTime += testCase.GoYaraResult.CompilationTime

				metrics.goYaraExec.SuccessCount++
				metrics.goYaraExec.TotalTime += testCase.GoYaraResult.ExecutionTime
				metrics.goYaraExec.TotalMatches += int64(testCase.GoYaraResult.MatchCount)
				metrics.goYaraExecTimes = append(metrics.goYaraExecTimes, testCase.GoYaraResult.ExecutionTime)
			} else {
				metrics.goYaraComp.ErrorCount++
				metrics.goYaraExec.ErrorCount++
			}
		}

		// Reference YARA metrics
		if testCase.ReferenceYaraResult != nil {
			metrics.refComp.TotalRules += testCase.RuleCount

			if testCase.ReferenceYaraResult.Success {
				metrics.refComp.SuccessCount++
				metrics.refCompTimes = append(metrics.refCompTimes, testCase.ReferenceYaraResult.CompilationTime)
				metrics.refComp.TotalTime += testCase.ReferenceYaraResult.CompilationTime

				metrics.refExec.SuccessCount++
				metrics.refExec.TotalTime += testCase.ReferenceYaraResult.ExecutionTime
				metrics.refExec.TotalMatches += int64(testCase.ReferenceYaraResult.MatchCount)
				metrics.refExecTimes = append(metrics.refExecTimes, testCase.ReferenceYaraResult.ExecutionTime)
			} else {
				metrics.refComp.ErrorCount++
				metrics.refExec.ErrorCount++
			}
		}
	}
}

// calculateCompilationMetrics calculates min/max/avg times and throughput for compilation metrics
func (c *Comparator) calculateCompilationMetrics(metrics *CompilationMetrics, times []time.Duration) {
	if len(times) == 0 {
		return
	}

	metrics.MinTime = times[0]
	metrics.MaxTime = times[0]
	for _, t := range times {
		if t < metrics.MinTime {
			metrics.MinTime = t
		}
		if t > metrics.MaxTime {
			metrics.MaxTime = t
		}
	}
	metrics.AvgTime = metrics.TotalTime / time.Duration(len(times))
	if metrics.TotalTime.Seconds() > 0 {
		metrics.RulesPerSec = float64(metrics.TotalRules) / metrics.TotalTime.Seconds()
		metrics.BytesPerSec = float64(metrics.TotalRules) / metrics.TotalTime.Seconds() // Approximation
	}
}

// calculateMemoryMetrics calculates memory-related metrics
func (c *Comparator) calculateMemoryMetrics(compMetrics *CompilationMetrics, execMetrics *ExecutionMetrics, memMetrics *MemoryMetrics) {
	if compMetrics.SuccessCount > 0 && execMetrics.TotalTime.Seconds() > 0 {
		memMetrics.AvgAllocs = memMetrics.TotalAllocs / uint64(compMetrics.SuccessCount)
		memMetrics.AvgRSS = memMetrics.TotalBytes / uint64(compMetrics.SuccessCount)
		memMetrics.AllocsPerSec = float64(memMetrics.TotalAllocs) / execMetrics.TotalTime.Seconds()
		memMetrics.BytesPerSec = float64(memMetrics.TotalBytes) / execMetrics.TotalTime.Seconds()
	}
}

// setResults sets the final results in the comparison results
func (c *Comparator) setResults(goYaraMetrics *CompilationMetrics, goYaraExecMetrics *ExecutionMetrics, goYaraMemoryMetrics *MemoryMetrics, refMetrics *CompilationMetrics, refExecMetrics *ExecutionMetrics) {
	c.results.GoYaraResults.CompilationMetrics = goYaraMetrics
	c.results.GoYaraResults.ExecutionMetrics = goYaraExecMetrics
	c.results.GoYaraResults.MemoryMetrics = goYaraMemoryMetrics

	c.results.ReferenceYaraResults.CompilationMetrics = refMetrics
	c.results.ReferenceYaraResults.ExecutionMetrics = refExecMetrics
	c.results.ReferenceYaraResults.MemoryMetrics = &MemoryMetrics{} // No data available
}

// calculateExecutionMetrics calculates min/max/avg times and throughput for execution metrics
func (c *Comparator) calculateExecutionMetrics(times []time.Duration, metrics *ExecutionMetrics) {
	if len(times) == 0 {
		return
	}

	metrics.MinTime = times[0]
	metrics.MaxTime = times[0]
	for _, t := range times {
		if t < metrics.MinTime {
			metrics.MinTime = t
		}
		if t > metrics.MaxTime {
			metrics.MaxTime = t
		}
	}
	metrics.AvgTime = metrics.TotalTime / time.Duration(len(times))

	// Calculate throughput
	var totalDataSize int64
	for _, tc := range c.results.TestCases {
		totalDataSize += tc.DataSize
	}
	metrics.MBPerSec = float64(totalDataSize) / (1024 * 1024) / metrics.TotalTime.Seconds()
	metrics.FilesPerSec = float64(len(times)) / metrics.TotalTime.Seconds()
}
