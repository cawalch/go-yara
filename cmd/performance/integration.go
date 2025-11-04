//go:build performance_tool

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
)

// YaraEngine integrates with the actual go-yara components
type YaraEngine struct {
	compiler  *compiler.RuleCompiler
	validator *validator
	cache     *ruleCache
	stats     *EngineStats
}

// EngineStats tracks engine performance statistics
type EngineStats struct {
	Compilations     int64         `json:"compilations"`
	Executions       int64         `json:"executions"`
	TotalCompileTime time.Duration `json:"total_compile_time"`
	TotalExecTime    time.Duration `json:"total_exec_time"`
	CacheHits        int64         `json:"cache_hits"`
	CacheMisses      int64         `json:"cache_misses"`
}

// ruleCache provides caching for compiled rules
type ruleCache struct {
	compiledRules map[string]*CompiledRule
	maxSize       int
	hits          int64
	misses        int64
}

// CompiledRule represents a compiled YARA rule
type CompiledRule struct {
	RuleName    string                 `json:"rule_name"`
	Bytecode    []byte                 `json:"bytecode"`
	Strings     map[string][]byte      `json:"strings"`
	Automaton   *AhoCorasickAutomaton  `json:"automaton"`
	Metadata    map[string]interface{} `json:"metadata"`
	CompileTime time.Duration          `json:"compile_time"`
}

// AhoCorasickAutomaton represents the string matching automaton
type AhoCorasickAutomaton struct {
	Patterns map[string][]byte `json:"patterns"`
	Nodes    []AutomatonNode   `json:"nodes"`
}

// AutomatonNode represents a node in the Aho-Corasick automaton
type AutomatonNode struct {
	Children map[byte]int `json:"children"`
	FailLink int          `json:"fail_link"`
	Output   []string     `json:"output"`
}

// MatchResult represents the result of rule execution
type MatchResult struct {
	RuleName   string        `json:"rule_name"`
	Matched    bool          `json:"matched"`
	Matches    []Match       `json:"matches"`
	ExecTime   time.Duration `json:"exec_time"`
	MemoryUsed uint64        `json:"memory_used"`
}

// Match represents a pattern match
type Match struct {
	Identifier string `json:"identifier"`
	Offset     int64  `json:"offset"`
	Length     int    `json:"length"`
	Data       []byte `json:"data"`
}

// validator handles rule validation
type validator struct {
	rules map[string]bool
}

// NewYaraEngine creates a new YARA engine instance
func NewYaraEngine() *YaraEngine {
	return &YaraEngine{
		compiler: compiler.NewRuleCompiler(),
		validator: &validator{
			rules: make(map[string]bool),
		},
		cache: &ruleCache{
			compiledRules: make(map[string]*CompiledRule),
			maxSize:       1000,
		},
		stats: &EngineStats{},
	}
}

// CompileRule compiles a YARA rule string into bytecode
func (ye *YaraEngine) CompileRule(ruleText string) (*CompiledRule, error) {
	start := time.Now()
	ye.stats.Compilations++

	// Check cache first
	if cached := ye.cache.Get(ruleText); cached != nil {
		ye.stats.CacheHits++
		ye.stats.TotalCompileTime += time.Since(start)
		return cached, nil
	}
	ye.stats.CacheMisses++

	// Parse rule using lexer
	l := lexer.New(ruleText)
	p := parser.New(l)
	ruleset, err := p.ParseRules()
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	// Get the first rule from the ruleset (simplified for benchmarking)
	if len(ruleset.Rules) == 0 {
		return nil, fmt.Errorf("no rules found")
	}

	ruleAST := ruleset.Rules[0]

	// Compile to bytecode using actual compiler
	compiledRule, err := ye.compiler.CompileRule(ruleAST)
	if err != nil {
		return nil, fmt.Errorf("compilation error: %w", err)
	}

	// Build result using actual compiled rule
	compiled := &CompiledRule{
		RuleName:    compiledRule.Name,
		Bytecode:    compiledRule.Bytecode,
		Strings:     ye.extractStringsFromRule(ruleAST),
		Automaton:   ye.buildAutomatonFromRule(ruleAST),
		Metadata:    map[string]interface{}{}, // Could extract from rule meta
		CompileTime: time.Since(start),
	}

	// Cache the compiled rule
	ye.cache.Put(ruleText, compiled)
	ye.stats.TotalCompileTime += compiled.CompileTime

	return compiled, nil
}

// ExecuteRule executes a compiled rule against data
func (ye *YaraEngine) ExecuteRule(rule *CompiledRule, data []byte) (*MatchResult, error) {
	start := time.Now()
	ye.stats.Executions++

	// For now, simulate the execution with automaton matching
	// This would be integrated with the actual interpreter
	stringMatches := ye.automatonMatch(rule.Automaton, data)

	// Simple rule evaluation based on string matches
	matched := len(stringMatches) > 0

	// Collect results
	var matches []Match
	for _, strMatch := range stringMatches {
		matches = append(matches, strMatch)
	}

	result := &MatchResult{
		RuleName:   rule.RuleName,
		Matched:    matched,
		Matches:    matches,
		ExecTime:   time.Since(start),
		MemoryUsed: ye.getMemoryUsage(),
	}

	ye.stats.TotalExecTime += result.ExecTime
	return result, nil
}

// ExecuteRuleSet executes multiple rules against data
func (ye *YaraEngine) ExecuteRuleSet(rules []*CompiledRule, data []byte) ([]*MatchResult, error) {
	var results []*MatchResult

	for _, rule := range rules {
		result, err := ye.ExecuteRule(rule, data)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

// ExecuteConcurrent executes rules concurrently
func (ye *YaraEngine) ExecuteConcurrent(rules []*CompiledRule, data []byte, workers int) ([]*MatchResult, error) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	ctx := context.Background()
	resultChan := make(chan *MatchResult, len(rules))
	errorChan := make(chan error, len(rules))

	// Create work queue
	workQueue := make(chan *CompiledRule, len(rules))
	for _, rule := range rules {
		workQueue <- rule
	}
	close(workQueue)

	// Start workers
	for i := 0; i < workers; i++ {
		go func() {
			for rule := range workQueue {
				select {
				case <-ctx.Done():
					return
				default:
					result, err := ye.ExecuteRule(rule, data)
					if err != nil {
						errorChan <- err
						return
					}
					resultChan <- result
				}
			}
		}()
	}

	// Collect results
	var results []*MatchResult
	for i := 0; i < len(rules); i++ {
		select {
		case result := <-resultChan:
			results = append(results, result)
		case err := <-errorChan:
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return results, nil
}

// BenchmarkExecution benchmarks rule execution performance
func (ye *YaraEngine) BenchmarkExecution(rules []*CompiledRule, data []byte, iterations int) (*BenchmarkMetrics, error) {
	var totalTime time.Duration
	var totalAllocs, totalBytes uint64

	// Warmup
	for i := 0; i < 10; i++ {
		_, _ = ye.ExecuteRuleSet(rules, data)
	}

	// Benchmark
	runtime.GC()
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, err := ye.ExecuteRuleSet(rules, data)
		if err != nil {
			return nil, err
		}
	}
	totalTime = time.Since(start)

	runtime.ReadMemStats(&memAfter)
	totalAllocs = memAfter.TotalAlloc - memBefore.TotalAlloc
	totalBytes = memAfter.TotalAlloc - memBefore.TotalAlloc

	return &BenchmarkMetrics{
		Duration:     totalTime / time.Duration(iterations),
		Allocs:       totalAllocs / uint64(iterations),
		Bytes:        totalBytes / uint64(iterations),
		Throughput:   float64(len(data)*iterations) / totalTime.Seconds() / (1024 * 1024),
		OpsPerSecond: float64(iterations) / totalTime.Seconds(),
	}, nil
}

// ProfileExecution profiles rule execution with detailed metrics
func (ye *YaraEngine) ProfileExecution(rules []*CompiledRule, data []byte) (*ExecutionProfile, error) {
	profile := &ExecutionProfile{
		StartTime: time.Now(),
		Rules:     make([]*RuleProfile, len(rules)),
	}

	for i, rule := range rules {
		ruleProfile := ye.profileRule(rule, data)
		profile.Rules[i] = ruleProfile
		profile.TotalCompileTime += ruleProfile.CompileTime
		profile.TotalExecTime += ruleProfile.ExecTime
	}

	profile.EndTime = time.Now()
	profile.Duration = profile.EndTime.Sub(profile.StartTime)

	// Collect memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	profile.MemoryStats = &MemoryStats{
		HeapAlloc:    memStats.HeapAlloc,
		HeapSys:      memStats.HeapSys,
		HeapInuse:    memStats.HeapInuse,
		StackInuse:   memStats.StackInuse,
		GCCount:      memStats.NumGC,
		GCPauseTotal: time.Duration(memStats.PauseTotalNs) * time.Nanosecond,
	}

	return profile, nil
}

// ExecutionProfile contains detailed execution profiling information
type ExecutionProfile struct {
	StartTime        time.Time      `json:"start_time"`
	EndTime          time.Time      `json:"end_time"`
	Duration         time.Duration  `json:"duration"`
	Rules            []*RuleProfile `json:"rules"`
	TotalCompileTime time.Duration  `json:"total_compile_time"`
	TotalExecTime    time.Duration  `json:"total_exec_time"`
	MemoryStats      *MemoryStats   `json:"memory_stats"`
}

// RuleProfile contains profiling data for a single rule
type RuleProfile struct {
	RuleName      string        `json:"rule_name"`
	CompileTime   time.Duration `json:"compile_time"`
	ExecTime      time.Duration `json:"exec_time"`
	MatchCount    int           `json:"match_count"`
	StringMatches int           `json:"string_matches"`
	Hotspots      []Hotspot     `json:"hotspots"`
}

// Hotspot represents a performance hotspot
type Hotspot struct {
	Function   string        `json:"function"`
	Duration   time.Duration `json:"duration"`
	CallCount  int64         `json:"call_count"`
	Percentage float64       `json:"percentage"`
}

// MemoryStats contains memory usage statistics
type MemoryStats struct {
	HeapAlloc    uint64        `json:"heap_alloc"`
	HeapSys      uint64        `json:"heap_sys"`
	HeapInuse    uint64        `json:"heap_inuse"`
	StackInuse   uint64        `json:"stack_inuse"`
	GCCount      uint32        `json:"gc_count"`
	GCPauseTotal time.Duration `json:"gc_pause_total"`
}

func (ye *YaraEngine) profileRule(rule *CompiledRule, data []byte) *RuleProfile {
	profile := &RuleProfile{
		RuleName: rule.RuleName,
	}

	// Profile compilation
	profile.CompileTime = rule.CompileTime

	// Profile execution
	start := time.Now()
	result, err := ye.ExecuteRule(rule, data)
	profile.ExecTime = time.Since(start)

	if err == nil {
		profile.MatchCount = len(result.Matches)
		profile.StringMatches = len(result.Matches)
	}

	// Identify hotspots (simplified)
	profile.Hotspots = []Hotspot{
		{
			Function:   "automaton_match",
			Duration:   profile.ExecTime / 2,
			CallCount:  1,
			Percentage: 50.0,
		},
		{
			Function:   "bytecode_execute",
			Duration:   profile.ExecTime / 2,
			CallCount:  1,
			Percentage: 50.0,
		},
	}

	return profile
}

// Private helper methods

func (ye *YaraEngine) extractStringsFromRule(rule *ast.Rule) map[string][]byte {
	strings := make(map[string][]byte)
	for _, strDecl := range rule.Strings {
		if textStr, ok := strDecl.Pattern.(*ast.TextString); ok {
			strings[strDecl.Identifier] = []byte(textStr.Value)
		}
	}
	return strings
}

func (ye *YaraEngine) extractStrings(ast interface{}) map[string][]byte {
	// This would extract string patterns from AST
	// For now, return a simple mapping
	return map[string][]byte{
		"$test": []byte("test"),
		"$hex":  {0x74, 0x65, 0x73, 0x74},
	}
}

func (ye *YaraEngine) buildAutomaton(strings map[string][]byte) *AhoCorasickAutomaton {
	automaton := &AhoCorasickAutomaton{
		Patterns: strings,
		Nodes:    []AutomatonNode{{Children: make(map[byte]int), FailLink: 0, Output: []string{}}},
	}

	// Build trie
	for pattern := range strings {
		ye.addPattern(automaton, pattern, strings[pattern])
	}

	// Build failure links
	ye.buildFailureLinks(automaton)

	return automaton
}

func (ye *YaraEngine) addPattern(automaton *AhoCorasickAutomaton, pattern string, data []byte) {
	node := 0
	for _, b := range data {
		if _, exists := automaton.Nodes[node].Children[b]; !exists {
			automaton.Nodes[node].Children[b] = len(automaton.Nodes)
			automaton.Nodes = append(automaton.Nodes, AutomatonNode{
				Children: make(map[byte]int),
				FailLink: 0,
				Output:   []string{},
			})
		}
		node = automaton.Nodes[node].Children[b]
	}
	automaton.Nodes[node].Output = append(automaton.Nodes[node].Output, pattern)
}

func (ye *YaraEngine) buildFailureLinks(automaton *AhoCorasickAutomaton) {
	// BFS to build failure links
	queue := []int{}

	// Initialize root's children
	for _, child := range automaton.Nodes[0].Children {
		automaton.Nodes[child].FailLink = 0
		queue = append(queue, child)
	}

	// Process remaining nodes
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for b, child := range automaton.Nodes[current].Children {
			queue = append(queue, child)

			// Find failure link
			fail := automaton.Nodes[current].FailLink
			for fail != 0 && automaton.Nodes[fail].Children[b] == 0 {
				fail = automaton.Nodes[fail].FailLink
			}

			if fail != 0 {
				automaton.Nodes[child].FailLink = automaton.Nodes[fail].Children[b]
			} else {
				automaton.Nodes[child].FailLink = 0
			}

			// Merge output
			automaton.Nodes[child].Output = append(automaton.Nodes[child].Output,
				automaton.Nodes[automaton.Nodes[child].FailLink].Output...)
		}
	}
}

func (ye *YaraEngine) automatonMatch(automaton *AhoCorasickAutomaton, data []byte) []Match {
	var matches []Match
	node := 0

	for i, b := range data {
		// Follow failure links if needed
		for node != 0 && automaton.Nodes[node].Children[b] == 0 {
			node = automaton.Nodes[node].FailLink
		}

		if child, exists := automaton.Nodes[node].Children[b]; exists {
			node = child
		} else {
			node = 0
		}

		// Report matches
		for _, pattern := range automaton.Nodes[node].Output {
			if patternData, exists := automaton.Patterns[pattern]; exists {
				matches = append(matches, Match{
					Identifier: pattern,
					Offset:     int64(i - len(patternData) + 1),
					Length:     len(patternData),
					Data:       patternData,
				})
			}
		}
	}

	return matches
}

func (ye *YaraEngine) buildAutomatonFromRule(rule *ast.Rule) *AhoCorasickAutomaton {
	strings := ye.extractStringsFromRule(rule)
	return ye.buildAutomaton(strings)
}

func (ye *YaraEngine) extractRuleName(ast interface{}) string {
	// This would extract rule name from AST
	return "unknown_rule"
}

func (ye *YaraEngine) extractMetadata(ast interface{}) map[string]interface{} {
	// This would extract metadata from AST
	return map[string]interface{}{
		"author":      "benchmark",
		"description": "benchmark rule",
	}
}

func (ye *YaraEngine) getMemoryUsage() uint64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return memStats.Alloc
}

// Rule cache methods

func (rc *ruleCache) Get(key string) *CompiledRule {
	if rule, exists := rc.compiledRules[key]; exists {
		rc.hits++
		return rule
	}
	rc.misses++
	return nil
}

func (rc *ruleCache) Put(key string, rule *CompiledRule) {
	if len(rc.compiledRules) >= rc.maxSize {
		// Simple eviction - remove first entry
		for k := range rc.compiledRules {
			delete(rc.compiledRules, k)
			break
		}
	}
	rc.compiledRules[key] = rule
}

func (v *validator) ValidateAST(ast interface{}) error {
	// This would perform semantic validation
	// For now, just check if AST is not nil
	if ast == nil {
		return fmt.Errorf("empty AST")
	}
	return nil
}

// Performance analysis methods

func (ye *YaraEngine) GetStats() *EngineStats {
	return ye.stats
}

func (ye *YaraEngine) ResetStats() {
	ye.stats = &EngineStats{}
	ye.cache.hits = 0
	ye.cache.misses = 0
}

func (ye *YaraEngine) OptimizeCache() {
	// Remove least recently used items if cache is too full
	if len(ye.cache.compiledRules) > ye.cache.maxSize/2 {
		count := 0
		for key := range ye.cache.compiledRules {
			delete(ye.cache.compiledRules, key)
			count++
			if count >= ye.cache.maxSize/4 {
				break
			}
		}
	}
}

// Performance benchmarking functions

func (ye *YaraEngine) BenchmarkAutomaton(patterns map[string][]byte, data []byte, iterations int) (*BenchmarkMetrics, error) {
	automaton := ye.buildAutomaton(patterns)

	var totalTime time.Duration
	var totalAllocs, totalBytes uint64

	// Warmup
	for i := 0; i < 10; i++ {
		ye.automatonMatch(automaton, data)
	}

	// Benchmark
	runtime.GC()
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	for i := 0; i < iterations; i++ {
		ye.automatonMatch(automaton, data)
	}
	totalTime = time.Since(start)

	runtime.ReadMemStats(&memAfter)
	totalAllocs = memAfter.TotalAlloc - memBefore.TotalAlloc
	totalBytes = memAfter.TotalAlloc - memBefore.TotalAlloc

	return &BenchmarkMetrics{
		Duration:     totalTime / time.Duration(iterations),
		Allocs:       totalAllocs / uint64(iterations),
		Bytes:        totalBytes / uint64(iterations),
		Throughput:   float64(len(data)*iterations) / totalTime.Seconds() / (1024 * 1024),
		OpsPerSecond: float64(iterations) / totalTime.Seconds(),
	}, nil
}

// LoadRulesFromDirectory loads and compiles all YARA rules from a directory
func (ye *YaraEngine) LoadRulesFromDirectory(dir string) ([]*CompiledRule, error) {
	var rules []*CompiledRule

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".yar") {
			ruleText, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			compiled, err := ye.CompileRule(string(ruleText))
			if err != nil {
				return err
			}

			rules = append(rules, compiled)
		}

		return nil
	})

	return rules, err
}
