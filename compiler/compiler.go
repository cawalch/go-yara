// Package compiler provides YARA rule compilation functionality.
//
// The compiler transforms YARA source code into executable bytecode through
// four main phases:
//  1. Lexical analysis (tokenization)
//  2. Parsing (AST generation)
//  3. Semantic analysis (validation)
//  4. Code generation (bytecode emission)
//
// Basic usage:
//
//	c := compiler.NewCompiler()
//	program, err := c.CompileSource("rule test { condition: true }")
//	if err != nil {
//		log.Fatal(err)
//	}
//
// The Compiler is not safe for concurrent use. Create a separate instance
// for each goroutine if compiling concurrently.
//
// Context Support:
//
// All compilation operations support context.Context for cancellation and timeout:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	program, err := c.CompileSourceWithContext(ctx, source)
package compiler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/semantic"
	"github.com/cawalch/go-yara/utils/fs"
)

// Compiler represents the main YARA compiler.
//
// The compiler manages the entire compilation pipeline from source code to bytecode.
// It maintains state for configuration, error tracking, and statistics.
//
// Thread Safety:
//   - The Compiler is NOT safe for concurrent use
//   - Each goroutine should use its own Compiler instance
//   - CompiledProgram instances are safe for concurrent reading
type Compiler struct {
	// Compilation phases
	parser    *parser.Parser      // YARA source parser
	analyzer  *semantic.Validator // Semantic analysis and validation
	generator *RuleCompiler       // Bytecode generation

	// Configuration
	options CompilationOptions // Compilation settings and limits

	// File resolution
	baseDir string // Base directory for resolving relative includes

	// Statistics
	stats CompilationStats // Timing and resource usage metrics
}

// CompilationOptions configures the compilation process.
//
// These options control compiler behavior, optimization levels, and security limits.
// Use NewCompilerWithOptions() to create a compiler with custom options.
type CompilationOptions struct {
	EnableOptimizations bool   // Enable bytecode optimizations (default: true)
	EnableDebugInfo     bool   // Include debug information in bytecode (default: false)
	EnableWarnings      bool   // Collect and report compilation warnings (default: true)
	IgnoreInvalidRules  bool   // Compile valid rules while reporting invalid rules (default: false)
	TargetVersion       string // Target YARA version compatibility (default: "latest")
	Modules             map[string]Module

	// Security limits to prevent resource exhaustion attacks
	MaxInputSize      int64 // Maximum input file size in bytes (0 = no limit, default: 10MB)
	MaxIncludeSize    int64 // Maximum include file size in bytes (0 = no limit, default: 1MB)
	MaxRecursionDepth int   // Maximum nesting depth for rules (0 = no limit, default: 100)
}

// CompilationStats tracks compilation metrics
type CompilationStats struct {
	StartTime         time.Time
	EndTime           time.Time
	LexerTime         time.Duration
	ParserTime        time.Duration
	SemanticTime      time.Duration
	CodeGenTime       time.Duration
	TotalTime         time.Duration
	RulesCompiled     int
	TotalInstructions int
	TotalBytecodeSize int
	Errors            []CompilationError
	Warnings          []CompilationWarning
	IgnoredRules      []IgnoredRule
}

// CompilationError represents a compilation error
type CompilationError struct {
	Phase   string
	Message string
	Line    int
	Column  int
}

// CompilationWarning represents a compilation warning
type CompilationWarning struct {
	Code    string
	Phase   string
	Message string
	Rule    string
	String  string
	Line    int
	Column  int
}

const (
	WarningUnusedString     = "unused-string"
	WarningMissingCondition = "missing-condition"
	WarningTrivialCondition = "trivial-condition"
	WarningDuplicatePattern = "duplicate-pattern"
	WarningSlowPattern      = "slow-pattern"
)

// IgnoredRule describes a rule omitted from an otherwise successful
// compilation when WithIgnoreInvalidRules is enabled.
type IgnoredRule struct {
	Rule       string
	Phase      string
	Message    string
	Dependency string
	Global     bool
	Line       int
	Column     int
}

// Option represents a functional option for configuring a Compiler
type Option func(*CompilationOptions)

// NewCompiler creates a new YARA compiler with default options.
//
// The default compiler enables optimizations and warnings with reasonable security limits.
//
// Example:
//
//	c := compiler.NewCompiler()
//	program, err := c.CompileSource("rule test { condition: true }")
//
// With options:
//
//	c := compiler.NewCompiler(
//		compiler.WithOptimizations(false),
//		compiler.WithWarnings(true),
//		compiler.WithMaxInputSize(50*1024*1024), // 50MB
//	)
func NewCompiler(opts ...Option) *Compiler {
	options := CompilationOptions{
		EnableOptimizations: true,
		EnableDebugInfo:     false,
		EnableWarnings:      true,
		IgnoreInvalidRules:  false,
		TargetVersion:       "1.0",
		Modules:             defaultModules(),
		MaxInputSize:        100 * 1024 * 1024, // 100MB default
		MaxIncludeSize:      10 * 1024 * 1024,  // 10MB default
		MaxRecursionDepth:   1000,              // 1000 levels default
	}

	// Apply functional options
	for _, opt := range opts {
		opt(&options)
	}

	return &Compiler{
		options: options,
		stats: CompilationStats{
			Errors:       make([]CompilationError, 0),
			Warnings:     make([]CompilationWarning, 0),
			IgnoredRules: make([]IgnoredRule, 0),
		},
	}
}

// NewCompilerWithOptions creates a new YARA compiler with custom options.
//
// Deprecated: Use NewCompiler with functional options instead.
//
// Old way:
//
//	c := compiler.NewCompilerWithOptions(compiler.CompilationOptions{...})
//
// New way:
//
//	c := compiler.NewCompiler(
//		compiler.WithOptimizations(false),
//		compiler.WithWarnings(true),
//	)
func NewCompilerWithOptions(options CompilationOptions) *Compiler {
	return NewCompiler(func(opts *CompilationOptions) {
		*opts = options
	})
}

// ===== Functional Options =====

// WithOptimizations enables or disables optimizations
func WithOptimizations(enabled bool) Option {
	return func(opts *CompilationOptions) {
		opts.EnableOptimizations = enabled
	}
}

// WithWarnings enables or disables warning collection
func WithWarnings(enabled bool) Option {
	return func(opts *CompilationOptions) {
		opts.EnableWarnings = enabled
	}
}

// WithIgnoreInvalidRules compiles rules that pass parsing and semantic
// validation while reporting omitted rules through GetIgnoredRules. Rules that
// depend on an omitted rule are omitted as well. Strict compilation remains
// the default.
func WithIgnoreInvalidRules(enabled bool) Option {
	return func(opts *CompilationOptions) {
		opts.IgnoreInvalidRules = enabled
	}
}

// WithModule registers or replaces a pluggable module. The module name is the
// namespace used by import statements and dotted function calls.
func WithModule(module Module) Option {
	return func(opts *CompilationOptions) {
		if opts.Modules == nil {
			opts.Modules = make(map[string]Module)
		}
		opts.Modules[module.Name] = module
	}
}

// WithMaxInputSize sets the maximum input file size limit (0 = no limit)
func WithMaxInputSize(size int64) Option {
	return func(opts *CompilationOptions) {
		opts.MaxInputSize = size
	}
}

// CompileSource compiles YARA source code to bytecode.
//
// Deprecated: Use CompileSourceWithContext for better cancellation and timeout support.
func (c *Compiler) CompileSource(source string) (*CompiledProgram, error) {
	return c.CompileSourceWithContext(context.Background(), source)
}

// CompileSourceWithContext compiles YARA source code to bytecode with context support
func (c *Compiler) CompileSourceWithContext(ctx context.Context, source string) (*CompiledProgram, error) {
	// Check for cancellation early
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	c.stats = CompilationStats{
		StartTime:    time.Now(),
		Errors:       make([]CompilationError, 0),
		Warnings:     make([]CompilationWarning, 0),
		IgnoredRules: make([]IgnoredRule, 0),
	}

	// Validate input size to prevent DoS attacks
	if c.options.MaxInputSize > 0 && int64(len(source)) > c.options.MaxInputSize {
		return nil, fmt.Errorf("input size %d bytes exceeds maximum allowed %d bytes", len(source), c.options.MaxInputSize)
	}

	// Phase 1: Parsing (parser creates its own lexer, no need for separate lexical analysis)
	program, err := c.compileParseWithContext(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", err)
	}

	// Check for cancellation before proceeding to next phase
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Phase 2: Process imports
	if len(program.Imports) > 0 {
		if err := c.processImportsWithContext(ctx, program); err != nil {
			return nil, fmt.Errorf("processing imports failed: %w", err)
		}
	}

	// Check for cancellation before proceeding to next phase
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Phase 3: Semantic Analysis
	if semErr := c.compileSemanticWithContext(ctx, program); semErr != nil {
		return nil, fmt.Errorf("semantic analysis failed: %w", semErr)
	}

	// Check for cancellation before proceeding to next phase
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Phase 4: Code Generation
	compiledProgram, codeGenErr := c.compileCodeGenWithContext(ctx, program)
	if codeGenErr != nil {
		return nil, fmt.Errorf("code generation failed: %w", codeGenErr)
	}

	c.stats.EndTime = time.Now()
	c.stats.TotalTime = c.stats.EndTime.Sub(c.stats.StartTime)

	return compiledProgram, nil
}

// CompileFile compiles a YARA file to bytecode.
//
// Deprecated: Use CompileFileWithContext for better cancellation and timeout support.
func (c *Compiler) CompileFile(filename string) (*CompiledProgram, error) {
	return c.CompileFileWithContext(context.Background(), filename)
}

// CompileFileWithContext compiles a YARA file to bytecode with context support
func (c *Compiler) CompileFileWithContext(ctx context.Context, filename string) (*CompiledProgram, error) {
	// Check for cancellation early
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Read file content
	source, err := c.readFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", filename, err)
	}

	// Store the base directory for resolving includes
	c.baseDir = filepath.Dir(filename)

	return c.CompileSourceWithContext(ctx, source)
}

// compileParseWithContext performs parsing with context support
func (c *Compiler) compileParseWithContext(ctx context.Context, source string) (*ast.Program, error) {
	start := time.Now()

	// Check for cancellation before creating parser
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Create a fresh lexer for the parser
	// (the previous lexer was consumed during tokenization)
	freshLexer := lexer.New(source)

	// Create parser with fresh lexer and recursion depth limit
	c.parser = parser.NewWithOptions(freshLexer, parser.Options{
		MaxRecursionDepth: c.options.MaxRecursionDepth,
	})
	if c.options.IgnoreInvalidRules {
		c.parser.SetErrorRecovery(true)
		c.parser.SetSkipInvalidRules(true)
	}

	// Parse with context support
	program, err := c.parser.ParseRulesWithContext(ctx)
	if err != nil {
		var partialErr *parser.PartialParseError
		if !c.options.IgnoreInvalidRules || !errors.As(err, &partialErr) || len(c.parser.ProgramErrors()) != 0 {
			c.stats.Errors = append(c.stats.Errors, CompilationError{
				Phase:   "parsing",
				Message: err.Error(),
				Line:    0,
				Column:  0,
			})
			return nil, fmt.Errorf("parsing rules: %w", err)
		}
		program = partialErr.Program
		for _, invalid := range c.parser.InvalidRules() {
			c.recordParseInvalidRule(invalid)
		}
	}

	// Process includes - resolve and parse included files
	if len(program.Includes) > 0 {
		includeErr := c.processIncludesWithContext(ctx, program)
		if includeErr != nil {
			c.stats.Errors = append(c.stats.Errors, CompilationError{
				Phase:   "parsing",
				Message: includeErr.Error(),
				Line:    0,
				Column:  0,
			})
			return nil, includeErr
		}
	}

	c.stats.ParserTime = time.Since(start)

	// Check for parser errors
	if len(c.parser.Errors()) > 0 && !c.options.IgnoreInvalidRules {
		for _, err := range c.parser.Errors() {
			c.stats.Errors = append(c.stats.Errors, CompilationError{
				Phase:   "parsing",
				Message: err.Error(),
				Line:    0,
				Column:  0,
			})
		}
		return nil, errors.New("parser errors found")
	}

	return program, nil
}

func (c *Compiler) recordParseInvalidRule(invalid parser.InvalidRule) {
	ignored := IgnoredRule{
		Phase:   "parsing",
		Message: "rule contains parse errors",
	}
	if invalid.Rule != nil {
		ignored.Rule = invalid.Rule.Name
		ignored.Line = invalid.Rule.Pos.Line
		ignored.Column = invalid.Rule.Pos.Column
		ignored.Global = ruleHasModifier(invalid.Rule, ast.ModifierGlobal)
	}
	if len(invalid.Errors) > 0 {
		ignored.Message = invalid.Errors[0].Error()
	}
	c.recordIgnoredRule(ignored)
}

func (c *Compiler) recordIgnoredRule(ignored IgnoredRule) {
	for _, existing := range c.stats.IgnoredRules {
		if existing.Rule == ignored.Rule {
			return
		}
	}
	c.stats.IgnoredRules = append(c.stats.IgnoredRules, ignored)
}

func (c *Compiler) ignoredRuleNames() []string {
	names := make([]string, 0, len(c.stats.IgnoredRules))
	for _, ignored := range c.stats.IgnoredRules {
		if ignored.Rule != "" {
			names = append(names, ignored.Rule)
		}
	}
	return names
}

func (c *Compiler) ignoredRuleNameSet() map[string]bool {
	ignored := make(map[string]bool, len(c.stats.IgnoredRules))
	for _, rule := range c.stats.IgnoredRules {
		if rule.Rule != "" {
			ignored[rule.Rule] = true
		}
	}
	return ignored
}

func (c *Compiler) removeSemanticallyInvalidRules(program *ast.Program, validationErrors []error) error {
	for len(validationErrors) > 0 {
		ruleErrors := make(map[string]*semantic.Error)
		var programErrors []error
		for _, err := range validationErrors {
			semanticErr, ok := err.(*semantic.Error)
			if !ok || semanticErr.Rule == "" {
				programErrors = append(programErrors, err)
				continue
			}
			if _, exists := ruleErrors[semanticErr.Rule]; !exists {
				ruleErrors[semanticErr.Rule] = semanticErr
			}
		}

		if len(programErrors) > 0 {
			for _, err := range programErrors {
				c.stats.Errors = append(c.stats.Errors, CompilationError{
					Phase:   "semantic",
					Message: err.Error(),
				})
			}
			return fmt.Errorf("%d program-level semantic errors: first: %w", len(programErrors), programErrors[0])
		}
		if len(ruleErrors) == 0 {
			return errors.New("semantic validation failed without an attributable rule error")
		}

		for _, rule := range program.Rules {
			semanticErr, invalid := ruleErrors[rule.Name]
			if !invalid {
				continue
			}
			c.recordIgnoredRule(IgnoredRule{
				Rule:    rule.Name,
				Phase:   "semantic",
				Message: semanticErr.Message,
				Global:  ruleHasModifier(rule, ast.ModifierGlobal),
				Line:    semanticErr.Position.Line,
				Column:  semanticErr.Position.Column,
			})
		}

		c.propagateIgnoredRuleDependencies(program)
		program.Rules = filterIgnoredRules(program.Rules, c.ignoredRuleNameSet())
		validationErrors = c.analyzer.ValidateProgram(program)
	}
	return nil
}

func (c *Compiler) propagateIgnoredRuleDependencies(program *ast.Program) {
	dependencies := semantic.RuleDependencies(program, c.ignoredRuleNames()...)
	ignored := c.ignoredRuleNameSet()

	for {
		changed := false
		globalDependency := ""
		for _, ignoredRule := range c.stats.IgnoredRules {
			if ignoredRule.Global {
				globalDependency = ignoredRule.Rule
				break
			}
		}

		for _, rule := range program.Rules {
			if ignored[rule.Name] {
				continue
			}

			dependency := ""
			if globalDependency != "" {
				dependency = globalDependency
			} else {
				for _, candidate := range dependencies[rule.Name] {
					if ignored[candidate] {
						dependency = candidate
						break
					}
				}
			}
			if dependency == "" {
				continue
			}

			c.recordIgnoredRule(IgnoredRule{
				Rule:       rule.Name,
				Phase:      "dependency",
				Message:    fmt.Sprintf("depends on ignored rule %q", dependency),
				Dependency: dependency,
				Global:     ruleHasModifier(rule, ast.ModifierGlobal),
				Line:       rule.Pos.Line,
				Column:     rule.Pos.Column,
			})
			ignored[rule.Name] = true
			changed = true
		}
		if !changed {
			return
		}
	}
}

func filterIgnoredRules(rules []*ast.Rule, ignored map[string]bool) []*ast.Rule {
	filtered := make([]*ast.Rule, 0, len(rules))
	for _, rule := range rules {
		if !ignored[rule.Name] {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

func ruleHasModifier(rule *ast.Rule, modifier ast.Modifier) bool {
	if rule == nil {
		return false
	}
	for _, candidate := range rule.Modifiers {
		if candidate == modifier {
			return true
		}
	}
	return false
}

// compileSemanticWithContext performs semantic analysis with context support
func (c *Compiler) compileSemanticWithContext(ctx context.Context, program *ast.Program) error {
	start := time.Now()

	// Check for cancellation before semantic analysis
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Create semantic analyzer
	c.analyzer = semantic.NewValidatorWithModules(semanticModuleFunctions(c.options.Modules))

	// Analyze - ValidateProgram returns errors, not error
	errs := c.analyzer.ValidateProgram(program)
	if len(errs) > 0 && c.options.IgnoreInvalidRules {
		if err := c.removeSemanticallyInvalidRules(program, errs); err != nil {
			return err
		}
		errs = nil
	}
	if len(errs) > 0 {
		for _, err := range errs {
			c.stats.Errors = append(c.stats.Errors, CompilationError{
				Phase:   "semantic",
				Message: err.Error(),
				Line:    0,
				Column:  0,
			})
		}
		return fmt.Errorf("%d semantic errors: first: %w", len(errs), errs[0])
	}

	c.stats.SemanticTime = time.Since(start)

	// Collect warnings if enabled (check for cancellation before expensive operations)
	if c.options.EnableWarnings {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		c.collectSemanticWarnings(program)
	}

	return nil
}

// collectSemanticWarnings collects semantic warnings from the compiled program
func (c *Compiler) collectSemanticWarnings(program *ast.Program) {
	for _, rule := range program.Rules {
		c.collectRuleWarnings(rule)
	}
}

// collectRuleWarnings collects warnings for a specific rule
func (c *Compiler) collectRuleWarnings(rule *ast.Rule) {
	// Check for unused strings
	c.checkUnusedStrings(rule)

	// Check for empty rules
	c.checkEmptyRule(rule)

	// Check for potentially problematic patterns
	c.checkProblematicPatterns(rule)

	// Duplicate patterns waste compilation and matching work, and often signal
	// a copy/paste error in a rule.
	c.checkDuplicatePatterns(rule)
}

// checkUnusedStrings warns about strings that are defined but never used
func (c *Compiler) checkUnusedStrings(rule *ast.Rule) {
	if len(rule.Strings) == 0 {
		return // No strings to check
	}

	// Track which strings are referenced in the condition
	referenced := make(map[string]bool)
	c.collectReferencedStrings(rule.Condition, referenced)

	// Check for unused strings
	for _, str := range rule.Strings {
		if !stringIsReferenced(str.Identifier, referenced) {
			// YARA spec: strings prefixed with $_ suppress the unreferenced warning
			if len(str.Identifier) >= 2 && str.Identifier[:2] == "$_" {
				continue
			}
			c.addRuleWarning(CompilationWarning{
				Code: WarningUnusedString, Phase: "semantic",
				Message: fmt.Sprintf("String '%s' is defined but never used in condition", str.Identifier),
				Rule:    rule.Name, String: str.Identifier, Line: str.Pos.Line, Column: str.Pos.Column,
			})
		}
	}
}

// collectReferencedStrings recursively collects string references from an expression
func (c *Compiler) collectReferencedStrings(expr ast.Expression, referenced map[string]bool) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		// This could be a string reference
		if e.Name == "them" {
			referenced["*"] = true
		} else if len(e.Name) > 0 && e.Name[0] == '$' {
			referenced[e.Name+e.Quantifier] = true
		}
	case *ast.OfExpression:
		// Check strings in "of" expressions
		if e.Strings != nil {
			c.collectReferencedStrings(e.Strings, referenced)
		}
		c.collectReferencedStrings(e.Count, referenced)
		c.collectReferencedStrings(e.InRange, referenced)
		c.collectReferencedStrings(e.AtOffset, referenced)
	case *ast.BinaryOp:
		c.collectReferencedStrings(e.Left, referenced)
		c.collectReferencedStrings(e.Right, referenced)
	case *ast.UnaryOp:
		c.collectReferencedStrings(e.Right, referenced)
	case *ast.FunctionCall:
		// Check arguments for string references
		for _, arg := range e.Args {
			c.collectReferencedStrings(arg, referenced)
		}
	case *ast.StringCount:
		c.collectReferencedStrings(e.String, referenced)
		c.collectReferencedStrings(e.Index, referenced)
	case *ast.StringOffset:
		c.collectReferencedStrings(e.String, referenced)
		c.collectReferencedStrings(e.Index, referenced)
	case *ast.StringLength:
		c.collectReferencedStrings(e.String, referenced)
		c.collectReferencedStrings(e.Index, referenced)
	case *ast.LengthOf:
		c.collectReferencedStrings(e.Target, referenced)
	case *ast.ForLoop:
		c.collectReferencedStrings(e.Range, referenced)
		c.collectReferencedStrings(e.Condition, referenced)
		c.collectReferencedStrings(e.InRange, referenced)
		c.collectReferencedStrings(e.AtOffset, referenced)
	case *ast.PercentExpression:
		c.collectReferencedStrings(e.Value, referenced)
	case *ast.StringTuple:
		for _, element := range e.Elements {
			c.collectReferencedStrings(element, referenced)
		}
	}
}

func stringIsReferenced(id string, referenced map[string]bool) bool {
	if referenced["*"] || referenced[id] {
		return true
	}
	for pattern := range referenced {
		if strings.HasSuffix(pattern, "*") && strings.HasPrefix(id, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

// checkEmptyRule warns about rules with empty conditions
func (c *Compiler) checkEmptyRule(rule *ast.Rule) {
	// This is a basic check - could be expanded
	if rule.Condition == nil {
		c.addRuleWarning(CompilationWarning{
			Code: WarningMissingCondition, Phase: "semantic",
			Message: fmt.Sprintf("Rule '%s' has no condition", rule.Name),
			Rule:    rule.Name, Line: rule.Pos.Line, Column: rule.Pos.Column,
		})
	}
}

// checkProblematicPatterns warns about potentially problematic patterns
func (c *Compiler) checkProblematicPatterns(rule *ast.Rule) {
	// Check for rules with only trivial conditions
	if c.isTrivialCondition(rule.Condition) {
		c.addRuleWarning(CompilationWarning{
			Code: WarningTrivialCondition, Phase: "semantic",
			Message: fmt.Sprintf("Rule '%s' has a trivial condition that may always be true", rule.Name),
			Rule:    rule.Name, Line: rule.Pos.Line, Column: rule.Pos.Column,
		})
	}
}

func (c *Compiler) checkDuplicatePatterns(rule *ast.Rule) {
	seen := make(map[string]string, len(rule.Strings))
	for _, str := range rule.Strings {
		signature := patternSignature(str)
		if original, duplicate := seen[signature]; duplicate {
			c.addRuleWarning(CompilationWarning{
				Code: WarningDuplicatePattern, Phase: "semantic",
				Message: fmt.Sprintf("String '%s' duplicates pattern from '%s'", str.Identifier, original),
				Rule:    rule.Name, String: str.Identifier, Line: str.Pos.Line, Column: str.Pos.Column,
			})
			continue
		}
		seen[signature] = str.Identifier
	}
}

func patternSignature(str *ast.String) string {
	if str == nil || str.Pattern == nil {
		return ""
	}
	kind := "unknown"
	value := ""
	switch pattern := str.Pattern.(type) {
	case *ast.TextString:
		kind, value = "text", pattern.Value
	case *ast.RegexPattern:
		kind, value = "regex", pattern.Value
	case *ast.HexString:
		kind, value = "hex", strings.Join(strings.Fields(pattern.Value), " ")
	}
	modifiers := make([]string, 0, len(str.Modifiers))
	for _, modifier := range str.Modifiers {
		modifiers = append(modifiers, fmt.Sprintf("%d=%v", modifier.Type, modifier.Value))
	}
	slices.Sort(modifiers)
	return kind + "\x00" + value + "\x00" + strings.Join(modifiers, ",")
}

func (c *Compiler) collectCompiledPatternWarnings(program *ast.Program, compiledRules []*CompiledRule) {
	astRules := make(map[string]*ast.Rule, len(program.Rules))
	for _, rule := range program.Rules {
		astRules[rule.Name] = rule
	}

	for _, rule := range compiledRules {
		for _, id := range rule.StringIdentifiers() {
			reason := slowPatternReason(rule, id)
			if reason == "" {
				continue
			}
			line, column := 0, 0
			if sourceRule := astRules[rule.Name]; sourceRule != nil {
				if sourceString := findASTString(sourceRule.Strings, id); sourceString != nil {
					line, column = sourceString.Pos.Line, sourceString.Pos.Column
				}
			}
			c.addRuleWarning(CompilationWarning{
				Code: WarningSlowPattern, Phase: "performance",
				Message: fmt.Sprintf("String '%s' %s and may slow scanning", id, reason),
				Rule:    rule.Name, String: id, Line: line, Column: column,
			})
		}
	}
}

func slowPatternReason(rule *CompiledRule, id string) string {
	switch rule.StringKinds[id] {
	case StringKindText:
		if len(rule.TextPatterns[id]) < 3 {
			return "is shorter than three bytes"
		}
	case StringKindRegex:
		pattern, ok := rule.RegexPatterns[id]
		if !ok || pattern.anchored {
			return ""
		}
		if len(pattern.prefix) >= 2 || len(pattern.atom) >= 2 || pattern.leadingGap != nil {
			return ""
		}
		for _, atom := range pattern.alternativeAtoms {
			if len(atom.data) >= 2 {
				return ""
			}
		}
		return "has no selective literal prefilter"
	case StringKindHex:
		pattern := rule.HexPatterns[id]
		if pattern == nil {
			return ""
		}
		atom, ok := selectHexAtom(pattern.Tokens)
		if !ok || len(atom.data) < 2 {
			return "has no selective two-byte atom"
		}
	}
	return ""
}

func findASTString(strings []*ast.String, id string) *ast.String {
	for _, str := range strings {
		if str.Identifier == id {
			return str
		}
	}
	return nil
}

// isTrivialCondition checks if a condition is overly simple (e.g., just "true")
func (c *Compiler) isTrivialCondition(expr ast.Expression) bool {
	if lit, ok := expr.(*ast.Literal); ok {
		if boolVal, ok := lit.Value.(bool); ok && boolVal {
			return true
		}
	}
	return false
}

// compileCodeGenWithContext performs code generation with context support
func (c *Compiler) compileCodeGenWithContext(ctx context.Context, program *ast.Program) (*CompiledProgram, error) {
	start := time.Now()

	// Check for cancellation before code generation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var compiledRules []*CompiledRule
	for {
		generator, moduleErr := NewRuleCompilerWithModules(c.options.Modules)
		if moduleErr != nil {
			return nil, fmt.Errorf("configuring modules: %w", moduleErr)
		}
		c.generator = generator

		var err error
		compiledRules, err = c.generator.CompileProgram(program)
		if err == nil {
			break
		}

		var ruleErr *RuleCompileError
		if c.options.IgnoreInvalidRules && errors.As(err, &ruleErr) {
			rule := findRule(program.Rules, ruleErr.Rule)
			if rule == nil {
				return nil, fmt.Errorf("code generation identified unknown rule %q: %w", ruleErr.Rule, err)
			}
			c.recordIgnoredRule(IgnoredRule{
				Rule:    rule.Name,
				Phase:   "codegen",
				Message: ruleErr.Err.Error(),
				Global:  ruleHasModifier(rule, ast.ModifierGlobal),
				Line:    rule.Pos.Line,
				Column:  rule.Pos.Column,
			})
			c.propagateIgnoredRuleDependencies(program)
			program.Rules = filterIgnoredRules(program.Rules, c.ignoredRuleNameSet())
			continue
		}

		c.stats.Errors = append(c.stats.Errors, CompilationError{
			Phase:   "codegen",
			Message: err.Error(),
			Line:    0,
			Column:  0,
		})
		return nil, err
	}

	c.stats.CodeGenTime = time.Since(start)

	// Build integer string ID indices for each rule (enables int-keyed match routing).
	for _, rule := range compiledRules {
		rule.BuildStringIndex()
	}

	// Wrap in CompiledProgram
	compiledProgram := NewCompiledProgram(compiledRules)
	compiledProgram.dependencies = semantic.RuleDependencies(program)
	compiledProgram.nonTextCacheSize = assignNonTextCacheIndices(compiledRules)
	compiledProgram.fixedRegexScan = buildFixedRegexDispatch(compiledRules)

	// Combine text strings and safe regex/hex atoms into one global candidate pass.
	sharedAutomaton, sharedLookup, err := buildSharedPatternAutomaton(compiledRules)
	if err != nil {
		return nil, err
	}
	compiledProgram.SetSharedAutomaton(sharedAutomaton)
	compiledProgram.SharedLookup = sharedLookup
	if c.options.EnableWarnings {
		c.collectCompiledPatternWarnings(program, compiledRules)
	}

	// Update statistics (check for cancellation before expensive operations)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	c.stats.RulesCompiled = compiledProgram.GetRuleCount()
	c.stats.TotalInstructions = compiledProgram.GetTotalBytecodeSize()
	c.stats.TotalBytecodeSize = compiledProgram.GetTotalBytecodeSize()

	return compiledProgram, nil
}

func findRule(rules []*ast.Rule, name string) *ast.Rule {
	for _, rule := range rules {
		if rule.Name == name {
			return rule
		}
	}
	return nil
}

// GetStats returns compilation statistics
func (c *Compiler) GetStats() CompilationStats {
	return c.stats
}

// GetErrors returns all compilation errors
func (c *Compiler) GetErrors() []CompilationError {
	return c.stats.Errors
}

// GetWarnings returns all compilation warnings
func (c *Compiler) GetWarnings() []CompilationWarning {
	return c.stats.Warnings
}

// GetIgnoredRules returns rules omitted by resilient compilation.
func (c *Compiler) GetIgnoredRules() []IgnoredRule {
	return append([]IgnoredRule(nil), c.stats.IgnoredRules...)
}

// AddWarning adds a compilation warning
//
//nolint:revive // argument-limit: API surface
func (c *Compiler) AddWarning(phase, message string, line, column int) {
	c.addRuleWarning(CompilationWarning{Phase: phase, Message: message, Line: line, Column: column})
}

func (c *Compiler) addRuleWarning(warning CompilationWarning) {
	c.stats.Warnings = append(c.stats.Warnings, warning)
}

// HasErrors returns true if there were compilation errors
func (c *Compiler) HasErrors() bool {
	return len(c.stats.Errors) > 0
}

// HasWarnings returns true if there were compilation warnings
func (c *Compiler) HasWarnings() bool {
	return len(c.stats.Warnings) > 0
}

// SetOptions updates the compilation options
func (c *Compiler) SetOptions(options CompilationOptions) {
	c.options = options
}

// GetOptions returns the current compilation options
func (c *Compiler) GetOptions() CompilationOptions {
	return c.options
}

// SetBaseDir sets the base directory for resolving relative include paths
func (c *Compiler) SetBaseDir(dir string) {
	c.baseDir = dir
}

// Reset resets the compiler state
func (c *Compiler) Reset() {
	c.parser = nil
	c.analyzer = nil
	c.generator = nil
	c.stats = CompilationStats{
		Errors:       make([]CompilationError, 0),
		Warnings:     make([]CompilationWarning, 0),
		IgnoredRules: make([]IgnoredRule, 0),
	}
}

// processIncludesWithContext processes include statements in the YARA rules with context support
func (c *Compiler) processIncludesWithContext(ctx context.Context, program *ast.Program) error {
	// Check for cancellation before processing includes
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return c.processIncludesWithBaseDirContext(ctx, program, c.baseDir)
}

// processIncludesWithBaseDir processes includes with a specific base directory
func (c *Compiler) processIncludesWithBaseDir(program *ast.Program, baseDir string) error {
	return c.processIncludesWithBaseDirContext(context.Background(), program, baseDir)
}

// processIncludesWithBaseDirContext processes includes with a specific base directory and context support
func (c *Compiler) processIncludesWithBaseDirContext(ctx context.Context, program *ast.Program, baseDir string) error {
	// Process each include statement
	for _, include := range program.Includes {
		// Check for cancellation before processing each include
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Resolve the include path relative to base directory
		includePath := filepath.Join(baseDir, include.File)

		// Clean the path to resolve any .. components
		cleanIncludePath := filepath.Clean(includePath)

		// Get the absolute base directory
		absBaseDir, err := filepath.Abs(baseDir)
		if err != nil {
			return fmt.Errorf("failed to resolve base directory: %w", err)
		}
		absBaseDir = filepath.Clean(absBaseDir)

		// Get the absolute include path
		absIncludePath, err := filepath.Abs(cleanIncludePath)
		if err != nil {
			return fmt.Errorf("failed to resolve include path: %w", err)
		}
		absIncludePath = filepath.Clean(absIncludePath)

		// Check if the include path is within the base directory (prevents directory traversal)
		if !strings.HasPrefix(absIncludePath, absBaseDir+string(filepath.Separator)) && absIncludePath != absBaseDir {
			return fmt.Errorf("failed to read include file %s: path traversal detected", include.File)
		}

		// Read the included file content (use the cleaned, validated path)
		includedContent, err := os.ReadFile(cleanIncludePath)
		if err != nil {
			return fmt.Errorf("failed to read include file %s: %w", include.File, err)
		}

		// Check file size limit if set
		if c.options.MaxIncludeSize > 0 && int64(len(includedContent)) > c.options.MaxIncludeSize {
			return fmt.Errorf("include file %s size %d bytes exceeds maximum allowed %d bytes",
				include.File, len(includedContent), c.options.MaxIncludeSize)
		}

		// Parse the included content
		includedLexer := lexer.New(string(includedContent))
		includedParser := parser.NewWithOptions(includedLexer, parser.Options{
			MaxRecursionDepth: c.options.MaxRecursionDepth,
		})
		if c.options.IgnoreInvalidRules {
			includedParser.SetErrorRecovery(true)
			includedParser.SetSkipInvalidRules(true)
		}
		includedProgram, parseErr := includedParser.ParseRulesWithContext(ctx)
		if parseErr != nil {
			var partialErr *parser.PartialParseError
			if !c.options.IgnoreInvalidRules || !errors.As(parseErr, &partialErr) || len(includedParser.ProgramErrors()) != 0 {
				return fmt.Errorf("failed to parse include file %s: %w", include.File, parseErr)
			}
			includedProgram = partialErr.Program
			for _, invalid := range includedParser.InvalidRules() {
				c.recordParseInvalidRule(invalid)
			}
		}

		// Check for parser errors in included file
		if len(includedParser.Errors()) > 0 && !c.options.IgnoreInvalidRules {
			return fmt.Errorf("parser errors in include file %s: %v", include.File, includedParser.Errors())
		}

		// Recursively process includes in the included file first
		// Use the directory of the included file as the new baseDir
		if len(includedProgram.Includes) > 0 {
			// Resolve the actual path for the included file to get its directory
			// We use filepath.Join and filepath.Clean to get the canonical path
			includedFilePath := filepath.Join(baseDir, include.File)
			includedFileDir := filepath.Dir(filepath.Clean(includedFilePath))
			processErr := c.processIncludesWithBaseDirContext(ctx, includedProgram, includedFileDir)
			if processErr != nil {
				return fmt.Errorf("failed to process includes in %s: %w", include.File, processErr)
			}
		}

		// Add all rules from included file (including nested includes) to main program
		program.Rules = append(program.Rules, includedProgram.Rules...)

		// Also add any imports from the included file
		program.Imports = append(program.Imports, includedProgram.Imports...)
	}

	return nil
}

// ProcessIncludes is a public wrapper for processIncludesWithBaseDir
func (c *Compiler) ProcessIncludes(program *ast.Program) error {
	return c.processIncludesWithBaseDir(program, c.baseDir)
}

// processImportsWithContext processes import statements with context support
func (c *Compiler) processImportsWithContext(ctx context.Context, program *ast.Program) error {
	if len(program.Imports) == 0 {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	for _, importStmt := range program.Imports {
		if _, supported := c.options.Modules[importStmt.Module]; supported {
			continue
		}
		message := "unsupported module: " + importStmt.Module
		c.stats.Errors = append(c.stats.Errors, CompilationError{
			Phase:   "imports",
			Message: message,
			Line:    importStmt.Pos.Line,
			Column:  importStmt.Pos.Column,
		})
		return errors.New(message)
	}
	return nil
}

func (c *Compiler) readFile(filename string) (string, error) {
	// Use centralized file reading utility
	return fs.ReadFileString(c.baseDir, filename)
}

// PrintStats prints compilation statistics
func (c *Compiler) PrintStats() {
	stats := c.stats

	fmt.Printf("Compilation Statistics:\n")
	fmt.Printf("  Total Time: %v\n", stats.TotalTime)
	fmt.Printf("  Lexer Time: %v\n", stats.LexerTime)
	fmt.Printf("  Parser Time: %v\n", stats.ParserTime)
	fmt.Printf("  Semantic Time: %v\n", stats.SemanticTime)
	fmt.Printf("  Code Gen Time: %v\n", stats.CodeGenTime)
	fmt.Printf("  Rules Compiled: %d\n", stats.RulesCompiled)
	fmt.Printf("  Total Instructions: %d\n", stats.TotalInstructions)
	fmt.Printf("  Total Bytecode Size: %d bytes\n", stats.TotalBytecodeSize)
	fmt.Printf("  Errors: %d\n", len(stats.Errors))
	fmt.Printf("  Warnings: %d\n", len(stats.Warnings))

	if len(stats.Errors) > 0 {
		fmt.Printf("\nErrors:\n")
		for _, err := range stats.Errors {
			fmt.Printf("  [%s] %s at line %d, column %d\n",
				err.Phase, err.Message, err.Line, err.Column)
		}
	}

	if len(stats.Warnings) > 0 {
		fmt.Printf("\nWarnings:\n")
		for _, warn := range stats.Warnings {
			fmt.Printf("  [%s] %s at line %d, column %d\n",
				warn.Phase, warn.Message, warn.Line, warn.Column)
		}
	}
}

// ValidateOptions validates the compilation options
func (c *Compiler) ValidateOptions() error {
	// Validate target version
	if c.options.TargetVersion == "" {
		return errors.New("target version cannot be empty")
	}

	return nil
}

// GetVersion returns the compiler version
func (c *Compiler) GetVersion() string {
	return "go-yara compiler v1.0"
}

// BatchCompile compiles multiple sources efficiently
func (c *Compiler) BatchCompile(sources []string) ([]*CompiledProgram, error) {
	programs := make([]*CompiledProgram, 0, len(sources))

	for i, source := range sources {
		program, err := c.CompileSource(source)
		if err != nil {
			return nil, fmt.Errorf("compiling source %d: %w", i, err)
		}
		programs = append(programs, program)
	}

	return programs, nil
}

// CompileWithProgress compiles source with progress reporting
func (c *Compiler) CompileWithProgress(source string, progressCallback func(phase string, percent float64)) (*CompiledProgram, error) {
	// Set up progress callback
	if progressCallback != nil {
		progressCallback("starting", 0)
	}

	// Parsing (parser creates its own lexer)
	if progressCallback != nil {
		progressCallback("parsing", 30)
	}
	program, err := c.compileParseWithContext(context.Background(), source)
	if err != nil {
		return nil, err
	}

	// Semantic analysis
	if progressCallback != nil {
		progressCallback("semantic", 60)
	}
	if semErr := c.compileSemanticWithContext(context.Background(), program); semErr != nil {
		return nil, semErr
	}

	// Code generation
	if progressCallback != nil {
		progressCallback("codegen", 90)
	}
	compiledProgram, codeGenErr := c.compileCodeGenWithContext(context.Background(), program)
	if codeGenErr != nil {
		return nil, codeGenErr
	}

	if progressCallback != nil {
		progressCallback("complete", 100)
	}

	return compiledProgram, nil
}

// GetPhaseDependencies returns the dependencies between compilation phases
func (c *Compiler) GetPhaseDependencies() map[string][]string {
	return map[string][]string{
		"lexical":  {},
		"parsing":  {"lexical"},
		"semantic": {"parsing"},
		"codegen":  {"semantic"},
		"optimize": {"codegen"},
	}
}

// ValidateCompilation validates that the compilation completed successfully
func (c *Compiler) ValidateCompilation(program *CompiledProgram) error {
	if program == nil {
		return errors.New("compiled program is nil")
	}

	if err := program.Validate(); err != nil {
		return fmt.Errorf("program validation failed: %w", err)
	}

	if c.stats.RulesCompiled != program.GetRuleCount() {
		return fmt.Errorf("rule count mismatch: expected %d, got %d",
			c.stats.RulesCompiled, program.GetRuleCount())
	}

	return nil
}

// GetCompilationReport returns a detailed report of the compilation
func (c *Compiler) GetCompilationReport() string {
	report := "Go-YARA Compilation Report\n"
	report += "========================\n\n"
	report += fmt.Sprintf("Version: %s\n", c.GetVersion())
	report += fmt.Sprintf("Target: %s\n", c.options.TargetVersion)
	report += fmt.Sprintf("Options: Optimizations=%v, Debug=%v, Warnings=%v\n",
		c.options.EnableOptimizations, c.options.EnableDebugInfo, c.options.EnableWarnings)
	report += "\n"

	// Timing information
	report += "Timing:\n"
	report += fmt.Sprintf("  Total: %v\n", c.stats.TotalTime)
	report += fmt.Sprintf("  Lexer: %v\n", c.stats.LexerTime)
	report += fmt.Sprintf("  Parser: %v\n", c.stats.ParserTime)
	report += fmt.Sprintf("  Semantic: %v\n", c.stats.SemanticTime)
	report += fmt.Sprintf("  Code Generation: %v\n", c.stats.CodeGenTime)
	report += "\n"

	// Results
	report += "Results:\n"
	report += fmt.Sprintf("  Rules Compiled: %d\n", c.stats.RulesCompiled)
	report += fmt.Sprintf("  Total Instructions: %d\n", c.stats.TotalInstructions)
	report += fmt.Sprintf("  Total Bytecode Size: %d bytes\n", c.stats.TotalBytecodeSize)
	report += "\n"

	// Errors and warnings
	if len(c.stats.Errors) > 0 {
		report += fmt.Sprintf("Errors (%d):\n", len(c.stats.Errors))
		var reportSb626 strings.Builder
		for _, err := range c.stats.Errors {
			fmt.Fprintf(&reportSb626, "  [%s] %s at %d:%d\n", err.Phase, err.Message, err.Line, err.Column)
		}
		report += reportSb626.String()
		report += "\n"
	}

	if len(c.stats.Warnings) > 0 {
		report += fmt.Sprintf("Warnings (%d):\n", len(c.stats.Warnings))
		var reportSb634 strings.Builder
		for _, warn := range c.stats.Warnings {
			fmt.Fprintf(&reportSb634, "  [%s] %s at %d:%d\n", warn.Phase, warn.Message, warn.Line, warn.Column)
		}
		report += reportSb634.String()
		report += "\n"
	}

	return report
}
