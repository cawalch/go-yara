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
	TargetVersion       string // Target YARA version compatibility (default: "latest")

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
	Phase   string
	Message string
	Line    int
	Column  int
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
		TargetVersion:       "1.0",
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
			Errors:   make([]CompilationError, 0),
			Warnings: make([]CompilationWarning, 0),
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
		StartTime: time.Now(),
		Errors:    make([]CompilationError, 0),
		Warnings:  make([]CompilationWarning, 0),
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

	// Parse with context support
	program, err := c.parser.ParseRulesWithContext(ctx)
	if err != nil {
		c.stats.Errors = append(c.stats.Errors, CompilationError{
			Phase:   "parsing",
			Message: err.Error(),
			Line:    0,
			Column:  0,
		})
		return nil, fmt.Errorf("parsing rules: %w", err)
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
	if len(c.parser.Errors()) > 0 {
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
	c.analyzer = semantic.NewValidator()

	// Analyze - ValidateProgram returns errors, not error
	errs := c.analyzer.ValidateProgram(program)
	if len(errs) > 0 {
		for _, err := range errs {
			c.stats.Errors = append(c.stats.Errors, CompilationError{
				Phase:   "semantic",
				Message: err.Error(),
				Line:    0,
				Column:  0,
			})
		}
		return fmt.Errorf("semantic analysis failed: %d errors", len(errs))
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
		if !referenced[str.Identifier] {
			c.AddWarning("semantic",
				fmt.Sprintf("String '%s' is defined but never used in condition", str.Identifier),
				rule.Pos.Line,
				rule.Pos.Column)
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
		if len(e.Name) > 0 && e.Name[0] == '$' {
			referenced[e.Name] = true
		}
	case *ast.OfExpression:
		// Check strings in "of" expressions
		if e.Strings != nil {
			c.collectReferencedStrings(e.Strings, referenced)
		}
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
	}
}

// checkEmptyRule warns about rules with empty conditions
func (c *Compiler) checkEmptyRule(rule *ast.Rule) {
	// This is a basic check - could be expanded
	if rule.Condition == nil {
		c.AddWarning("semantic",
			fmt.Sprintf("Rule '%s' has no condition", rule.Name),
			rule.Pos.Line,
			rule.Pos.Column)
	}
}

// checkProblematicPatterns warns about potentially problematic patterns
func (c *Compiler) checkProblematicPatterns(rule *ast.Rule) {
	// Check for rules with only trivial conditions
	if c.isTrivialCondition(rule.Condition) {
		c.AddWarning("semantic",
			fmt.Sprintf("Rule '%s' has a trivial condition that may always be true", rule.Name),
			rule.Pos.Line,
			rule.Pos.Column)
	}
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

	// Create code generator
	c.generator = NewRuleCompiler()

	// Generate code - CompileProgram returns []*CompiledRule
	compiledRules, err := c.generator.CompileProgram(program)
	if err != nil {
		c.stats.Errors = append(c.stats.Errors, CompilationError{
			Phase:   "codegen",
			Message: err.Error(),
			Line:    0,
			Column:  0,
		})
		return nil, err
	}

	c.stats.CodeGenTime = time.Since(start)

	// Wrap in CompiledProgram
	compiledProgram := NewCompiledProgram(compiledRules)

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

// AddWarning adds a compilation warning
func (c *Compiler) AddWarning(phase, message string, line, column int) {
	warning := CompilationWarning{
		Phase:   phase,
		Message: message,
		Line:    line,
		Column:  column,
	}
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
		Errors:   make([]CompilationError, 0),
		Warnings: make([]CompilationWarning, 0),
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

		// Read the included file content
		includedContent, err := os.ReadFile(includePath) // #nosec G304 - include file processing is intentional
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
		includedParser := parser.New(includedLexer)
		includedProgram, parseErr := includedParser.ParseRulesWithContext(ctx)
		if parseErr != nil {
			return fmt.Errorf("failed to parse include file %s: %w", include.File, parseErr)
		}

		// Check for parser errors in included file
		if len(includedParser.Errors()) > 0 {
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
	// For now, just log the imports - full implementation would load modules
	for _, importStmt := range program.Imports {
		// Check for cancellation before processing each import
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// In a full implementation, we would:
		// 1. Resolve module path
		// 2. Load module definition
		// 3. Register module functions and variables
		// 4. Make module available to the condition compiler

		// For now, just acknowledge the import
		fmt.Printf("Import module: %s\n", importStmt.Module)
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

// GetSupportedFeatures returns the features supported by this compiler
func (c *Compiler) GetSupportedFeatures() []string {
	return []string{
		"lexical_analysis",
		"parsing",
		"semantic_analysis",
		"code_generation",
		"bytecode_optimization",
		"pattern_matching",
		"string_modifiers",
		"rule_modifiers",
		"metadata",
		"conditions",
		"expressions",
		"functions",
	}
}

// EstimateCompilationTime estimates compilation time for given source size
func (c *Compiler) EstimateCompilationTime(sourceSize int) time.Duration {
	// Rough estimate based on typical compilation speeds
	// TODO: Real implementation would use historical data and profiling
	// Currently uses a simple linear approximation based on typical YARA rule complexity

	baseTime := 10 * time.Millisecond    // Base overhead
	perByteTime := 100 * time.Nanosecond // Time per source byte

	estimated := baseTime + time.Duration(sourceSize)*perByteTime

	return estimated
}

// GetMemoryRequirements estimates memory requirements for compilation
func (c *Compiler) GetMemoryRequirements(sourceSize int) int {
	// Rough estimate of memory usage during compilation
	// TODO: Real implementation would analyze rule complexity, string patterns, and AST size
	// Currently provides a conservative estimate suitable for most YARA rule sets

	baseMemory := 1024 * 1024 // 1MB base
	perByteMemory := 4        // 4 bytes per source byte

	estimated := baseMemory + sourceSize*perByteMemory

	return estimated
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
			reportSb626.WriteString(fmt.Sprintf("  [%s] %s at %d:%d\n", err.Phase, err.Message, err.Line, err.Column))
		}
		report += reportSb626.String()
		report += "\n"
	}

	if len(c.stats.Warnings) > 0 {
		report += fmt.Sprintf("Warnings (%d):\n", len(c.stats.Warnings))
		var reportSb634 strings.Builder
		for _, warn := range c.stats.Warnings {
			reportSb634.WriteString(fmt.Sprintf("  [%s] %s at %d:%d\n", warn.Phase, warn.Message, warn.Line, warn.Column))
		}
		report += reportSb634.String()
		report += "\n"
	}

	return report
}
