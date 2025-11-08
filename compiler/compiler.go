package compiler

import (
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
)

// Compiler represents the main YARA compiler
type Compiler struct {
	// Compilation phases
	parser    *parser.Parser
	analyzer  *semantic.Validator
	generator *RuleCompiler

	// Configuration
	options CompilationOptions

	// File resolution
	baseDir string // Base directory for resolving relative includes

	// Statistics
	stats CompilationStats
}

// CompilationOptions configures the compilation process
type CompilationOptions struct {
	EnableOptimizations bool
	EnableDebugInfo     bool
	EnableWarnings      bool
	TargetVersion       string
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

// NewCompiler creates a new YARA compiler with default options
func NewCompiler() *Compiler {
	return &Compiler{
		options: CompilationOptions{
			EnableOptimizations: true,
			EnableDebugInfo:     false,
			EnableWarnings:      true,
			TargetVersion:       "1.0",
		},
		stats: CompilationStats{
			Errors:   make([]CompilationError, 0),
			Warnings: make([]CompilationWarning, 0),
		},
	}
}

// NewCompilerWithOptions creates a new YARA compiler with custom options
func NewCompilerWithOptions(options CompilationOptions) *Compiler {
	compiler := NewCompiler()
	compiler.options = options
	return compiler
}

// CompileSource compiles YARA source code to bytecode
func (c *Compiler) CompileSource(source string) (*CompiledProgram, error) {
	c.stats = CompilationStats{
		StartTime: time.Now(),
		Errors:    make([]CompilationError, 0),
		Warnings:  make([]CompilationWarning, 0),
	}

	// Phase 1: Parsing (parser creates its own lexer, no need for separate lexical analysis)
	program, err := c.compileParse(source)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", err)
	}

	// Phase 2: Process imports
	if len(program.Imports) > 0 {
		c.processImports(program)
	}

	// Phase 3: Semantic Analysis
	if semErr := c.compileSemantic(program); semErr != nil {
		return nil, fmt.Errorf("semantic analysis failed: %w", semErr)
	}

	// Phase 4: Code Generation
	compiledProgram, codeGenErr := c.compileCodeGen(program)
	if codeGenErr != nil {
		return nil, fmt.Errorf("code generation failed: %w", codeGenErr)
	}

	c.stats.EndTime = time.Now()
	c.stats.TotalTime = c.stats.EndTime.Sub(c.stats.StartTime)

	return compiledProgram, nil
}

// CompileFile compiles a YARA file to bytecode
func (c *Compiler) CompileFile(filename string) (*CompiledProgram, error) {
	// Read file content
	source, err := c.readFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", filename, err)
	}

	// Store the base directory for resolving includes
	c.baseDir = filepath.Dir(filename)

	return c.CompileSource(source)
}

// compileParse performs parsing
func (c *Compiler) compileParse(source string) (*ast.Program, error) {
	start := time.Now()

	// Create a fresh lexer for the parser
	// (the previous lexer was consumed during tokenization)
	freshLexer := lexer.New(source)

	// Create parser with fresh lexer
	c.parser = parser.New(freshLexer)

	// Parse
	program, err := c.parser.ParseRules()
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
		includeErr := c.processIncludes(program)
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

// compileSemantic performs semantic analysis
func (c *Compiler) compileSemantic(program *ast.Program) error {
	start := time.Now()

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
		// Print individual errors for debugging
		for _, err := range errs {
			fmt.Printf("Semantic error: %s\n", err.Error())
		}
		return fmt.Errorf("semantic analysis failed: %d errors", len(errs))
	}

	c.stats.SemanticTime = time.Since(start)

	// Collect warnings if enabled
	if c.options.EnableWarnings {
		// TODO: Add semantic warnings collection when implemented
		// For now, this is a placeholder for future warning handling
	}

	return nil
}

// compileCodeGen performs code generation
func (c *Compiler) compileCodeGen(program *ast.Program) (*CompiledProgram, error) {
	start := time.Now()

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

	// Update statistics
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

// readFile reads a file (placeholder implementation)
func (c *Compiler) processIncludes(program *ast.Program) error {
	return c.processIncludesWithBaseDir(program, c.baseDir)
}

// processIncludesWithBaseDir processes includes with a specific base directory
func (c *Compiler) processIncludesWithBaseDir(program *ast.Program, baseDir string) error {
	// Process each include statement
	for _, include := range program.Includes {
		// Resolve the include path relative to the current baseDir
		includePath := include.File
		if !filepath.IsAbs(includePath) {
			includePath = filepath.Join(baseDir, include.File)
		}

		// Read the included file content
		includedContent, err := os.ReadFile(includePath)
		if err != nil {
			return fmt.Errorf("failed to read include file %s: %w", include.File, err)
		}

		// Parse the included content
		includedLexer := lexer.New(string(includedContent))
		includedParser := parser.New(includedLexer)
		includedProgram, parseErr := includedParser.ParseRules()
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
			includedFileDir := filepath.Dir(includePath)
			processErr := c.processIncludesWithBaseDir(includedProgram, includedFileDir)
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

// processImports processes import statements
func (c *Compiler) processImports(program *ast.Program) {
	// For now, just log the imports - full implementation would load modules
	for _, importStmt := range program.Imports {
		// In a full implementation, we would:
		// 1. Resolve module path
		// 2. Load module definition
		// 3. Register module functions and variables
		// 4. Make module available to the condition compiler

		// For now, just acknowledge the import
		fmt.Printf("Import module: %s\n", importStmt.Module)
	}
}

func (c *Compiler) readFile(filename string) (string, error) {
	// Read file content
	// Check if filename is absolute or relative
	if filepath.IsAbs(filename) {
		// Absolute path - read directly
		content, err := os.ReadFile(filename)
		if err != nil {
			return "", fmt.Errorf("reading file %s: %w", filename, err)
		}
		return string(content), nil
	}
	// Relative path - resolve relative to base directory if available
	var fullPath string
	if c.baseDir != "" {
		fullPath = filepath.Join(c.baseDir, filename)
	} else {
		fullPath = filename
	}

	content, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("reading file %s: %w", fullPath, err)
	}
	return string(content), nil
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
	// This is a placeholder - real implementation would use historical data

	baseTime := 10 * time.Millisecond    // Base overhead
	perByteTime := 100 * time.Nanosecond // Time per source byte

	estimated := baseTime + time.Duration(sourceSize)*perByteTime

	return estimated
}

// GetMemoryRequirements estimates memory requirements for compilation
func (c *Compiler) GetMemoryRequirements(sourceSize int) int {
	// Rough estimate of memory usage during compilation
	// This is a placeholder - real implementation would be more accurate

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
	program, err := c.compileParse(source)
	if err != nil {
		return nil, err
	}

	// Semantic analysis
	if progressCallback != nil {
		progressCallback("semantic", 60)
	}
	if semErr := c.compileSemantic(program); semErr != nil {
		return nil, semErr
	}

	// Code generation
	if progressCallback != nil {
		progressCallback("codegen", 90)
	}
	compiledProgram, codeGenErr := c.compileCodeGen(program)
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
