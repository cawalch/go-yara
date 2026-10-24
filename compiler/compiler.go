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
//	program, err := c.CompileSourceWithContext(
//		context.Background(),
//		"rule test { condition: true }",
//	)
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
//
// Experimental SIMD Vectorization:
//
// When built with Go 1.27+ and the GOEXPERIMENT=simd compile flag, the package enables
// hardware-vectorized single-byte ASCII case-folding (nocase), byte range matching,
// and Aho-Corasick automaton root-miss skipping across amd64 (AVX-512, AVX2, SSE) and
// arm64 (NEON). Vector widths can be controlled at runtime with the GODEBUG=simd flag.
package compiler

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/semantic"
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
	generator *ruleCompiler       // Bytecode generation

	// Configuration
	options CompilationOptions // Compilation settings and limits

	// File resolution
	baseDir string // Base directory for resolving relative includes

	// Statistics
	stats CompilationStats // Timing and resource usage metrics
}

// NewCompiler creates a new YARA compiler with default options.
//
// The default compiler enables warnings with reasonable security limits.
//
// Example:
//
//	c := compiler.NewCompiler()
//	program, err := c.CompileSourceWithContext(
//		context.Background(),
//		"rule test { condition: true }",
//	)
//
// With options:
//
//	c := compiler.NewCompiler(
//		compiler.WithWarnings(true),
//		compiler.WithMaxInputSize(50*1024*1024), // 50MB
//	)
func NewCompiler(opts ...Option) *Compiler {
	options := CompilationOptions{
		EnableWarnings:     true,
		IgnoreInvalidRules: false,
		Modules:            defaultModules(),
		MaxInputSize:       100 * 1024 * 1024, // 100MB default
		MaxIncludeSize:     10 * 1024 * 1024,  // 10MB default
		MaxRecursionDepth:  1000,              // 1000 levels default
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
// Deprecated: Use [NewCompiler] with functional [Option] arguments instead.
//
// Old way:
//
//	c := compiler.NewCompilerWithOptions(compiler.CompilationOptions{...})
//
// New way:
//
//	c := compiler.NewCompiler(
//		compiler.WithWarnings(true),
//	)
func NewCompilerWithOptions(options CompilationOptions) *Compiler {
	return NewCompiler(func(opts *CompilationOptions) {
		*opts = options
		opts.Modules = cloneModules(options.Modules)
	})
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

	resolvedFilename, err := resolveFilePath(c.baseDir, filename)
	if err != nil {
		return nil, fmt.Errorf("resolving file %s: %w", filename, err)
	}

	// Bound file reads before allocating the source buffer. CompileSource also
	// retains its in-memory size check for callers that already have source.
	source, err := readFileWithLimit(resolvedFilename, c.options.MaxInputSize)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", filename, err)
	}

	// Store the base directory for resolving includes
	c.baseDir = filepath.Dir(resolvedFilename)

	return c.CompileSourceWithContext(ctx, string(source))
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
			c.recordParserDiagnostics(err)
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
		c.recordParserDiagnostics(nil)
		return nil, errors.New("parser errors found")
	}

	return program, nil
}

func (c *Compiler) recordParserDiagnostics(fallback error) {
	parserErrors := c.parser.Errors()
	if len(parserErrors) == 0 {
		message := "parser errors found"
		if fallback != nil {
			message = fallback.Error()
		}
		c.stats.Errors = append(c.stats.Errors, CompilationError{
			Phase:   "parsing",
			Message: message,
		})
		return
	}
	for _, parseErr := range parserErrors {
		line, column := 0, 0
		var lexicalErr *lexer.Error
		if errors.As(parseErr, &lexicalErr) {
			line = lexicalErr.Position.Line
			column = lexicalErr.Position.Column
		}
		c.stats.Errors = append(c.stats.Errors, CompilationError{
			Phase:   "parsing",
			Message: parseErr.Error(),
			Line:    line,
			Column:  column,
		})
	}
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
			var semanticErr *semantic.Error
			if !errors.As(err, &semanticErr) || semanticErr.Rule == "" {
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
				Code:    semanticErr.Code,
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
	for name, module := range c.options.Modules {
		if err := validateModuleSchema(module.Schema); err != nil {
			return fmt.Errorf("module %s: %w", name, err)
		}
	}
	c.analyzer = semantic.NewValidatorWithModuleSchemas(semanticModuleFunctions(c.options.Modules), semanticModuleSchemas(c.options.Modules))

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
			line, col := 0, 0
			code := ""
			var semErr *semantic.Error
			if errors.As(err, &semErr) {
				line = semErr.Position.Line
				col = semErr.Position.Column
				code = semErr.Code
			}
			c.stats.Errors = append(c.stats.Errors, CompilationError{
				Code:    code,
				Phase:   "semantic",
				Message: err.Error(),
				Line:    line,
				Column:  col,
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
		generator, moduleErr := newRuleCompilerWithModules(c.options.Modules)
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

	compiledProgram := newCompiledProgram(compiledRules)
	if err := compiledProgram.preparationErr; err != nil {
		return nil, err
	}
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
	c.stats.TotalInstructions = compiledProgram.totalInstructionCount()
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
	return cloneCompilationStats(c.stats)
}

// GetErrors returns all compilation errors
func (c *Compiler) GetErrors() []CompilationError {
	return slices.Clone(c.stats.Errors)
}

// GetWarnings returns all compilation warnings
func (c *Compiler) GetWarnings() []CompilationWarning {
	return slices.Clone(c.stats.Warnings)
}

// GetIgnoredRules returns rules omitted by resilient compilation.
func (c *Compiler) GetIgnoredRules() []IgnoredRule {
	return slices.Clone(c.stats.IgnoredRules)
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

// GetOptions returns the current compilation options
func (c *Compiler) GetOptions() CompilationOptions {
	options := c.options
	options.Modules = cloneModules(c.options.Modules)
	return options
}

func cloneCompilationStats(stats CompilationStats) CompilationStats {
	stats.Errors = slices.Clone(stats.Errors)
	stats.Warnings = slices.Clone(stats.Warnings)
	stats.IgnoredRules = slices.Clone(stats.IgnoredRules)
	return stats
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
