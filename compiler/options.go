package compiler

import "time"

// CompilationOptions configures the compilation process.
//
// These options control compiler behavior, modules, and security limits.
// Prefer NewCompiler with functional options for custom settings.
type CompilationOptions struct {
	EnableWarnings     bool // Collect and report compilation warnings (default: true)
	IgnoreInvalidRules bool // Compile valid rules while reporting invalid rules (default: false)
	Modules            map[string]Module

	// Security limits to prevent resource exhaustion attacks
	MaxInputSize      int64 // Maximum input file size in bytes (0 = no limit, default: 100MB)
	MaxIncludeSize    int64 // Maximum include file size in bytes (0 = no limit, default: 10MB)
	MaxRecursionDepth int   // Maximum nesting depth for rules (0 = no limit, default: 1000)
}

// CompilationStats tracks compilation metrics
type CompilationStats struct {
	StartTime         time.Time
	EndTime           time.Time
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
	Code    string
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

// Compiler warning category identifiers.
const (
	// WarningUnusedString indicates a string declared in the strings section is never referenced in the condition.
	WarningUnusedString = "unused-string"
	// WarningMissingCondition indicates a rule is missing a condition section.
	WarningMissingCondition = "missing-condition"
	// WarningTrivialCondition indicates a rule condition always evaluates to true (e.g. "true").
	WarningTrivialCondition = "trivial-condition"
	// WarningDuplicatePattern indicates identical string patterns defined in the same rule.
	WarningDuplicatePattern = "duplicate-pattern"
	// WarningSlowPattern indicates a pattern known to trigger high regex backtracking or poor selectivity.
	WarningSlowPattern = "slow-pattern"
	// WarningWildcardAbsorption indicates a string identifier matches a wildcard prefix in a quantifier expression, causing condition absorption or unintentional set expansion.
	WarningWildcardAbsorption = "wildcard-absorption"
)

// IgnoredRule describes a rule omitted from an otherwise successful
// compilation when WithIgnoreInvalidRules is enabled.
type IgnoredRule struct {
	Rule       string
	Phase      string
	Message    string
	Code       string
	Dependency string
	Global     bool
	Line       int
	Column     int
}

// Option represents a functional option for configuring a Compiler
type Option func(*CompilationOptions)

// ===== Functional Options =====

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
		opts.Modules[module.Name] = cloneModule(module)
	}
}

// WithMaxInputSize sets the maximum input file size limit (0 = no limit)
func WithMaxInputSize(size int64) Option {
	return func(opts *CompilationOptions) {
		opts.MaxInputSize = size
	}
}

// WithMaxIncludeSize sets the maximum included file size limit (0 = no limit).
func WithMaxIncludeSize(size int64) Option {
	return func(opts *CompilationOptions) {
		opts.MaxIncludeSize = size
	}
}

// WithMaxRecursionDepth sets the parser recursion limit (0 = no limit).
func WithMaxRecursionDepth(depth int) Option {
	return func(opts *CompilationOptions) {
		opts.MaxRecursionDepth = depth
	}
}
