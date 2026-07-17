package parser

import (
	"context"
	"errors"
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// ErrNotQuantifier is a sentinel error indicating that a token sequence is not a quantifier
var ErrNotQuantifier = errors.New("not a quantifier")

// ErrNotLiteral is a sentinel error indicating that a token is not a literal
var ErrNotLiteral = errors.New("not a literal")

// PartialParseError contains both the partially parsed program and any parsing errors
type PartialParseError struct {
	Program *ast.Program
	Errors  []error
}

// InvalidRule describes a rule that could not be parsed completely while
// error recovery was enabled. Rule contains the best-effort AST, which lets
// callers inspect its name and dependencies without treating it as valid.
type InvalidRule struct {
	Rule   *ast.Rule
	Errors []error
}

// Error implements the error interface
func (ppe *PartialParseError) Error() string {
	if len(ppe.Errors) == 0 {
		return "no errors"
	}
	if len(ppe.Errors) == 1 {
		return fmt.Sprintf("parsing completed with 1 error: %v", ppe.Errors[0])
	}
	return fmt.Sprintf(
		"parsing completed with %d errors, first error: %v",
		len(ppe.Errors),
		ppe.Errors[0],
	)
}

// Unwrap returns the underlying errors
func (ppe *PartialParseError) Unwrap() []error {
	return ppe.Errors
}

// Parser represents a YARA rule parser coordinator that delegates to specialized parsers
type Parser struct {
	lexer             *lexer.Lexer
	current           token.Token
	peek              token.Token
	errors            []error
	programErrors     []error
	invalidRules      []InvalidRule
	builder           *ast.Builder
	errorRecovery     bool // Enable error recovery mode
	skipInvalidRules  bool // Keep invalid partial rules out of the returned program
	recoveringRule    bool // Record nested parser errors without program-level synchronization
	maxRecursionDepth int  // Maximum allowed recursion depth

	// Specialized parsers
	exprParser  *ExpressionParser
	quantParser *QuantifierParser
	declParser  *DeclarationParser
	ruleParser  *RuleParser
}

// New creates a new parser instance with specialized sub-parsers
func New(l *lexer.Lexer) *Parser {
	return NewWithOptions(
		l,
		Options{MaxRecursionDepth: 0},
	) // 0 means no limit for backward compatibility
}

// Options configures parser behavior
type Options struct {
	MaxRecursionDepth int
}

// NewWithOptions creates a new parser instance with custom options
func NewWithOptions(l *lexer.Lexer, options Options) *Parser {
	p := &Parser{
		lexer:             l,
		errors:            make([]error, 0),
		programErrors:     make([]error, 0),
		invalidRules:      make([]InvalidRule, 0),
		builder:           ast.NewBuilder(),
		errorRecovery:     false, // Default to strict parsing for backward compatibility
		maxRecursionDepth: options.MaxRecursionDepth,
	}

	// Initialize specialized parsers
	p.exprParser = NewExpressionParser(l, p.builder)
	p.quantParser = NewQuantifierParser(l, p.builder, p.exprParser)
	p.declParser = NewDeclarationParser(l, p.builder)
	p.ruleParser = NewRuleParser(l, p.builder, p.exprParser, p.declParser)

	// Set recursion depth limit in expression parser
	p.exprParser.SetMaxRecursionDepth(p.maxRecursionDepth)

	// Set up token handlers
	p.exprParser.SetTokenHandler(p.nextToken, p.addError)
	p.quantParser.SetTokenHandler(p.nextToken, p.addError)
	p.declParser.SetTokenHandler(p.nextToken, p.addError)
	p.ruleParser.SetTokenHandler(p.nextToken, p.addError)

	// Connect parsers
	p.exprParser.SetQuantifierParser(p.quantParser)

	// Initialize current and peek tokens
	p.current = token.Token{Type: token.EOF} // Initialize to EOF
	p.peek = token.Token{Type: token.EOF}    // Initialize to EOF
	p.nextToken()                            // This sets current=EOF, peek=first token
	p.nextToken()                            // This sets current=first token, peek=second token
	return p
}

// ParseRules parses a complete YARA rules file with error recovery (if enabled).
//
// Deprecated: Use ParseRulesWithContext for better cancellation and timeout support.
func (p *Parser) ParseRules() (*ast.Program, error) {
	return p.ParseRulesWithContext(context.Background())
}

// ParseRulesWithContext parses a complete YARA rules file with context support
func (p *Parser) ParseRulesWithContext(ctx context.Context) (*ast.Program, error) {
	program := p.builder.Program(make([]*ast.Rule, 0))

	for !p.currentTokenIs(token.EOF) {
		// Check for cancellation before parsing each element
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if err := p.parseProgramElement(ctx, program); err != nil {
			p.addProgramError(err)
		}
	}

	p.collectLexerErrors()

	if len(p.errors) > 0 {
		if p.errorRecovery {
			// Return partial program with errors instead of failing completely
			return program, &PartialParseError{
				Program: program,
				Errors:  p.errors,
			}
		}
		// Traditional strict parsing - fail completely
		return nil, fmt.Errorf("parsing failed with %d errors", len(p.errors))
	}

	return program, nil
}

func (p *Parser) collectLexerErrors() {
	for _, err := range p.lexer.Errors() {
		lexErr := err
		p.recordProgramError(&lexErr)
	}
}

// SetErrorRecovery enables or disables error recovery mode
func (p *Parser) SetErrorRecovery(enabled bool) {
	p.errorRecovery = enabled
}

// SetSkipInvalidRules controls whether partial rules with parse errors are
// omitted from the returned program. It only has an effect in error recovery
// mode. InvalidRules still reports every omitted rule and its errors.
func (p *Parser) SetSkipInvalidRules(enabled bool) {
	p.skipInvalidRules = enabled
}

// InvalidRules returns rules omitted by SetSkipInvalidRules.
func (p *Parser) InvalidRules() []InvalidRule {
	result := make([]InvalidRule, len(p.invalidRules))
	for i, invalid := range p.invalidRules {
		result[i] = InvalidRule{
			Rule:   invalid.Rule,
			Errors: append([]error(nil), invalid.Errors...),
		}
	}
	return result
}

// ProgramErrors returns errors that are not attributable to an individual
// rule, such as invalid top-level declarations or lexer failures.
func (p *Parser) ProgramErrors() []error {
	return append([]error(nil), p.programErrors...)
}

// ParseRulesStrict parses a complete YARA rules file without error recovery (original behavior)
func (p *Parser) ParseRulesStrict() (*ast.Program, error) {
	// Save current recovery setting
	oldRecovery := p.errorRecovery
	// Disable recovery for strict parsing
	p.errorRecovery = false
	defer func() {
		p.errorRecovery = oldRecovery
	}()

	program := p.builder.Program(make([]*ast.Rule, 0))

	for !p.currentTokenIs(token.EOF) {
		if err := p.parseProgramElement(context.Background(), program); err != nil {
			p.addProgramError(err)
		}
	}

	if len(p.errors) > 0 {
		return nil, fmt.Errorf("strict parsing failed with %d errors", len(p.errors))
	}

	return program, nil
}

func (p *Parser) parseProgramElement(ctx context.Context, program *ast.Program) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	// Update current tokens for all specialized parsers
	p.updateParserTokens()

	switch {
	case p.currentTokenIs(token.GLOBAL):
		return p.parseGlobalDeclaration(ctx, program)
	case p.currentTokenIs(token.EXTERNAL):
		return p.parseExternalDeclaration(ctx, program)
	case p.currentTokenIs(token.IMPORT):
		return p.parseImportDeclaration(ctx, program)
	case p.currentTokenIs(token.INCLUDE):
		return p.parseIncludeDeclaration(ctx, program)
	case p.currentTokenIs(token.PRIVATE) || p.currentTokenIs(token.RULE):
		// Delegate to rule parser with or without error recovery
		p.updateParserTokens()
		if p.errorRecovery {
			beforeErrors := len(p.errors)
			p.recoveringRule = true
			rule, ruleErrors := p.ruleParser.ParseRulePartial()
			p.recoveringRule = false

			allRuleErrors := append([]error(nil), p.errors[beforeErrors:]...)
			for _, ruleErr := range ruleErrors {
				if !containsError(allRuleErrors, ruleErr) {
					p.recordError(ruleErr)
					allRuleErrors = append(allRuleErrors, ruleErr)
				}
			}

			if p.skipInvalidRules && len(allRuleErrors) > 0 {
				p.invalidRules = append(p.invalidRules, InvalidRule{
					Rule:   rule,
					Errors: allRuleErrors,
				})
			} else {
				program.Rules = append(program.Rules, rule)
			}
			return nil // Don't return error since we want to continue parsing
		}
		rule, err := p.ruleParser.ParseRule()
		if err == nil {
			program.Rules = append(program.Rules, rule)
		}
		return err
	default:
		return fmt.Errorf("unexpected token %s at %v", p.current.Type, p.current.Pos)
	}
}

func (p *Parser) parseGlobalDeclaration(ctx context.Context, program *ast.Program) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	p.updateParserTokens()

	// Check if this is a global variable declaration or a global rule modifier
	if p.peekTokenIs(token.RULE) || p.peekTokenIs(token.PRIVATE) {
		// This is a global rule modifier - delegate to rule parser to handle GLOBAL modifier
		rule, err := p.ruleParser.ParseRule()
		if err == nil {
			program.Rules = append(program.Rules, rule)
		}
		return err
	}
	// This is a global variable declaration - consume GLOBAL and parse variable
	p.nextToken() // consume GLOBAL token
	p.updateParserTokens()
	globalVar, err := p.declParser.ParseGlobalVariable()
	if err == nil {
		program.GlobalVariables = append(program.GlobalVariables, globalVar)
	}
	return err
}

func (p *Parser) parseIncludeDeclaration(ctx context.Context, program *ast.Program) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	p.nextToken() // consume INCLUDE token
	p.updateParserTokens()
	includeStmt, err := p.declParser.ParseInclude()
	if err == nil {
		program.Includes = append(program.Includes, includeStmt)
	}
	return err
}

func (p *Parser) parseExternalDeclaration(ctx context.Context, program *ast.Program) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	p.nextToken() // consume EXTERNAL token
	p.updateParserTokens()
	externalVar, err := p.declParser.ParseExternalVariable()
	if err == nil {
		program.ExternalVariables = append(program.ExternalVariables, externalVar)
	}
	return err
}

func (p *Parser) parseImportDeclaration(ctx context.Context, program *ast.Program) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	p.nextToken() // consume IMPORT token
	p.updateParserTokens()
	importStmt, err := p.declParser.ParseImport()
	if err == nil {
		program.Imports = append(program.Imports, importStmt)
	}
	return err
}

func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// Errors returns any parsing errors encountered
func (p *Parser) Errors() []error {
	return p.errors
}

// Token management methods
func (p *Parser) nextToken() {
	p.current = p.peek
	p.peek = p.lexer.NextToken()
	// Update all specialized parsers with new token positions
	p.updateParserTokens()
}

func (p *Parser) currentTokenIs(t token.Type) bool {
	return p.current.Type == t
}

func (p *Parser) peekTokenIs(t token.Type) bool {
	return p.peek.Type == t
}

func (p *Parser) addError(err error) {
	if err != nil {
		p.recordError(err)
		if p.recoveringRule {
			return
		}
		p.synchronize()
	}
}

func (p *Parser) addProgramError(err error) {
	if err != nil {
		p.recordProgramError(err)
		p.synchronize()
	}
}

func (p *Parser) recordError(err error) {
	if err != nil {
		p.errors = append(p.errors, err)
	}
}

func (p *Parser) recordProgramError(err error) {
	if err != nil {
		p.programErrors = append(p.programErrors, err)
		p.recordError(err)
	}
}

func containsError(errs []error, candidate error) bool {
	if candidate == nil {
		return true
	}
	for _, err := range errs {
		if err != nil && err.Error() == candidate.Error() {
			return true
		}
	}
	return false
}

// synchronize recovers from parsing errors by skipping to the next valid program element
func (p *Parser) synchronize() {
	p.nextToken()

	for !p.currentTokenIs(token.EOF) {
		// Synchronization points: tokens that can start a new program element
		if p.currentTokenIs(token.RULE) || p.currentTokenIs(token.IMPORT) ||
			p.currentTokenIs(token.GLOBAL) || p.currentTokenIs(token.INCLUDE) ||
			p.currentTokenIs(token.EXTERNAL) || p.currentTokenIs(token.PRIVATE) {
			return
		}
		p.nextToken()
	}
}

// updateParserTokens updates the current tokens for all specialized parsers
func (p *Parser) updateParserTokens() {
	p.exprParser.SetCurrentTokens(p.current, p.peek)
	p.quantParser.SetCurrentTokens(p.current, p.peek)
	p.declParser.SetCurrentTokens(p.current, p.peek)
	p.ruleParser.SetCurrentTokens(p.current, p.peek)
}
