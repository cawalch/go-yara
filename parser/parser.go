package parser

import (
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

// Parser represents a YARA rule parser coordinator that delegates to specialized parsers
type Parser struct {
	lexer   *lexer.Lexer
	current token.Token
	peek    token.Token
	errors  []error
	builder *ast.Builder

	// Specialized parsers
	exprParser  *ExpressionParser
	quantParser *QuantifierParser
	declParser  *DeclarationParser
	ruleParser  *RuleParser
}

// New creates a new parser instance with specialized sub-parsers
func New(l *lexer.Lexer) *Parser {
	p := &Parser{
		lexer:   l,
		errors:  make([]error, 0),
		builder: ast.NewBuilder(),
	}

	// Initialize specialized parsers
	p.exprParser = NewExpressionParser(NewLexerAdapter(l), p.builder)
	p.quantParser = NewQuantifierParser(l, p.builder, p.exprParser)
	p.declParser = NewDeclarationParser(l, p.builder)
	p.ruleParser = NewRuleParser(l, p.builder, p.exprParser, p.declParser)

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

// ParseRules parses a complete YARA rules file
func (p *Parser) ParseRules() (*ast.Program, error) {
	program := p.builder.Program(make([]*ast.Rule, 0))

	for !p.currentTokenIs(token.EOF) {
		if err := p.parseProgramElement(program); err != nil {
			p.addError(err)
		}
	}

	if len(p.errors) > 0 {
		return nil, fmt.Errorf("parsing failed with %d errors", len(p.errors))
	}

	return program, nil
}

func (p *Parser) parseProgramElement(program *ast.Program) error {
	// Update current tokens for all specialized parsers
	p.updateParserTokens()

	switch {
	case p.currentTokenIs(token.GLOBAL):
		return p.parseGlobalDeclaration(program)
	case p.currentTokenIs(token.EXTERNAL):
		return p.parseExternalDeclaration(program)
	case p.currentTokenIs(token.IMPORT):
		return p.parseImportDeclaration(program)
	case p.currentTokenIs(token.INCLUDE):
		return p.parseIncludeDeclaration(program)
	case p.currentTokenIs(token.PRIVATE) || p.currentTokenIs(token.RULE):
		// Direct delegate to rule parser - it handles both modifiers and rule parsing
		p.updateParserTokens()
		rule, err := p.ruleParser.ParseRule()
		if err == nil {
			program.Rules = append(program.Rules, rule)
		}
		return err
	default:
		return fmt.Errorf("unexpected token %s at %v", p.current.Type, p.current.Pos)
	}
}

func (p *Parser) parseGlobalDeclaration(program *ast.Program) error {
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

func (p *Parser) parseExternalDeclaration(program *ast.Program) error {
	p.nextToken() // consume EXTERNAL token
	p.updateParserTokens()
	externalVar, err := p.declParser.ParseExternalVariable()
	if err == nil {
		program.ExternalVariables = append(program.ExternalVariables, externalVar)
	}
	return err
}

func (p *Parser) parseImportDeclaration(program *ast.Program) error {
	p.nextToken() // consume IMPORT token
	p.updateParserTokens()
	importStmt, err := p.declParser.ParseImport()
	if err == nil {
		program.Imports = append(program.Imports, importStmt)
	}
	return err
}

func (p *Parser) parseIncludeDeclaration(program *ast.Program) error {
	p.nextToken() // consume INCLUDE token
	p.updateParserTokens()
	includeStmt, err := p.declParser.ParseInclude()
	if err == nil {
		program.Includes = append(program.Includes, includeStmt)
	}
	return err
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
		p.errors = append(p.errors, err)
		p.synchronize()
	}
}

// synchronize recovers from parsing errors by skipping to next rule, import, or global variable
func (p *Parser) synchronize() {
	p.nextToken()

	for !p.currentTokenIs(token.EOF) {
		if p.currentTokenIs(token.RULE) || p.currentTokenIs(token.IMPORT) ||
			p.currentTokenIs(token.GLOBAL) ||
			p.currentTokenIs(token.INCLUDE) {
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
