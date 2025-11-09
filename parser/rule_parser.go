package parser

import (
	"errors"
	"fmt"

	"github.com/cawalch/go-yara/ast"
	internal "github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// RuleParser handles parsing of rules in YARA rule files
type RuleParser struct {
	lexer      *internal.Lexer
	current    token.Token
	peek       token.Token
	errors     []error
	builder    *ast.Builder
	nextToken  func()
	addError   func(error)
	exprParser *ExpressionParser
	declParser *DeclarationParser
}

// NewRuleParser creates a new rule parser instance
func NewRuleParser(lexer *internal.Lexer, builder *ast.Builder, exprParser *ExpressionParser, declParser *DeclarationParser) *RuleParser {
	rp := &RuleParser{
		lexer:      lexer,
		errors:     make([]error, 0),
		builder:    builder,
		exprParser: exprParser,
		declParser: declParser,
	}

	// Set up token handler delegation
	exprParser.SetTokenHandler(rp.nextToken, rp.addError)
	declParser.SetTokenHandler(rp.nextToken, rp.addError)

	return rp
}

// SetTokenHandler sets the token handling functions for the parser
func (p *RuleParser) SetTokenHandler(nextToken func(), addError func(error)) {
	p.nextToken = nextToken
	p.addError = addError
	p.exprParser.SetTokenHandler(nextToken, addError)
	p.declParser.SetTokenHandler(nextToken, addError)
}

// SetCurrentTokens sets the current and peek tokens
func (p *RuleParser) SetCurrentTokens(current, peek token.Token) {
	p.current = current
	p.peek = peek
	p.exprParser.SetCurrentTokens(current, peek)
	p.declParser.SetCurrentTokens(current, peek)
}

// ParseRule parses a single YARA rule with the following structure:
//
//	rule <identifier>[: <tags>] {
//	    meta:
//	        <meta_statements>
//	    strings:
//	        <string_statements>
//	    condition:
//	        <expression>
//	}
//
// Modifiers (private, global) come before the RULE keyword
func (p *RuleParser) ParseRule() (*ast.Rule, error) {
	modifiers, err := p.parseRuleModifiers()
	if err != nil {
		return nil, err
	}

	if err := p.expectTokenWithMessage(token.RULE, "expected 'rule' keyword"); err != nil {
		return nil, err
	}

	ruleName, err := p.expectIdentifier()
	if err != nil {
		return nil, fmt.Errorf("expected rule name, %w", err)
	}

	tags := p.declParser.ParseTagList()

	if !p.expectToken(token.LBRACE) {
		return nil, errors.New("expected '{' after rule declaration")
	}

	meta, strings, condition, err := p.parseRuleBody()
	if err != nil {
		return nil, err
	}

	if !p.expectToken(token.RBRACE) {
		return nil, errors.New("expected '}' at end of rule")
	}

	return p.buildRule(modifiers, ruleName, tags, meta, strings, condition), nil
}

// parseRuleModifiers parses rule modifiers (private, global)
func (p *RuleParser) parseRuleModifiers() ([]ast.Modifier, error) {
	modifiers := make([]ast.Modifier, 0)
	for p.currentTokenIs(token.PRIVATE) || p.currentTokenIs(token.GLOBAL) {
		if p.currentTokenIs(token.PRIVATE) {
			modifiers = append(modifiers, ast.ModifierPrivate)
		} else {
			modifiers = append(modifiers, ast.ModifierGlobal)
		}
		p.nextToken()
	}
	return modifiers, nil
}

// parseRuleBody parses the meta, strings, and condition sections of a rule
func (p *RuleParser) parseRuleBody() ([]*ast.Meta, []*ast.String, ast.Expression, error) {
	meta, err := p.declParser.ParseMetaSection()
	if err != nil {
		return nil, nil, nil, err
	}

	strings, err := p.declParser.ParseStringsSection()
	if err != nil {
		return nil, nil, nil, err
	}

	condition, err := p.parseConditionSection()
	if err != nil {
		return nil, nil, nil, err
	}

	return meta, strings, condition, nil
}

// parseConditionSection parses the required condition section
func (p *RuleParser) parseConditionSection() (ast.Expression, error) {
	if !p.expectToken(token.CONDITION) {
		return nil, errors.New("expected condition section")
	}
	if !p.expectToken(token.COLON) {
		return nil, errors.New("expected ':' after condition")
	}

	return p.exprParser.ParseExpression()
}

// buildRule constructs and returns the final rule AST node
func (p *RuleParser) buildRule(modifiers []ast.Modifier, ruleName string, tags []string, meta []*ast.Meta, strings []*ast.String, condition ast.Expression) *ast.Rule {
	rule := p.builder.Rule(p.current.Pos, ruleName)
	rule.Modifiers = modifiers
	rule.Tags = tags
	rule.Meta = meta
	rule.Strings = strings
	rule.Condition = condition
	return rule
}

// expectIdentifier expects and returns an identifier token
func (p *RuleParser) expectIdentifier() (string, error) {
	if !p.currentTokenIs(token.IDENTIFIER) {
		return "", fmt.Errorf("expected identifier, got %s at %v", p.current.Type, p.current.Pos)
	}

	value := p.current.Literal
	p.nextToken()
	return value, nil
}

// expectTokenWithMessage checks for expected token and advances if matched, returns error message
func (p *RuleParser) expectTokenWithMessage(tokenType token.TokenType, message string) error {
	if !p.expectToken(tokenType) {
		return fmt.Errorf("%s", message)
	}
	return nil
}

// Helper methods
func (p *RuleParser) currentTokenIs(t token.TokenType) bool {
	return p.current.Type == t
}


func (p *RuleParser) expectToken(t token.TokenType) bool {
	if p.currentTokenIs(t) {
		p.nextToken()
		return true
	}
	p.errors = append(
		p.errors,
		fmt.Errorf("expected %s, got %s at %v", t, p.current.Type, p.current.Pos),
	)
	return false
}
