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

// ruleFields groups the components of a parsed rule before assembly.
type ruleFields struct {
	modifiers []ast.Modifier
	ruleName  string
	tags      []string
	meta      []*ast.Meta
	strings   []*ast.String
	condition ast.Expression
}

// NewRuleParser creates a new rule parser instance
//
//nolint:revive // argument-limit: constructor
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

	return p.buildRule(ruleFields{modifiers, ruleName, tags, meta, strings, condition}), nil
}

// ParseRulePartial parses a rule with error recovery, returning partial results
func (p *RuleParser) ParseRulePartial() (*ast.Rule, []error) {
	var errors []error

	modifiers, err := p.parseRuleModifiers()
	if err != nil {
		errors = append(errors, fmt.Errorf("rule modifiers error: %w", err))
		// Try to continue with empty modifiers
		modifiers = []ast.Modifier{}
	}

	// Try to parse rule name
	if p.currentTokenIs(token.RULE) {
		p.nextToken() // consume RULE token
	}

	ruleName := "invalid_rule"
	if p.currentTokenIs(token.IDENTIFIER) {
		ruleName = p.current.Literal
		p.nextToken() // consume identifier
	} else {
		errors = append(errors, fmt.Errorf("expected rule name at %v", p.current.Pos))
		// Try to synchronize
		p.synchronizeToSection()
	}

	tags := p.declParser.ParseTagList()

	if !p.expectToken(token.LBRACE) {
		errors = append(errors, fmt.Errorf("expected '{' after rule declaration at %v", p.current.Pos))
		// Try to find next opening brace
		for !p.currentTokenIs(token.EOF) && !p.currentTokenIs(token.LBRACE) {
			if p.currentTokenIs(token.RULE) || p.currentTokenIs(token.IMPORT) ||
				p.currentTokenIs(token.GLOBAL) || p.currentTokenIs(token.INCLUDE) {
				// Give up on this rule and let upper level handle synchronization
				return p.buildRule(ruleFields{modifiers, ruleName, tags, nil, nil, p.createMinimalCondition()}), errors
			}
			p.nextToken()
		}
		if p.currentTokenIs(token.LBRACE) {
			p.nextToken() // consume LBRACE
		}
	}

	// Parse rule body with error recovery
	meta, strings, condition, sectionErrors := p.parseRuleBodyPartial()
	errors = append(errors, sectionErrors...)

	// Try to consume closing brace
	if !p.expectToken(token.RBRACE) {
		errors = append(errors, fmt.Errorf("expected '}' at end of rule at %v", p.current.Pos))
		// Try to find the closing brace or next rule
		for !p.currentTokenIs(token.EOF) {
			if p.currentTokenIs(token.RBRACE) {
				p.nextToken() // consume RBRACE
				break
			}
			if p.currentTokenIs(token.RULE) || p.currentTokenIs(token.IMPORT) ||
				p.currentTokenIs(token.GLOBAL) || p.currentTokenIs(token.INCLUDE) {
				// Next rule starting, let upper level handle synchronization
				break
			}
			p.nextToken()
		}
	}

	return p.buildRule(ruleFields{modifiers, ruleName, tags, meta, strings, condition}), errors
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

// parseRuleBodyPartial parses rule sections with error recovery
func (p *RuleParser) parseRuleBodyPartial() ([]*ast.Meta, []*ast.String, ast.Expression, []error) {
	var errors []error
	var meta []*ast.Meta
	var strings []*ast.String
	var condition ast.Expression

	// Try to parse meta section
	sectionMeta, err := p.declParser.ParseMetaSection()
	if err != nil {
		errors = append(errors, fmt.Errorf("meta section error: %w", err))
		// Try to synchronize to next section
		p.synchronizeToSection()
	} else {
		meta = sectionMeta
	}

	// Try to parse strings section
	sectionStrings, err := p.declParser.ParseStringsSection()
	if err != nil {
		errors = append(errors, fmt.Errorf("strings section error: %w", err))
		// Try to synchronize to next section
		p.synchronizeToSection()
	} else {
		strings = sectionStrings
	}

	// Try to parse condition section (required)
	sectionCondition, err := p.parseConditionSection()
	if err != nil {
		errors = append(errors, fmt.Errorf("condition section error: %w", err))
		// Try to create a minimal condition for recovery
		condition = p.createMinimalCondition()
	} else {
		condition = sectionCondition
	}

	return meta, strings, condition, errors
}

// synchronizeToSection synchronizes to the next rule section
func (p *RuleParser) synchronizeToSection() {
	for !p.currentTokenIs(token.EOF) && !p.currentTokenIs(token.RBRACE) {
		if p.currentTokenIs(token.META) || p.currentTokenIs(token.STRINGS) || p.currentTokenIs(token.CONDITION) {
			return
		}
		p.nextToken()
	}
}

// createMinimalCondition creates a minimal fallback condition for error recovery
func (p *RuleParser) createMinimalCondition() ast.Expression {
	// Create a simple "false" literal as fallback condition
	return p.builder.Literal(p.current.Pos, token.FALSE, false)
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
func (p *RuleParser) buildRule(fields ruleFields) *ast.Rule {
	rule := p.builder.Rule(p.current.Pos, fields.ruleName)
	rule.Modifiers = fields.modifiers
	rule.Tags = fields.tags
	rule.Meta = fields.meta
	rule.Strings = fields.strings
	rule.Condition = fields.condition
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
func (p *RuleParser) expectTokenWithMessage(tokenType token.Type, message string) error {
	if !p.expectToken(tokenType) {
		return fmt.Errorf("%s", message)
	}
	return nil
}

// Helper methods
func (p *RuleParser) currentTokenIs(t token.Type) bool {
	return p.current.Type == t
}

func (p *RuleParser) expectToken(t token.Type) bool {
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
