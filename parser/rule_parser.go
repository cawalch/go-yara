package parser

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

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
	evidence  []*ast.EvidenceDeclaration
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

	meta, strings, evidence, condition, err := p.parseRuleBody()
	if err != nil {
		return nil, err
	}

	if !p.expectToken(token.RBRACE) {
		return nil, errors.New("expected '}' at end of rule")
	}

	return p.buildRule(ruleFields{modifiers, ruleName, tags, meta, strings, evidence, condition}), nil
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
				return p.buildRule(ruleFields{modifiers, ruleName, tags, nil, nil, nil, p.createMinimalCondition()}), errors
			}
			p.nextToken()
		}
		if p.currentTokenIs(token.LBRACE) {
			p.nextToken() // consume LBRACE
		}
	}

	// Parse rule body with error recovery
	meta, strings, evidence, condition, sectionErrors := p.parseRuleBodyPartial()
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

	return p.buildRule(ruleFields{modifiers, ruleName, tags, meta, strings, evidence, condition}), errors
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
func (p *RuleParser) parseRuleBody() ([]*ast.Meta, []*ast.String, []*ast.EvidenceDeclaration, ast.Expression, error) {
	meta, err := p.declParser.ParseMetaSection()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	strings, err := p.declParser.ParseStringsSection()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	evidence, err := p.parseEvidenceSection()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	condition, err := p.parseConditionSection()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return meta, strings, evidence, condition, nil
}

// parseRuleBodyPartial parses rule sections with error recovery
func (p *RuleParser) parseRuleBodyPartial() ([]*ast.Meta, []*ast.String, []*ast.EvidenceDeclaration, ast.Expression, []error) {
	var errors []error
	var meta []*ast.Meta
	var strings []*ast.String
	var evidence []*ast.EvidenceDeclaration
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

	sectionEvidence, err := p.parseEvidenceSection()
	if err != nil {
		errors = append(errors, fmt.Errorf("evidence section error: %w", err))
		p.synchronizeToSection()
	} else {
		evidence = sectionEvidence
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

	return meta, strings, evidence, condition, errors
}

// synchronizeToSection synchronizes to the next rule section
func (p *RuleParser) synchronizeToSection() {
	for !p.currentTokenIs(token.EOF) && !p.currentTokenIs(token.RBRACE) {
		if p.currentTokenIs(token.META) || p.currentTokenIs(token.STRINGS) ||
			p.currentTokenIs(token.EVIDENCE) || p.currentTokenIs(token.CONDITION) {
			return
		}
		p.nextToken()
	}
}

func (p *RuleParser) parseEvidenceSection() ([]*ast.EvidenceDeclaration, error) {
	if !p.currentTokenIs(token.EVIDENCE) {
		return []*ast.EvidenceDeclaration{}, nil
	}
	p.nextToken()
	if !p.expectToken(token.COLON) {
		return nil, errors.New("expected ':' after evidence")
	}

	declarations := make([]*ast.EvidenceDeclaration, 0, 1)
	for !p.currentTokenIs(token.CONDITION) && !p.currentTokenIs(token.RBRACE) && !p.currentTokenIs(token.EOF) {
		if !p.currentTokenIs(token.IDENTIFIER) {
			return nil, fmt.Errorf("expected evidence declaration name at %v", p.current.Pos)
		}
		pos := p.current.Pos
		name := p.current.Literal
		p.nextToken()
		if !p.expectToken(token.ASSIGN) || !p.expectToken(token.LPAREN) {
			return nil, fmt.Errorf("expected '= (' after evidence declaration %q", name)
		}
		fields := make([]string, 0, 3)
		for {
			if !p.currentTokenIs(token.IDENTIFIER) {
				return nil, fmt.Errorf("expected capture field in evidence declaration %q", name)
			}
			fields = append(fields, p.current.Literal)
			p.nextToken()
			if !p.currentTokenIs(token.COMMA) {
				break
			}
			p.nextToken()
		}
		if !p.expectToken(token.RPAREN) || !p.expectToken(token.WITHIN) {
			return nil, fmt.Errorf("expected ') within' in evidence declaration %q", name)
		}
		within, err := p.parseEvidenceDistance()
		if err != nil {
			return nil, fmt.Errorf("evidence declaration %q: %w", name, err)
		}
		if !p.expectToken(token.OF) {
			return nil, fmt.Errorf("expected 'of' in evidence declaration %q", name)
		}
		if !p.currentTokenIs(token.IDENTIFIER) {
			return nil, fmt.Errorf("expected anchor capture name in evidence declaration %q", name)
		}
		anchor := p.current.Literal
		p.nextToken()
		declarations = append(declarations, p.builder.EvidenceDeclaration(pos, name, fields, anchor, within))
	}
	return declarations, nil
}

func (p *RuleParser) parseEvidenceDistance() (int64, error) {
	literal := p.current.Literal
	typeOf := p.current.Type
	if typeOf != token.IntegerLit && typeOf != token.HexIntegerLit &&
		typeOf != token.OctalIntegerLit && typeOf != token.SizeLit {
		return 0, fmt.Errorf("expected non-negative integer or size after 'within'")
	}
	p.nextToken()
	if typeOf != token.SizeLit {
		value, err := strconv.ParseInt(literal, 0, 64)
		if err != nil || value < 0 {
			return 0, fmt.Errorf("invalid evidence distance %q", literal)
		}
		return value, nil
	}
	upper := strings.ToUpper(literal)
	units := map[string]int64{"KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30, "TB": 1 << 40}
	for suffix, multiplier := range units {
		if !strings.HasSuffix(upper, suffix) {
			continue
		}
		number := strings.TrimSuffix(upper, suffix)
		value, err := strconv.ParseInt(number, 0, 64)
		if err != nil || value < 0 || value > math.MaxInt64/multiplier {
			return 0, fmt.Errorf("invalid evidence distance %q", literal)
		}
		return value * multiplier, nil
	}
	return 0, fmt.Errorf("invalid evidence distance %q", literal)
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
	rule.Evidence = fields.evidence
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
