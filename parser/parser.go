// Package parser implements a recursive descent parser for YARA rules.
// It consumes tokens from the lexer and builds an Abstract Syntax Tree (AST).
package parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// Parser represents a YARA rule parser
type Parser struct {
	lexer     *lexer.Lexer
	current   token.Token
	peek      token.Token
	errors    []error
	builder   *ast.Builder
}

// New creates a new parser instance
func New(l *lexer.Lexer) *Parser {
	p := &Parser{
		lexer:   l,
		errors:  make([]error, 0),
		builder: ast.NewBuilder(),
	}
	// Initialize current and peek tokens
	p.nextToken()
	p.nextToken()
	return p
}

// ParseRules parses a complete YARA rules file
func (p *Parser) ParseRules() (*ast.Program, error) {
	program := p.builder.Program(make([]*ast.Rule, 0))

	for !p.currentTokenIs(token.EOF) {
		// Check for rule modifiers (private, global) or rule keyword
		if p.currentTokenIs(token.PRIVATE) || p.currentTokenIs(token.GLOBAL) || p.currentTokenIs(token.RULE) {
			rule, err := p.parseRule()
			if err != nil {
				p.errors = append(p.errors, err)
				p.synchronize()
				continue
			}
			program.Rules = append(program.Rules, rule)
		} else if p.currentTokenIs(token.IMPORT) {
			p.nextToken() // consume IMPORT keyword
			if err := p.parseImport(); err != nil {
				p.errors = append(p.errors, err)
				p.synchronize()
				continue
			}
		} else {
			p.errors = append(p.errors, fmt.Errorf("unexpected token %s at %v", p.current.Type, p.current.Pos))
			p.synchronize()
		}
	}

	if len(p.errors) > 0 {
		return nil, fmt.Errorf("parsing failed with %d errors", len(p.errors))
	}

	return program, nil
}

// Errors returns any parsing errors encountered
func (p *Parser) Errors() []error {
	return p.errors
}

// nextToken advances to the next token
func (p *Parser) nextToken() {
	p.current = p.peek
	p.peek = p.lexer.NextToken()
}

// currentTokenIs checks if current token matches the given type
func (p *Parser) currentTokenIs(t token.TokenType) bool {
	return p.current.Type == t
}

// peekTokenIs checks if peek token matches the given type
func (p *Parser) peekTokenIs(t token.TokenType) bool {
	return p.peek.Type == t
}

// expectToken checks for expected token and advances if matched
func (p *Parser) expectToken(t token.TokenType) bool {
	if p.currentTokenIs(t) {
		p.nextToken()
		return true
	}
	p.errors = append(p.errors, fmt.Errorf("expected %s, got %s at %v", t, p.current.Type, p.current.Pos))
	return false
}

// synchronize recovers from parsing errors by skipping to next rule or import
func (p *Parser) synchronize() {
	p.nextToken()

	for !p.currentTokenIs(token.EOF) {
		if p.currentTokenIs(token.RULE) || p.currentTokenIs(token.IMPORT) {
			return
		}
		p.nextToken()
	}
}

// parseRule parses a single YARA rule
// Modifiers (private, global) come before the RULE keyword
func (p *Parser) parseRule() (*ast.Rule, error) {
	// Parse modifiers (private, global) - they come before RULE keyword
	modifiers := make([]ast.Modifier, 0)
	for p.currentTokenIs(token.PRIVATE) || p.currentTokenIs(token.GLOBAL) {
		if p.currentTokenIs(token.PRIVATE) {
			modifiers = append(modifiers, ast.ModifierPrivate)
		} else {
			modifiers = append(modifiers, ast.ModifierGlobal)
		}
		p.nextToken()
	}

	// Expect RULE keyword
	if !p.expectToken(token.RULE) {
		return nil, fmt.Errorf("expected 'rule' keyword")
	}

	// Current token should be the rule name (IDENTIFIER)
	if !p.currentTokenIs(token.IDENTIFIER) {
		return nil, fmt.Errorf("expected rule name, got %s at %v", p.current.Type, p.current.Pos)
	}

	ruleName := p.current.Literal
	p.nextToken()

	// Parse tags
	tags := make([]string, 0)
	if p.currentTokenIs(token.COLON) {
		p.nextToken()
		for p.currentTokenIs(token.IDENTIFIER) {
			tags = append(tags, p.current.Literal)
			p.nextToken()
		}
	}

	if !p.expectToken(token.LBRACE) {
		return nil, fmt.Errorf("expected '{' after rule declaration")
	}

	// Parse meta section
	meta := make([]*ast.Meta, 0)
	if p.currentTokenIs(token.META) {
		p.nextToken()
		if !p.expectToken(token.COLON) {
			return nil, fmt.Errorf("expected ':' after meta")
		}
		meta = p.parseMetaDeclarations()
	}

	// Parse strings section
	strings := make([]*ast.String, 0)
	if p.currentTokenIs(token.STRINGS) {
		p.nextToken()
		if !p.expectToken(token.COLON) {
			return nil, fmt.Errorf("expected ':' after strings")
		}
		strings = p.parseStringDeclarations()
	}

	// Parse condition section
	if !p.expectToken(token.CONDITION) {
		return nil, fmt.Errorf("expected condition section")
	}
	if !p.expectToken(token.COLON) {
		return nil, fmt.Errorf("expected ':' after condition")
	}

	condition, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if !p.expectToken(token.RBRACE) {
		return nil, fmt.Errorf("expected '}' at end of rule")
	}

	rule := p.builder.Rule(p.current.Pos, ruleName)
	rule.Modifiers = modifiers
	rule.Tags = tags
	rule.Meta = meta
	rule.Strings = strings
	rule.Condition = condition

	return rule, nil
}

// parseImport parses an import statement
func (p *Parser) parseImport() error {
	if !p.expectToken(token.STRING_LIT) {
		return fmt.Errorf("expected string after import")
	}
	// For now, just consume the import - full implementation later
	return nil
}

// parseMetaDeclarations parses meta declarations
func (p *Parser) parseMetaDeclarations() []*ast.Meta {
	meta := make([]*ast.Meta, 0)

	for !p.currentTokenIs(token.STRINGS) && !p.currentTokenIs(token.CONDITION) && !p.currentTokenIs(token.RBRACE) {
		if !p.currentTokenIs(token.IDENTIFIER) {
			break
		}

		key := p.current.Literal
		pos := p.current.Pos
		p.nextToken()

		if !p.expectToken(token.ASSIGN) {
			break
		}

		var value interface{}
		if p.currentTokenIs(token.STRING_LIT) {
			value = p.current.Literal
			p.nextToken()
		} else if p.currentTokenIs(token.INTEGER_LIT) {
			// Parse integer literal properly
			value = p.parseIntegerLiteral()
			p.nextToken()
		} else if p.currentTokenIs(token.TRUE) {
			value = true
			p.nextToken()
		} else if p.currentTokenIs(token.FALSE) {
			value = false
			p.nextToken()
		} else {
			p.errors = append(p.errors, fmt.Errorf("invalid meta value type at %v", p.current.Pos))
			break
		}

		meta = append(meta, p.builder.Meta(pos, key, value))
	}

	return meta
}

// parseStringDeclarations parses string declarations
func (p *Parser) parseStringDeclarations() []*ast.String {
	strings := make([]*ast.String, 0)

	for !p.currentTokenIs(token.CONDITION) && !p.currentTokenIs(token.RBRACE) {
		if !p.currentTokenIs(token.STRING_IDENTIFIER) {
			break
		}

		identifier := p.current.Literal
		pos := p.current.Pos
		p.nextToken()

		if !p.expectToken(token.ASSIGN) {
			break
		}

		// Parse string patterns - support text strings, hex strings, and regex patterns
		var pattern ast.Pattern

		if p.currentTokenIs(token.STRING_LIT) {
			// Text string literal
			patternValue := p.current.Literal
			p.nextToken()
			pattern = p.builder.TextString(pos, patternValue)
		} else if p.currentTokenIs(token.HEX_STRING_LIT) {
			// Hex string literal
			patternValue := p.current.Literal
			p.nextToken()
			pattern = p.builder.HexString(pos, patternValue)
		} else if p.currentTokenIs(token.REGEX_LIT) {
			// Regex pattern literal
			patternValue := p.current.Literal
			p.nextToken()
			pattern = p.builder.RegexPattern(pos, patternValue)
		} else {
			p.errors = append(p.errors, fmt.Errorf("expected string, hex, or regex literal, got %s at %v", p.current.Type, p.current.Pos))
			break
		}

		str := p.builder.String(pos, identifier, pattern, nil)
		strings = append(strings, str)
	}

	return strings
}

// parseExpression parses expressions with operator precedence
func (p *Parser) parseExpression() (ast.Expression, error) {
	return p.parseLogicalOr()
}

// parseLogicalOr parses logical OR expressions (lowest precedence)
func (p *Parser) parseLogicalOr() (ast.Expression, error) {
	left, err := p.parseLogicalAnd()
	if err != nil {
		return nil, err
	}

	for p.currentTokenIs(token.OR) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := p.parseLogicalAnd()
		if err != nil {
			return nil, err
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parseLogicalAnd parses logical AND expressions
func (p *Parser) parseLogicalAnd() (ast.Expression, error) {
	left, err := p.parseLogicalNot()
	if err != nil {
		return nil, err
	}

	for p.currentTokenIs(token.AND) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := p.parseLogicalNot()
		if err != nil {
			return nil, err
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parseLogicalNot parses logical NOT expressions
func (p *Parser) parseLogicalNot() (ast.Expression, error) {
	if p.currentTokenIs(token.NOT) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := p.parseLogicalNot()
		if err != nil {
			return nil, err
		}

		return p.builder.UnaryOp(pos, op, right), nil
	}

	return p.parseComparison()
}

// parseComparison parses comparison expressions
func (p *Parser) parseComparison() (ast.Expression, error) {
	left, err := p.parseAdditive()
	if err != nil {
		return nil, err
	}

	for p.isComparisonOp(p.current.Type) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := p.parseAdditive()
		if err != nil {
			return nil, err
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parseAdditive parses addition and subtraction
func (p *Parser) parseAdditive() (ast.Expression, error) {
	left, err := p.parseMultiplicative()
	if err != nil {
		return nil, err
	}

	for p.currentTokenIs(token.PLUS) || p.currentTokenIs(token.MINUS) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := p.parseMultiplicative()
		if err != nil {
			return nil, err
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parseMultiplicative parses multiplication, division, and modulo
func (p *Parser) parseMultiplicative() (ast.Expression, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	for p.currentTokenIs(token.MULTIPLY) || p.currentTokenIs(token.DIVIDE) || p.currentTokenIs(token.MODULO) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parsePrimary parses primary expressions
func (p *Parser) parsePrimary() (ast.Expression, error) {
	pos := p.current.Pos

	// Literals
	if p.currentTokenIs(token.TRUE) {
		p.nextToken()
		return p.builder.Literal(pos, token.TRUE, true), nil
	}

	if p.currentTokenIs(token.FALSE) {
		p.nextToken()
		return p.builder.Literal(pos, token.FALSE, false), nil
	}

	if p.currentTokenIs(token.INTEGER_LIT) {
		// Parse integer literal properly
		value := p.parseIntegerLiteral()
		p.nextToken()
		return p.builder.Literal(pos, token.INTEGER_LIT, value), nil
	}

	if p.currentTokenIs(token.HEX_INTEGER_LIT) {
		// Parse hex integer literal properly
		value := p.parseHexIntegerLiteral()
		p.nextToken()
		return p.builder.Literal(pos, token.HEX_INTEGER_LIT, value), nil
	}

	if p.currentTokenIs(token.SIZE_LIT) {
		// Parse size literal (e.g., 1KB, 2MB)
		literal := p.current.Literal
		p.nextToken()
		return p.builder.Literal(pos, token.SIZE_LIT, literal), nil
	}

	if p.currentTokenIs(token.STRING_LIT) {
		literal := p.current.Literal
		p.nextToken()
		return p.builder.Literal(pos, token.STRING_LIT, literal), nil
	}

	// String identifiers ($s1, $hex, etc.)
	if p.currentTokenIs(token.STRING_IDENTIFIER) {
		ident := p.current.Literal
		p.nextToken()
		return p.builder.Identifier(pos, ident), nil
	}

	// Quantifier expressions: all/any/none of them or string patterns
	if p.currentTokenIs(token.ALL) || p.currentTokenIs(token.ANY) || p.currentTokenIs(token.NONE) {
		quantifier := p.current.Literal
		p.nextToken()

		if !p.expectToken(token.OF) {
			return nil, fmt.Errorf("expected 'of' after quantifier")
		}

		// Parse the target (them, string patterns, etc.)
		var target ast.Expression
		if p.currentTokenIs(token.THEM) {
			target = p.builder.Identifier(pos, "them")
			p.nextToken()
		} else if p.currentTokenIs(token.STRING_IDENTIFIER) {
			// Could be a pattern like $s* or just $s1
			target = p.builder.Identifier(pos, p.current.Literal)
			p.nextToken()
		} else {
			return nil, fmt.Errorf("expected 'them' or string pattern after 'of'")
		}

		// Create a binary operation representing the quantifier
		return p.builder.BinaryOp(pos, p.builder.Identifier(pos, quantifier), token.OF, target), nil
	}

	// Special keywords: filesize, entrypoint, defined
	if p.currentTokenIs(token.FILESIZE) {
		p.nextToken()
		return p.builder.Identifier(pos, "filesize"), nil
	}

	if p.currentTokenIs(token.ENTRYPOINT) {
		p.nextToken()
		return p.builder.Identifier(pos, "entrypoint"), nil
	}

	if p.currentTokenIs(token.DEFINED) {
		p.nextToken()
		expr, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return p.builder.UnaryOp(pos, token.DEFINED, expr), nil
	}

	if p.currentTokenIs(token.AT) {
		p.nextToken()
		expr, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return p.builder.UnaryOp(pos, token.AT, expr), nil
	}

	if p.currentTokenIs(token.IN) {
		p.nextToken()
		expr, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return p.builder.UnaryOp(pos, token.IN, expr), nil
	}

	// Regular identifiers
	if p.currentTokenIs(token.IDENTIFIER) {
		ident := p.current.Literal
		p.nextToken()
		return p.builder.Identifier(pos, ident), nil
	}

	// Parenthesized expressions
	if p.currentTokenIs(token.LPAREN) {
		p.nextToken()
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if !p.expectToken(token.RPAREN) {
			return nil, fmt.Errorf("expected ')' after expression")
		}
		return expr, nil
	}

	return nil, fmt.Errorf("unexpected token %s at %v", p.current.Type, p.current.Pos)
}

// isComparisonOp checks if a token is a comparison operator
func (p *Parser) isComparisonOp(t token.TokenType) bool {
	return t == token.EQ || t == token.NEQ || t == token.LT || t == token.LE || t == token.GT || t == token.GE
}

// parseIntegerLiteral parses an integer literal token and returns the int64 value
func (p *Parser) parseIntegerLiteral() int64 {
	literal := p.current.Literal

	// Parse decimal integer
	if value, err := strconv.ParseInt(literal, 10, 64); err == nil {
		return value
	}

	// If parsing fails, return 0 and log error
	p.errors = append(p.errors, fmt.Errorf("invalid integer literal: %s at %v", literal, p.current.Pos))
	return 0
}

// parseHexIntegerLiteral parses a hex integer literal token and returns the int64 value
func (p *Parser) parseHexIntegerLiteral() int64 {
	literal := p.current.Literal

	// Remove 0x prefix if present
	literal = strings.TrimPrefix(literal, "0x")
	literal = strings.TrimPrefix(literal, "0X")

	// Parse hexadecimal integer
	if value, err := strconv.ParseInt(literal, 16, 64); err == nil {
		return value
	}

	// If parsing fails, return 0 and log error
	p.errors = append(p.errors, fmt.Errorf("invalid hex integer literal: %s at %v", p.current.Literal, p.current.Pos))
	return 0
}