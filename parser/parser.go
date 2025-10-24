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
	lexer   *lexer.Lexer
	current token.Token
	peek    token.Token
	errors  []error
	builder *ast.Builder
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
		switch {
		case p.currentTokenIs(token.PRIVATE) || p.currentTokenIs(token.GLOBAL) || p.currentTokenIs(token.RULE):
			rule, err := p.parseRule()
			if err != nil {
				p.errors = append(p.errors, err)
				p.synchronize()
				continue
			}
			program.Rules = append(program.Rules, rule)
		case p.currentTokenIs(token.IMPORT):
			p.nextToken() // consume IMPORT keyword
			if err := p.parseImport(); err != nil {
				p.errors = append(p.errors, err)
				p.synchronize()
				continue
			}
		default:
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
		switch {
		case p.currentTokenIs(token.STRING_LIT):
			value = p.current.Literal
			p.nextToken()
		case p.currentTokenIs(token.INTEGER_LIT):
			// Parse integer literal properly
			value = p.parseIntegerLiteral()
			p.nextToken()
		case p.currentTokenIs(token.TRUE):
			value = true
			p.nextToken()
		case p.currentTokenIs(token.FALSE):
			value = false
			p.nextToken()
		default:
			p.errors = append(p.errors, fmt.Errorf("invalid meta value type at %v", p.current.Pos))
		}

		if value != nil {
			meta = append(meta, p.builder.Meta(pos, key, value))
		}
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

		switch {
		case p.currentTokenIs(token.STRING_LIT):
			// Text string literal
			patternValue := p.current.Literal
			p.nextToken()
			pattern = p.builder.TextString(pos, patternValue)
		case p.currentTokenIs(token.HEX_STRING_LIT):
			// Hex string literal
			patternValue := p.current.Literal
			p.nextToken()
			pattern = p.builder.HexString(pos, patternValue)
		case p.currentTokenIs(token.REGEX_LIT):
			// Regex pattern literal
			patternValue := p.current.Literal
			p.nextToken()
			pattern = p.builder.RegexPattern(pos, patternValue)
		default:
			p.errors = append(p.errors, fmt.Errorf("expected string, hex, or regex literal, got %s at %v", p.current.Type, p.current.Pos))
		}

		// Parse string modifiers after the pattern
		modifiers := p.parseStringModifiers()

		str := p.builder.String(pos, identifier, pattern, modifiers)
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

		right, orErr := p.parseLogicalAnd()
		if orErr != nil {
			return nil, orErr
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

		right, andErr := p.parseLogicalNot()
		if andErr != nil {
			return nil, andErr
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
	left, err := p.parseBitwiseOr()
	if err != nil {
		return nil, err
	}

	for p.isComparisonOp(p.current.Type) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, cmpErr := p.parseBitwiseOr()
		if cmpErr != nil {
			return nil, cmpErr
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

		right, addErr := p.parseMultiplicative()
		if addErr != nil {
			return nil, addErr
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parseMultiplicative parses multiplication, division, and modulo
func (p *Parser) parseMultiplicative() (ast.Expression, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}

	for p.currentTokenIs(token.MULTIPLY) || p.currentTokenIs(token.DIVIDE) || p.currentTokenIs(token.MODULO) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, mulErr := p.parseUnary()
		if mulErr != nil {
			return nil, mulErr
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parseUnary parses unary expressions (unary minus, bitwise NOT)
func (p *Parser) parseUnary() (ast.Expression, error) {
	if p.currentTokenIs(token.MINUS) || p.currentTokenIs(token.BITWISE_NOT) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}

		return p.builder.UnaryOp(pos, op, right), nil
	}

	return p.parsePrimary()
}

// parseBitwiseShift parses bitwise shift operations
func (p *Parser) parseBitwiseShift() (ast.Expression, error) {
	left, err := p.parseAdditive()
	if err != nil {
		return nil, err
	}

	for p.currentTokenIs(token.LEFT_SHIFT) || p.currentTokenIs(token.RIGHT_SHIFT) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, shiftErr := p.parseAdditive()
		if shiftErr != nil {
			return nil, shiftErr
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parseBitwiseAnd parses bitwise AND operations
func (p *Parser) parseBitwiseAnd() (ast.Expression, error) {
	left, err := p.parseBitwiseShift()
	if err != nil {
		return nil, err
	}

	for p.currentTokenIs(token.BITWISE_AND) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, andErr := p.parseBitwiseShift()
		if andErr != nil {
			return nil, andErr
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parseBitwiseXor parses bitwise XOR operations
func (p *Parser) parseBitwiseXor() (ast.Expression, error) {
	left, err := p.parseBitwiseAnd()
	if err != nil {
		return nil, err
	}

	for p.currentTokenIs(token.BITWISE_XOR) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, xorErr := p.parseBitwiseAnd()
		if xorErr != nil {
			return nil, xorErr
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parseBitwiseOr parses bitwise OR operations
func (p *Parser) parseBitwiseOr() (ast.Expression, error) {
	left, err := p.parseBitwiseXor()
	if err != nil {
		return nil, err
	}

	for p.currentTokenIs(token.BITWISE_OR) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, orErr := p.parseBitwiseXor()
		if orErr != nil {
			return nil, orErr
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// parsePrimary parses primary expressions
func (p *Parser) parsePrimary() (ast.Expression, error) {
	pos := p.current.Pos

	// Try to parse literals first
	if expr, err := p.parseLiteral(pos); expr != nil || err != nil {
		return expr, err
	}

	// Try to parse string identifiers
	if p.currentTokenIs(token.STRING_IDENTIFIER) {
		ident := p.current.Literal
		p.nextToken()
		return p.builder.Identifier(pos, ident), nil
	}

	// Try to parse quantifier expressions
	if expr, err := p.parseQuantifier(pos); expr != nil || err != nil {
		return expr, err
	}

	// Try to parse special keywords
	if expr := p.parseSpecialKeyword(pos); expr != nil {
		return expr, nil
	}

	// Try to parse unary operators
	if expr, err := p.parseUnaryOperator(pos); expr != nil || err != nil {
		return expr, err
	}

	// Try to parse function calls
	if expr, err := p.parseFunctionCall(pos); expr != nil || err != nil {
		return expr, err
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

// parseLiteral parses literal values (true, false, numbers, strings)
func (p *Parser) parseLiteral(pos token.Position) (ast.Expression, error) {
	if p.currentTokenIs(token.TRUE) {
		p.nextToken()
		return p.builder.Literal(pos, token.TRUE, true), nil
	}

	if p.currentTokenIs(token.FALSE) {
		p.nextToken()
		return p.builder.Literal(pos, token.FALSE, false), nil
	}

	if p.currentTokenIs(token.INTEGER_LIT) {
		value := p.parseIntegerLiteral()
		p.nextToken()
		return p.builder.Literal(pos, token.INTEGER_LIT, value), nil
	}

	if p.currentTokenIs(token.HEX_INTEGER_LIT) {
		value := p.parseHexIntegerLiteral()
		p.nextToken()
		return p.builder.Literal(pos, token.HEX_INTEGER_LIT, value), nil
	}

	if p.currentTokenIs(token.FLOAT_LIT) {
		value := p.parseFloatLiteral()
		p.nextToken()
		return p.builder.Literal(pos, token.FLOAT_LIT, value), nil
	}

	if p.currentTokenIs(token.SIZE_LIT) {
		literal := p.current.Literal
		p.nextToken()
		return p.builder.Literal(pos, token.SIZE_LIT, literal), nil
	}

	if p.currentTokenIs(token.STRING_LIT) {
		literal := p.current.Literal
		p.nextToken()
		return p.builder.Literal(pos, token.STRING_LIT, literal), nil
	}

	return nil, nil
}

// parseQuantifier parses quantifier expressions (all/any/none of them)
func (p *Parser) parseQuantifier(pos token.Position) (ast.Expression, error) {
	if !p.currentTokenIs(token.ALL) && !p.currentTokenIs(token.ANY) && !p.currentTokenIs(token.NONE) {
		return nil, nil
	}

	quantifier := p.current.Literal
	p.nextToken()

	if !p.expectToken(token.OF) {
		return nil, fmt.Errorf("expected 'of' after quantifier")
	}

	// Parse the target (them, string patterns, etc.)
	var target ast.Expression
	var err error
	switch {
	case p.currentTokenIs(token.THEM):
		target = p.builder.Identifier(pos, "them")
		p.nextToken()
	case p.currentTokenIs(token.STRING_IDENTIFIER):
		target = p.builder.Identifier(pos, p.current.Literal)
		p.nextToken()
	case p.currentTokenIs(token.LPAREN):
		// Handle parenthesized expressions like ($*)
		p.nextToken()
		target, err = p.parseExpression()
		if err != nil {
			return nil, err
		}
		if !p.expectToken(token.RPAREN) {
			return nil, fmt.Errorf("expected ')' after expression")
		}
	default:
		return nil, fmt.Errorf("expected 'them', string pattern, or '(' after 'of'")
	}

	return p.builder.BinaryOp(pos, p.builder.Identifier(pos, quantifier), token.OF, target), nil
}

// parseSpecialKeyword parses special keywords (filesize, entrypoint)
func (p *Parser) parseSpecialKeyword(pos token.Position) ast.Expression {
	if p.currentTokenIs(token.FILESIZE) {
		p.nextToken()
		return p.builder.Identifier(pos, "filesize")
	}

	if p.currentTokenIs(token.ENTRYPOINT) {
		p.nextToken()
		return p.builder.Identifier(pos, "entrypoint")
	}

	return nil
}

// parseUnaryOperator parses unary operators (defined, at/@, in, #)
func (p *Parser) parseUnaryOperator(pos token.Position) (ast.Expression, error) {
	var op token.TokenType

	switch {
	case p.currentTokenIs(token.DEFINED):
		op = token.DEFINED
	case p.currentTokenIs(token.AT): // supports both '@' symbol and 'at' keyword if lexer maps them to AT
		op = token.AT
	case p.currentTokenIs(token.IN):
		op = token.IN
	case p.currentTokenIs(token.HASH): // '#' count operator
		op = token.HASH
	default:
		return nil, nil
	}

	p.nextToken()
	expr, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	return p.builder.UnaryOp(pos, op, expr), nil
}

// isComparisonOp checks if a token is a comparison operator
func (p *Parser) isComparisonOp(t token.TokenType) bool {
	return t == token.EQ || t == token.NEQ || t == token.LT || t == token.LE || t == token.GT || t == token.GE || t == token.MATCHES
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

// parseFloatLiteral parses a float literal token and returns the float64 value
func (p *Parser) parseFloatLiteral() float64 {
	literal := p.current.Literal

	// Parse float
	if value, err := strconv.ParseFloat(literal, 64); err == nil {
		return value
	}

	// If parsing fails, return 0 and log error
	p.errors = append(p.errors, fmt.Errorf("invalid float literal: %s at %v", literal, p.current.Pos))
	return 0
}

// parseStringModifiers parses string modifiers (nocase, wide, ascii, etc.)
func (p *Parser) parseStringModifiers() []ast.StringModifier {
	modifiers := make([]ast.StringModifier, 0)

	for p.isStringModifier(p.current.Type) {
		var modifierType ast.StringModifierType
		switch p.current.Type {
		case token.NOCASE:
			modifierType = ast.StringModifierNocase
		case token.WIDE:
			modifierType = ast.StringModifierWide
		case token.ASCII:
			modifierType = ast.StringModifierASCII
		case token.FULLWORD:
			modifierType = ast.StringModifierFullword
		case token.PRIVATE:
			modifierType = ast.StringModifierPrivate
		case token.XOR:
			modifierType = ast.StringModifierXor
		case token.BASE64:
			modifierType = ast.StringModifierBase64
		case token.BASE64WIDE:
			modifierType = ast.StringModifierBase64Wide
		}

		modifiers = append(modifiers, ast.StringModifier{Type: modifierType})
		p.nextToken()
	}

	return modifiers
}

// isStringModifier checks if a token is a string modifier
func (p *Parser) isStringModifier(t token.TokenType) bool {
	return t == token.NOCASE || t == token.WIDE || t == token.ASCII ||
		t == token.FULLWORD || t == token.PRIVATE || t == token.XOR ||
		t == token.BASE64 || t == token.BASE64WIDE
}

// parseFunctionCall parses function calls like uint32be(0), filesize, etc.
func (p *Parser) parseFunctionCall(pos token.Position) (ast.Expression, error) {
	// Check if this is a data type function (uint32, int16be, etc.)
	if p.isDataTypeFunction(p.current.Type) {
		funcName := p.current.Literal
		p.nextToken()

		// Check if this function call has parentheses (arguments)
		if p.currentTokenIs(token.LPAREN) {
			p.nextToken() // consume '('

			// Parse the argument expression
			arg, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			if !p.expectToken(token.RPAREN) {
				return nil, fmt.Errorf("expected ')' after function argument")
			}

			// For now, create a binary operation to represent function call
			// This is a temporary solution until we have proper FunctionCall AST nodes
			return p.builder.BinaryOp(pos, p.builder.Identifier(pos, funcName), token.LPAREN, arg), nil
		} else {
			// Simple function call without arguments
			return p.builder.Identifier(pos, funcName), nil
		}
	}

	return nil, nil
}

// isDataTypeFunction checks if a token is a data type function
func (p *Parser) isDataTypeFunction(t token.TokenType) bool {
	return t == token.UINT8 || t == token.UINT16 || t == token.UINT32 ||
		t == token.UINT8BE || t == token.UINT16BE || t == token.UINT32BE ||
		t == token.INT8 || t == token.INT16 || t == token.INT32 ||
		t == token.INT8BE || t == token.INT16BE || t == token.INT32BE ||
		t == token.FILESIZE || t == token.ENTRYPOINT
}
