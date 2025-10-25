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
		// Check for global variables, imports, includes, rule modifiers (private, global) or rule keyword
		switch {
		case p.currentTokenIs(token.GLOBAL):
			// Check if this is a global variable declaration or a global rule modifier
			// Look ahead to see if we can find RULE after any modifiers
			if p.peekTokenIs(token.RULE) || p.peekTokenIs(token.PRIVATE) {
				// This is a global rule modifier
				rule, err := p.parseRule()
				if err != nil {
					p.errors = append(p.errors, err)
					p.synchronize()
					continue
				}
				program.Rules = append(program.Rules, rule)
			} else {
				// This is a global variable declaration
				p.nextToken() // consume GLOBAL token
				globalVar, err := p.parseGlobalVariable()
				if err != nil {
					p.errors = append(p.errors, err)
					p.synchronize()
					continue
				}
				program.GlobalVariables = append(program.GlobalVariables, globalVar)
			}
		case p.currentTokenIs(token.IMPORT):
			importStmt, err := p.parseImport()
			if err != nil {
				p.errors = append(p.errors, err)
				p.synchronize()
				continue
			}
			program.Imports = append(program.Imports, importStmt)
		case p.currentTokenIs(token.INCLUDE):
			includeStmt, err := p.parseInclude()
			if err != nil {
				p.errors = append(p.errors, err)
				p.synchronize()
				continue
			}
			program.Includes = append(program.Includes, includeStmt)
		case p.currentTokenIs(token.PRIVATE) || p.currentTokenIs(token.RULE):
			rule, err := p.parseRule()
			if err != nil {
				p.errors = append(p.errors, err)
				p.synchronize()
				continue
			}
			program.Rules = append(program.Rules, rule)
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

// synchronize recovers from parsing errors by skipping to next rule, import, or global variable
func (p *Parser) synchronize() {
	p.nextToken()

	for !p.currentTokenIs(token.EOF) {
		if p.currentTokenIs(token.RULE) || p.currentTokenIs(token.IMPORT) || p.currentTokenIs(token.GLOBAL) || p.currentTokenIs(token.INCLUDE) {
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
func (p *Parser) parseImport() (*ast.Import, error) {
	pos := p.current.Pos

	// Expect IMPORT keyword
	if !p.expectToken(token.IMPORT) {
		return nil, fmt.Errorf("expected 'import' keyword")
	}

	// Expect string literal for module name
	if !p.currentTokenIs(token.STRING_LIT) {
		return nil, fmt.Errorf("expected string literal after 'import'")
	}
	module := p.current.Literal
	p.nextToken()

	return p.builder.Import(pos, module), nil
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
		// Handle both string identifiers and anonymous strings
		if !p.currentTokenIs(token.STRING_IDENTIFIER) && !p.currentTokenIs(token.IDENTIFIER) {
			break
		}

		var identifier string
		pos := p.current.Pos

		// Check if this is an anonymous string (just $)
		switch {
		case p.currentTokenIs(token.STRING_IDENTIFIER) && p.current.Literal == "$":
			identifier = "$"
			p.nextToken()
		case p.currentTokenIs(token.STRING_IDENTIFIER):
			identifier = p.current.Literal
			p.nextToken()
		case p.currentTokenIs(token.IDENTIFIER):
			// This might be an anonymous string identifier
			identifier = p.current.Literal
			p.nextToken()
		default:
			return []*ast.String{}
		}

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

	return p.parseQuantifierExpression()
}

// parseQuantifierExpression parses quantifier expressions (of operator)
func (p *Parser) parseQuantifierExpression() (ast.Expression, error) {
	// Try to parse quantifier expressions first
	if expr, err := p.parseQuantifier(p.current.Pos); expr != nil || err != nil {
		return expr, err
	}

	return p.parseComparison()
}

// parseComparison parses comparison expressions
func (p *Parser) parseComparison() (ast.Expression, error) {
	left, err := p.parseBitwiseOr()
	if err != nil {
		return nil, err
	}

	// Check for range expression (..) - this should be handled after parsing left operand
	if p.currentTokenIs(token.DOT) && p.peekTokenIs(token.DOT) {
		// This is a range expression like "0..100"
		dotPos := p.current.Pos
		p.nextToken() // consume first DOT
		p.nextToken() // consume second DOT

		// Parse the right operand of the range
		right, rangeErr := p.parseBitwiseOr()
		if rangeErr != nil {
			return nil, rangeErr
		}

		// Create a binary operation to represent the range
		// This is a workaround until we have proper range expression AST nodes
		return p.builder.BinaryOp(dotPos, left, token.DOT, right), nil
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

		// Check for string offset operators (at, in)
		if p.currentTokenIs(token.AT) || p.currentTokenIs(token.IN) {
			op := p.current.Type
			opPos := p.current.Pos
			p.nextToken()

			// Parse the offset expression
			offsetExpr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Create binary operation for string offset
			return p.builder.BinaryOp(opPos, p.builder.Identifier(pos, ident), op, offsetExpr), nil
		}

		// Check for string length operator
		if p.currentTokenIs(token.LENGTH) {
			lengthPos := p.current.Pos
			p.nextToken()

			// Create string length expression
			return p.builder.StringLength(lengthPos, p.builder.Identifier(pos, ident)), nil
		}

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
		if err != nil {
			return nil, err
		}

		// Check for array indexing after function call
		if p.currentTokenIs(token.LBRACKET) {
			p.nextToken() // consume '['

			indexExpr, indexErr := p.parseExpression()
			if indexErr != nil {
				return nil, indexErr
			}

			if !p.expectToken(token.RBRACKET) {
				return nil, fmt.Errorf("expected ']' after array index")
			}

			// Create array index expression
			return p.builder.ArrayIndex(pos, expr, indexExpr), nil
		}

		return expr, nil
	}

	// Regular identifiers
	if p.currentTokenIs(token.IDENTIFIER) {
		ident := p.current.Literal
		p.nextToken()

		// Check for module access (dot notation)
		if p.currentTokenIs(token.DOT) {
			p.nextToken() // consume '.'

			if !p.currentTokenIs(token.IDENTIFIER) {
				return nil, fmt.Errorf("expected identifier after '.' for module access")
			}

			memberIdent := p.current.Literal
			p.nextToken()

			// Create a binary operation to represent module access
			// This is a temporary solution until we have proper ModuleAccess AST nodes
			return p.builder.BinaryOp(pos, p.builder.Identifier(pos, ident), token.DOT, p.builder.Identifier(pos, memberIdent)), nil
		}

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

	if p.currentTokenIs(token.REGEX_LIT) {
		literal := p.current.Literal
		p.nextToken()
		return p.builder.Literal(pos, token.REGEX_LIT, literal), nil
	}

	return nil, nil
}

// parseQuantifier parses quantifier expressions (all/any/none of them, for any of them)
func (p *Parser) parseQuantifier(pos token.Position) (ast.Expression, error) {
	// Handle "for" quantifier syntax
	if p.currentTokenIs(token.FOR) {
		p.nextToken() // consume 'for'

		// Parse the quantifier after 'for'
		if !p.currentTokenIs(token.ALL) && !p.currentTokenIs(token.ANY) && !p.currentTokenIs(token.NONE) {
			return nil, fmt.Errorf("expected quantifier (all/any/none) after 'for'")
		}

		quantifier := p.current.Literal
		p.nextToken()

		// Check if this is a for loop with variable (for all i in (0..9) : ...)
		// In this case, we don't expect 'of' after the quantifier
		if p.currentTokenIs(token.IDENTIFIER) {
			variableName := p.current.Literal
			p.nextToken()

			if !p.expectToken(token.IN) {
				return nil, fmt.Errorf("expected 'in' after variable name in for loop")
			}

			// Parse the range expression - handle it specially for for loops
			var rangeExpr ast.Expression
			var rangeErr error

			// Check if this is a parenthesized range expression like (0..9)
			if p.currentTokenIs(token.LPAREN) {
				p.nextToken() // consume '('

				// Parse the left operand of the range
				left, leftErr := p.parsePrimary()
				if leftErr != nil {
					return nil, leftErr
				}

				// Check for range expression (..)
				if p.currentTokenIs(token.DOT) && p.peekTokenIs(token.DOT) {
					dotPos := p.current.Pos
					p.nextToken() // consume first DOT
					p.nextToken() // consume second DOT

					// Parse the right operand of the range
					right, rightErr := p.parsePrimary()
					if rightErr != nil {
						return nil, rightErr
					}

					// Create a binary operation to represent the range
					rangeExpr = p.builder.BinaryOp(dotPos, left, token.DOT, right)
				} else {
					// Not a range expression, parse the rest as a regular expression
					// Put back the left operand and continue parsing
					// For now, just use the left operand as the range expression
					rangeExpr = left
				}

				if !p.expectToken(token.RPAREN) {
					return nil, fmt.Errorf("expected ')' after range expression")
				}
			} else {
				// Parse regular expression
				rangeExpr, rangeErr = p.parsePrimary()
				if rangeErr != nil {
					return nil, rangeErr
				}
			}

			// Check for colon syntax in "for" quantifiers
			if p.currentTokenIs(token.COLON) {
				p.nextToken() // consume ':'

				// Parse the expression after colon
				expr, parseErr := p.parseExpression()
				if parseErr != nil {
					return nil, parseErr
				}

				// Create a ForLoop node for "for" quantifiers with colon
				return p.builder.ForLoop(pos, quantifier, variableName, rangeExpr, expr), nil
			}

			return nil, fmt.Errorf("expected ':' after for loop range")
		}

		// For standard "for" quantifiers without variables, we expect 'of'
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
			// Handle parenthesized expressions like ($)
			p.nextToken()

			// Special case for ($) which means "any string"
			switch {
			case p.currentTokenIs(token.STRING_IDENTIFIER) && p.current.Literal == "$":
				// Validate that this is a proper string identifier format
				if !strings.HasPrefix(p.current.Literal, "$") {
					return nil, fmt.Errorf("invalid string identifier format: %s at %v", p.current.Literal, p.current.Pos)
				}
				target = p.builder.Identifier(pos, "$")
				p.nextToken()
			case p.currentTokenIs(token.STRING_IDENTIFIER):
				return nil, fmt.Errorf("unexpected string identifier %s in quantifier expression at %v", p.current.Literal, p.current.Pos)
			default:
				// Parse regular expression
				target, err = p.parseExpression()
				if err != nil {
					return nil, err
				}
			}

			if !p.expectToken(token.RPAREN) {
				return nil, fmt.Errorf("expected ')' after expression")
			}
		default:
			return nil, fmt.Errorf("expected 'them', string pattern, or '(' after 'of'")
		}

		// Check for colon syntax in "for" quantifiers
		if p.currentTokenIs(token.COLON) {
			p.nextToken() // consume ':'

			// Parse the expression after colon
			expr, parseErr := p.parseExpression()
			if parseErr != nil {
				return nil, parseErr
			}

			// Create a ForLoop node for "for" quantifiers with colon
			return p.builder.ForLoop(pos, quantifier, "", target, expr), nil
		}

		return p.builder.OfExpression(pos, p.builder.Identifier(pos, quantifier), target), nil
	}

	// Handle standard quantifier syntax (all/any/none of them) and numeric quantifiers
	var quantifierExpr ast.Expression

	// Check for numeric quantifier first (e.g., "1 of", "2 of")
	// Only treat as quantifier if the next token is OF
	switch {
	case (p.currentTokenIs(token.INTEGER_LIT) || p.currentTokenIs(token.HEX_INTEGER_LIT)) && p.peekTokenIs(token.OF):
		var err error
		quantifierExpr, err = p.parsePrimary()
		if err != nil {
			return nil, err
		}

		if !p.expectToken(token.OF) {
			return nil, fmt.Errorf("expected 'of' after count")
		}
	case p.currentTokenIs(token.ALL) || p.currentTokenIs(token.ANY) || p.currentTokenIs(token.NONE):
		quantifier := p.current.Literal
		p.nextToken()

		if !p.expectToken(token.OF) {
			return nil, fmt.Errorf("expected 'of' after quantifier")
		}

		quantifierExpr = p.builder.Identifier(pos, quantifier)
	default:
		return nil, nil
	}

	// Parse the target (them, string patterns, etc.)
	var target ast.Expression
	switch {
	case p.currentTokenIs(token.THEM):
		target = p.builder.Identifier(pos, "them")
		p.nextToken()
	case p.currentTokenIs(token.STRING_IDENTIFIER):
		target = p.builder.Identifier(pos, p.current.Literal)
		p.nextToken()
	case p.currentTokenIs(token.LPAREN):
		// Handle parenthesized expressions like ($*) or comma-separated lists
		p.nextToken()

		// Check if this is a comma-separated list of string identifiers
		var expressions []ast.Expression
		expressions = append(expressions, nil) // placeholder for first expression

		// Parse the first expression
		switch {
		case p.currentTokenIs(token.STRING_IDENTIFIER) && p.current.Literal == "$":
			// Validate that this is a proper string identifier format
			if !strings.HasPrefix(p.current.Literal, "$") {
				return nil, fmt.Errorf("invalid string identifier format: %s at %v", p.current.Literal, p.current.Pos)
			}
			expressions[0] = p.builder.Identifier(pos, "$")
			p.nextToken()
		case p.currentTokenIs(token.STRING_IDENTIFIER):
			expressions[0] = p.builder.Identifier(pos, p.current.Literal)
			p.nextToken()
		default:
			// Parse regular expression
			expr, parseErr := p.parseExpression()
			if parseErr != nil {
				return nil, parseErr
			}
			expressions[0] = expr
		}

		// Check for comma-separated list
		for p.currentTokenIs(token.COMMA) {
			p.nextToken() // consume ','

			// Parse next expression
			var nextExpr ast.Expression
			switch {
			case p.currentTokenIs(token.STRING_IDENTIFIER):
				nextExpr = p.builder.Identifier(pos, p.current.Literal)
				p.nextToken()
			default:
				var err error
				nextExpr, err = p.parseExpression()
				if err != nil {
					return nil, err
				}
			}
			expressions = append(expressions, nextExpr)
		}

		if !p.expectToken(token.RPAREN) {
			return nil, fmt.Errorf("expected ')' after expression")
		}

		// If we have multiple expressions, create a comma expression
		if len(expressions) > 1 {
			// Create a temporary representation for comma-separated list
			// This is a workaround until we have proper list AST nodes
			target = expressions[0]
			for i := 1; i < len(expressions); i++ {
				target = p.builder.BinaryOp(pos, target, token.COMMA, expressions[i])
			}
		} else {
			target = expressions[0]
		}
	default:
		return nil, fmt.Errorf("expected 'them', string pattern, or '(' after 'of'")
	}

	// Create an OfExpression node
	return p.builder.OfExpression(pos, quantifierExpr, target), nil
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

	// Check for array indexing after the primary expression
	if p.currentTokenIs(token.LBRACKET) {
		// This is an array indexing operation
		p.nextToken() // consume '['

		indexExpr, indexErr := p.parseExpression()
		if indexErr != nil {
			return nil, indexErr
		}

		if !p.expectToken(token.RBRACKET) {
			return nil, fmt.Errorf("expected ']' after array index")
		}

		// Create array index expression
		arrayExpr := p.builder.UnaryOp(pos, op, expr)
		return p.builder.ArrayIndex(pos, arrayExpr, indexExpr), nil
	}

	// Check for string length after the primary expression
	if p.currentTokenIs(token.LENGTH) {
		// This is a string length operation
		p.nextToken() // consume 'length'

		// Create string length expression
		stringExpr := p.builder.UnaryOp(pos, op, expr)
		return p.builder.StringLength(pos, stringExpr), nil
	}

	return p.builder.UnaryOp(pos, op, expr), nil
}

// comparisonOps is a map of comparison operator tokens for efficient lookup
var comparisonOps = map[token.TokenType]bool{
	token.EQ:          true,
	token.NEQ:         true,
	token.LT:          true,
	token.LE:          true,
	token.GT:          true,
	token.GE:          true,
	token.MATCHES:     true,
	token.CONTAINS:    true,
	token.ICONTAINS:   true,
	token.STARTSWITH:  true,
	token.ISTARTSWITH: true,
	token.ENDSWITH:    true,
	token.IENDSWITH:   true,
	token.IEQUALS:     true,
}

// isComparisonOp checks if a token is a comparison operator
func (p *Parser) isComparisonOp(t token.TokenType) bool {
	return comparisonOps[t]
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

// peekTokenIs checks if peek token matches the given type
func (p *Parser) peekTokenIs(t token.TokenType) bool {
	return p.peek.Type == t
}

// parseGlobalVariable parses a global variable declaration
func (p *Parser) parseGlobalVariable() (*ast.GlobalVariable, error) {
	pos := p.current.Pos

	// Parse variable name (GLOBAL token was already consumed in the main loop)
	if !p.currentTokenIs(token.IDENTIFIER) {
		return nil, fmt.Errorf("expected variable name after 'global'")
	}
	name := p.current.Literal
	p.nextToken()

	// Expect assignment operator
	if !p.expectToken(token.ASSIGN) {
		return nil, fmt.Errorf("expected '=' after variable name")
	}

	// Parse variable value
	value, err := p.parseExpression()
	if err != nil {
		return nil, fmt.Errorf("expected expression after '='")
	}

	return p.builder.GlobalVariable(pos, name, value), nil
}

// parseInclude parses an include statement
func (p *Parser) parseInclude() (*ast.Include, error) {
	pos := p.current.Pos

	// Expect INCLUDE keyword
	if !p.expectToken(token.INCLUDE) {
		return nil, fmt.Errorf("expected 'include' keyword")
	}

	// Expect string literal for file name
	if !p.currentTokenIs(token.STRING_LIT) {
		return nil, fmt.Errorf("expected string literal after 'include'")
	}
	file := p.current.Literal
	p.nextToken()

	return p.builder.Include(pos, file), nil
}
