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
				p.addError(err)
				if err == nil {
					program.Rules = append(program.Rules, rule)
				}
			} else {
				// This is a global variable declaration
				p.nextToken() // consume GLOBAL token
				globalVar, err := p.parseGlobalVariable()
				p.addError(err)
				if err == nil {
					program.GlobalVariables = append(program.GlobalVariables, globalVar)
				}
			}
		case p.currentTokenIs(token.EXTERNAL):
			// This is an external variable declaration
			p.nextToken() // consume EXTERNAL token
			externalVar, err := p.parseExternalVariable()
			p.addError(err)
			if err == nil {
				program.ExternalVariables = append(program.ExternalVariables, externalVar)
			}
		case p.currentTokenIs(token.IMPORT):
			importStmt, err := p.parseImport()
			p.addError(err)
			if err == nil {
				program.Imports = append(program.Imports, importStmt)
			}
		case p.currentTokenIs(token.INCLUDE):
			includeStmt, err := p.parseInclude()
			p.addError(err)
			if err == nil {
				program.Includes = append(program.Includes, includeStmt)
			}
		case p.currentTokenIs(token.PRIVATE) || p.currentTokenIs(token.RULE):
			rule, err := p.parseRule()
			p.addError(err)
			if err == nil {
				program.Rules = append(program.Rules, rule)
			}
		default:
			p.addError(fmt.Errorf("unexpected token %s at %v", p.current.Type, p.current.Pos))
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

// addError records an error and synchronizes the parser state
func (p *Parser) addError(err error) {
	if err != nil {
		p.errors = append(p.errors, err)
		p.synchronize()
	}
}

// expectTokenWithMessage checks for expected token and advances if matched, returns error message
func (p *Parser) expectTokenWithMessage(tokenType token.TokenType, message string) error {
	if !p.expectToken(tokenType) {
		return fmt.Errorf("%s", message)
	}
	return nil
}

// expectIdentifier expects and returns an identifier token
func (p *Parser) expectIdentifier() (string, error) {
	if !p.currentTokenIs(token.IDENTIFIER) {
		return "", fmt.Errorf("expected identifier, got %s at %v", p.current.Type, p.current.Pos)
	}

	value := p.current.Literal
	p.nextToken()
	return value, nil
}

// consumeIdentifierSequence consumes consecutive identifiers and returns them
func (p *Parser) consumeIdentifierSequence() []string {
	identifiers := make([]string, 0)
	for p.currentTokenIs(token.IDENTIFIER) {
		identifiers = append(identifiers, p.current.Literal)
		p.nextToken()
	}
	return identifiers
}

// parseTagList parses a colon-separated list of identifiers (tags)
func (p *Parser) parseTagList() []string {
	tags := make([]string, 0)
	if p.currentTokenIs(token.COLON) {
		p.nextToken()
		tags = p.consumeIdentifierSequence()
	}
	return tags
}

// parseMetaValue parses a meta value with comprehensive error handling
// Supports: string literals, integers, boolean values (true/false)
// Returns: parsed value or nil if error occurred
func (p *Parser) parseMetaValue() ast.MetaValue {
	pos := p.current.Pos

	switch {
	case p.currentTokenIs(token.STRING_LIT):
		value := p.current.Literal
		p.nextToken()
		return ast.MetaString(value)
	case p.currentTokenIs(token.INTEGER_LIT):
		value := p.parseIntegerLiteral()
		if value == 0 && p.current.Literal != "0" {
			p.addError(fmt.Errorf("invalid integer literal '%s' at %v", p.current.Literal, pos))
		}
		p.nextToken()
		return ast.MetaInt(value)
	case p.currentTokenIs(token.TRUE):
		p.nextToken()
		return ast.MetaBool(true)
	case p.currentTokenIs(token.FALSE):
		p.nextToken()
		return ast.MetaBool(false)
	default:
		p.addError(fmt.Errorf("invalid meta value type '%s' at %v - expected string, integer, or boolean", p.current.Type, pos))
		return nil
	}
}

// parseMetaEntry parses a single meta entry (key = value)
func (p *Parser) parseMetaEntry() (*ast.Meta, error) {
	if !p.currentTokenIs(token.IDENTIFIER) {
		return nil, fmt.Errorf("expected identifier for meta key at %v", p.current.Pos)
	}

	key := p.current.Literal
	pos := p.current.Pos
	p.nextToken()

	if err := p.expectTokenWithMessage(token.ASSIGN, "expected '=' after meta key"); err != nil {
		return nil, err
	}

	value := p.parseMetaValue()
	if value == nil {
		return nil, fmt.Errorf("failed to parse meta value for key '%s'", key)
	}

	return p.builder.Meta(pos, key, value), nil
}

// getStringModifierType converts a token type to its corresponding string modifier type
// Precondition: tokenType should be a valid string modifier token
func (p *Parser) getStringModifierType(tokenType token.TokenType) ast.StringModifierType {
	switch tokenType {
	case token.NOCASE:
		return ast.StringModifierNocase
	case token.WIDE:
		return ast.StringModifierWide
	case token.ASCII:
		return ast.StringModifierASCII
	case token.FULLWORD:
		return ast.StringModifierFullword
	case token.PRIVATE:
		return ast.StringModifierPrivate
	case token.XOR:
		return ast.StringModifierXor
	case token.BASE64:
		return ast.StringModifierBase64
	case token.BASE64WIDE:
		return ast.StringModifierBase64Wide
	default:
		// This should not happen if isStringModifier is called first
		return ast.StringModifierNocase // Fallback
	}
}

// parseStringIdentifier parses a string identifier and returns its components.
// String identifiers can be:
//   - Anonymous: "$" (standalone anonymous string)
//   - Named: "$name" or "name" (named string with $ prefix)
//   - Regular: "name" (regular identifier)
//
// Returns: (identifier, position, error) where error is non-nil if parsing fails
func (p *Parser) parseStringIdentifier() (string, token.Position, error) {
	if !p.currentTokenIs(token.STRING_IDENTIFIER) && !p.currentTokenIs(token.IDENTIFIER) {
		return "", token.Position{}, fmt.Errorf("expected string identifier at %v, got %s", p.current.Pos, p.current.Type)
	}

	identifier := p.current.Literal
	pos := p.current.Pos
	p.nextToken()

	return identifier, pos, nil
}

// parseStringPattern parses a string pattern and returns the appropriate AST node.
// Supported pattern types:
//   - Text strings: "hello world" (STRING_LIT)
//   - Hex strings: { 48 65 6C 6C 6F } (HEX_STRING_LIT)
//   - Regex patterns: /hello.*world/ (REGEX_LIT)
//
// Parameters:
//   - pos: Position where the pattern starts (for error reporting)
//
// Returns: (ast.Pattern, error) where pattern is nil and error is non-nil if parsing fails
func (p *Parser) parseStringPattern(pos token.Position) (ast.Pattern, error) {
	switch {
	case p.currentTokenIs(token.STRING_LIT):
		// Text string literal
		patternValue := p.current.Literal
		p.nextToken()
		return p.builder.TextString(pos, patternValue), nil
	case p.currentTokenIs(token.HEX_STRING_LIT):
		// Hex string literal
		patternValue := p.current.Literal
		p.nextToken()
		return p.builder.HexString(pos, patternValue), nil
	case p.currentTokenIs(token.REGEX_LIT):
		// Regex pattern literal
		patternValue := p.current.Literal
		p.nextToken()
		return p.builder.RegexPattern(pos, patternValue), nil
	default:
		return nil, fmt.Errorf("expected string, hex, or regex literal at %v, got %s", p.current.Pos, p.current.Type)
	}
}

// parseStringDeclaration parses a complete string declaration in the format:
// $identifier = "text" [modifiers]
// $ = "text" [modifiers]  // anonymous string
func (p *Parser) parseStringDeclaration() (*ast.String, error) {
	// Parse string identifier
	identifier, pos, err := p.parseStringIdentifier()
	if err != nil {
		return nil, err
	}

	// Expect assignment operator
	if assignErr := p.expectTokenWithMessage(token.ASSIGN, "expected '=' after string identifier"); assignErr != nil {
		return nil, assignErr
	}

	// Parse string pattern
	pattern, patternErr := p.parseStringPattern(pos)
	if patternErr != nil {
		p.addError(patternErr)
		return nil, patternErr
	}

	// Parse string modifiers
	modifiers := p.parseStringModifiers()

	// Create string node
	str := p.builder.String(pos, identifier, pattern, modifiers)
	return str, nil
}

// parseBinaryExpression parses binary expressions with left-associative binding.
// This is a generic helper for parsing expressions that follow the pattern:
// left op right [op right]*
// Parameters:
//   - leftOperand: initial left operand
//   - parseRightOperand: function to parse right operands
//   - operatorTypes: slice of operator token types to match
//
// Returns: parsed expression or error
func (p *Parser) parseBinaryExpression(
	left ast.Expression,
	parseRightOperand func() (ast.Expression, error),
	operatorTypes []token.TokenType,
) (ast.Expression, error) {
	for p.isAnyToken(operatorTypes) {
		op := p.current.Type
		pos := p.current.Pos
		p.nextToken()

		right, err := parseRightOperand()
		if err != nil {
			return nil, err
		}

		left = p.builder.BinaryOp(pos, left, op, right)
	}

	return left, nil
}

// isAnyToken checks if current token matches any of the provided token types
func (p *Parser) isAnyToken(tokenTypes []token.TokenType) bool {
	for _, tokenType := range tokenTypes {
		if p.currentTokenIs(tokenType) {
			return true
		}
	}
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

// parseRule parses a single YARA rule with the following structure:
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
	if err := p.expectTokenWithMessage(token.RULE, "expected 'rule' keyword"); err != nil {
		return nil, err
	}

	// Get rule name
	ruleName, err := p.expectIdentifier()
	if err != nil {
		return nil, fmt.Errorf("expected rule name, %v", err)
	}

	// Parse tags
	tags := p.parseTagList()

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

// parseMetaDeclarations parses meta declarations in the format:
// meta:
//
//	key = value
//	another_key = "string value"
//	numeric_key = 42
//	bool_key = true
func (p *Parser) parseMetaDeclarations() []*ast.Meta {
	meta := make([]*ast.Meta, 0)

	for !p.currentTokenIs(token.STRINGS) && !p.currentTokenIs(token.CONDITION) && !p.currentTokenIs(token.RBRACE) {
		if !p.currentTokenIs(token.IDENTIFIER) {
			break
		}

		metaEntry, err := p.parseMetaEntry()
		if err != nil {
			p.addError(err)
		} else if metaEntry != nil {
			meta = append(meta, metaEntry)
		}
	}

	return meta
}

// parseStringDeclarations parses string declarations in the strings section
// Supports: $identifier = "pattern" [modifiers], $ = "pattern" [modifiers]
// Returns a slice of parsed string declarations
func (p *Parser) parseStringDeclarations() []*ast.String {
	strings := make([]*ast.String, 0)

	for !p.currentTokenIs(token.CONDITION) && !p.currentTokenIs(token.RBRACE) {
		if !p.currentTokenIs(token.STRING_IDENTIFIER) && !p.currentTokenIs(token.IDENTIFIER) {
			break
		}

		str, err := p.parseStringDeclaration()
		if err != nil {
			p.addError(err)
		} else if str != nil {
			strings = append(strings, str)
		}
	}

	return strings
}

// parseExpression parses expressions using the following operator precedence (highest to lowest):
// 1. Primary expressions (literals, identifiers, function calls, parenthesized expressions)
// 2. Unary operators (NOT, -, ~)
// 3. Multiplicative operators (*, /, %)
// 4. Additive operators (+, -)
// 5. Bitwise shift operators (<<, >>)
// 6. Bitwise AND (&)
// 7. Bitwise XOR (^)
// 8. Bitwise OR (|)
// 9. Comparison operators (==, !=, <, <=, >, >=, contains, matches, startswith, endswith)
// 10. Quantifiers (any, all, none)
// 11. Logical AND (and)
// 12. Logical OR (or) - lowest precedence
func (p *Parser) parseExpression() (ast.Expression, error) {
	return p.parseLogicalOr()
}

// parseLogicalOr parses logical OR expressions with left-associative binding.
// Handles expressions like: expr1 or expr2 or expr3
// Returns: ast.BinaryOp nodes with token.OR operator
func (p *Parser) parseLogicalOr() (ast.Expression, error) {
	left, err := p.parseLogicalAnd()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseLogicalAnd, []token.TokenType{token.OR})
}

// parseLogicalAnd parses logical AND expressions with left-associative binding.
// Handles expressions like: expr1 and expr2 and expr3
// Returns: ast.BinaryOp nodes with token.AND operator
func (p *Parser) parseLogicalAnd() (ast.Expression, error) {
	left, err := p.parseLogicalNot()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseLogicalNot, []token.TokenType{token.AND})
}

// parseLogicalNot parses logical NOT expressions
func (p *Parser) parseLogicalNot() (ast.Expression, error) {
	if p.currentTokenIs(token.NOT) {
		// Check if this is a string length operation (!string)
		// If the next token is an identifier, handle it directly
		if p.peekTokenIs(token.STRING_IDENTIFIER) || p.peekTokenIs(token.IDENTIFIER) {
			pos := p.current.Pos
			p.nextToken() // consume '!'

			// Parse the identifier
			if !p.currentTokenIs(token.STRING_IDENTIFIER) && !p.currentTokenIs(token.IDENTIFIER) {
				return nil, fmt.Errorf("expected identifier after '!' at %v", p.current.Pos)
			}

			ident := p.current.Literal
			identPos := p.current.Pos
			p.nextToken() // consume identifier

			// For string operators, we need to ensure the identifier is treated as a string
			// If it doesn't have a $ prefix, we'll add one for the AST node
			if !strings.HasPrefix(ident, "$") {
				ident = "$" + ident
			}

			// Create a StringLength expression and continue parsing the rest of the expression
			stringLengthExpr := p.builder.StringLength(pos, p.builder.Identifier(identPos, ident))

			// Check if there's a comparison operator after the string length expression
			if p.isComparisonOp(p.current.Type) {
				op := p.current.Type
				opPos := p.current.Pos
				p.nextToken()

				right, cmpErr := p.parseBitwiseOr()
				if cmpErr != nil {
					return nil, cmpErr
				}

				return p.builder.BinaryOp(opPos, stringLengthExpr, op, right), nil
			}

			return stringLengthExpr, nil
		}

		// Otherwise, this is a logical NOT operation
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

	// Try to parse data type function calls (uint8, uint16, uint32, etc.)
	if p.isDataTypeFunction(p.current.Type) {
		functionName := p.current.Literal
		funcPos := p.current.Pos
		p.nextToken()

		// Check for function call
		if p.currentTokenIs(token.LPAREN) {
			return p.parseFunctionCall(funcPos, functionName)
		}

		return nil, fmt.Errorf("expected '(' after data type function %s", functionName)
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
		identPos := p.current.Pos
		p.nextToken()

		// Check for function call
		if p.currentTokenIs(token.LPAREN) {
			return p.parseFunctionCall(identPos, ident)
		}

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

	// Special handling for string identifiers with #, @ operators
	// These operators can be used with string identifiers with or without $ prefix
	var expr ast.Expression
	var err error

	// Check if the next token is an identifier (string identifier or regular identifier)
	if p.currentTokenIs(token.STRING_IDENTIFIER) || p.currentTokenIs(token.IDENTIFIER) {
		ident := p.current.Literal
		identPos := p.current.Pos
		p.nextToken()

		// For string operators (#, @), we need to ensure the identifier is treated as a string
		// If it doesn't have a $ prefix, we'll add one for the AST node
		if op == token.HASH || op == token.AT {
			if !strings.HasPrefix(ident, "$") {
				ident = "$" + ident
			}
		}

		expr = p.builder.Identifier(identPos, ident)
	} else {
		// For other expressions, parse normally
		expr, err = p.parsePrimary()
		if err != nil {
			return nil, err
		}
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

// isDataTypeFunction checks if a token is a data type function (uint8, uint16, uint32, etc.)
func (p *Parser) isDataTypeFunction(t token.TokenType) bool {
	switch t {
	case token.INT8, token.INT16, token.INT32, token.UINT8, token.UINT16, token.UINT32,
		token.INT8BE, token.INT16BE, token.INT32BE, token.UINT8BE, token.UINT16BE, token.UINT32BE:
		return true
	default:
		return false
	}
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

// parseStringModifiers parses string modifiers (nocase, wide, ascii, fullword, private, xor, base64, etc.)
// Returns a slice of StringModifier structs representing the parsed modifiers
func (p *Parser) parseStringModifiers() []ast.StringModifier {
	modifiers := make([]ast.StringModifier, 0)

	for p.isStringModifier(p.current.Type) {
		modifierType := p.getStringModifierType(p.current.Type)
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

// parseExternalVariable parses an external variable declaration
func (p *Parser) parseExternalVariable() (*ast.ExternalVariable, error) {
	pos := p.current.Pos

	// Parse variable name
	if !p.currentTokenIs(token.IDENTIFIER) {
		return nil, fmt.Errorf("expected variable name after 'external'")
	}
	name := p.current.Literal
	p.nextToken()

	// External variables in YARA are declared as simple identifiers
	// The actual values are provided at runtime
	// Optional: support for type hints in the future
	var typeHint string
	if p.currentTokenIs(token.COLON) {
		p.nextToken() // consume ':'
		if p.currentTokenIs(token.IDENTIFIER) {
			typeHint = p.current.Literal
			p.nextToken()
		} else {
			return nil, fmt.Errorf("expected type hint after ':'")
		}
	}

	return p.builder.ExternalVariable(pos, name, name, typeHint), nil
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

// parseFunctionCall parses a function call expression
func (p *Parser) parseFunctionCall(pos token.Position, functionName string) (ast.Expression, error) {
	// Expect '('
	if !p.expectToken(token.LPAREN) {
		return nil, fmt.Errorf("expected '(' after function name")
	}

	// Parse arguments
	var args []ast.Expression

	// Check if this is an empty argument list
	if !p.currentTokenIs(token.RPAREN) {
		// Parse first argument
		arg, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)

		// Parse additional arguments separated by commas
		for p.currentTokenIs(token.COMMA) {
			p.nextToken() // consume ','

			nextArg, parseErr := p.parseExpression()
			if parseErr != nil {
				return nil, parseErr
			}
			args = append(args, nextArg)
		}
	}

	// Expect ')'
	if !p.expectToken(token.RPAREN) {
		return nil, fmt.Errorf("expected ')' after function arguments")
	}

	// Create function call node
	funcCall := p.builder.FunctionCall(pos, functionName, args)

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
		return p.builder.ArrayIndex(pos, funcCall, indexExpr), nil
	}

	// Return just the function call if no array indexing
	return funcCall, nil
}
