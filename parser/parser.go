// Package parser implements a recursive descent parser for YARA rules.
// It consumes tokens from the lexer and builds an Abstract Syntax Tree (AST).
package parser

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// ErrNotQuantifier is a sentinel error indicating that a token sequence is not a quantifier
var ErrNotQuantifier = errors.New("not a quantifier")

// ErrNotLiteral is a sentinel error indicating that a token is not a literal
var ErrNotLiteral = errors.New("not a literal")

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

// isUnaryOperator checks if the given token type represents a unary operator
func (p *Parser) isUnaryOperator(tokenType token.TokenType) bool {
	switch tokenType {
	case token.DEFINED, token.AT, token.IN, token.HASH:
		return true
	default:
		return false
	}
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
		return p.parseRuleDeclaration(program)
	default:
		return fmt.Errorf("unexpected token %s at %v", p.current.Type, p.current.Pos)
	}
}

func (p *Parser) parseGlobalDeclaration(program *ast.Program) error {
	// Check if this is a global variable declaration or a global rule modifier
	if p.peekTokenIs(token.RULE) || p.peekTokenIs(token.PRIVATE) {
		// This is a global rule modifier
		rule, err := p.parseRule()
		if err == nil {
			program.Rules = append(program.Rules, rule)
		}
		return err
	} else {
		// This is a global variable declaration
		p.nextToken() // consume GLOBAL token
		globalVar, err := p.parseGlobalVariable()
		if err == nil {
			program.GlobalVariables = append(program.GlobalVariables, globalVar)
		}
		return err
	}
}

func (p *Parser) parseExternalDeclaration(program *ast.Program) error {
	p.nextToken() // consume EXTERNAL token
	externalVar, err := p.parseExternalVariable()
	if err == nil {
		program.ExternalVariables = append(program.ExternalVariables, externalVar)
	}
	return err
}

func (p *Parser) parseImportDeclaration(program *ast.Program) error {
	importStmt, err := p.parseImport()
	if err == nil {
		program.Imports = append(program.Imports, importStmt)
	}
	return err
}

func (p *Parser) parseIncludeDeclaration(program *ast.Program) error {
	includeStmt, err := p.parseInclude()
	if err == nil {
		program.Includes = append(program.Includes, includeStmt)
	}
	return err
}

func (p *Parser) parseRuleDeclaration(program *ast.Program) error {
	rule, err := p.parseRule()
	if err == nil {
		program.Rules = append(program.Rules, rule)
	}
	return err
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
	p.errors = append(
		p.errors,
		fmt.Errorf("expected %s, got %s at %v", t, p.current.Type, p.current.Pos),
	)
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
		p.addError(
			fmt.Errorf(
				"invalid meta value type '%s' at %v - expected string, integer, or boolean",
				p.current.Type,
				pos,
			),
		)
		return nil
	}
}

// parseMetaEntry parses a single meta entry (key = value)
func (p *Parser) parseMetaEntry() (*ast.Meta, error) {
	// Meta keys can be identifiers or keywords that can also serve as identifiers
	if !p.currentTokenIs(token.IDENTIFIER) && !p.isIdentifierKeyword(p.current.Type) {
		return nil, fmt.Errorf(
			"expected identifier for meta key at %v, got %s",
			p.current.Pos,
			p.current.Type,
		)
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

// isIdentifierKeyword checks if a token type represents a keyword that can also be used as an identifier
// This is needed for contexts like meta keys where keywords like "hash" should be treated as identifiers
func (p *Parser) isIdentifierKeyword(tokenType token.TokenType) bool {
	// Keywords that can also be used as identifiers in certain contexts
	identifierKeywords := []token.TokenType{
		token.HASH,     // hash can be a meta key
		token.LENGTH,   // length can be a meta key
		token.CONTAINS, // contains can be a meta key
		token.MATCHES,  // matches can be a meta key
		// Add more as needed
	}

	return slices.Contains(identifierKeywords, tokenType)
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
		return "", token.Position{}, fmt.Errorf(
			"expected string identifier at %v, got %s",
			p.current.Pos,
			p.current.Type,
		)
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
		return nil, fmt.Errorf(
			"expected string, hex, or regex literal at %v, got %s",
			p.current.Pos,
			p.current.Type,
		)
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
	return slices.ContainsFunc(tokenTypes, p.currentTokenIs)
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
		return nil, fmt.Errorf("expected rule name, %w", err)
	}

	// Parse tags
	tags := p.parseTagList()

	if !p.expectToken(token.LBRACE) {
		return nil, errors.New("expected '{' after rule declaration")
	}

	// Parse meta section
	meta := make([]*ast.Meta, 0)
	if p.currentTokenIs(token.META) {
		p.nextToken()
		if !p.expectToken(token.COLON) {
			return nil, errors.New("expected ':' after meta")
		}
		meta = p.parseMetaDeclarations()
	}

	// Parse strings section
	ruleStrings := make([]*ast.String, 0)
	if p.currentTokenIs(token.STRINGS) {
		p.nextToken()
		if !p.expectToken(token.COLON) {
			return nil, errors.New("expected ':' after strings")
		}
		ruleStrings = p.parseStringDeclarations()
	}

	// Parse condition section
	if !p.expectToken(token.CONDITION) {
		return nil, errors.New("expected condition section")
	}
	if !p.expectToken(token.COLON) {
		return nil, errors.New("expected ':' after condition")
	}

	condition, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if !p.expectToken(token.RBRACE) {
		return nil, errors.New("expected '}' at end of rule")
	}

	rule := p.builder.Rule(p.current.Pos, ruleName)
	rule.Modifiers = modifiers
	rule.Tags = tags
	rule.Meta = meta
	rule.Strings = ruleStrings
	rule.Condition = condition

	return rule, nil
}

// parseImport parses an import statement
func (p *Parser) parseImport() (*ast.Import, error) {
	pos := p.current.Pos

	// Expect IMPORT keyword
	if !p.expectToken(token.IMPORT) {
		return nil, errors.New("expected 'import' keyword")
	}

	// Expect string literal for module name
	if !p.currentTokenIs(token.STRING_LIT) {
		return nil, errors.New("expected string literal after 'import'")
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
		if !p.currentTokenIs(token.IDENTIFIER) && !p.isIdentifierKeyword(p.current.Type) {
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
	parsedStrings := make([]*ast.String, 0)

	for !p.currentTokenIs(token.CONDITION) && !p.currentTokenIs(token.RBRACE) {
		if !p.currentTokenIs(token.STRING_IDENTIFIER) && !p.currentTokenIs(token.IDENTIFIER) {
			break
		}

		str, err := p.parseStringDeclaration()
		if err != nil {
			p.addError(err)
		} else if str != nil {
			parsedStrings = append(parsedStrings, str)
		}
	}

	return parsedStrings
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
		if errors.Is(err, ErrNotQuantifier) {
			// Not a quantifier, continue with other parsing methods
			return p.parseComparison()
		}
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

	return p.parseBinaryExpression(left, p.parseMultiplicative, []token.TokenType{token.PLUS, token.MINUS})
}

// parseMultiplicative parses multiplication, division, and modulo
func (p *Parser) parseMultiplicative() (ast.Expression, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseUnary, []token.TokenType{token.MULTIPLY, token.DIVIDE, token.MODULO, token.INT_DIVIDE})
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

	return p.parseBinaryExpression(left, p.parseAdditive, []token.TokenType{token.LEFT_SHIFT, token.RIGHT_SHIFT})
}

// parseBitwiseAnd parses bitwise AND operations
func (p *Parser) parseBitwiseAnd() (ast.Expression, error) {
	left, err := p.parseBitwiseShift()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseBitwiseShift, []token.TokenType{token.BITWISE_AND})
}

// parseBitwiseXor parses bitwise XOR operations
func (p *Parser) parseBitwiseXor() (ast.Expression, error) {
	left, err := p.parseBitwiseAnd()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseBitwiseAnd, []token.TokenType{token.BITWISE_XOR})
}

// parseBitwiseOr parses bitwise OR operations
func (p *Parser) parseBitwiseOr() (ast.Expression, error) {
	left, err := p.parseBitwiseXor()
	if err != nil {
		return nil, err
	}

	return p.parseBinaryExpression(left, p.parseBitwiseXor, []token.TokenType{token.BITWISE_OR})
}

// parseStringIdentifierExpression parses string identifier expressions with optional offset/length
func (p *Parser) parseStringIdentifierExpression(pos token.Position) (ast.Expression, error) {
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

// parseDataTypeFunction parses data type function calls (uint8, uint16, uint32, etc.)
func (p *Parser) parseDataTypeFunction(pos token.Position) (ast.Expression, error) {
	functionName := p.current.Literal
	funcPos := p.current.Pos
	p.nextToken()

	// Check for function call
	if p.currentTokenIs(token.LPAREN) {
		return p.parseFunctionCall(funcPos, functionName)
	}

	return nil, fmt.Errorf("expected '(' after data type function %s", functionName)
}

// parseParenthesizedExpression parses parenthesized expressions
func (p *Parser) parseParenthesizedExpression() (ast.Expression, error) {
	p.nextToken()
	expr, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	if !p.expectToken(token.RPAREN) {
		return nil, errors.New("expected ')' after expression")
	}
	return expr, nil
}

// parseUnaryWithArrayIndex parses unary operator expressions with optional array indexing
func (p *Parser) parseUnaryWithArrayIndex(pos token.Position) (ast.Expression, error) {
	expr, err := p.parseUnaryOperator(pos)
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
			return nil, errors.New("expected ']' after array index")
		}

		// Create array index expression
		return p.builder.ArrayIndex(pos, expr, indexExpr), nil
	}

	return expr, nil
}

// parsePrimary parses primary expressions
func (p *Parser) parsePrimary() (ast.Expression, error) {
	pos := p.current.Pos

	// Try to parse string identifiers first (highest priority for string tokens)
	if p.currentTokenIs(token.STRING_IDENTIFIER) {
		return p.parseStringIdentifierExpression(pos)
	}

	// Try to parse literals
	if expr, err := p.parseLiteral(pos); expr != nil || (err != nil && !errors.Is(err, ErrNotLiteral)) {
		return expr, err
	}

	// Try to parse data type function calls (uint8, uint16, uint32, etc.)
	if p.isDataTypeFunction(p.current.Type) {
		return p.parseDataTypeFunction(pos)
	}

	// Try to parse quantifier expressions
	if expr, err := p.parseQuantifier(pos); expr != nil || (err != nil && !errors.Is(err, ErrNotQuantifier)) {
		return expr, err
	}

	// Try to parse special keywords
	if expr := p.parseSpecialKeyword(pos); expr != nil {
		return expr, nil
	}

	// Parenthesized expressions
	if p.currentTokenIs(token.LPAREN) {
		return p.parseParenthesizedExpression()
	}

	// Try to parse unary operators
	if p.isUnaryOperator(p.current.Type) {
		return p.parseUnaryWithArrayIndex(pos)
	}

	// Regular identifiers
	if p.currentTokenIs(token.IDENTIFIER) {
		ident := p.current.Literal
		p.nextToken()

		// Handle member access for enums
		if p.currentTokenIs(token.DOT) {
			p.nextToken() // consume '.'
			memberIdent := p.current.Literal
			if !p.currentTokenIs(token.IDENTIFIER) {
				return nil, errors.New("expected identifier after '.' for enum member access")
			}
			p.nextToken()

			return p.builder.BinaryOp(
				pos,
				p.builder.Identifier(pos, ident),
				token.DOT,
				p.builder.Identifier(pos, memberIdent),
			), nil
		}

		return p.builder.Identifier(pos, ident), nil
	}

	return nil, fmt.Errorf("unexpected token %s at %v", p.current.Type, p.current.Pos)
}

// parsePrimaryExcludingUnary parses primary expressions but excludes unary operators
// This is used to avoid infinite recursion when parsing unary operator operands
func (p *Parser) parsePrimaryExcludingUnary() (ast.Expression, error) {
	pos := p.current.Pos

	// Try to parse string identifiers first (highest priority for string tokens)
	if p.currentTokenIs(token.STRING_IDENTIFIER) {
		return p.parseStringIdentifierExpression(pos)
	}

	// Try to parse literals
	if expr, err := p.parseLiteral(pos); expr != nil || (err != nil && !errors.Is(err, ErrNotLiteral)) {
		return expr, err
	}

	// Try to parse data type function calls (uint8, uint16, uint32, etc.)
	if p.isDataTypeFunction(p.current.Type) {
		return p.parseDataTypeFunction(pos)
	}

	// Try to parse quantifier expressions
	if expr, err := p.parseQuantifier(pos); expr != nil || (err != nil && !errors.Is(err, ErrNotQuantifier)) {
		return expr, err
	}

	// Try to parse special keywords
	if expr := p.parseSpecialKeyword(pos); expr != nil {
		return expr, nil
	}

	// Parenthesized expressions
	if p.currentTokenIs(token.LPAREN) {
		return p.parseParenthesizedExpression()
	}

	// Regular identifiers
	if p.currentTokenIs(token.IDENTIFIER) {
		ident := p.current.Literal
		p.nextToken()

		// Handle member access for enums
		if p.currentTokenIs(token.DOT) {
			p.nextToken() // consume '.'
			memberIdent := p.current.Literal
			if !p.currentTokenIs(token.IDENTIFIER) {
				return nil, errors.New("expected identifier after '.' for enum member access")
			}
			p.nextToken()

			return p.builder.BinaryOp(
				pos,
				p.builder.Identifier(pos, ident),
				token.DOT,
				p.builder.Identifier(pos, memberIdent),
			), nil
		}

		return p.builder.Identifier(pos, ident), nil
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

	if p.currentTokenIs(token.OCTAL_INTEGER_LIT) {
		value := p.parseOctalIntegerLiteral()
		p.nextToken()
		return p.builder.Literal(pos, token.OCTAL_INTEGER_LIT, value), nil
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

	// Not a literal token, return ErrNotLiteral to let other parsing methods handle it
	return nil, ErrNotLiteral
}

// parseForQuantifier parses "for" quantifier expressions with optional variables and ranges
func (p *Parser) parseForQuantifier(pos token.Position) (ast.Expression, error) {
	// Parse the quantifier after 'for'
	if !p.currentTokenIs(token.ALL) && !p.currentTokenIs(token.ANY) &&
		!p.currentTokenIs(token.NONE) {
		return nil, errors.New("expected quantifier (all/any/none) after 'for'")
	}

	quantifier := p.current.Literal
	p.nextToken()

	// Check if this is a for loop with variable (for all i in (0..9) : ...)
	// In this case, we don't expect 'of' after the quantifier
	if p.currentTokenIs(token.IDENTIFIER) {
		return p.parseForLoopWithVariable(pos, quantifier)
	}

	// For standard "for" quantifiers without variables, we expect 'of'
	if !p.expectToken(token.OF) {
		return nil, errors.New("expected 'of' after quantifier")
	}

	// Parse the target (them, string patterns, etc.)
	target, err := p.parseQuantifierTarget(pos)
	if err != nil {
		return nil, err
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

// parseForLoopWithVariable parses for loops with variables like "for all i in (0..9) : ..."
func (p *Parser) parseForLoopWithVariable(pos token.Position, quantifier string) (ast.Expression, error) {
	variableName := p.current.Literal
	p.nextToken()

	if !p.expectToken(token.IN) {
		return nil, errors.New("expected 'in' after variable name in for loop")
	}

	// Parse the range expression
	rangeExpr, err := p.parseRangeExpression()
	if err != nil {
		return nil, err
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

	return nil, errors.New("expected ':' after for loop range")
}

// parseRangeExpression parses range expressions, handling both parenthesized ranges and regular expressions
func (p *Parser) parseRangeExpression() (ast.Expression, error) {
	var rangeExpr ast.Expression
	var err error

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
			rangeExpr = left
		}

		if !p.expectToken(token.RPAREN) {
			return nil, errors.New("expected ')' after range expression")
		}
	} else {
		// Parse regular expression
		rangeExpr, err = p.parsePrimary()
		if err != nil {
			return nil, err
		}
	}

	return rangeExpr, nil
}

// parseStandardQuantifier parses standard quantifiers (all/any/none of them) and numeric quantifiers
func (p *Parser) parseStandardQuantifier(pos token.Position) (ast.Expression, error) {
	var quantifierExpr ast.Expression

	// Check for numeric quantifier first (e.g., "1 of", "2 of")
	// Only treat as quantifier if the next token is OF
	switch {
	case (p.currentTokenIs(token.INTEGER_LIT) || p.currentTokenIs(token.HEX_INTEGER_LIT) || p.currentTokenIs(token.OCTAL_INTEGER_LIT)) && p.peekTokenIs(token.OF):
		var err error
		quantifierExpr, err = p.parsePrimary()
		if err != nil {
			return nil, err
		}

		if !p.expectToken(token.OF) {
			return nil, errors.New("expected 'of' after count")
		}
	case p.currentTokenIs(token.ALL) || p.currentTokenIs(token.ANY) || p.currentTokenIs(token.NONE):
		quantifier := p.current.Literal
		p.nextToken()

		if !p.expectToken(token.OF) {
			return nil, errors.New("expected 'of' after quantifier")
		}

		quantifierExpr = p.builder.Identifier(pos, quantifier)
	default:
		return nil, fmt.Errorf("invalid quantifier token %s at %v", p.current.Type, p.current.Pos)
	}

	// Parse the target (them, string patterns, etc.)
	target, err := p.parseQuantifierTarget(pos)
	if err != nil {
		return nil, err
	}

	// Create an OfExpression node
	return p.builder.OfExpression(pos, quantifierExpr, target), nil
}

// parseQuantifierTarget parses the target part of quantifier expressions (them, string patterns, etc.)
func (p *Parser) parseQuantifierTarget(pos token.Position) (ast.Expression, error) {
	switch {
	case p.currentTokenIs(token.THEM):
		target := p.builder.Identifier(pos, "them")
		p.nextToken()
		return target, nil
	case p.currentTokenIs(token.STRING_IDENTIFIER):
		target := p.builder.Identifier(pos, p.current.Literal)
		p.nextToken()
		return target, nil
	case p.currentTokenIs(token.LPAREN):
		return p.parseParenthesizedTarget(pos)
	default:
		return nil, errors.New("expected 'them', string pattern, or '(' after 'of'")
	}
}

// parseParenthesizedTarget parses parenthesized expressions in quantifier targets
func (p *Parser) parseParenthesizedTarget(pos token.Position) (ast.Expression, error) {
	p.nextToken() // consume '('

	// Check if this is a comma-separated list of string identifiers
	var expressions []ast.Expression
	expressions = append(expressions, nil) // placeholder for first expression

	// Parse the first expression
	switch {
	case p.currentTokenIs(token.STRING_IDENTIFIER) && p.current.Literal == "$":
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
		return nil, errors.New("expected ')' after expression")
	}

	// If we have multiple expressions, create a comma expression
	if len(expressions) > 1 {
		// Create a temporary representation for comma-separated list
		// This is a workaround until we have proper list AST nodes
		target := expressions[0]
		for i := 1; i < len(expressions); i++ {
			target = p.builder.BinaryOp(pos, target, token.COMMA, expressions[i])
		}
		return target, nil
	}

	return expressions[0], nil
}

// parseQuantifier parses quantifier expressions (all/any/none of them, for any of them)
func (p *Parser) parseQuantifier(pos token.Position) (ast.Expression, error) {
	// Handle "for" quantifier syntax
	if p.currentTokenIs(token.FOR) {
		p.nextToken() // consume 'for'
		return p.parseForQuantifier(pos)
	}

	// Check if this could be a standard quantifier (all/any/none) or numeric quantifier
	isQuantifierToken := p.currentTokenIs(token.ALL) ||
		p.currentTokenIs(token.ANY) ||
		p.currentTokenIs(token.NONE) ||
		(p.currentTokenIs(token.INTEGER_LIT) && p.peekTokenIs(token.OF)) ||
		(p.currentTokenIs(token.HEX_INTEGER_LIT) && p.peekTokenIs(token.OF)) ||
		(p.currentTokenIs(token.OCTAL_INTEGER_LIT) && p.peekTokenIs(token.OF))

	if !isQuantifierToken {
		// Not a quantifier, return nil to allow other parsing methods to try
		return nil, ErrNotQuantifier
	}

	// Handle standard quantifier syntax (all/any/none of them) and numeric quantifiers
	return p.parseStandardQuantifier(pos)
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
		return nil, fmt.Errorf("expected unary operator at %v", p.current.Pos)
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
		// For other expressions, parse normally but avoid recursion
		// Call parsePrimaryExcludingUnary to avoid infinite recursion
		expr, err = p.parsePrimaryExcludingUnary()
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
			return nil, errors.New("expected ']' after array index")
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

// parseIntLiteralWithBase parses an integer literal with specified base and prefixes
func (p *Parser) parseIntLiteralWithBase(base int, prefixes []string, literalType string) int64 {
	literal := p.current.Literal

	// Remove specified prefixes
	for _, prefix := range prefixes {
		literal = strings.TrimPrefix(literal, prefix)
		literal = strings.TrimPrefix(literal, strings.ToUpper(prefix))
	}

	// Parse integer with specified base
	if value, err := strconv.ParseInt(literal, base, 64); err == nil {
		return value
	}

	// If parsing fails, return 0 and log error
	if literalType == "" {
		p.errors = append(p.errors, fmt.Errorf("invalid integer literal: %s at %v", p.current.Literal, p.current.Pos))
	} else {
		p.errors = append(p.errors, fmt.Errorf("invalid %s integer literal: %s at %v", literalType, p.current.Literal, p.current.Pos))
	}
	return 0
}

// parseIntegerLiteral parses a decimal integer literal token and returns the int64 value
func (p *Parser) parseIntegerLiteral() int64 {
	return p.parseIntLiteralWithBase(10, nil, "")
}

// parseHexIntegerLiteral parses a hex integer literal token and returns the int64 value
func (p *Parser) parseHexIntegerLiteral() int64 {
	return p.parseIntLiteralWithBase(16, []string{"0x"}, "hex")
}

// parseOctalIntegerLiteral parses an octal integer literal token and returns the int64 value
func (p *Parser) parseOctalIntegerLiteral() int64 {
	return p.parseIntLiteralWithBase(8, []string{"0o"}, "octal")
}

// parseFloatLiteral parses a float literal token and returns the float64 value
func (p *Parser) parseFloatLiteral() float64 {
	literal := p.current.Literal

	// Parse float
	if value, err := strconv.ParseFloat(literal, 64); err == nil {
		return value
	}

	// If parsing fails, return 0 and log error
	p.errors = append(
		p.errors,
		fmt.Errorf("invalid float literal: %s at %v", literal, p.current.Pos),
	)
	return 0
}

// parseStringModifiers parses string modifiers (nocase, wide, ascii, fullword, private, xor, base64, etc.)
// Returns a slice of StringModifier structs representing the parsed modifiers
func (p *Parser) parseStringModifiers() []ast.StringModifier {
	modifiers := make([]ast.StringModifier, 0)

	for p.isStringModifier(p.current.Type) {
		modifierType := p.getStringModifierType(p.current.Type)

		if modifierType == ast.StringModifierXor {
			// XOR modifier requires a value
			p.nextToken() // consume XOR token

			// Parse the XOR value (integer literal)
			if !p.currentTokenIs(token.INTEGER_LIT) && !p.currentTokenIs(token.HEX_INTEGER_LIT) {
				p.addError(errors.New("expected integer value after 'xor' modifier"))
				// Add a default XOR modifier to continue parsing
				modifiers = append(modifiers, ast.StringModifier{Type: modifierType, Value: 0})
				continue
			}

			xorValue, err := strconv.ParseInt(p.current.Literal, 0, 64)
			if err != nil {
				p.addError(
					fmt.Errorf("invalid integer value for xor modifier: %s", p.current.Literal),
				)
				xorValue = 0
			}

			modifiers = append(modifiers, ast.StringModifier{Type: modifierType, Value: xorValue})
			p.nextToken() // consume the XOR value
		} else {
			// Other modifiers don't need values
			modifiers = append(modifiers, ast.StringModifier{Type: modifierType})
			p.nextToken()
		}
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
		return nil, errors.New("expected variable name after 'global'")
	}
	name := p.current.Literal
	p.nextToken()

	// Expect assignment operator
	if !p.expectToken(token.ASSIGN) {
		return nil, errors.New("expected '=' after variable name")
	}

	// Parse variable value
	value, err := p.parseExpression()
	if err != nil {
		return nil, errors.New("expected expression after '='")
	}

	return p.builder.GlobalVariable(pos, name, value), nil
}

// parseExternalVariable parses an external variable declaration
func (p *Parser) parseExternalVariable() (*ast.ExternalVariable, error) {
	pos := p.current.Pos

	// Parse variable name
	if !p.currentTokenIs(token.IDENTIFIER) {
		return nil, errors.New("expected variable name after 'external'")
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
			return nil, errors.New("expected type hint after ':'")
		}
	}

	return p.builder.ExternalVariable(pos, name, name, typeHint), nil
}

// parseInclude parses an include statement
func (p *Parser) parseInclude() (*ast.Include, error) {
	pos := p.current.Pos

	// Expect INCLUDE keyword
	if !p.expectToken(token.INCLUDE) {
		return nil, errors.New("expected 'include' keyword")
	}

	// Expect string literal for file name
	if !p.currentTokenIs(token.STRING_LIT) {
		return nil, errors.New("expected string literal after 'include'")
	}
	file := p.current.Literal
	p.nextToken()

	return p.builder.Include(pos, file), nil
}

// parseFunctionCall parses a function call expression
func (p *Parser) parseFunctionCall(
	pos token.Position,
	functionName string,
) (ast.Expression, error) {
	// Expect '('
	if !p.expectToken(token.LPAREN) {
		return nil, errors.New("expected '(' after function name")
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
		return nil, errors.New("expected ')' after function arguments")
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
			return nil, errors.New("expected ']' after array index")
		}

		// Create array index expression
		return p.builder.ArrayIndex(pos, funcCall, indexExpr), nil
	}

	// Return just the function call if no array indexing
	return funcCall, nil
}
