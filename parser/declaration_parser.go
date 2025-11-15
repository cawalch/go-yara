package parser

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
	internal "github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// DeclarationParser handles parsing of declarations in YARA rules (meta, strings, variables)
type DeclarationParser struct {
	lexer     *internal.Lexer
	current   token.Token
	peek      token.Token
	errors    []error
	builder   *ast.Builder
	nextToken func()
	addError  func(error)
}

// NewDeclarationParser creates a new declaration parser instance
func NewDeclarationParser(lexer *internal.Lexer, builder *ast.Builder) *DeclarationParser {
	return &DeclarationParser{
		lexer:   lexer,
		errors:  make([]error, 0),
		builder: builder,
	}
}

// SetTokenHandler sets the token handling functions for the parser
func (p *DeclarationParser) SetTokenHandler(nextToken func(), addError func(error)) {
	p.nextToken = nextToken
	p.addError = addError
}

// SetCurrentTokens sets the current and peek tokens
func (p *DeclarationParser) SetCurrentTokens(current, peek token.Token) {
	p.current = current
	p.peek = peek
}

// ParseMetaSection parses the optional meta section
func (p *DeclarationParser) ParseMetaSection() ([]*ast.Meta, error) {
	if !p.currentTokenIs(token.META) {
		return make([]*ast.Meta, 0), nil
	}

	p.nextToken()
	if !p.expectToken(token.COLON) {
		return nil, errors.New("expected ':' after meta")
	}

	return p.parseMetaDeclarations(), nil
}

// parseMetaDeclarations parses meta declarations in the format:
// meta:
//
//	key = value
//	another_key = "string value"
//	numeric_key = 42
//	bool_key = true
func (p *DeclarationParser) parseMetaDeclarations() []*ast.Meta {
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

// parseMetaEntry parses a single meta entry (key = value)
func (p *DeclarationParser) parseMetaEntry() (*ast.Meta, error) {
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

// parseMetaValue parses a meta value with comprehensive error handling
func (p *DeclarationParser) parseMetaValue() ast.MetaValue {
	pos := p.current.Pos

	switch {
	case p.currentTokenIs(token.StringLit):
		value := p.current.Literal
		p.nextToken()
		return ast.MetaString(value)
	case p.currentTokenIs(token.IntegerLit):
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

// ParseStringsSection parses the optional strings section
func (p *DeclarationParser) ParseStringsSection() ([]*ast.String, error) {
	if !p.currentTokenIs(token.STRINGS) {
		return make([]*ast.String, 0), nil
	}

	p.nextToken()
	if !p.expectToken(token.COLON) {
		return nil, errors.New("expected ':' after strings")
	}

	return p.parseStringDeclarations(), nil
}

// parseStringDeclarations parses string declarations in the strings section
func (p *DeclarationParser) parseStringDeclarations() []*ast.String {
	parsedStrings := make([]*ast.String, 0)

	for !p.currentTokenIs(token.CONDITION) && !p.currentTokenIs(token.RBRACE) {
		if !p.currentTokenIs(token.StringIdentifier) && !p.currentTokenIs(token.IDENTIFIER) {
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

// parseStringDeclaration parses a complete string declaration
func (p *DeclarationParser) parseStringDeclaration() (*ast.String, error) {
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

// parseStringIdentifier parses a string identifier and returns its components
func (p *DeclarationParser) parseStringIdentifier() (string, token.Position, error) {
	if !p.currentTokenIs(token.StringIdentifier) && !p.currentTokenIs(token.IDENTIFIER) {
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

// parseStringPattern parses a string pattern and returns the appropriate AST node
func (p *DeclarationParser) parseStringPattern(pos token.Position) (ast.Pattern, error) {
	switch {
	case p.currentTokenIs(token.StringLit):
		// Text string literal
		patternValue := p.current.Literal
		p.nextToken()
		return p.builder.TextString(pos, patternValue), nil
	case p.currentTokenIs(token.HexStringLit):
		// Hex string literal
		patternValue := p.current.Literal
		p.nextToken()
		return p.builder.HexString(pos, patternValue), nil
	case p.currentTokenIs(token.RegexLit):
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

// parseStringModifiers parses string modifiers (nocase, wide, ascii, fullword, private, xor, base64, etc.)
func (p *DeclarationParser) parseStringModifiers() []ast.StringModifier {
	modifiers := make([]ast.StringModifier, 0)

	for p.isStringModifier(p.current.Type) {
		modifierType := p.getStringModifierType(p.current.Type)

		if modifierType == ast.StringModifierXor {
			// XOR modifier requires a value
			p.nextToken() // consume XOR token

			// Parse the XOR value (integer literal)
			if !p.currentTokenIs(token.IntegerLit) && !p.currentTokenIs(token.HexIntegerLit) {
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

// ParseTagList parses a colon-separated list of identifiers (tags)
func (p *DeclarationParser) ParseTagList() []string {
	tags := make([]string, 0)
	if p.currentTokenIs(token.COLON) {
		p.nextToken()
		tags = p.consumeIdentifierSequence()
	}
	return tags
}

// consumeIdentifierSequence consumes consecutive identifiers and returns them
func (p *DeclarationParser) consumeIdentifierSequence() []string {
	identifiers := make([]string, 0)
	for p.currentTokenIs(token.IDENTIFIER) {
		identifiers = append(identifiers, p.current.Literal)
		p.nextToken()
	}
	return identifiers
}

// ParseGlobalVariable parses a global variable declaration
func (p *DeclarationParser) ParseGlobalVariable() (*ast.GlobalVariable, error) {
	pos := p.current.Pos

	// Parse variable name (GLOBAL token was already consumed)
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

// ParseExternalVariable parses an external variable declaration
func (p *DeclarationParser) ParseExternalVariable() (*ast.ExternalVariable, error) {
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

// ParseImport parses an import statement (IMPORT token already consumed)
func (p *DeclarationParser) ParseImport() (*ast.Import, error) {
	pos := p.current.Pos

	// Expect string literal for module name
	if !p.currentTokenIs(token.StringLit) {
		return nil, errors.New("expected string literal after 'import'")
	}
	module := p.current.Literal
	p.nextToken()

	return p.builder.Import(pos, module), nil
}

// ParseInclude parses an include statement (INCLUDE token already consumed)
func (p *DeclarationParser) ParseInclude() (*ast.Include, error) {
	pos := p.current.Pos

	// Expect string literal for file name
	if !p.currentTokenIs(token.StringLit) {
		return nil, errors.New("expected string literal after 'include'")
	}
	file := p.current.Literal
	p.nextToken()

	return p.builder.Include(pos, file), nil
}

// parseExpression is a placeholder for expression parsing
// This would typically delegate to an ExpressionParser
func (p *DeclarationParser) parseExpression() (ast.Expression, error) {
	// Simplified implementation for now - in the full refactoring, this would
	// delegate to the ExpressionParser instance
	if p.currentTokenIs(token.IntegerLit) {
		value := p.parseIntegerLiteral()
		pos := p.current.Pos
		p.nextToken()
		return p.builder.Literal(pos, token.IntegerLit, value), nil
	}
	if p.currentTokenIs(token.StringLit) {
		literal := p.current.Literal
		pos := p.current.Pos
		p.nextToken()
		return p.builder.Literal(pos, token.StringLit, literal), nil
	}
	return nil, fmt.Errorf("unsupported expression type: %s", p.current.Type)
}

// Helper methods
func (p *DeclarationParser) currentTokenIs(t token.Type) bool {
	return p.current.Type == t
}

func (p *DeclarationParser) expectToken(t token.Type) bool {
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

func (p *DeclarationParser) expectTokenWithMessage(tokenType token.Type, message string) error {
	if !p.expectToken(tokenType) {
		return fmt.Errorf("%s", message)
	}
	return nil
}

func (p *DeclarationParser) isIdentifierKeyword(tokenType token.Type) bool {
	// Keywords that can also be used as identifiers in certain contexts
	identifierKeywords := []token.Type{
		token.HASH,     // hash can be a meta key
		token.LENGTH,   // length can be a meta key
		token.CONTAINS, // contains can be a meta key
		token.MATCHES,  // matches can be a meta key
		// Add more as needed
	}

	return slices.Contains(identifierKeywords, tokenType)
}

func (p *DeclarationParser) getStringModifierType(tokenType token.Type) ast.StringModifierType {
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

func (p *DeclarationParser) isStringModifier(t token.Type) bool {
	return t == token.NOCASE || t == token.WIDE || t == token.ASCII ||
		t == token.FULLWORD || t == token.PRIVATE || t == token.XOR ||
		t == token.BASE64 || t == token.BASE64WIDE
}

func (p *DeclarationParser) parseIntegerLiteral() int64 {
	return p.parseIntLiteralWithBase(10, nil, "")
}

func (p *DeclarationParser) parseIntLiteralWithBase(base int, prefixes []string, literalType string) int64 {
	literal := p.current.Literal

	// Remove specified prefixes
	for _, prefix := range prefixes {
		literal = strings.TrimPrefix(literal, prefix)
		literal = strings.TrimPrefix(literal, strings.ToUpper(prefix))
	}

	if value, err := strconv.ParseInt(literal, base, 64); err == nil {
		return value
	}

	if literalType == "" {
		p.errors = append(p.errors, fmt.Errorf("invalid integer literal: %s at %v", p.current.Literal, p.current.Pos))
	} else {
		p.errors = append(p.errors, fmt.Errorf("invalid %s integer literal: %s at %v", literalType, p.current.Literal, p.current.Pos))
	}
	return 0
}
