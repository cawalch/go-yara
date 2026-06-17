package lexer

import (
	"github.com/cawalch/go-yara/token"
)

// NextToken returns the next token from the input
func (l *Lexer) NextToken() token.Token {
	tok := NextTokenImpl(l)
	l.updateSectionState(tok)
	l.lastTokenType = tok.Type
	return tok
}

// Implement TokenCreator interface methods
func (l *Lexer) getCurrentPosition() token.Position {
	return l.reader.CurrentPosition()
}

func (l *Lexer) getCurrentChar() byte {
	return l.reader.Current()
}

func (l *Lexer) getPeekChar() byte {
	return l.reader.PeekChar()
}

// isStringLengthContext checks if the current ! should be treated as the
// StringLength operator.
//
// Upstream YARA lexes '!' + an identifier run as a single _STRING_LENGTH_
// token via the regex `!({letter}|{digit}|_)*` — the '*' means a BARE '!' also
// matches, becoming the string-length placeholder for the current iteration's
// string in a for-loop body ("for all of them : (! > 3)"). '!' is documented
// ONLY as the string-length operator (logical NOT is the keyword `not`).
//
// History: go-yara originally treated '!' as StringLength only when followed
// by '$', so "!a" lexed as NOT + IDENTIFIER and the bare placeholder never
// parsed. #147 extended it to identifier characters so "!a" works. This change
// completes the upstream match: a bare '!' (no following identifier) is also
// StringLength — the loop placeholder.
//
// The one exception preserved for backward compatibility is '!' followed by
// '(': that remains logical NOT, so "!($a and $b)" keeps working. Every other
// following character (comparison operator, ')', EOF, etc.) makes '!' the
// StringLength placeholder, matching upstream.
func (l *Lexer) isStringLengthContext() bool {
	snapshot := l.reader.SavePosition()
	defer l.reader.RestorePosition(snapshot)

	// Skip whitespace
	for l.reader.PeekChar() == ' ' || l.reader.PeekChar() == '\t' ||
		l.reader.PeekChar() == '\n' || l.reader.PeekChar() == '\r' {
		l.reader.ReadChar()
	}

	// '!' followed by '(' is logical NOT of a grouped expression; everything
	// else is the string-length operator (named, $-prefixed, or bare
	// placeholder).
	return l.reader.PeekChar() != '('
}

// isRegexAllowed returns true when regex literals are valid in the current context.
func (l *Lexer) isRegexAllowed() bool {
	if l.section == sectionStrings {
		return true
	}
	// Allow standalone regex lexing before any section is known (compatibility/tests).
	if l.section == sectionNone {
		return true
	}
	return l.lastTokenType == token.MATCHES
}

// updateSectionState updates section tracking based on recently emitted tokens.
func (l *Lexer) updateSectionState(tok token.Token) {
	switch tok.Type {
	case token.META:
		l.pendingSection = sectionMeta
	case token.STRINGS:
		l.pendingSection = sectionStrings
	case token.CONDITION:
		l.pendingSection = sectionCondition
	case token.COLON:
		if l.pendingSection != sectionNone {
			l.section = l.pendingSection
			l.pendingSection = sectionNone
		}
	case token.RBRACE:
		l.section = sectionNone
		l.pendingSection = sectionNone
	default:
		if l.pendingSection != sectionNone && tok.Type != token.ILLEGAL {
			l.pendingSection = sectionNone
		}
	}
}
