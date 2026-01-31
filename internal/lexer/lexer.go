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

// isStringLengthContext checks if the current ! should be treated as StringLength operator
// This is true when the next non-whitespace character starts an identifier that represents a string
func (l *Lexer) isStringLengthContext() bool {
	// Save current position
	snapshot := l.reader.SavePosition()
	defer l.reader.RestorePosition(snapshot)

	// Skip whitespace
	for l.reader.PeekChar() == ' ' || l.reader.PeekChar() == '\t' ||
		l.reader.PeekChar() == '\n' || l.reader.PeekChar() == '\r' {
		l.reader.ReadChar()
	}

	// String length applies only to $-prefixed string identifiers.
	peekChar := l.reader.PeekChar()
	return peekChar == '$'
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
