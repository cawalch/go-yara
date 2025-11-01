package ast

import "github.com/cawalch/go-yara/token"

// Modifier represents a rule modifier (private, global)
type Modifier int

const (
	// ModifierPrivate marks a rule as private
	ModifierPrivate Modifier = iota
	// ModifierGlobal marks a rule as global
	ModifierGlobal
)

// StringModifier represents string modifiers (nocase, wide, etc.)
type StringModifier struct {
	Type  StringModifierType
	Value any // for xor ranges, base64 alphabets, etc.
}

// StringModifierType defines the type of string modifier
type StringModifierType int

const (
	// StringModifierNocase makes string matching case-insensitive
	StringModifierNocase StringModifierType = iota
	// StringModifierWide matches wide (UTF-16) strings
	StringModifierWide
	// StringModifierASCII matches ASCII strings
	StringModifierASCII
	// StringModifierFullword matches full words only
	StringModifierFullword
	// StringModifierPrivate marks string as private
	StringModifierPrivate
	// StringModifierXor applies XOR encoding
	StringModifierXor
	// StringModifierBase64 applies Base64 encoding
	StringModifierBase64
	// StringModifierBase64Wide applies Base64 encoding to wide strings
	StringModifierBase64Wide
)

// Pattern represents different types of string patterns
type Pattern interface {
	Node
	pattern()
}

// TextString represents a text string pattern
type TextString struct {
	Pos   token.Position
	Value string
}

func (t *TextString) node() {}

// Position returns the position of the TextString node
func (t *TextString) Position() token.Position { return t.Pos }

func (t *TextString) pattern() {}

// Accept implements the Visitor pattern for TextString
func (t *TextString) Accept(v Visitor) any {
	return v.VisitTextString(t)
}

// HexString represents a hex string pattern
type HexString struct {
	Pos   token.Position
	Value string
}

func (h *HexString) node() {}

// Position returns the position of the HexString node
func (h *HexString) Position() token.Position { return h.Pos }

func (h *HexString) pattern() {}

// Accept implements the Visitor pattern for HexString
func (h *HexString) Accept(v Visitor) any {
	return v.VisitHexString(h)
}

// RegexPattern represents a regular expression pattern
type RegexPattern struct {
	Pos   token.Position
	Value string
}

func (r *RegexPattern) node() {}

// Position returns the position of the RegexPattern node
func (r *RegexPattern) Position() token.Position { return r.Pos }

func (r *RegexPattern) pattern() {}

// Accept implements the Visitor pattern for RegexPattern
func (r *RegexPattern) Accept(v Visitor) any {
	return v.VisitRegexPattern(r)
}
