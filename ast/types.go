package ast

import "github.com/cawalch/go-yara/token"

// Modifier represents a rule modifier (private, global)
type Modifier int

const (
	ModifierPrivate Modifier = iota
	ModifierGlobal
)

// StringModifier represents string modifiers (nocase, wide, etc.)
type StringModifier struct {
	Type  StringModifierType
	Value interface{} // for xor ranges, base64 alphabets, etc.
}

// StringModifierType defines the type of string modifier
type StringModifierType int

const (
	StringModifierNocase StringModifierType = iota
	StringModifierWide
	StringModifierASCII
	StringModifierFullword
	StringModifierPrivate
	StringModifierXor
	StringModifierBase64
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

func (t *TextString) node()                    {}
func (t *TextString) Position() token.Position { return t.Pos }
func (t *TextString) pattern()                 {}
func (t *TextString) Accept(v Visitor) interface{} {
	return v.VisitTextString(t)
}

// HexString represents a hex string pattern
type HexString struct {
	Pos   token.Position
	Value string
}

func (h *HexString) node()                    {}
func (h *HexString) Position() token.Position { return h.Pos }
func (h *HexString) pattern()                 {}
func (h *HexString) Accept(v Visitor) interface{} {
	return v.VisitHexString(h)
}

// RegexPattern represents a regular expression pattern
type RegexPattern struct {
	Pos   token.Position
	Value string
}

func (r *RegexPattern) node()                    {}
func (r *RegexPattern) Position() token.Position { return r.Pos }
func (r *RegexPattern) pattern()                 {}
func (r *RegexPattern) Accept(v Visitor) interface{} {
	return v.VisitRegexPattern(r)
}