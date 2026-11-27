// Package ast provides abstract syntax tree (AST) definitions for YARA rules.
// It defines the structure and interfaces for representing YARA language constructs
// in a tree format that can be traversed and analyzed.
package ast

import (
	"errors"
	"fmt"

	"github.com/cawalch/go-yara/token"
)

// Node is the base interface for all AST nodes
type Node interface {
	// node() ensures only AST nodes can be assigned to this interface
	node()
	// Position returns the position of the node in the source
	Position() token.Position
}

// Expression is the interface for expression nodes
type Expression interface {
	Node
	expression()
}

// Statement is the interface for statement nodes
type Statement interface {
	Node
	statement()
}

// DefaultBase64Alphabet is the alphabet used by base64 modifiers without an argument.
const DefaultBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// ValidateBase64Alphabet validates a custom 64-character base64 alphabet modifier value.
func ValidateBase64Alphabet(value any) error {
	alphabet, ok := value.(string)
	if !ok || alphabet == "" {
		return nil
	}
	if len(alphabet) != 64 {
		return fmt.Errorf("invalid base64 alphabet length: expected 64, got %d", len(alphabet))
	}
	var seen [256]bool
	for i := 0; i < len(alphabet); i++ {
		ch := alphabet[i]
		if ch == '=' {
			return errors.New("invalid base64 alphabet: '=' is not allowed")
		}
		if seen[ch] {
			return errors.New("invalid base64 alphabet: duplicate characters")
		}
		seen[ch] = true
	}
	return nil
}

// ValidateBase64Modifiers validates the alphabets of base64 and base64wide.
// Both modifiers may be present if their effective alphabets agree.
func ValidateBase64Modifiers(modifiers []StringModifier) error {
	var alphabet string
	for _, mod := range modifiers {
		if mod.Type != StringModifierBase64 && mod.Type != StringModifierBase64Wide {
			continue
		}
		if err := ValidateBase64Alphabet(mod.Value); err != nil {
			return err
		}
		effective, _ := mod.Value.(string)
		if effective == "" {
			effective = DefaultBase64Alphabet
		}
		if alphabet != "" && alphabet != effective {
			return errors.New("cannot specify multiple alphabets for 'base64' and 'base64wide'")
		}
		alphabet = effective
	}
	return nil
}

// ValidateXorModifier validates a xor modifier value (single byte or XorRange).
func ValidateXorModifier(value any) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case XorRange:
		return ValidateXorRange(v.Min, v.Max)
	case *XorRange:
		if v == nil {
			return nil
		}
		return ValidateXorRange(v.Min, v.Max)
	case int64:
		return ValidateXorRange(v, v)
	case int:
		return ValidateXorRange(int64(v), int64(v))
	default:
		return nil
	}
}

// ValidateXorRange validates an inclusive xor byte range [0, 255].
func ValidateXorRange(minVal, maxVal int64) error {
	if minVal < 0 || maxVal < 0 || minVal > 255 || maxVal > 255 {
		return errors.New("xor range must be within 0..255")
	}
	if maxVal < minVal {
		return errors.New("xor range max must be >= min")
	}
	return nil
}
