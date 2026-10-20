package semantic

import (
	"errors"
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func (v *Validator) validateStringModifiers(rule *ast.Rule) {
	for _, str := range rule.Strings {
		if str == nil {
			continue
		}

		seenModifiers := make(map[ast.StringModifierType]token.Position)
		hasWide := false
		hasASCII := false
		hasBase64 := false
		hasBase64Wide := false
		hasXor := false
		hasNocase := false
		hasFullword := false

		_, isRegex := str.Pattern.(*ast.RegexPattern)
		_, isHex := str.Pattern.(*ast.HexString)

		for _, mod := range str.Modifiers {
			if mod.Type != ast.StringModifierCapture {
				if prevPos, exists := seenModifiers[mod.Type]; exists {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  fmt.Sprintf("string %s declares duplicate modifier '%s' (previously at %v)", str.Identifier, modifierTypeName(mod.Type), prevPos),
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
				seenModifiers[mod.Type] = str.Pos
			}

			switch mod.Type {
			case ast.StringModifierWide:
				hasWide = true
				if isHex {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  fmt.Sprintf("hex string %s cannot have 'wide' modifier", str.Identifier),
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
			case ast.StringModifierASCII:
				hasASCII = true
				if isHex {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  fmt.Sprintf("hex string %s cannot have 'ascii' modifier", str.Identifier),
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
			case ast.StringModifierNocase:
				hasNocase = true
				if isHex {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  fmt.Sprintf("hex string %s cannot have 'nocase' modifier", str.Identifier),
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
			case ast.StringModifierFullword:
				hasFullword = true
				if isHex {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  fmt.Sprintf("hex string %s cannot have 'fullword' modifier", str.Identifier),
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
			case ast.StringModifierBase64:
				hasBase64 = true
				if isHex || isRegex {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  "base64 modifiers are only supported for text strings",
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
				if err := validateSemanticBase64Alphabet(mod.Value); err != nil {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  err.Error(),
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
			case ast.StringModifierBase64Wide:
				hasBase64Wide = true
				if isHex || isRegex {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  "base64 modifiers are only supported for text strings",
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
				if err := validateSemanticBase64Alphabet(mod.Value); err != nil {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  err.Error(),
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
			case ast.StringModifierXor:
				hasXor = true
				if isRegex {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  fmt.Sprintf("regex string %s cannot have 'xor' modifier", str.Identifier),
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
				if err := validateSemanticXorModifier(mod.Value); err != nil {
					v.addError(&Error{
						Code:     ErrCodeInvalidModifier,
						Message:  err.Error(),
						Position: str.Pos,
						Rule:     rule.Name,
					})
				}
			}
		}

		if hasBase64 && hasBase64Wide {
			v.addError(&Error{
				Code:     ErrCodeInvalidModifier,
				Message:  "cannot use both 'base64' and 'base64wide' modifiers",
				Position: str.Pos,
				Rule:     rule.Name,
			})
		}
		if (hasBase64 || hasBase64Wide) && (hasXor || hasNocase || hasFullword) {
			v.addError(&Error{
				Code:     ErrCodeInvalidModifier,
				Message:  "base64 modifiers are incompatible with 'xor', 'nocase', or 'fullword'",
				Position: str.Pos,
				Rule:     rule.Name,
			})
		}
		if (hasBase64 || hasBase64Wide) && (hasWide || hasASCII) {
			v.addError(&Error{
				Code:     ErrCodeInvalidModifier,
				Message:  "base64 modifiers are incompatible with 'wide' or 'ascii'",
				Position: str.Pos,
				Rule:     rule.Name,
			})
		}
	}
}

func validateSemanticBase64Alphabet(value any) error {
	alphabet, ok := value.(string)
	if !ok || alphabet == "" {
		return nil
	}
	if len(alphabet) != 64 {
		return fmt.Errorf("invalid base64 alphabet length: expected 64, got %d", len(alphabet))
	}
	seen := make(map[byte]struct{}, 64)
	for i := 0; i < len(alphabet); i++ {
		ch := alphabet[i]
		if ch == '=' {
			return errors.New("invalid base64 alphabet: '=' is not allowed")
		}
		if _, exists := seen[ch]; exists {
			return errors.New("invalid base64 alphabet: duplicate characters")
		}
		seen[ch] = struct{}{}
	}
	return nil
}

func validateSemanticXorModifier(value any) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case int:
		if v < 0 || v > 255 {
			return fmt.Errorf("xor value must be between 0 and 255, got %d", v)
		}
	case int64:
		if v < 0 || v > 255 {
			return fmt.Errorf("xor value must be between 0 and 255, got %d", v)
		}
	case [2]int:
		if v[0] < 0 || v[0] > 255 || v[1] < 0 || v[1] > 255 {
			return fmt.Errorf("xor range values must be between 0 and 255, got %d-%d", v[0], v[1])
		}
		if v[0] > v[1] {
			return errors.New("xor range minimum cannot be greater than maximum")
		}
	case ast.XorRange:
		if v.Min < 0 || v.Min > 255 || v.Max < 0 || v.Max > 255 {
			return fmt.Errorf("xor range values must be between 0 and 255, got %d-%d", v.Min, v.Max)
		}
		if v.Min > v.Max {
			return errors.New("xor range minimum cannot be greater than maximum")
		}
	}
	return nil
}

func modifierTypeName(t ast.StringModifierType) string {
	switch t {
	case ast.StringModifierNocase:
		return "nocase"
	case ast.StringModifierWide:
		return "wide"
	case ast.StringModifierASCII:
		return "ascii"
	case ast.StringModifierFullword:
		return "fullword"
	case ast.StringModifierPrivate:
		return "private"
	case ast.StringModifierXor:
		return "xor"
	case ast.StringModifierBase64:
		return "base64"
	case ast.StringModifierBase64Wide:
		return "base64wide"
	case ast.StringModifierCapture:
		return "capture"
	default:
		return "unknown"
	}
}
