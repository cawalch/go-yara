package semantic

import (
	"errors"
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func (v *Validator) addModifierError(pos token.Position, ruleName, message string) {
	v.addError(&Error{
		Code:     ErrCodeInvalidModifier,
		Message:  message,
		Position: pos,
		Rule:     ruleName,
	})
}

func (v *Validator) validateStringModifiers(rule *ast.Rule) {
	for _, str := range rule.Strings {
		if str == nil {
			continue
		}

		var seenModifiers [ast.StringModifierCapture + 1]bool
		var unknownModifiers map[ast.StringModifierType]bool
		hasBase64 := false
		hasXor := false
		hasNocase := false
		hasFullword := false

		regexPat, isRegex := str.Pattern.(*ast.RegexPattern)
		_, isHex := str.Pattern.(*ast.HexString)

		for _, mod := range str.Modifiers {
			// Capture modifiers are validated separately by validateEvidence.
			if mod.Type == ast.StringModifierCapture {
				continue
			}
			duplicate := false
			if mod.Type >= 0 && int(mod.Type) < len(seenModifiers) {
				duplicate = seenModifiers[mod.Type]
				seenModifiers[mod.Type] = true
			} else {
				// Preserve duplicate diagnostics for unknown modifier values in
				// caller-built ASTs without indexing outside the fixed table.
				if unknownModifiers == nil {
					unknownModifiers = make(map[ast.StringModifierType]bool)
				}
				duplicate = unknownModifiers[mod.Type]
				unknownModifiers[mod.Type] = true
			}
			if duplicate {
				v.addModifierError(str.Pos, rule.Name, fmt.Sprintf("string %s declares duplicate modifier '%s' (previously at %v)", str.Identifier, modifierTypeName(mod.Type), str.Pos))
			}

			switch mod.Type {
			case ast.StringModifierWide:
				if isHex {
					v.addModifierError(str.Pos, rule.Name, fmt.Sprintf("hex string %s cannot have 'wide' modifier", str.Identifier))
				}
			case ast.StringModifierASCII:
				if isHex {
					v.addModifierError(str.Pos, rule.Name, fmt.Sprintf("hex string %s cannot have 'ascii' modifier", str.Identifier))
				}
			case ast.StringModifierNocase:
				hasNocase = true
				if isHex {
					v.addModifierError(str.Pos, rule.Name, fmt.Sprintf("hex string %s cannot have 'nocase' modifier", str.Identifier))
				}
			case ast.StringModifierFullword:
				hasFullword = true
				if isHex {
					v.addModifierError(str.Pos, rule.Name, fmt.Sprintf("hex string %s cannot have 'fullword' modifier", str.Identifier))
				}
			case ast.StringModifierBase64, ast.StringModifierBase64Wide:
				hasBase64 = true
				if isHex || isRegex {
					v.addModifierError(str.Pos, rule.Name, "base64 modifiers are only supported for text strings")
				}
			case ast.StringModifierXor:
				hasXor = true
				if isRegex {
					v.addModifierError(str.Pos, rule.Name, fmt.Sprintf("regex string %s cannot have 'xor' modifier", str.Identifier))
				}
				if err := validateSemanticXorModifier(mod.Value); err != nil {
					v.addModifierError(str.Pos, rule.Name, err.Error())
				}
			}
		}

		if hasBase64 {
			if err := ast.ValidateBase64Modifiers(str.Modifiers); err != nil {
				v.addModifierError(str.Pos, rule.Name, err.Error())
			}
			if hasXor || hasNocase || hasFullword {
				v.addModifierError(str.Pos, rule.Name, "base64 modifiers are incompatible with 'xor', 'nocase', or 'fullword'")
			}
		}
		if isRegex {
			if parsed, err := v.regexParser.Parse(cleanSemanticRegexPattern(regexPat.Value)); err == nil && parsed.HasMixedQuantifierGreediness() {
				v.addError(&Error{
					Code:     ErrCodeInvalidModifier,
					Message:  "greedy and ungreedy quantifiers can't be mixed in a regular expression",
					Position: str.Pos,
					Rule:     rule.Name,
				})
			}
		}
	}
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
