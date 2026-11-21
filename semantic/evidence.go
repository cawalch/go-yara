package semantic

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	regexengine "github.com/cawalch/go-yara/regex"
	"github.com/cawalch/go-yara/token"
)

const maxCaptureBindings = 32

func (v *Validator) validateEvidence(rule *ast.Rule) {
	ValidateCaptureAndEvidence(rule, true, func(position token.Position, message string) bool {
		v.addEvidenceError(position, message)
		return true
	})
}

// ValidateCaptureAndEvidence validates capture modifiers and evidence declarations on rule.
func ValidateCaptureAndEvidence(rule *ast.Rule, checkRegexGroups bool, onError func(token.Position, string) bool) {
	captureNames := make(map[string]struct{})
	for _, str := range rule.Strings {
		if str == nil {
			continue
		}
		captureModifiers := 0
		private := false
		var bindings []ast.CaptureBinding
		for _, modifier := range str.Modifiers {
			switch modifier.Type {
			case ast.StringModifierPrivate:
				private = true
			case ast.StringModifierCapture:
				captureModifiers++
				bindings, _ = modifier.Value.([]ast.CaptureBinding)
			}
		}
		if captureModifiers == 0 {
			continue
		}
		if captureModifiers > 1 && !onError(str.Pos, fmt.Sprintf("string %s has more than one capture modifier", str.Identifier)) {
			return
		}
		if (str.Identifier == "" || str.Identifier == "$") && !onError(str.Pos, fmt.Sprintf("anonymous string %s cannot declare captures", str.Identifier)) {
			return
		}
		if private && !onError(str.Pos, fmt.Sprintf("string %s cannot combine private and capture modifiers", str.Identifier)) {
			return
		}
		if len(bindings) == 0 {
			if !onError(str.Pos, fmt.Sprintf("string %s has an empty capture modifier", str.Identifier)) {
				return
			}
			continue
		}
		if len(bindings) > maxCaptureBindings && !onError(str.Pos, fmt.Sprintf(
			"string %s declares %d capture bindings; maximum is %d",
			str.Identifier, len(bindings), maxCaptureBindings,
		)) {
			return
		}
		var groupCount int
		var isRegex bool
		if checkRegexGroups {
			groupCount, isRegex = semanticRegexGroupCount(str.Pattern)
		} else {
			_, isRegex = str.Pattern.(*ast.RegexPattern)
		}
		seen := make(map[string]struct{}, len(bindings))
		for _, binding := range bindings {
			if !checkRegexGroups && binding.Name == "" && !onError(str.Pos, fmt.Sprintf("string %s has an empty capture name", str.Identifier)) {
				return
			}
			if _, duplicate := seen[binding.Name]; duplicate {
				if !onError(str.Pos, fmt.Sprintf("string %s declares capture name %q more than once", str.Identifier, binding.Name)) {
					return
				}
				continue
			}
			seen[binding.Name] = struct{}{}
			captureNames[binding.Name] = struct{}{}
			switch {
			case binding.Group < 0:
				if !onError(str.Pos, fmt.Sprintf("string %s capture %q has invalid group %d", str.Identifier, binding.Name, binding.Group)) {
					return
				}
			case binding.Group > 0 && !isRegex:
				if !onError(str.Pos, fmt.Sprintf(
					"string %s capture %q references group %d on a non-regex pattern",
					str.Identifier, binding.Name, binding.Group,
				)) {
					return
				}
			case checkRegexGroups && binding.Group > groupCount:
				if !onError(str.Pos, fmt.Sprintf("capture group %d is out of range for string %s", binding.Group, str.Identifier)) {
					return
				}
			}
		}
	}

	declarationNames := make(map[string]struct{}, len(rule.Evidence))
	for _, declaration := range rule.Evidence {
		if declaration == nil {
			continue
		}
		if declaration.Name == "" && !onError(declaration.Pos, "evidence declaration has an empty name") {
			return
		}
		if _, duplicate := declarationNames[declaration.Name]; duplicate && !onError(declaration.Pos, fmt.Sprintf("evidence declaration %q is duplicated", declaration.Name)) {
			return
		}
		declarationNames[declaration.Name] = struct{}{}
		if !checkRegexGroups && declaration.Within < 0 && !onError(declaration.Pos, fmt.Sprintf("evidence declaration %q has a negative window", declaration.Name)) {
			return
		}
		if len(declaration.Fields) == 0 && !onError(declaration.Pos, fmt.Sprintf("evidence declaration %q has no fields", declaration.Name)) {
			return
		}
		if checkRegexGroups && declaration.Within < 0 && !onError(declaration.Pos, fmt.Sprintf("evidence declaration %q has a negative window", declaration.Name)) {
			return
		}
		if checkRegexGroups && declaration.Anchor == "" && !onError(declaration.Pos, fmt.Sprintf("evidence declaration %q has an empty anchor", declaration.Name)) {
			return
		}
		seenFields := make(map[string]struct{}, len(declaration.Fields))
		anchorIncluded := false
		for _, field := range declaration.Fields {
			if _, duplicate := seenFields[field]; duplicate && !onError(declaration.Pos, fmt.Sprintf("evidence declaration %q repeats field %q", declaration.Name, field)) {
				return
			}
			seenFields[field] = struct{}{}
			anchorIncluded = anchorIncluded || field == declaration.Anchor
			if _, declared := captureNames[field]; !declared && !onError(declaration.Pos, fmt.Sprintf(
				"evidence declaration %q references undeclared capture %q", declaration.Name, field,
			)) {
				return
			}
		}
		if !checkRegexGroups && declaration.Anchor == "" && !onError(declaration.Pos, fmt.Sprintf("evidence declaration %q has an empty anchor", declaration.Name)) {
			return
		}
		if !anchorIncluded && !onError(declaration.Pos, fmt.Sprintf(
			"evidence declaration %q anchor %q is not in its field list", declaration.Name, declaration.Anchor,
		)) {
			return
		}
	}
}

func (v *Validator) addEvidenceError(position token.Position, message string) {
	v.addError(&Error{
		Code:     ErrCodeInvalidEvidence,
		Message:  message,
		Position: position,
		Rule:     v.currentRule,
	})
}

func semanticRegexGroupCount(pattern ast.Pattern) (int, bool) {
	regexPattern, ok := pattern.(*ast.RegexPattern)
	if !ok {
		return 0, false
	}
	parsed, err := regexengine.NewParser(0).Parse(cleanSemanticRegexPattern(regexPattern.Value))
	if err != nil {
		return int(^uint(0) >> 1), true
	}
	return parsed.GroupCount, true
}

func cleanSemanticRegexPattern(literal string) string {
	if len(literal) >= 2 && literal[0] == '/' {
		end := len(literal) - 1
		for end > 0 && literal[end] != '/' {
			end--
		}
		if end > 0 {
			return literal[1:end]
		}
	}
	return literal
}
