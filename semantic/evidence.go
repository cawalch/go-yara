package semantic

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	regexengine "github.com/cawalch/go-yara/regex"
	"github.com/cawalch/go-yara/token"
)

const maxCaptureBindings = 32

func (v *Validator) validateEvidence(rule *ast.Rule) {
	captureNames := make(map[string]struct{})
	for _, str := range rule.Strings {
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
		if captureModifiers > 1 {
			v.addEvidenceError(str.Pos, fmt.Sprintf("string %s has more than one capture modifier", str.Identifier))
		}
		if str.Identifier == "" || str.Identifier == "$" {
			v.addEvidenceError(str.Pos, fmt.Sprintf("anonymous string %s cannot declare captures", str.Identifier))
		}
		if private {
			v.addEvidenceError(str.Pos, fmt.Sprintf("string %s cannot combine private and capture modifiers", str.Identifier))
		}
		if len(bindings) == 0 {
			v.addEvidenceError(str.Pos, fmt.Sprintf("string %s has an empty capture modifier", str.Identifier))
			continue
		}
		if len(bindings) > maxCaptureBindings {
			v.addEvidenceError(str.Pos, fmt.Sprintf(
				"string %s declares %d capture bindings; maximum is %d",
				str.Identifier, len(bindings), maxCaptureBindings,
			))
		}
		groupCount, isRegex := semanticRegexGroupCount(str.Pattern)
		seen := make(map[string]struct{}, len(bindings))
		for _, binding := range bindings {
			if _, duplicate := seen[binding.Name]; duplicate {
				v.addEvidenceError(str.Pos, fmt.Sprintf("string %s declares capture name %q more than once", str.Identifier, binding.Name))
				continue
			}
			seen[binding.Name] = struct{}{}
			captureNames[binding.Name] = struct{}{}
			switch {
			case binding.Group < 0:
				v.addEvidenceError(str.Pos, fmt.Sprintf("string %s capture %q has invalid group %d", str.Identifier, binding.Name, binding.Group))
			case binding.Group > 0 && !isRegex:
				v.addEvidenceError(str.Pos, fmt.Sprintf(
					"string %s capture %q references group %d on a non-regex pattern",
					str.Identifier, binding.Name, binding.Group,
				))
			case binding.Group > groupCount:
				v.addEvidenceError(str.Pos, fmt.Sprintf("capture group %d is out of range for string %s", binding.Group, str.Identifier))
			}
		}
	}

	declarationNames := make(map[string]struct{}, len(rule.Evidence))
	for _, declaration := range rule.Evidence {
		if declaration == nil {
			continue
		}
		if declaration.Name == "" {
			v.addEvidenceError(declaration.Pos, "evidence declaration has an empty name")
		}
		if _, duplicate := declarationNames[declaration.Name]; duplicate {
			v.addEvidenceError(declaration.Pos, fmt.Sprintf("evidence declaration %q is duplicated", declaration.Name))
		}
		declarationNames[declaration.Name] = struct{}{}
		if len(declaration.Fields) == 0 {
			v.addEvidenceError(declaration.Pos, fmt.Sprintf("evidence declaration %q has no fields", declaration.Name))
		}
		if declaration.Within < 0 {
			v.addEvidenceError(declaration.Pos, fmt.Sprintf("evidence declaration %q has a negative window", declaration.Name))
		}
		if declaration.Anchor == "" {
			v.addEvidenceError(declaration.Pos, fmt.Sprintf("evidence declaration %q has an empty anchor", declaration.Name))
		}
		seenFields := make(map[string]struct{}, len(declaration.Fields))
		anchorIncluded := false
		for _, field := range declaration.Fields {
			if _, duplicate := seenFields[field]; duplicate {
				v.addEvidenceError(declaration.Pos, fmt.Sprintf("evidence declaration %q repeats field %q", declaration.Name, field))
			}
			seenFields[field] = struct{}{}
			anchorIncluded = anchorIncluded || field == declaration.Anchor
			if _, declared := captureNames[field]; !declared {
				v.addEvidenceError(declaration.Pos, fmt.Sprintf(
					"evidence declaration %q references undeclared capture %q", declaration.Name, field,
				))
			}
		}
		if !anchorIncluded {
			v.addEvidenceError(declaration.Pos, fmt.Sprintf(
				"evidence declaration %q anchor %q is not in its field list", declaration.Name, declaration.Anchor,
			))
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
	literal := regexPattern.Value
	if len(literal) >= 2 && literal[0] == '/' {
		end := len(literal) - 1
		for end > 0 && literal[end] != '/' {
			end--
		}
		if end > 0 {
			literal = literal[1:end]
		}
	}
	parsed, err := regexengine.NewParser(0).Parse(literal)
	if err != nil {
		return int(^uint(0) >> 1), true
	}
	return parsed.GroupCount, true
}
