package compiler

import (
	"fmt"
	"slices"

	"github.com/cawalch/go-yara/ast"
)

const maxCaptureBindings = 32

func validateCaptureAndEvidenceDeclarations(rule *ast.Rule) error {
	if rule == nil {
		return fmt.Errorf("cannot compile nil rule")
	}

	captureNames := make(map[string]struct{})
	for _, str := range rule.Strings {
		if str == nil {
			continue
		}
		captureModifiers := 0
		private := false
		for _, modifier := range str.Modifiers {
			switch modifier.Type {
			case ast.StringModifierPrivate:
				private = true
			case ast.StringModifierCapture:
				captureModifiers++
			}
		}
		if captureModifiers == 0 {
			continue
		}
		if captureModifiers > 1 {
			return fmt.Errorf("string %s has more than one capture modifier", str.Identifier)
		}
		if str.Identifier == "" || str.Identifier == "$" {
			return fmt.Errorf("anonymous string %s cannot declare captures", str.Identifier)
		}
		if private {
			return fmt.Errorf("string %s cannot combine private and capture modifiers", str.Identifier)
		}

		bindings := captureBindingsFromModifiers(str.Modifiers)
		if len(bindings) == 0 {
			return fmt.Errorf("string %s has an empty capture modifier", str.Identifier)
		}
		if len(bindings) > maxCaptureBindings {
			return fmt.Errorf("string %s declares %d capture bindings; maximum is %d", str.Identifier, len(bindings), maxCaptureBindings)
		}
		seen := make(map[string]struct{}, len(bindings))
		for _, binding := range bindings {
			if binding.Name == "" {
				return fmt.Errorf("string %s has an empty capture name", str.Identifier)
			}
			if _, duplicate := seen[binding.Name]; duplicate {
				return fmt.Errorf("string %s declares capture name %q more than once", str.Identifier, binding.Name)
			}
			seen[binding.Name] = struct{}{}
			captureNames[binding.Name] = struct{}{}
			if binding.Group < 0 {
				return fmt.Errorf("string %s capture %q has invalid group %d", str.Identifier, binding.Name, binding.Group)
			}
			if binding.Group > 0 {
				if _, ok := str.Pattern.(*ast.RegexPattern); !ok {
					return fmt.Errorf("string %s capture %q references group %d on a non-regex pattern", str.Identifier, binding.Name, binding.Group)
				}
			}
		}
	}

	evidenceNames := make(map[string]struct{}, len(rule.Evidence))
	for _, declaration := range rule.Evidence {
		if declaration == nil {
			continue
		}
		if declaration.Name == "" {
			return fmt.Errorf("evidence declaration has an empty name")
		}
		if _, duplicate := evidenceNames[declaration.Name]; duplicate {
			return fmt.Errorf("evidence declaration %q is duplicated", declaration.Name)
		}
		evidenceNames[declaration.Name] = struct{}{}
		if declaration.Within < 0 {
			return fmt.Errorf("evidence declaration %q has a negative window", declaration.Name)
		}
		if len(declaration.Fields) == 0 {
			return fmt.Errorf("evidence declaration %q has no fields", declaration.Name)
		}
		seenFields := make(map[string]struct{}, len(declaration.Fields))
		anchorIncluded := false
		for _, field := range declaration.Fields {
			if _, duplicate := seenFields[field]; duplicate {
				return fmt.Errorf("evidence declaration %q repeats field %q", declaration.Name, field)
			}
			seenFields[field] = struct{}{}
			if field == declaration.Anchor {
				anchorIncluded = true
			}
			if _, declared := captureNames[field]; !declared {
				return fmt.Errorf("evidence declaration %q references undeclared capture %q", declaration.Name, field)
			}
		}
		if declaration.Anchor == "" {
			return fmt.Errorf("evidence declaration %q has an empty anchor", declaration.Name)
		}
		if !anchorIncluded {
			return fmt.Errorf("evidence declaration %q anchor %q is not in its field list", declaration.Name, declaration.Anchor)
		}
	}

	return nil
}

func captureBindingsFromModifiers(modifiers []ast.StringModifier) []ast.CaptureBinding {
	for _, modifier := range modifiers {
		if modifier.Type != ast.StringModifierCapture {
			continue
		}
		bindings, ok := modifier.Value.([]ast.CaptureBinding)
		if !ok {
			return nil
		}
		return bindings
	}
	return nil
}

func positiveCaptureGroups(modifiers []ast.StringModifier) []int {
	var groups []int
	for _, binding := range captureBindingsFromModifiers(modifiers) {
		if binding.Group > 0 && !slices.Contains(groups, binding.Group) {
			groups = append(groups, binding.Group)
		}
	}
	slices.Sort(groups)
	return groups
}

func hasPositiveCaptureGroup(modifiers []ast.StringModifier) bool {
	return len(positiveCaptureGroups(modifiers)) != 0
}

func captureBindingsByPattern(rule *ast.Rule) map[string][]ast.CaptureBinding {
	bindings := make(map[string][]ast.CaptureBinding)
	for _, str := range rule.Strings {
		if str == nil {
			continue
		}
		declared := captureBindingsFromModifiers(str.Modifiers)
		if len(declared) != 0 {
			bindings[str.Identifier] = slices.Clone(declared)
		}
	}
	if len(bindings) == 0 {
		return nil
	}
	return bindings
}

func compileEvidencePlans(declarations []*ast.EvidenceDeclaration) []EvidencePlan {
	plans := make([]EvidencePlan, 0, len(declarations))
	for _, declaration := range declarations {
		if declaration == nil {
			continue
		}
		plans = append(plans, EvidencePlan{
			Name:   declaration.Name,
			Fields: slices.Clone(declaration.Fields),
			Anchor: declaration.Anchor,
			Within: declaration.Within,
		})
	}
	return plans
}

func ruleDeclaresEvidence(rule *ast.Rule) bool {
	if rule == nil {
		return false
	}
	if len(rule.Evidence) != 0 {
		return true
	}
	for _, str := range rule.Strings {
		if str != nil && len(captureBindingsFromModifiers(str.Modifiers)) != 0 {
			return true
		}
	}
	return false
}

func validateCompiledEvidence(rule *CompiledRule) error {
	if rule == nil {
		return fmt.Errorf("nil compiled rule")
	}
	if len(rule.CaptureBindings) == 0 && len(rule.EvidencePlans) == 0 {
		return nil
	}
	if rule.FastScanSafe {
		return fmt.Errorf("capture or evidence rule cannot be fast-scan safe")
	}

	captureNames := make(map[string]struct{})
	patterns := make([]string, 0, len(rule.CaptureBindings))
	for pattern := range rule.CaptureBindings {
		patterns = append(patterns, pattern)
	}
	slices.Sort(patterns)
	for _, pattern := range patterns {
		bindings := rule.CaptureBindings[pattern]
		if _, declared := rule.StringKinds[pattern]; !declared {
			return fmt.Errorf("capture pattern %q is not a declared string", pattern)
		}
		if len(bindings) == 0 || len(bindings) > maxCaptureBindings {
			return fmt.Errorf("capture pattern %q has invalid binding count %d", pattern, len(bindings))
		}
		if hasStringModifier(rule.StringModifiers[pattern], ast.StringModifierPrivate) {
			return fmt.Errorf("capture pattern %q is private", pattern)
		}
		seen := make(map[string]struct{}, len(bindings))
		for _, binding := range bindings {
			if binding.Name == "" || binding.Group < 0 {
				return fmt.Errorf("capture pattern %q has invalid binding %#v", pattern, binding)
			}
			if _, duplicate := seen[binding.Name]; duplicate {
				return fmt.Errorf("capture pattern %q repeats name %q", pattern, binding.Name)
			}
			seen[binding.Name] = struct{}{}
			captureNames[binding.Name] = struct{}{}
			if binding.Group == 0 {
				continue
			}
			regexPattern, ok := rule.RegexPatterns[pattern]
			if !ok || len(regexPattern.CaptureCode) == 0 || !slices.Contains(regexPattern.CaptureGroups, binding.Group) {
				return fmt.Errorf("capture pattern %q has no program for group %d", pattern, binding.Group)
			}
		}
	}

	planNames := make(map[string]struct{}, len(rule.EvidencePlans))
	for _, plan := range rule.EvidencePlans {
		if plan.Name == "" || len(plan.Fields) == 0 || plan.Anchor == "" || plan.Within < 0 {
			return fmt.Errorf("invalid evidence plan %#v", plan)
		}
		if _, duplicate := planNames[plan.Name]; duplicate {
			return fmt.Errorf("duplicate evidence plan %q", plan.Name)
		}
		planNames[plan.Name] = struct{}{}
		seenFields := make(map[string]struct{}, len(plan.Fields))
		anchorIncluded := false
		for _, field := range plan.Fields {
			if _, duplicate := seenFields[field]; duplicate {
				return fmt.Errorf("evidence plan %q repeats field %q", plan.Name, field)
			}
			seenFields[field] = struct{}{}
			if _, declared := captureNames[field]; !declared {
				return fmt.Errorf("evidence plan %q references unknown capture %q", plan.Name, field)
			}
			anchorIncluded = anchorIncluded || field == plan.Anchor
		}
		if !anchorIncluded {
			return fmt.Errorf("evidence plan %q anchor %q is not a field", plan.Name, plan.Anchor)
		}
	}
	return nil
}
