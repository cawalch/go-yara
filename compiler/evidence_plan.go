package compiler

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/semantic"
	"github.com/cawalch/go-yara/token"
)

const maxCaptureBindings = 32

func validateCaptureAndEvidenceDeclarations(rule *ast.Rule) error {
	if rule == nil {
		return errors.New("cannot compile nil rule")
	}
	var firstErr error
	semantic.ValidateCaptureAndEvidence(rule, false, func(_ token.Position, message string) bool {
		firstErr = errors.New(message)
		return false
	})
	return firstErr
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
	var bindings map[string][]ast.CaptureBinding
	for _, str := range rule.Strings {
		if str == nil {
			continue
		}
		declared := captureBindingsFromModifiers(str.Modifiers)
		if len(declared) != 0 {
			if bindings == nil {
				bindings = make(map[string][]ast.CaptureBinding)
			}
			bindings[str.Identifier] = slices.Clone(declared)
		}
	}
	return bindings
}

func compileEvidencePlans(declarations []*ast.EvidenceDeclaration) []EvidencePlan {
	if len(declarations) == 0 {
		return nil
	}
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
		return errors.New("nil compiled rule")
	}
	if len(rule.CaptureBindings) == 0 && len(rule.EvidencePlans) == 0 {
		return nil
	}
	if rule.FastScanSafe {
		return errors.New("capture or evidence rule cannot be fast-scan safe")
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
