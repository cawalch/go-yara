package compiler

import (
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/wordmatch"
	"github.com/cawalch/go-yara/token"
)

// WithBooleanRouting opts Matches into word routing for records up to 1024 bytes.
// Eligible rules use only positive pattern conjunctions and text or bounded
// regex patterns with long literal anchors. Other scans use the normal evaluator.
// The first opted-in scanner builds a shared plan, which can add substantial
// startup time and memory. Serialized programs do not retain eligibility.
func WithBooleanRouting() ScannerOption {
	return func(s *Scanner) { s.booleanRoutingEnabled = true }
}

func (cp *CompiledProgram) buildBooleanRouting() *wordmatch.RoutedProgram {
	if !cp.booleanRoutingInput() {
		return nil
	}
	conversion := newWordRoutingConverter()
	rules := make([]wordmatch.Rule, 0, len(cp.Rules))
	for _, rule := range cp.Rules {
		var compiled wordmatch.Rule
		for _, pattern := range rule.booleanPatterns {
			converted, ok := conversion.pattern(pattern)
			if !ok {
				return nil
			}
			compiled.All = append(compiled.All, converted)
		}
		rules = append(rules, compiled)
	}
	plan, err := wordmatch.CompileRouted(rules)
	if err != nil {
		return nil
	}
	return plan
}

func (cp *CompiledProgram) booleanRoutingInput() bool {
	if len(cp.Rules) == 0 || len(cp.Rules) > 4096 {
		return false
	}
	patterns, sourceBytes := 8192, 1<<20
	for _, rule := range cp.Rules {
		if rule == nil || len(rule.booleanPatterns) == 0 || len(rule.booleanPatterns) > patterns ||
			rule.IsGlobal || rule.IsPrivate || len(rule.CaptureBindings) != 0 ||
			len(rule.EvidencePlans) != 0 || len(rule.GlobalSlots) != 0 {
			return false
		}
		patterns -= len(rule.booleanPatterns)
		for _, pattern := range rule.booleanPatterns {
			var size int
			switch source := pattern.Pattern.(type) {
			case *ast.TextString:
				size = len(source.Value)
			case *ast.RegexPattern:
				size = len(source.Value)
			default:
				return false
			}
			if size > sourceBytes {
				return false
			}
			sourceBytes -= size
		}
	}
	return true
}

// Keep owned source only for exact conjunctions; parsing and route construction
// remain lazy. The ordinary requiredStrings metadata proves necessity only.
func booleanRoutingPatterns(rule *ast.Rule) []*ast.String {
	ids, ok := booleanRoutingConjunction(rule.Condition, rule.Strings)
	if !ok || len(ids) == 0 {
		return nil
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	patterns := make([]*ast.String, 0, len(ids))
	for _, pattern := range rule.Strings {
		if !slices.Contains(ids, pattern.Identifier) {
			continue
		}
		copyPattern := *pattern
		copyPattern.Modifiers = slices.Clone(pattern.Modifiers)
		for _, modifier := range copyPattern.Modifiers {
			if modifier.Type != ast.StringModifierASCII && modifier.Type != ast.StringModifierNocase {
				return nil
			}
		}
		switch source := pattern.Pattern.(type) {
		case *ast.TextString:
			value := *source
			copyPattern.Pattern = &value
		case *ast.RegexPattern:
			value := *source
			copyPattern.Pattern = &value
		default:
			return nil
		}
		patterns = append(patterns, &copyPattern)
	}
	if len(patterns) != len(ids) {
		return nil
	}
	return patterns
}

func booleanRoutingConjunction(expr ast.Expression, patterns []*ast.String) ([]string, bool) {
	switch e := expr.(type) {
	case *ast.Identifier:
		return []string{e.Name}, strings.HasPrefix(e.Name, "$") && e.Name != "$" && !strings.Contains(e.Name, "*")
	case *ast.BinaryOp:
		if e.Op != token.AND {
			return nil, false
		}
		left, leftOK := booleanRoutingConjunction(e.Left, patterns)
		right, rightOK := booleanRoutingConjunction(e.Right, patterns)
		return append(left, right...), leftOK && rightOK
	case *ast.OfExpression:
		count, ok := e.Count.(*ast.Identifier)
		if !ok || count.Name != QuantifierAll || e.InRange != nil || e.AtOffset != nil {
			return nil, false
		}
		ids, ok := requiredStringSet(e.Strings, patterns)
		return ids, ok && len(ids) > 0
	default:
		return nil, false
	}
}
