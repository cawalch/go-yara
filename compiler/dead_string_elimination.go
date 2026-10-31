package compiler

import (
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

type conditionStringReferences struct {
	fixedOffsets map[string]int64 // optional: collect constant at references separately
	fixedStrings []string
	them         bool
	anonymous    bool
	exact        map[string]struct{}
	prefixes     []string
}

func newConditionStringReferences() *conditionStringReferences {
	return &conditionStringReferences{
		exact:    make(map[string]struct{}),
		prefixes: make([]string, 0),
	}
}

// detectDeadStrings identifies strings declared in rule.Strings that are not reachable
// in the rule's (already folded) condition.
// If isDeadRule is true, all strings are marked as dead.
func detectDeadStrings(rule *ast.Rule, anonymousStrings []string, isDeadRule bool) map[string]bool {
	dead := make(map[string]bool, len(rule.Strings))
	if len(rule.Strings) == 0 {
		return dead
	}

	if isDeadRule {
		for _, str := range rule.Strings {
			dead[str.Identifier] = true
		}
		return dead
	}

	refs := newConditionStringReferences()
	collectConditionStringReferences(rule.Condition, refs)

	for _, str := range rule.Strings {
		isAnon := slices.Contains(anonymousStrings, str.Identifier)
		if !isStringReferenced(str.Identifier, isAnon, refs) {
			dead[str.Identifier] = true
		}
	}

	return dead
}

func isStringReferenced(id string, isAnonymous bool, refs *conditionStringReferences) bool {
	if refs.them {
		return true
	}
	if isAnonymous && refs.anonymous {
		return true
	}
	if _, ok := refs.exact[id]; ok {
		return true
	}
	trimmed := strings.TrimPrefix(id, "$")
	if _, ok := refs.exact[trimmed]; ok {
		return true
	}
	for _, prefix := range refs.prefixes {
		prefixTrimmed := strings.TrimPrefix(prefix, "$")
		if strings.HasPrefix(id, prefix) || strings.HasPrefix(trimmed, prefixTrimmed) {
			return true
		}
	}
	return false
}

func collectConditionStringReferences(expr ast.Expression, refs *conditionStringReferences) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		if refs.fixedOffsets != nil && e.Name != "them" && !strings.HasPrefix(e.Name, "$") {
			return // Rule, external, and loop identifiers do not observe strings.
		}
		handleIdentifierRef(e, refs)
	case *ast.StringCount:
		recordExpressionStringRef(e.String, refs)
		collectConditionStringReferences(e.Index, refs)
	case *ast.StringOffset:
		recordExpressionStringRef(e.String, refs)
		collectConditionStringReferences(e.Index, refs)
	case *ast.StringLength:
		recordExpressionStringRef(e.String, refs)
		collectConditionStringReferences(e.Index, refs)
	case *ast.LengthOf:
		if e.Quantifier != "" && strings.HasPrefix(e.Quantifier, "*") {
			refs.them = true
		}
		recordExpressionStringRef(e.Target, refs)
	case *ast.UnaryOp:
		switch e.Op {
		case token.HASH, token.AT, token.StringLength:
			recordExpressionStringRef(e.Right, refs)
		default:
			collectConditionStringReferences(e.Right, refs)
		}
	case *ast.BinaryOp:
		if refs.fixedOffsets != nil && collectFixedOffsetReference(e, refs) {
			return
		}
		collectConditionStringReferences(e.Left, refs)
		collectConditionStringReferences(e.Right, refs)
	case *ast.OfExpression:
		collectConditionStringReferences(e.Count, refs)
		collectConditionStringReferences(e.Strings, refs)
		collectConditionStringReferences(e.InRange, refs)
		collectConditionStringReferences(e.AtOffset, refs)
	case *ast.ForLoop:
		collectConditionStringReferences(e.Range, refs)
		collectConditionStringReferences(e.Condition, refs)
		collectConditionStringReferences(e.InRange, refs)
		collectConditionStringReferences(e.AtOffset, refs)
	case *ast.MemberAccess:
		collectConditionStringReferences(e.Object, refs)
	case *ast.IndexAccess:
		collectConditionStringReferences(e.Object, refs)
		collectConditionStringReferences(e.Index, refs)
	case *ast.FunctionCall:
		for _, arg := range e.Args {
			collectConditionStringReferences(arg, refs)
		}
	case *ast.PercentExpression:
		collectConditionStringReferences(e.Value, refs)
	case *ast.StringTuple:
		for _, element := range e.Elements {
			collectConditionStringReferences(element, refs)
		}
	}
}

func handleIdentifierRef(id *ast.Identifier, refs *conditionStringReferences) {
	name := id.Name
	if name == "them" {
		refs.them = true
		return
	}
	if name == "$" {
		if refs.fixedOffsets != nil {
			refs.them = true
		}
		refs.anonymous = true
		return
	}
	if id.Quantifier != "" && strings.HasSuffix(id.Quantifier, "*") {
		prefix := name
		if !strings.HasPrefix(prefix, "$") {
			prefix = "$" + prefix
		}
		refs.prefixes = append(refs.prefixes, prefix)
		return
	}
	if before, ok := strings.CutSuffix(name, "*"); ok {
		prefix := before
		if !strings.HasPrefix(prefix, "$") {
			prefix = "$" + prefix
		}
		refs.prefixes = append(refs.prefixes, prefix)
		return
	}
	refs.exact[name] = struct{}{}
	if !strings.HasPrefix(name, "$") {
		refs.exact["$"+name] = struct{}{}
	}
}

func recordExpressionStringRef(expr ast.Expression, refs *conditionStringReferences) {
	if expr == nil {
		return
	}
	if id, ok := expr.(*ast.Identifier); ok {
		handleIdentifierRef(id, refs)
		return
	}
	collectConditionStringReferences(expr, refs)
}
