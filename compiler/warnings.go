package compiler

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// collectSemanticWarnings collects semantic warnings from the compiled program
func (c *Compiler) collectSemanticWarnings(program *ast.Program) {
	for _, rule := range program.Rules {
		c.collectRuleWarnings(rule)
	}
}

// collectRuleWarnings collects warnings for a specific rule
func (c *Compiler) collectRuleWarnings(rule *ast.Rule) {
	// Check for unused strings
	c.checkUnusedStrings(rule)

	// Check for empty rules
	c.checkEmptyRule(rule)

	// Check for potentially problematic patterns
	c.checkProblematicPatterns(rule)

	// Duplicate patterns waste compilation and matching work, and often signal
	// a copy/paste error in a rule.
	c.checkDuplicatePatterns(rule)

	// Check for wildcard prefix collisions and quantifier absorption
	c.checkWildcardCollisions(rule)
}

// checkUnusedStrings warns about strings that are defined but never used
func (c *Compiler) checkUnusedStrings(rule *ast.Rule) {
	if len(rule.Strings) == 0 {
		return // No strings to check
	}

	// Track which strings are referenced in the condition
	referenced := make(map[string]bool)
	c.collectReferencedStrings(rule.Condition, referenced)

	// Check for unused strings
	for _, str := range rule.Strings {
		if !stringIsReferenced(str.Identifier, referenced) {
			// YARA spec: strings prefixed with $_ suppress the unreferenced warning
			if len(str.Identifier) >= 2 && str.Identifier[:2] == "$_" {
				continue
			}
			c.addRuleWarning(CompilationWarning{
				Code: WarningUnusedString, Phase: "semantic",
				Message: fmt.Sprintf("String '%s' is defined but never used in condition", str.Identifier),
				Rule:    rule.Name, String: str.Identifier, Line: str.Pos.Line, Column: str.Pos.Column,
			})
		}
	}
}

// collectReferencedStrings recursively collects string references from an expression
func (c *Compiler) collectReferencedStrings(expr ast.Expression, referenced map[string]bool) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		// This could be a string reference
		if e.Name == "them" {
			referenced["*"] = true
		} else if len(e.Name) > 0 && e.Name[0] == '$' {
			referenced[e.Name+e.Quantifier] = true
		}
	case *ast.OfExpression:
		// Check strings in "of" expressions
		if e.Strings != nil {
			c.collectReferencedStrings(e.Strings, referenced)
		}
		c.collectReferencedStrings(e.Count, referenced)
		c.collectReferencedStrings(e.InRange, referenced)
		c.collectReferencedStrings(e.AtOffset, referenced)
	case *ast.BinaryOp:
		c.collectReferencedStrings(e.Left, referenced)
		c.collectReferencedStrings(e.Right, referenced)
	case *ast.UnaryOp:
		c.collectReferencedStrings(e.Right, referenced)
	case *ast.FunctionCall:
		// Check arguments for string references
		for _, arg := range e.Args {
			c.collectReferencedStrings(arg, referenced)
		}
	case *ast.StringCount:
		c.collectReferencedStrings(e.String, referenced)
		c.collectReferencedStrings(e.Index, referenced)
	case *ast.StringOffset:
		c.collectReferencedStrings(e.String, referenced)
		c.collectReferencedStrings(e.Index, referenced)
	case *ast.StringLength:
		c.collectReferencedStrings(e.String, referenced)
		c.collectReferencedStrings(e.Index, referenced)
	case *ast.LengthOf:
		c.collectReferencedStrings(e.Target, referenced)
	case *ast.ForLoop:
		c.collectReferencedStrings(e.Range, referenced)
		c.collectReferencedStrings(e.Condition, referenced)
		c.collectReferencedStrings(e.InRange, referenced)
		c.collectReferencedStrings(e.AtOffset, referenced)
	case *ast.PercentExpression:
		c.collectReferencedStrings(e.Value, referenced)
	case *ast.StringTuple:
		for _, element := range e.Elements {
			c.collectReferencedStrings(element, referenced)
		}
	}
}

func stringIsReferenced(id string, referenced map[string]bool) bool {
	if referenced["*"] || referenced[id] {
		return true
	}
	for pattern := range referenced {
		if strings.HasSuffix(pattern, "*") && strings.HasPrefix(id, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

// checkEmptyRule warns about rules with empty conditions
func (c *Compiler) checkEmptyRule(rule *ast.Rule) {
	if rule.Condition == nil {
		c.addRuleWarning(CompilationWarning{
			Code: WarningMissingCondition, Phase: "semantic",
			Message: fmt.Sprintf("Rule '%s' has no condition", rule.Name),
			Rule:    rule.Name, Line: rule.Pos.Line, Column: rule.Pos.Column,
		})
	}
}

// checkProblematicPatterns warns about potentially problematic patterns
func (c *Compiler) checkProblematicPatterns(rule *ast.Rule) {
	// Check for rules with only trivial conditions
	if c.isTrivialCondition(rule.Condition) {
		c.addRuleWarning(CompilationWarning{
			Code: WarningTrivialCondition, Phase: "semantic",
			Message: fmt.Sprintf("Rule '%s' has a trivial condition that may always be true", rule.Name),
			Rule:    rule.Name, Line: rule.Pos.Line, Column: rule.Pos.Column,
		})
	}
}

func (c *Compiler) checkDuplicatePatterns(rule *ast.Rule) {
	seen := make(map[string]string, len(rule.Strings))
	for _, str := range rule.Strings {
		signature := patternSignature(str)
		if original, duplicate := seen[signature]; duplicate {
			c.addRuleWarning(CompilationWarning{
				Code: WarningDuplicatePattern, Phase: "semantic",
				Message: fmt.Sprintf("String '%s' duplicates pattern from '%s'", str.Identifier, original),
				Rule:    rule.Name, String: str.Identifier, Line: str.Pos.Line, Column: str.Pos.Column,
			})
			continue
		}
		seen[signature] = str.Identifier
	}
}

func patternSignature(str *ast.String) string {
	if str == nil || str.Pattern == nil {
		return ""
	}
	kind := "unknown"
	value := ""
	switch pattern := str.Pattern.(type) {
	case *ast.TextString:
		kind, value = "text", pattern.Value
	case *ast.RegexPattern:
		kind, value = "regex", pattern.Value
	case *ast.HexString:
		kind, value = "hex", strings.Join(strings.Fields(pattern.Value), " ")
	}
	modifiers := make([]string, 0, len(str.Modifiers))
	for _, modifier := range str.Modifiers {
		modifiers = append(modifiers, fmt.Sprintf("%d=%v", modifier.Type, modifier.Value))
	}
	slices.Sort(modifiers)
	return kind + "\x00" + value + "\x00" + strings.Join(modifiers, ",")
}

type wildcardStringRef struct {
	name string
	pos  token.Position
}

// checkWildcardCollisions warns when an explicit string identifier matches a wildcard prefix
// referenced in a condition quantifier, which leads to condition absorption or unintended set expansion.
func (c *Compiler) checkWildcardCollisions(rule *ast.Rule) {
	if rule.Condition == nil || len(rule.Strings) == 0 {
		return
	}

	definedStrings := make(map[string]bool, len(rule.Strings))
	for _, s := range rule.Strings {
		definedStrings[s.Identifier] = true
	}

	var wildcards []wildcardStringRef
	var explicitStrings []wildcardStringRef

	var walkExpr func(expr ast.Expression, inStringSet bool)
	walkExpr = func(expr ast.Expression, inStringSet bool) {
		if expr == nil {
			return
		}

		switch e := expr.(type) {
		case *ast.Identifier:
			name := e.Name
			if e.Quantifier != "" && !strings.HasSuffix(name, e.Quantifier) {
				name += e.Quantifier
			}
			isWildcard := strings.HasPrefix(name, "$") && len(name) > 2 && strings.HasSuffix(name, "*")
			isExplicit := strings.HasPrefix(name, "$") && name != "$" && !strings.HasSuffix(name, "*")
			if inStringSet && isWildcard {
				wildcards = append(wildcards, wildcardStringRef{name: name, pos: e.Pos})
			} else if isExplicit {
				explicitStrings = append(explicitStrings, wildcardStringRef{name: name, pos: e.Pos})
			}
		case *ast.OfExpression:
			if e.Strings != nil {
				walkExpr(e.Strings, true)
			}
			walkExpr(e.Count, false)
			walkExpr(e.InRange, false)
			walkExpr(e.AtOffset, false)
		case *ast.ForLoop:
			if e.Range != nil {
				walkExpr(e.Range, true)
			}
			walkExpr(e.Condition, false)
			walkExpr(e.InRange, false)
			walkExpr(e.AtOffset, false)
		case *ast.BinaryOp:
			walkExpr(e.Left, inStringSet)
			walkExpr(e.Right, inStringSet)
		case *ast.UnaryOp:
			walkExpr(e.Right, inStringSet)
		case *ast.FunctionCall:
			for _, arg := range e.Args {
				walkExpr(arg, inStringSet)
			}
		case *ast.StringCount:
			if ident, ok := e.String.(*ast.Identifier); ok && strings.HasPrefix(ident.Name, "$") && ident.Name != "$" {
				explicitStrings = append(explicitStrings, wildcardStringRef{name: ident.Name, pos: e.Pos})
			}
			walkExpr(e.Index, false)
		case *ast.StringOffset:
			if ident, ok := e.String.(*ast.Identifier); ok && strings.HasPrefix(ident.Name, "$") && ident.Name != "$" {
				explicitStrings = append(explicitStrings, wildcardStringRef{name: ident.Name, pos: e.Pos})
			}
			walkExpr(e.Index, false)
		case *ast.StringLength:
			if ident, ok := e.String.(*ast.Identifier); ok && strings.HasPrefix(ident.Name, "$") && ident.Name != "$" {
				explicitStrings = append(explicitStrings, wildcardStringRef{name: ident.Name, pos: e.Pos})
			}
			walkExpr(e.Index, false)
		case *ast.LengthOf:
			walkExpr(e.Target, inStringSet)
		case *ast.PercentExpression:
			walkExpr(e.Value, false)
		case *ast.StringTuple:
			for _, elem := range e.Elements {
				walkExpr(elem, inStringSet)
			}
		}
	}

	walkExpr(rule.Condition, false)

	if len(wildcards) == 0 || len(explicitStrings) == 0 {
		return
	}

	type collisionKey struct {
		ident    string
		wildcard string
	}
	reported := make(map[collisionKey]bool)

	for _, w := range wildcards {
		prefix := strings.TrimSuffix(w.name, "*")
		if prefix == "$" || prefix == "" {
			continue
		}
		for _, s := range explicitStrings {
			if !definedStrings[s.name] {
				continue
			}
			if strings.HasPrefix(s.name, prefix) {
				key := collisionKey{ident: s.name, wildcard: w.name}
				if reported[key] {
					continue
				}
				reported[key] = true
				c.addRuleWarning(CompilationWarning{
					Code:    WarningWildcardAbsorption,
					Phase:   "semantic",
					Message: fmt.Sprintf("String '%s' matches wildcard '%s' in condition, causing quantifier absorption or unintended set expansion", s.name, w.name),
					Rule:    rule.Name,
					String:  s.name,
					Line:    s.pos.Line,
					Column:  s.pos.Column,
				})
			}
		}
	}
}

func (c *Compiler) collectCompiledPatternWarnings(program *ast.Program, compiledRules []*CompiledRule) {
	astRules := make(map[string]*ast.Rule, len(program.Rules))
	for _, rule := range program.Rules {
		astRules[rule.Name] = rule
	}

	for _, rule := range compiledRules {
		for _, id := range rule.StringIdentifiers() {
			reason := slowPatternReason(rule, id)
			if reason == "" {
				continue
			}
			line, column := 0, 0
			if sourceRule := astRules[rule.Name]; sourceRule != nil {
				if sourceString := findASTString(sourceRule.Strings, id); sourceString != nil {
					line, column = sourceString.Pos.Line, sourceString.Pos.Column
				}
			}
			c.addRuleWarning(CompilationWarning{
				Code: WarningSlowPattern, Phase: "performance",
				Message: fmt.Sprintf("String '%s' %s and may slow scanning", id, reason),
				Rule:    rule.Name, String: id, Line: line, Column: column,
			})
		}
	}
}

func slowPatternReason(rule *CompiledRule, id string) string {
	switch rule.StringKinds[id] {
	case StringKindText:
		if len(rule.TextPatterns[id]) < 3 {
			return "is shorter than three bytes"
		}
	case StringKindRegex:
		pattern, ok := rule.RegexPatterns[id]
		if !ok || pattern.anchored {
			return ""
		}
		if len(pattern.prefix) >= 2 || len(pattern.atom) >= 2 || pattern.leadingGap != nil {
			return ""
		}
		for _, atom := range pattern.alternativeAtoms {
			if len(atom.data) >= 2 {
				return ""
			}
		}
		return "has no selective literal prefilter"
	case StringKindHex:
		pattern := rule.HexPatterns[id]
		if pattern == nil {
			return ""
		}
		atom, ok := selectHexAtom(pattern.Tokens)
		if !ok || len(atom.data) < 2 {
			return "has no selective two-byte atom"
		}
	}
	return ""
}

func findASTString(strings []*ast.String, id string) *ast.String {
	for _, str := range strings {
		if str.Identifier == id {
			return str
		}
	}
	return nil
}

// isTrivialCondition checks if a condition is overly simple (e.g., just "true")
func (c *Compiler) isTrivialCondition(expr ast.Expression) bool {
	if lit, ok := expr.(*ast.Literal); ok {
		if boolVal, ok := lit.Value.(bool); ok && boolVal {
			return true
		}
	}
	return false
}
