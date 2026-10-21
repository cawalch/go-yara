package semantic

import (
	"sort"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func (v *Validator) validateRuleDependencyCycles(program *ast.Program) {
	ruleNames := make(map[string]token.Position, len(program.Rules))
	for _, rule := range program.Rules {
		ruleNames[rule.Name] = rule.Pos
	}

	deps := make(map[string]map[string]token.Position, len(program.Rules))
	for _, rule := range program.Rules {
		collector := ruleReferenceCollector{
			ruleNames: ruleNames,
		}
		collector.collect(rule.Condition, nil)
		if len(collector.refs) > 0 {
			deps[rule.Name] = collector.refs
		}
	}

	state := make(map[string]int, len(program.Rules))
	reported := make(map[string]bool)
	var path []string
	var visit func(string)
	visit = func(ruleName string) {
		state[ruleName] = 1
		path = append(path, ruleName)

		for dep, pos := range deps[ruleName] {
			switch state[dep] {
			case 0:
				visit(dep)
			case 1:
				cycle := appendCyclePath(path, dep)
				key := strings.Join(cycle, " -> ")
				if reported[key] {
					continue
				}
				reported[key] = true
				v.addError(&Error{
					Code:     ErrCodeCircularDependency,
					Message:  "circular rule dependency: " + key,
					Position: pos,
					Rule:     ruleName,
				})
			}
		}

		path = path[:len(path)-1]
		state[ruleName] = 2
	}

	for _, rule := range program.Rules {
		if state[rule.Name] == 0 {
			visit(rule.Name)
		}
	}
}

func appendCyclePath(path []string, dep string) []string {
	for i, name := range path {
		if name == dep {
			cycle := make([]string, 0, len(path)-i+1)
			cycle = append(cycle, path[i:]...)
			cycle = append(cycle, dep)
			return cycle
		}
	}
	return append(append([]string{}, path...), dep)
}

type ruleReferenceCollector struct {
	ruleNames map[string]token.Position
	refs      map[string]token.Position
}

// RuleDependencies returns direct rule references for each rule in program.
// additionalRuleNames can be used to recognize references to rules that were
// removed from the AST, such as rules skipped during error recovery.
func RuleDependencies(program *ast.Program, additionalRuleNames ...string) map[string][]string {
	ruleNames := make(map[string]token.Position, len(program.Rules)+len(additionalRuleNames))
	for _, rule := range program.Rules {
		ruleNames[rule.Name] = rule.Pos
	}
	for _, name := range additionalRuleNames {
		if _, exists := ruleNames[name]; !exists {
			ruleNames[name] = token.Position{}
		}
	}

	dependencies := make(map[string][]string, len(program.Rules))
	for _, rule := range program.Rules {
		collector := ruleReferenceCollector{
			ruleNames: ruleNames,
		}
		collector.collect(rule.Condition, nil)

		ruleDeps := make([]string, 0, len(collector.refs))
		for name := range collector.refs {
			ruleDeps = append(ruleDeps, name)
		}
		sort.Strings(ruleDeps)
		dependencies[rule.Name] = ruleDeps
	}
	return dependencies
}

func (c *ruleReferenceCollector) collect(expr ast.Expression, scoped map[string]bool) {
	switch e := expr.(type) {
	case nil, *ast.Literal:
		return
	case *ast.Identifier:
		if scoped[e.Name] {
			return
		}
		if _, ok := c.ruleNames[e.Name]; ok {
			if c.refs == nil {
				c.refs = make(map[string]token.Position, 2)
			}
			c.refs[e.Name] = e.Position()
		}
	case *ast.BinaryOp:
		c.collect(e.Left, scoped)
		c.collect(e.Right, scoped)
	case *ast.UnaryOp:
		c.collect(e.Right, scoped)
	case *ast.FunctionCall:
		for _, arg := range e.Args {
			c.collect(arg, scoped)
		}
	case *ast.ForLoop:
		c.collect(e.Range, scoped)
		innerScoped := cloneBoolMap(scoped)
		for _, variable := range e.Variables {
			innerScoped[variable] = true
		}
		c.collect(e.Condition, innerScoped)
		c.collect(e.InRange, innerScoped)
		c.collect(e.AtOffset, innerScoped)
	case *ast.OfExpression:
		c.collect(e.Count, scoped)
		c.collect(e.InRange, scoped)
		c.collect(e.AtOffset, scoped)
	case *ast.StringLength:
		c.collect(e.Index, scoped)
	case *ast.StringOffset:
		c.collect(e.Index, scoped)
	case *ast.StringCount:
		c.collect(e.Index, scoped)
	case *ast.LengthOf:
		return
	case *ast.PercentExpression:
		c.collect(e.Value, scoped)
	case *ast.StringTuple:
		return
	}
}

func cloneBoolMap(src map[string]bool) map[string]bool {
	dst := make(map[string]bool, len(src)+1)
	for key, value := range src {
		dst[key] = value
	}
	return dst
}
