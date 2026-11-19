package semantic

import (
	"maps"
	"sort"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func (v *Validator) validateRuleDependencyCycles(program *ast.Program) {
	ruleIndex := make(map[string]int, len(program.Rules))
	for i, rule := range program.Rules {
		ruleIndex[rule.Name] = i
	}

	var deps map[int]map[string]token.Position
	for i, rule := range program.Rules {
		collector := ruleReferenceCollector{
			ruleNames: ruleIndex,
		}
		collector.collect(rule.Condition, nil)
		if len(collector.refs) > 0 {
			if deps == nil {
				deps = make(map[int]map[string]token.Position)
			}
			deps[i] = collector.refs
		}
	}
	if len(deps) == 0 {
		return
	}

	state := make([]uint8, len(program.Rules))
	reported := make(map[string]bool)
	var path []string
	var visit func(int)
	visit = func(idx int) {
		ruleName := program.Rules[idx].Name
		state[idx] = 1
		path = append(path, ruleName)

		for dep, pos := range deps[idx] {
			depIdx := ruleIndex[dep]
			switch state[depIdx] {
			case 0:
				visit(depIdx)
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
		state[idx] = 2
	}

	for i := range program.Rules {
		if state[i] == 0 && len(deps[i]) > 0 {
			visit(i)
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
	ruleNames map[string]int
	refs      map[string]token.Position
}

// RuleDependencies returns direct rule references for each rule in program.
// additionalRuleNames can be used to recognize references to rules that were
// removed from the AST, such as rules skipped during error recovery.
func RuleDependencies(program *ast.Program, additionalRuleNames ...string) map[string][]string {
	ruleNames := make(map[string]int, len(program.Rules)+len(additionalRuleNames))
	for i, rule := range program.Rules {
		ruleNames[rule.Name] = i
	}
	for _, name := range additionalRuleNames {
		if _, exists := ruleNames[name]; !exists {
			ruleNames[name] = -1
		}
	}

	dependencies := make(map[string][]string, len(program.Rules))
	collector := ruleReferenceCollector{
		ruleNames: ruleNames,
	}
	for _, rule := range program.Rules {
		clear(collector.refs)
		collector.collect(rule.Condition, nil)

		if len(collector.refs) == 0 {
			dependencies[rule.Name] = []string{}
			continue
		}
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
	case *ast.MemberAccess:
		// Field names are not rule references. Only indexes can reference rules.
		c.collectModuleIndexes(e.Object, scoped)
	case *ast.IndexAccess:
		c.collectModuleIndexes(e.Object, scoped)
		c.collect(e.Index, scoped)
	case *ast.FunctionCall:
		for _, arg := range e.Args {
			c.collect(arg, scoped)
		}
	case *ast.ForLoop:
		c.collect(e.QuantifierExpr, scoped)
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
	maps.Copy(dst, src)
	return dst
}

func (c *ruleReferenceCollector) collectModuleIndexes(expr ast.Expression, scoped map[string]bool) {
	switch e := expr.(type) {
	case *ast.MemberAccess:
		c.collectModuleIndexes(e.Object, scoped)
	case *ast.IndexAccess:
		c.collectModuleIndexes(e.Object, scoped)
		c.collect(e.Index, scoped)
	}
}
