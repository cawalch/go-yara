package compiler

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
	"github.com/cawalch/go-yara/token"
)

// HeaderConstraintKind identifies a cheap predicate that must hold before a
// rule can match.
type HeaderConstraintKind uint8

const (
	HeaderIntegerEquals HeaderConstraintKind = iota
	HeaderStringAt
)

// HeaderConstraint is a mandatory fixed-offset predicate derived from a rule
// condition. The scanner evaluates these before running pattern searches.
type HeaderConstraint struct {
	Kind      HeaderConstraintKind
	Offset    int64
	Width     int
	BigEndian bool
	Value     uint64
	String    string
}

func deriveHeaderConstraints(condition ast.Expression) []HeaderConstraint {
	constraints := mandatoryHeaderConstraints(condition)
	keys := make([]string, 0, len(constraints))
	for key := range constraints {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]HeaderConstraint, 0, len(keys))
	for _, key := range keys {
		result = append(result, constraints[key])
	}
	return result
}

func mandatoryHeaderConstraints(expr ast.Expression) map[string]HeaderConstraint {
	if constraint, ok := headerConstraintFromExpression(expr); ok {
		return map[string]HeaderConstraint{headerConstraintKey(constraint): constraint}
	}
	binaryExpr, ok := expr.(*ast.BinaryOp)
	if !ok {
		return nil
	}
	left := mandatoryHeaderConstraints(binaryExpr.Left)
	right := mandatoryHeaderConstraints(binaryExpr.Right)
	switch binaryExpr.Op {
	case token.AND:
		combined := make(map[string]HeaderConstraint, len(left)+len(right))
		for key, constraint := range left {
			combined[key] = constraint
		}
		for key, constraint := range right {
			combined[key] = constraint
		}
		return combined
	case token.OR:
		common := make(map[string]HeaderConstraint)
		for key, constraint := range left {
			if _, exists := right[key]; exists {
				common[key] = constraint
			}
		}
		return common
	default:
		return nil
	}
}

func headerConstraintFromExpression(expr ast.Expression) (HeaderConstraint, bool) {
	binaryExpr, ok := expr.(*ast.BinaryOp)
	if !ok {
		return HeaderConstraint{}, false
	}
	if binaryExpr.Op == token.AT {
		identifier, ok := binaryExpr.Left.(*ast.Identifier)
		if !ok || !strings.HasPrefix(identifier.Name, "$") || identifier.Quantifier != "" {
			return HeaderConstraint{}, false
		}
		offset, ok := nonNegativeLiteral(binaryExpr.Right)
		if !ok {
			return HeaderConstraint{}, false
		}
		return HeaderConstraint{Kind: HeaderStringAt, Offset: offset, String: identifier.Name}, true
	}
	if binaryExpr.Op != token.EQ {
		return HeaderConstraint{}, false
	}

	if constraint, ok := integerReadConstraint(binaryExpr.Left, binaryExpr.Right); ok {
		return constraint, true
	}
	return integerReadConstraint(binaryExpr.Right, binaryExpr.Left)
}

func integerReadConstraint(readExpr, valueExpr ast.Expression) (HeaderConstraint, bool) {
	call, ok := readExpr.(*ast.FunctionCall)
	if !ok || len(call.Args) != 1 {
		return HeaderConstraint{}, false
	}
	width, bigEndian, ok := integerReadShape(call.Function)
	if !ok {
		return HeaderConstraint{}, false
	}
	offset, ok := nonNegativeLiteral(call.Args[0])
	if !ok {
		return HeaderConstraint{}, false
	}
	value, ok := nonNegativeLiteral(valueExpr)
	if !ok {
		return HeaderConstraint{}, false
	}
	if width < 8 && uint64(value) >= uint64(1)<<(width*8) {
		return HeaderConstraint{}, false
	}
	return HeaderConstraint{
		Kind:      HeaderIntegerEquals,
		Offset:    offset,
		Width:     width,
		BigEndian: bigEndian,
		Value:     uint64(value),
	}, true
}

func integerReadShape(name string) (width int, bigEndian bool, ok bool) {
	name = strings.ToLower(name)
	bigEndian = strings.HasSuffix(name, "be")
	name = strings.TrimSuffix(name, "be")
	switch name {
	case "uint8", "int8":
		return 1, bigEndian, true
	case "uint16", "int16":
		return 2, bigEndian, true
	case "uint32", "int32":
		return 4, bigEndian, true
	case "uint64", "int64":
		return 8, bigEndian, true
	default:
		return 0, false, false
	}
}

func nonNegativeLiteral(expr ast.Expression) (int64, bool) {
	literal, ok := expr.(*ast.Literal)
	if !ok {
		return 0, false
	}
	switch value := literal.Value.(type) {
	case int64:
		return value, value >= 0
	case string:
		parsed, err := parseIntLiteral(value)
		return parsed, err == nil && parsed >= 0
	default:
		return 0, false
	}
}

func headerConstraintKey(constraint HeaderConstraint) string {
	return fmt.Sprintf("%d:%d:%d:%t:%d:%s", constraint.Kind, constraint.Offset, constraint.Width,
		constraint.BigEndian, constraint.Value, constraint.String)
}

func ruleHeaderConstraintsMatch(rule *CompiledRule, data []byte) bool {
	return ruleHeaderConstraintsMatchContext(rule, &MatchContext{Data: data})
}

func ruleHeaderConstraintsMatchContext(rule *CompiledRule, ctx *MatchContext) bool {
	for _, constraint := range rule.HeaderConstraints {
		switch constraint.Kind {
		case HeaderIntegerEquals:
			if !headerIntegerEquals(ctx, constraint) {
				return false
			}
		case HeaderStringAt:
			if !compiledPatternMatchesAtContext(rule, constraint.String, ctx, constraint.Offset) {
				return false
			}
		}
	}
	return true
}

func headerIntegerEquals(ctx *MatchContext, constraint HeaderConstraint) bool {
	if constraint.Width <= 0 {
		return false
	}
	bytes, ok := ctx.dataRange(constraint.Offset, int64(constraint.Width))
	if !ok {
		return false
	}
	var value uint64
	switch constraint.Width {
	case 1:
		value = uint64(bytes[0])
	case 2:
		if constraint.BigEndian {
			value = uint64(binary.BigEndian.Uint16(bytes))
		} else {
			value = uint64(binary.LittleEndian.Uint16(bytes))
		}
	case 4:
		if constraint.BigEndian {
			value = uint64(binary.BigEndian.Uint32(bytes))
		} else {
			value = uint64(binary.LittleEndian.Uint32(bytes))
		}
	case 8:
		if constraint.BigEndian {
			value = binary.BigEndian.Uint64(bytes)
		} else {
			value = binary.LittleEndian.Uint64(bytes)
		}
	default:
		return false
	}
	return value == constraint.Value
}

//nolint:revive // argument-limit: scan-hot internal predicate
func compiledPatternMatchesAtContext(rule *CompiledRule, id string, ctx *MatchContext, offset int64) bool {
	if ctx == nil {
		return false
	}
	if ctx.Data != nil {
		return compiledPatternMatchesAt(rule, id, ctx.Data, offset)
	}
	for _, block := range ctx.Blocks {
		if offset < block.Base || offset > block.Base+int64(len(block.Data)) {
			continue
		}
		if compiledPatternMatchesAt(rule, id, block.Data, offset-block.Base) {
			return true
		}
	}
	return false
}

//nolint:revive // argument-limit: scan-hot internal predicate
func compiledPatternMatchesAt(rule *CompiledRule, id string, data []byte, offset int64) bool {
	if offset < 0 || offset > int64(len(data)) {
		return false
	}
	switch rule.StringKinds[id] {
	case StringKindText:
		for _, info := range rule.Automaton.Strings {
			if info.Identifier != id {
				continue
			}
			candidate := Match{Pattern: id, Offset: offset, Length: info.Length}
			wide := info.Flags&regex.FlagsWide != 0
			nocase := info.Flags&regex.FlagsNoCase != 0
			if verifyTextMatch(data, candidate, info.Data, nocase) &&
				matchPassesModifiers(data, candidate, rule.StringModifiers[id], wide) {
				return true
			}
		}
	case StringKindRegex:
		pattern := rule.RegexPatterns[id]
		modifiers := rule.StringModifiers[id]
		wide := hasModifier(modifiers, ast.StringModifierWide)
		ascii := hasModifier(modifiers, ast.StringModifierASCII)
		for _, useWide := range []bool{wide, false} {
			if !useWide && wide && !ascii {
				continue
			}
			flags := pattern.Flags &^ regex.FlagsWide
			if useWide {
				flags |= regex.FlagsWide
			}
			matched, start, end := execRegexMatchAt(nil, pattern, data, flags, useWide, int(offset))
			candidate := Match{Pattern: id, Offset: offset + int64(start), Length: end - start}
			if matched && start == 0 && matchPassesModifiers(data, candidate, modifiers, useWide) {
				return true
			}
			if !wide || ascii {
				break
			}
		}
	case StringKindHex:
		pattern := rule.HexPatterns[id]
		for _, match := range FindHexMatches(pattern, data[int(offset):]) {
			if match.Offset > 0 {
				break
			}
			match.Offset += offset
			match.Pattern = id
			if matchPassesModifiers(data, match, rule.StringModifiers[id], false) {
				return true
			}
		}
	}
	return false
}
