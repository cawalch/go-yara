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
	// HeaderIntegerEquals asserts that an integer at a fixed offset equals an expected value.
	HeaderIntegerEquals HeaderConstraintKind = iota
	// HeaderStringAt asserts that a literal string occurs at a fixed offset.
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
		return compiledPatternMatchesAtWithCancel(rule, id, ctx.Data, offset, ctx.cancelDone)
	}
	for _, block := range ctx.Blocks {
		if offset < block.Base || offset > block.Base+int64(len(block.Data)) {
			continue
		}
		if compiledPatternMatchesAtWithCancel(rule, id, block.Data, offset-block.Base, ctx.cancelDone) {
			return true
		}
	}
	return false
}

//nolint:revive // cancellation signal accompanies the fixed-offset predicate
func compiledPatternMatchesAtWithCancel(rule *CompiledRule, id string, data []byte, offset int64, done <-chan struct{}) bool {
	if offset < 0 || offset > int64(len(data)) {
		return false
	}
	switch rule.StringKinds[id] {
	case StringKindText:
		for _, info := range rule.automaton.strings {
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
			matched, start, end := execRegexMatchAt(nil, pattern, data, flags, useWide, int(offset), done)
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
		if pattern == nil || len(pattern.Tokens) == 0 {
			return false
		}
		keys := pattern.XorKeys
		if len(keys) == 0 && len(pattern.XorRange) > 0 {
			keys = expandXorKeys(pattern.XorRange)
		}
		return hexConstraintCheck{
			tokens:    pattern.Tokens,
			keys:      keys,
			data:      data,
			subData:   data[int(offset):],
			modifiers: rule.StringModifiers[id],
			offset:    offset,
			id:        id,
		}.match()
	}
	return false
}

type hexConstraintCheck struct {
	tokens    []HexPatternToken
	keys      []byte
	data      []byte
	subData   []byte
	modifiers []ast.StringModifier
	offset    int64
	id        string
}

func (c hexConstraintCheck) match() bool {
	if isLinearHexPattern(c.tokens) {
		return c.matchLinear()
	}
	return c.matchNonLinear()
}

func (c hexConstraintCheck) matchLinear() bool {
	if len(c.keys) == 0 {
		end, ok := matchLinearHexPattern(c.tokens, c.subData, 0, nil)
		return ok && matchPassesModifiers(c.data, Match{Pattern: c.id, Offset: c.offset, Length: end}, c.modifiers, false)
	}
	for _, k := range c.keys {
		if end, ok := matchLinearHexPattern(c.tokens, c.subData, 0, &k); ok {
			if matchPassesModifiers(c.data, Match{Pattern: c.id, Offset: c.offset, Length: end}, c.modifiers, false) {
				return true
			}
		}
	}
	return false
}

func (c hexConstraintCheck) matchNonLinear() bool {
	var scratch hexMatchScratch
	testKey := func(key *byte) bool {
		matched := false
		scratch.matchEach(c.tokens, c.subData, 0, key, func(end int) bool {
			if end > 0 && matchPassesModifiers(c.data, Match{Pattern: c.id, Offset: c.offset, Length: end}, c.modifiers, false) {
				matched = true
				return false
			}
			return true
		})
		return matched
	}
	if len(c.keys) == 0 {
		return testKey(nil)
	}
	for _, k := range c.keys {
		if testKey(&k) {
			return true
		}
	}
	return false
}
