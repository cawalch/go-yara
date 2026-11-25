package compiler

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/cawalch/go-yara/regex"
)

// executeLengthOperation executes OpLength.
func (i *Interpreter) executeIndexedMatchMetric(op Opcode, extract func(matchSpan) int64) error {
	if err := i.validateStackUnderflowN(op, 2); err != nil {
		return err
	}

	index := i.stack[len(i.stack)-1]
	pattern := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if pattern.Type == ValueTypeUndefined || index.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}
	if index.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer index operand required"}
	}
	if i.matchContext == nil || index.IntVal < 1 {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	match, exists := i.matchContext.matchAt(i.getString(pattern), int(index.IntVal-1))
	if !exists {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: extract(match)})
}

func (i *Interpreter) executeLengthOperation() error {
	return i.executeIndexedMatchMetric(OpLength, func(m matchSpan) int64 { return int64(m.Length) })
}

// executeCountOperation executes OpCount.
func (i *Interpreter) pushPatternBool(pattern Value, fn func(string) bool) error {
	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}
	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(fn(i.getString(pattern)))})
}

func (i *Interpreter) executeCountOperation() error {
	if err := i.validateStackUnderflow(OpCount); err != nil {
		return err
	}

	pattern := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: int64(i.matchContext.matchCount(i.getString(pattern)))})
}

// executeLengthOfOperation executes OpLengthOf: "length of (X)".
// Stack: [setIndex] -> [totalLength]
func (i *Interpreter) executeLengthOfOperation() error {
	if err := i.validateStackUnderflow(OpLengthOf); err != nil {
		return err
	}

	setIndex := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]

	set, err := i.resolveStringSet(setIndex)
	if err != nil {
		return err
	}

	if len(set) == 0 || i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	// Sum the total length of all matches for all strings in the set
	var totalLength int64
	for _, id := range set {
		i.matchContext.eachMatch(id, func(match matchSpan) bool {
			totalLength += int64(match.Length)
			return true
		})
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: totalLength})
}

// executeFoundOperation executes OpFound.
func (i *Interpreter) executeFoundOperation() error {
	if err := i.validateStackUnderflow(OpFound); err != nil {
		return err
	}
	pattern := i.stack[len(i.stack)-1]
	i.stack = i.stack[:len(i.stack)-1]
	return i.pushPatternBool(pattern, func(id string) bool {
		return i.matchContext.matchCount(id) > 0
	})
}

// executeFoundAtOperation executes OpFoundAt.
func (i *Interpreter) executeFoundAtOperation() error {
	if err := i.validateStackUnderflowN(OpFoundAt, 2); err != nil {
		return err
	}

	offset := i.stack[len(i.stack)-1]
	pattern := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if pattern.Type == ValueTypeString && offset.Type != ValueTypeInt {
		if offset.Type == ValueTypeUndefined {
			return i.push(Value{Type: ValueTypeUndefined})
		}
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer offset operand required"}
	}
	return i.pushPatternBool(pattern, func(id string) bool {
		return i.matchContext.hasMatchAt(id, offset.IntVal)
	})
}

// executeFoundInOperation executes OpFoundIn.
func (i *Interpreter) executeFoundInOperation() error {
	if err := i.validateStackUnderflowN(OpFoundIn, 3); err != nil {
		return err
	}

	endOffset := i.stack[len(i.stack)-1]
	startOffset := i.stack[len(i.stack)-2]
	pattern := i.stack[len(i.stack)-3]
	i.stack = i.stack[:len(i.stack)-3]

	if pattern.Type == ValueTypeString && (startOffset.Type != ValueTypeInt || endOffset.Type != ValueTypeInt) {
		if (startOffset.Type == ValueTypeInt || startOffset.Type == ValueTypeUndefined) &&
			(endOffset.Type == ValueTypeInt || endOffset.Type == ValueTypeUndefined) {
			return i.push(Value{Type: ValueTypeUndefined})
		}
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer offset operands required"}
	}
	return i.pushPatternBool(pattern, func(id string) bool {
		return i.matchContext.hasMatchInRange(id, startOffset.IntVal, endOffset.IntVal)
	})
}

func (i *Interpreter) executeCountMatchesIn() error {
	if err := i.validateStackUnderflowN(OpCountMatchesIn, 3); err != nil {
		return err
	}
	base := len(i.stack) - 3
	pattern, lower, upper := i.stack[base], i.stack[base+1], i.stack[base+2]
	i.stack = i.stack[:base]
	if pattern.Type == ValueTypeUndefined || lower.Type == ValueTypeUndefined || upper.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if pattern.Type != ValueTypeString || lower.Type != ValueTypeInt || upper.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCountMatchesIn, Message: "count-in requires a string pattern and integer offsets"}
	}

	count := i.countMatchesIn(i.getString(pattern), lower.IntVal, upper.IntVal)
	return i.push(Value{Type: ValueTypeInt, IntVal: count})
}

func (i *Interpreter) countMatchesIn(id string, lower, upper int64) int64 {
	if i.matchContext == nil || lower > upper {
		return 0
	}
	// Scanner conditions evaluate normalized spans. A monotonic rule can
	// also run during collection, before its spans are sorted.
	if i.scannerOwned && i.currentCompiledRule != nil && !i.currentCompiledRule.ConditionMonotonic {
		spans := i.matchContext.spansFor(id)
		if len(spans) != 0 && lower <= spans[0].Offset && spans[len(spans)-1].Offset <= upper {
			return int64(len(spans))
		}
		start := sort.Search(len(spans), func(n int) bool { return spans[n].Offset >= lower })
		spans = spans[start:]
		return int64(sort.Search(len(spans), func(n int) bool { return spans[n].Offset > upper }))
	}

	var count int64
	i.matchContext.eachMatch(id, func(match matchSpan) bool {
		if lower <= match.Offset && match.Offset <= upper {
			count++
		}
		return true
	})
	return count
}

// Legacy compiled artifacts retain the original count predicates.
// executeCountInRange executes OpCountIn.
// Stack: count, min, max → pops 3, pushes (count >= min && count <= max)
func (i *Interpreter) executeCountInRange() error {
	if err := i.validateStackUnderflowN(OpCountIn, 3); err != nil {
		return err
	}

	maxVal := i.stack[len(i.stack)-1]
	minVal := i.stack[len(i.stack)-2]
	count := i.stack[len(i.stack)-3]
	i.stack = i.stack[:len(i.stack)-3]

	if count.Type != ValueTypeInt || minVal.Type != ValueTypeInt || maxVal.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCountIn, Message: "count-in requires integer operands"}
	}

	result := count.IntVal >= minVal.IntVal && count.IntVal <= maxVal.IntVal
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
}

func (i *Interpreter) executeCountInOf() error {
	if err := i.validateStackUnderflowN(OpCountInOf, 3); err != nil {
		return err
	}

	maxVal := i.stack[len(i.stack)-1]
	minVal := i.stack[len(i.stack)-2]
	setIndex := i.stack[len(i.stack)-3]
	i.stack = i.stack[:len(i.stack)-3]

	if minVal.Type != ValueTypeInt || maxVal.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpCountInOf, Message: "count-in-of requires integer range bounds"}
	}

	set, err := i.resolveStringSet(setIndex)
	if err != nil {
		return err
	}

	if len(set) == 0 {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(minVal.IntVal <= 0 && maxVal.IntVal >= 0)})
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(minVal.IntVal <= 0 && maxVal.IntVal >= 0)})
	}

	// Count how many strings in the set have at least one match
	matchedCount := 0
	for _, id := range set {
		if i.matchContext.matchCount(id) > 0 {
			matchedCount++
		}
	}

	result := int64(matchedCount) >= minVal.IntVal && int64(matchedCount) <= maxVal.IntVal
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
}

// executeProximityOperation executes OpProximity.
// Stack layout: [strA, strB, minDist, maxDist] -> OpProximity -> [boolResult]
func (i *Interpreter) executeProximityOperation() error {
	if err := i.validateStackUnderflowN(OpProximity, 4); err != nil {
		return err
	}

	maxDist := i.stack[len(i.stack)-1]
	minDist := i.stack[len(i.stack)-2]
	strB := i.stack[len(i.stack)-3]
	strA := i.stack[len(i.stack)-4]
	i.stack = i.stack[:len(i.stack)-4]

	if strA.Type != ValueTypeString || strB.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpProximity, Message: "proximity requires string pattern operands"}
	}
	if minDist.Type != ValueTypeInt || maxDist.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpProximity, Message: "proximity requires integer distance bounds"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	nameA := i.getString(strA)
	nameB := i.getString(strB)

	matched := i.matchContext.hasProximity(nameA, nameB, minDist.IntVal, maxDist.IntVal)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(matched)})
}

// executeOffsetOperation executes OpOffset.
func (i *Interpreter) executeOffsetOperation() error {
	return i.executeIndexedMatchMetric(OpOffset, func(m matchSpan) int64 { return m.Offset })
}

// executeOfOperation executes OpOf.
func (i *Interpreter) executeOfOperation() error {
	if err := i.validateStackUnderflowN(OpOf, 2); err != nil {
		return err
	}

	stringsID := i.stack[len(i.stack)-1]
	count := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	set, err := i.resolveStringSet(stringsID)
	if err != nil {
		return err
	}
	result := i.applyCountLogic(set, count)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
}

// executeOfPercentOperation executes OpOfPercent.
// Stack: [percentage, string_set_id]
// Result: true if (matched/total)*100 >= percentage
func (i *Interpreter) pushOfPercent(set []string, percent Value, matchFn func(string) bool) error {
	if len(set) == 0 {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}
	if percent.IntVal <= 0 {
		return i.push(Value{Type: ValueTypeInt, IntVal: 1})
	}
	if percent.IntVal > 100 {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}
	matched := 0
	for _, id := range set {
		if matchFn(id) {
			matched++
		}
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(int64(matched)*100 >= percent.IntVal*int64(len(set)))})
}

func (i *Interpreter) executeOfPercentOperation() error {
	if err := i.validateStackUnderflowN(OpOfPercent, 2); err != nil {
		return err
	}

	stringsID := i.stack[len(i.stack)-1]
	percent := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	set, err := i.resolveStringSet(stringsID)
	if err != nil {
		return err
	}

	if percent.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if percent.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfPercent, Message: "percentage must be an integer"}
	}
	return i.pushOfPercent(set, percent, func(id string) bool {
		return i.matchContext != nil && i.matchContext.matchCount(id) > 0
	})
}

// executeOfFoundIn executes OpOfFoundIn.
// Stack: [count, string_set_id, min, max] (bottom to top)
// Counts how many strings in the set have at least one match within [min, max].
// Returns true if matched_count >= count.
func (i *Interpreter) pushStringSetCount(stringsID, count Value, matchFn func(string) bool) error {
	set, err := i.resolveStringSet(stringsID)
	if err != nil {
		return err
	}
	result := i.evaluateStringSetCount(set, count, matchFn)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
}

func (i *Interpreter) executeOfFoundIn() error {
	if err := i.validateStackUnderflowN(OpOfFoundIn, 4); err != nil {
		return err
	}

	maxVal := i.stack[len(i.stack)-1]
	minVal := i.stack[len(i.stack)-2]
	stringsID := i.stack[len(i.stack)-3]
	count := i.stack[len(i.stack)-4]
	i.stack = i.stack[:len(i.stack)-4]

	if minVal.Type != ValueTypeInt || maxVal.Type != ValueTypeInt {
		if (minVal.Type == ValueTypeInt || minVal.Type == ValueTypeUndefined) &&
			(maxVal.Type == ValueTypeInt || maxVal.Type == ValueTypeUndefined) {
			return i.push(Value{Type: ValueTypeUndefined})
		}
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfFoundIn, Message: "range bounds must be integers"}
	}
	return i.pushStringSetCount(stringsID, count, func(id string) bool {
		return i.matchContext != nil && i.matchContext.hasMatchInRange(id, minVal.IntVal, maxVal.IntVal)
	})
}

// executeOfFoundAt executes OpOfFoundAt.
// Stack: [count, string_set_id, offset] (bottom to top)
// Counts how many strings in the set have at least one match at exactly the given offset.
// Returns true if matched_count >= count.
func (i *Interpreter) executeOfFoundAt() error {
	if err := i.validateStackUnderflowN(OpOfFoundAt, 3); err != nil {
		return err
	}

	offsetVal := i.stack[len(i.stack)-1]
	stringsID := i.stack[len(i.stack)-2]
	count := i.stack[len(i.stack)-3]
	i.stack = i.stack[:len(i.stack)-3]

	if offsetVal.Type != ValueTypeInt {
		if offsetVal.Type == ValueTypeUndefined {
			return i.push(Value{Type: ValueTypeUndefined})
		}
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfFoundAt, Message: "offset must be integer"}
	}
	return i.pushStringSetCount(stringsID, count, func(id string) bool {
		return i.matchContext != nil && i.matchContext.hasMatchAt(id, offsetVal.IntVal)
	})
}

// executeOfPercentIn executes OpOfPercentIn.
// Stack: [percent, string_set_id, min, max] (bottom to top)
// Counts how many strings in the set have at least one match within [min, max].
// Returns true if (matched/total)*100 >= percent.
func (i *Interpreter) executeOfPercentIn() error {
	if err := i.validateStackUnderflowN(OpOfPercentIn, 4); err != nil {
		return err
	}

	maxVal := i.stack[len(i.stack)-1]
	minVal := i.stack[len(i.stack)-2]
	stringsID := i.stack[len(i.stack)-3]
	percent := i.stack[len(i.stack)-4]
	i.stack = i.stack[:len(i.stack)-4]

	if minVal.Type != ValueTypeInt || maxVal.Type != ValueTypeInt {
		if (minVal.Type == ValueTypeInt || minVal.Type == ValueTypeUndefined) &&
			(maxVal.Type == ValueTypeInt || maxVal.Type == ValueTypeUndefined) {
			return i.push(Value{Type: ValueTypeUndefined})
		}
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfPercentIn, Message: "range bounds must be integers"}
	}
	if percent.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if percent.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfPercentIn, Message: "percentage must be an integer"}
	}

	set, err := i.resolveStringSet(stringsID)
	if err != nil {
		return err
	}
	return i.pushOfPercent(set, percent, func(id string) bool {
		return i.matchContext != nil && i.matchContext.hasMatchInRange(id, minVal.IntVal, maxVal.IntVal)
	})
}

// executeOfPercentAt executes OpOfPercentAt.
// Stack: [percent, string_set_id, offset] (bottom to top)
// Counts how many strings in the set have at least one match at the given offset.
// Returns true if (matched/total)*100 >= percent.
func (i *Interpreter) executeOfPercentAt() error {
	if err := i.validateStackUnderflowN(OpOfPercentAt, 3); err != nil {
		return err
	}

	offsetVal := i.stack[len(i.stack)-1]
	stringsID := i.stack[len(i.stack)-2]
	percent := i.stack[len(i.stack)-3]
	i.stack = i.stack[:len(i.stack)-3]

	if offsetVal.Type != ValueTypeInt {
		if offsetVal.Type == ValueTypeUndefined {
			return i.push(Value{Type: ValueTypeUndefined})
		}
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfPercentAt, Message: "offset must be integer"}
	}
	if percent.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if percent.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfPercentAt, Message: "percentage must be an integer"}
	}

	set, err := i.resolveStringSet(stringsID)
	if err != nil {
		return err
	}
	return i.pushOfPercent(set, percent, func(id string) bool {
		return i.matchContext != nil && i.matchContext.hasMatchAt(id, offsetVal.IntVal)
	})
}

func (i *Interpreter) resolveStringSet(stringsID Value) ([]string, error) {
	switch stringsID.Type {
	case ValueTypeInt:
		if stringsID.IntVal == stringSetAll {
			return i.allStringIdentifiers(), nil
		}
		if stringsID.IntVal == stringSetAnonymous {
			return i.anonymousStringIdentifiers(), nil
		}
		if stringsID.IntVal < 0 || int(stringsID.IntVal) >= len(i.stringSets) {
			return nil, &InterpreterError{Type: ErrorRuntime, Opcode: OpOf, Message: "string set index out of range"}
		}
		return i.stringSets[stringsID.IntVal], nil
	case ValueTypeString:
		return []string{i.getString(stringsID)}, nil
	case ValueTypeUndefined:
		return nil, nil
	default:
		return nil, &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOf, Message: "string set operand required"}
	}
}

// allStringIdentifiers returns all string identifiers known to the interpreter.
func (i *Interpreter) allStringIdentifiers() []string {
	if len(i.allStrings) > 0 {
		return i.allStrings
	}
	if i.matchContext == nil {
		return nil
	}
	return i.matchContext.matchIDs()
}

// anonymousStringIdentifiers returns all anonymous string identifiers.
func (i *Interpreter) anonymousStringIdentifiers() []string {
	if len(i.anonymousStrings) == 0 {
		return nil
	}
	ids := make([]string, len(i.anonymousStrings))
	copy(ids, i.anonymousStrings)
	return ids
}

func allStringsMatch(set []string, predicate func(string) bool) bool {
	if len(set) == 0 {
		return false
	}
	for _, id := range set {
		if !predicate(id) {
			return false
		}
	}
	return true
}

// evaluateStringSetCount counts how many strings in set satisfy predicate, short-circuiting
// as soon as the outcome is mathematically determined by count.
func (i *Interpreter) evaluateStringSetCount(set []string, count Value, predicate func(string) bool) bool {
	if count.Type == ValueTypeUndefined {
		// libyara encodes "all" as YR_UNDEFINED, so an undefined count expression
		// requires every string in a non-empty set to match.
		return allStringsMatch(set, predicate)
	}
	if count.Type != ValueTypeInt {
		return false
	}
	total := len(set)
	if count.IntVal == countAll {
		return allStringsMatch(set, predicate)
	}
	if count.IntVal == 0 {
		return !slices.ContainsFunc(set, predicate)
	}
	if count.IntVal < 0 {
		return true
	}
	matched := 0
	target := count.IntVal
	for idx, id := range set {
		if predicate(id) {
			matched++
			if int64(matched) >= target {
				return true
			}
		}
		remaining := total - 1 - idx
		if int64(matched+remaining) < target {
			return false
		}
	}
	return int64(matched) >= target
}

// applyCountLogic applies count logic to determine if enough strings matched.
func (i *Interpreter) applyCountLogic(ids []string, count Value) bool {
	if i.matchContext == nil {
		return false
	}
	return i.evaluateStringSetCount(ids, count, func(id string) bool {
		return i.matchContext.matchCount(id) > 0
	})
}

// executeMatchesOperation executes OpMatches.
func (i *Interpreter) executeMatchesOperation() error {
	return i.executeRegexMatch(OpMatches)
}

func (i *Interpreter) executeMatchesValueOperation() error {
	return i.executeRegexMatch(OpMatchesValue)
}

func (i *Interpreter) executeRegexMatch(op Opcode) error {
	if err := i.validateStackUnderflowN(op, 2); err != nil {
		return err
	}

	regexVal := i.stack[len(i.stack)-1]
	value := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if regexVal.Type == ValueTypeUndefined || value.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if regexVal.Type != ValueTypeString || value.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string operands required"}
	}

	compiled, flags, err := i.compileRegexLiteral(i.getString(regexVal))
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: op, Message: err.Error()}
	}

	var done <-chan struct{}
	if i.matchContext != nil {
		done = i.matchContext.cancelDone
	}
	valueStr := i.getString(value)
	if op == OpMatches && strings.HasPrefix(valueStr, "$") {
		var matchErr error
		matched := i.matchContext.anyMatch(valueStr, func(match matchSpan) bool {
			data, ok := i.matchContext.dataRange(match.Offset, int64(match.Length))
			if !ok {
				return false
			}
			found, err := regex.ExecWithCancel(compiled, data, flags|regex.FlagsScan, done)
			matchErr = err
			return found || err != nil // Stop visiting occurrences on cancellation.
		})
		if matchErr != nil {
			return matchErr
		}
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(matched)})
	}
	matched, err := regex.ExecWithCancel(compiled, []byte(valueStr), flags|regex.FlagsScan, done)
	if err != nil {
		return err
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(matched)})
}

// compileRegexLiteral compiles a regex literal string into bytecode.
func (i *Interpreter) compileRegexLiteral(literal string) ([]byte, regex.Flags, error) {
	if cached, ok := i.regexCache[literal]; ok {
		return cached.code, cached.flags, nil
	}
	cleaned := cleanRegexPattern(literal)
	flags := parseInlineRegexFlags(literal)
	parser := regex.NewParser(0)
	astRe, err := parser.Parse(cleaned)
	if err != nil {
		return nil, flags, fmt.Errorf("parse regex: %w", err)
	}
	code, err := regex.Compile(astRe)
	if err != nil {
		return nil, flags, fmt.Errorf("compile regex: %w", err)
	}
	i.regexCache[literal] = compiledRegex{code: code, flags: flags}
	return code, flags, nil
}

// parseInlineRegexFlags parses inline flags from a regex literal like /pattern/i.
func parseInlineRegexFlags(pattern string) regex.Flags {
	var flags regex.Flags
	if len(pattern) < 2 || pattern[0] != '/' {
		return flags
	}
	endIdx := len(pattern) - 1
	for endIdx > 0 && pattern[endIdx] != '/' {
		endIdx--
	}
	if endIdx > 0 && endIdx < len(pattern)-1 {
		for i := endIdx + 1; i < len(pattern); i++ {
			switch pattern[i] {
			case 'i', 'I':
				flags |= regex.FlagsNoCase
			case 's', 'S':
				flags |= regex.FlagsDotAll
			}
		}
	}
	return flags
}

// --- String binary operation wrappers ---

func (i *Interpreter) executeContainsOperation() error {
	return i.executeStringBinaryOp(OpContains, strings.Contains)
}

func (i *Interpreter) executeStartswithOperation() error {
	return i.executeStringBinaryOp(OpStartswith, strings.HasPrefix)
}

func (i *Interpreter) executeEndswithOperation() error {
	return i.executeStringBinaryOp(OpEndswith, strings.HasSuffix)
}

func (i *Interpreter) executeIcontainsOperation() error {
	return i.executeStringBinaryOp(OpIcontains, func(a, b string) bool {
		return strings.Contains(strings.ToLower(a), strings.ToLower(b))
	})
}

func (i *Interpreter) executeIstartswithOperation() error {
	return i.executeStringBinaryOp(OpIstartswith, func(a, b string) bool {
		return len(a) >= len(b) && strings.EqualFold(a[:len(b)], b)
	})
}

func (i *Interpreter) executeIendswithOperation() error {
	return i.executeStringBinaryOp(OpIendswith, func(a, b string) bool {
		return len(a) >= len(b) && strings.EqualFold(a[len(a)-len(b):], b)
	})
}

func (i *Interpreter) executeIequalsOperation() error {
	return i.executeStringBinaryOp(OpIequals, strings.EqualFold)
}

// executeStringBinaryOp executes a two-operand string operation.
func (i *Interpreter) executeStringBinaryOp(op Opcode, fn func(string, string) bool) error {
	if err := i.validateStackUnderflowN(op, 2); err != nil {
		return err
	}
	right := i.stack[len(i.stack)-1]
	left := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]
	if left.Type == ValueTypeUndefined || right.Type == ValueTypeUndefined {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	if left.Type != ValueTypeString || right.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: op, Message: "string operands required"}
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(fn(i.getString(left), i.getString(right)))})
}
