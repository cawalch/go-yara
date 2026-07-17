package compiler

import (
	"fmt"
	"strings"

	"github.com/cawalch/go-yara/regex"
)

// executeLengthOperation executes OpLength.
func (i *Interpreter) executeLengthOperation() error {
	if err := i.validateStackUnderflowN(OpLength, 2); err != nil {
		return err
	}

	index := i.stack[len(i.stack)-1]
	pattern := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if index.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer index operand required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	if index.IntVal < 1 {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}
	match, exists := i.matchContext.matchAt(i.getString(pattern), int(index.IntVal-1))
	if !exists {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: int64(match.Length)})
}

// executeCountOperation executes OpCount.
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

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	found := i.matchContext.matchCount(i.getString(pattern)) > 0
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(found)})
}

// executeFoundAtOperation executes OpFoundAt.
func (i *Interpreter) executeFoundAtOperation() error {
	if err := i.validateStackUnderflowN(OpFoundAt, 2); err != nil {
		return err
	}

	offset := i.stack[len(i.stack)-1]
	pattern := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if offset.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer offset operand required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
	}

	found := i.matchContext.anyMatch(i.getString(pattern), func(match matchSpan) bool {
		return match.Offset == offset.IntVal
	})
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(found)})
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

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if startOffset.Type != ValueTypeInt || endOffset.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer offset operands required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
	}

	found := i.matchContext.anyMatch(i.getString(pattern), func(match matchSpan) bool {
		return match.Offset >= startOffset.IntVal && match.Offset <= endOffset.IntVal
	})
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(found)})
}

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

// executeCountInOf executes OpCountInOf: "#a in (min..max) of ($str*)".
// Stack: [setIndex, min, max]
// Counts how many strings in the set have at least one match, then checks if that count is within [min, max].
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

// executeOffsetOperation executes OpOffset.
func (i *Interpreter) executeOffsetOperation() error {
	if err := i.validateStackUnderflowN(OpOffset, 2); err != nil {
		return err
	}

	index := i.stack[len(i.stack)-1]
	pattern := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if pattern.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string pattern operand required"}
	}

	if index.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer index operand required"}
	}

	if i.matchContext == nil {
		return i.push(Value{Type: ValueTypeInt, IntVal: -1})
	}

	if index.IntVal < 1 {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	match, exists := i.matchContext.matchAt(i.getString(pattern), int(index.IntVal-1))
	if !exists {
		return i.push(Value{Type: ValueTypeUndefined})
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: match.Offset})
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

	total := len(set)
	matched := 0
	for _, id := range set {
		if i.matchContext.matchCount(id) > 0 {
			matched++
		}
	}

	if total == 0 {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	percentFloat := float64(matched) / float64(total) * 100.0
	result := percentFloat >= float64(percent.IntVal)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
}

// executeOfFoundIn executes OpOfFoundIn.
// Stack: [count, string_set_id, min, max] (bottom to top)
// Counts how many strings in the set have at least one match within [min, max].
// Returns true if matched_count >= count.
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
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfFoundIn, Message: "range bounds must be integers"}
	}

	set, err := i.resolveStringSet(stringsID)
	if err != nil {
		return err
	}

	matched := 0
	for _, id := range set {
		if i.matchContext.anyMatch(id, func(match matchSpan) bool {
			return match.Offset >= minVal.IntVal && match.Offset <= maxVal.IntVal
		}) {
			matched++
		}
	}

	result := i.applyCountLogicWithValue(count, int64(matched), len(set))
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
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
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfFoundAt, Message: "offset must be integer"}
	}

	set, err := i.resolveStringSet(stringsID)
	if err != nil {
		return err
	}

	matched := 0
	for _, id := range set {
		if i.matchContext.anyMatch(id, func(match matchSpan) bool {
			return match.Offset == offsetVal.IntVal
		}) {
			matched++
		}
	}

	result := i.applyCountLogicWithValue(count, int64(matched), len(set))
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
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
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfPercentIn, Message: "range bounds must be integers"}
	}

	set, err := i.resolveStringSet(stringsID)
	if err != nil {
		return err
	}

	matched := 0
	for _, id := range set {
		if i.matchContext.anyMatch(id, func(match matchSpan) bool {
			return match.Offset >= minVal.IntVal && match.Offset <= maxVal.IntVal
		}) {
			matched++
		}
	}

	if len(set) == 0 {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	percentFloat := float64(matched) / float64(len(set)) * 100.0
	result := percentFloat >= float64(percent.IntVal)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
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
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: OpOfPercentAt, Message: "offset must be integer"}
	}

	set, err := i.resolveStringSet(stringsID)
	if err != nil {
		return err
	}

	matched := 0
	for _, id := range set {
		if i.matchContext.anyMatch(id, func(match matchSpan) bool {
			return match.Offset == offsetVal.IntVal
		}) {
			matched++
		}
	}

	if len(set) == 0 {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	percentFloat := float64(matched) / float64(len(set)) * 100.0
	result := percentFloat >= float64(percent.IntVal)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(result)})
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

// applyCountLogic applies count logic to determine if enough strings matched.
func (i *Interpreter) applyCountLogic(ids []string, count Value) bool {
	if i.matchContext == nil {
		return false
	}
	total := len(ids)
	matched := 0
	for _, id := range ids {
		if i.matchContext.matchCount(id) > 0 {
			matched++
		}
	}
	return i.applyCountLogicWithValue(count, int64(matched), total)
}

// applyCountLogicWithValue applies count logic given a pre-computed matched count.
// The optional total parameter is used for the "all" (countAll) quantifier check.
func (i *Interpreter) applyCountLogicWithValue(count Value, matched int64, total ...int) bool {
	if count.Type != ValueTypeInt {
		return false
	}
	var totalCount int
	if len(total) > 0 {
		totalCount = total[0]
	}
	switch count.IntVal {
	case 0:
		return matched == 0
	case countAll:
		return totalCount > 0 && matched == int64(totalCount)
	default:
		if count.IntVal < 0 {
			return false
		}
		return matched >= count.IntVal
	}
}

// executeMatchesOperation executes OpMatches.
func (i *Interpreter) executeMatchesOperation() error {
	if err := i.validateStackUnderflowN(OpMatches, 2); err != nil {
		return err
	}

	regexVal := i.stack[len(i.stack)-1]
	value := i.stack[len(i.stack)-2]
	i.stack = i.stack[:len(i.stack)-2]

	if regexVal.Type != ValueTypeString || value.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "string operands required"}
	}

	compiled, flags, err := i.compileRegexLiteral(i.getString(regexVal))
	if err != nil {
		return &InterpreterError{Type: ErrorRuntime, Opcode: OpMatches, Message: err.Error()}
	}

	valueStr := i.getString(value)
	if strings.HasPrefix(valueStr, "$") {
		// String identifier: check if any match content matches the regex
		matched := i.matchContext.anyMatch(valueStr, func(match matchSpan) bool {
			end := min(int(match.Offset)+match.Length, len(i.matchContext.Data))
			return regex.Exec(compiled, i.matchContext.Data[int(match.Offset):end], flags|regex.FlagsScan)
		})
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(matched)})
	}

	matched := regex.Exec(compiled, []byte(valueStr), flags|regex.FlagsScan)
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(matched)})
}

// compileRegexLiteral compiles a regex literal string into bytecode.
func (i *Interpreter) compileRegexLiteral(literal string) ([]byte, regex.Flags, error) {
	if cached, ok := i.regexCache[literal]; ok {
		return cached.code, cached.flags, nil
	}
	cleaned := cleanRegexPattern(literal)
	flags := parseInlineRegexFlags(literal)
	parser := regex.NewParser(regex.ParserFlagEnableStrictEscapeSequences)
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
		return strings.HasPrefix(strings.ToLower(a), strings.ToLower(b))
	})
}

func (i *Interpreter) executeIendswithOperation() error {
	return i.executeStringBinaryOp(OpIendswith, func(a, b string) bool {
		return strings.HasSuffix(strings.ToLower(a), strings.ToLower(b))
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
	if left.Type != ValueTypeString || right.Type != ValueTypeString {
		return &InterpreterError{Type: ErrorTypeMismatch, Opcode: op, Message: "string operands required"}
	}
	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(fn(i.getString(left), i.getString(right)))})
}
