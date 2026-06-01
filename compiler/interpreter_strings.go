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

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	if !exists || index.IntVal < 1 || int(index.IntVal-1) >= len(matches) {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	match := matches[index.IntVal-1] // Convert to 0-based indexing
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

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	if !exists {
		return i.push(Value{Type: ValueTypeInt, IntVal: 0})
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: int64(len(matches))})
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

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	found := exists && len(matches) > 0
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

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	if !exists {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
	}

	for _, match := range matches {
		if match.Offset == offset.IntVal {
			return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(true)})
		}
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
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

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	if !exists {
		return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
	}

	for _, match := range matches {
		if match.Offset >= startOffset.IntVal && match.Offset <= endOffset.IntVal {
			return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(true)})
		}
	}

	return i.push(Value{Type: ValueTypeInt, IntVal: boolToInt(false)})
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

	matches, exists := i.matchContext.Matches[i.getString(pattern)]
	if !exists || index.IntVal < 1 || int(index.IntVal-1) >= len(matches) {
		return i.push(Value{Type: ValueTypeUndefined})
	}

	match := matches[index.IntVal-1]
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
		if matches, ok := i.matchContext.Matches[id]; ok && len(matches) > 0 {
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
	ids := make([]string, 0, len(i.matchContext.Matches))
	for id := range i.matchContext.Matches {
		ids = append(ids, id)
	}
	return ids
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
		if matches, ok := i.matchContext.Matches[id]; ok && len(matches) > 0 {
			matched++
		}
	}
	if count.Type != ValueTypeInt {
		return false
	}
	switch count.IntVal {
	case 0:
		return matched == 0
	case countAll:
		return total > 0 && matched == total
	default:
		if count.IntVal < 0 {
			return false
		}
		return matched >= int(count.IntVal)
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

	matched := regex.Exec(compiled, []byte(i.getString(value)), flags|regex.FlagsScan)
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
