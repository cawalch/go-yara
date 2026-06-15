package compiler

import "fmt"

func (i *Interpreter) debugExecution(opcode Opcode) {
	fmt.Printf("DEBUG: Executing opcode %d (%s) at ip %d\n", opcode, opcode.String(), i.ip-1)

	// Print memory state for specific opcodes that interact with memory.
	switch opcode {
	case OpPushM, OpPopM:
		fmt.Printf("DEBUG: Memory slots in use: %d\n", i.countUsedMemorySlots())
	case OpPush, OpPop:
		fmt.Printf("DEBUG: Stack operation - current depth: %d\n", len(i.stack))
	}
}

func (i *Interpreter) debugStackState(opcode Opcode) {
	fmt.Printf("DEBUG: Stack after %s: len=%d\n", opcode.String(), len(i.stack))
	if len(i.stack) > 0 {
		top := i.stack[len(i.stack)-1]
		switch top.Type {
		case ValueTypeInt:
			fmt.Printf("DEBUG: Top of stack: Type=Int, Value=%d\n", top.IntVal)
		case ValueTypeDouble:
			fmt.Printf("DEBUG: Top of stack: Type=Double, Value=%f\n", top.DoubleVal)
		case ValueTypeString:
			fmt.Printf("DEBUG: Top of stack: Type=String, Length=%d\n", len(i.getString(top)))
		default:
			fmt.Printf("DEBUG: Top of stack: Type=%d, IntVal=%d\n", top.Type, top.IntVal)
		}
	}
}

// countUsedMemorySlots counts how many memory slots are currently in use.
func (i *Interpreter) countUsedMemorySlots() int {
	count := 0
	for _, slot := range i.memory {
		if slot.Type != ValueTypeUndefined {
			count++
		}
	}
	return count
}

// GetStats returns execution statistics.
func (i *Interpreter) GetStats() map[string]any {
	return map[string]any{
		"instructions_executed": i.ip,
		"stack_depth":           len(i.stack),
		"rules_executed":        len(i.ruleResults),
		"halted":                i.stopped,
		"current_rule":          i.currentRule,
	}
}

// EnableDebugMode enables debug information collection.
func (i *Interpreter) EnableDebugMode() {
	i.debugMode = true
}

// DisableDebugMode disables debug information collection.
func (i *Interpreter) DisableDebugMode() {
	i.debugMode = false
}

// IsDebugModeEnabled returns true if debug mode is currently enabled.
func (i *Interpreter) IsDebugModeEnabled() bool {
	return i.debugMode
}
