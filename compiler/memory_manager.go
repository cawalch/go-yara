package compiler

import (
	"fmt"
)

// MemoryManager handles stack and memory slot operations for the interpreter
type MemoryManager struct {
	stack  []Value
	memory [256]Value
}

// NewMemoryManager creates a new memory manager
func NewMemoryManager() *MemoryManager {
	return &MemoryManager{
		stack: make([]Value, 0, 256),
	}
}

// Stack operations

// Push pushes a value onto the stack
func (m *MemoryManager) Push(v Value) error {
	m.stack = append(m.stack, v)
	return nil
}

// Pop pops a value from the stack
func (m *MemoryManager) Pop() (Value, error) {
	if len(m.stack) == 0 {
		return Value{Type: ValueTypeUndefined}, fmt.Errorf("stack underflow")
	}
	v := m.stack[len(m.stack)-1]
	m.stack = m.stack[:len(m.stack)-1]
	return v, nil
}

// PopTwo pops two values from the stack
func (m *MemoryManager) PopTwo() (Value, Value, error) {
	if len(m.stack) < 2 {
		return Value{Type: ValueTypeUndefined}, Value{Type: ValueTypeUndefined}, fmt.Errorf("stack underflow: need 2 values, have %d", len(m.stack))
	}
	b := m.stack[len(m.stack)-1]
	a := m.stack[len(m.stack)-2]
	m.stack = m.stack[:len(m.stack)-2]
	return a, b, nil
}

// PopN pops N values from the stack
func (m *MemoryManager) PopN(n int) ([]Value, error) {
	if len(m.stack) < n {
		return nil, fmt.Errorf("stack underflow: need %d values, have %d", n, len(m.stack))
	}
	values := make([]Value, n)
	for i := 0; i < n; i++ {
		values[i] = m.stack[len(m.stack)-1-i]
	}
	m.stack = m.stack[:len(m.stack)-n]
	return values, nil
}

// Peek returns the top value without removing it
func (m *MemoryManager) Peek() (Value, error) {
	if len(m.stack) == 0 {
		return Value{Type: ValueTypeUndefined}, fmt.Errorf("stack underflow")
	}
	return m.stack[len(m.stack)-1], nil
}

// PeekN returns the Nth value from the top without removing it
func (m *MemoryManager) PeekN(n int) (Value, error) {
	if len(m.stack) <= n {
		return Value{Type: ValueTypeUndefined}, fmt.Errorf("stack underflow: need at least %d values, have %d", n+1, len(m.stack))
	}
	return m.stack[len(m.stack)-1-n], nil
}

// StackSize returns the current stack size
func (m *MemoryManager) StackSize() int {
	return len(m.stack)
}

// IsStackEmpty returns true if the stack is empty
func (m *MemoryManager) IsStackEmpty() bool {
	return len(m.stack) == 0
}

// StackUnderflow returns true if there are fewer than n values on the stack
func (m *MemoryManager) StackUnderflow(n int) bool {
	return len(m.stack) < n
}

// GetStack returns a copy of the current stack
func (m *MemoryManager) GetStack() []Value {
	result := make([]Value, len(m.stack))
	copy(result, m.stack)
	return result
}

// SetStack replaces the current stack with the provided values
func (m *MemoryManager) SetStack(stack []Value) {
	m.stack = make([]Value, len(stack))
	copy(m.stack, stack)
}

// ClearStack empties the stack
func (m *MemoryManager) ClearStack() {
	m.stack = m.stack[:0]
}

// Memory slot operations

// GetMemory retrieves a value from a memory slot
func (m *MemoryManager) GetMemory(slot int) Value {
	if slot < 0 || slot >= len(m.memory) {
		return Value{Type: ValueTypeUndefined}
	}
	return m.memory[slot]
}

// SetMemory stores a value in a memory slot
func (m *MemoryManager) SetMemory(slot int, value Value) {
	if slot >= 0 && slot < len(m.memory) {
		m.memory[slot] = value
	}
}

// GetMemorySlotRange validates and returns a memory slot index
func (m *MemoryManager) GetMemorySlotRange() int {
	return len(m.memory)
}

// ClearMemory clears a memory slot (sets it to undefined)
func (m *MemoryManager) ClearMemory(slot int) {
	if slot >= 0 && slot < len(m.memory) {
		m.memory[slot] = Value{Type: ValueTypeUndefined}
	}
}

// ClearAllMemory clears all memory slots
func (m *MemoryManager) ClearAllMemory() {
	for i := range m.memory {
		m.memory[i] = Value{Type: ValueTypeUndefined}
	}
}

// IncrementMemory increments an integer value in a memory slot
func (m *MemoryManager) IncrementMemory(slot int) error {
	if slot < 0 || slot >= len(m.memory) {
		return fmt.Errorf("memory slot %d out of range", slot)
	}

	val := m.memory[slot]
	switch val.Type {
	case ValueTypeInt:
		val.IntVal++
		m.memory[slot] = val
	case ValueTypeDouble:
		val.DoubleVal++
		m.memory[slot] = val
	default:
		return fmt.Errorf("cannot increment non-numeric value in memory slot %d", slot)
	}

	return nil
}

// DecrementMemory decrements an integer value in a memory slot
func (m *MemoryManager) DecrementMemory(slot int) error {
	if slot < 0 || slot >= len(m.memory) {
		return fmt.Errorf("memory slot %d out of range", slot)
	}

	val := m.memory[slot]
	switch val.Type {
	case ValueTypeInt:
		val.IntVal--
		m.memory[slot] = val
	case ValueTypeDouble:
		val.DoubleVal--
		m.memory[slot] = val
	default:
		return fmt.Errorf("cannot decrement non-numeric value in memory slot %d", slot)
	}

	return nil
}

// GetMemoryCopy returns a copy of all memory slots
func (m *MemoryManager) GetMemoryCopy() [256]Value {
	var result [256]Value
	copy(result[:], m.memory[:])
	return result
}

// SetMemoryFromArray copies values from an array into memory
func (m *MemoryManager) SetMemoryFromArray(memory [256]Value) {
	copy(m.memory[:], memory[:])
}

// MemoryStringSet stores a string identifier in a memory slot (special case for string identifiers)
func (m *MemoryManager) MemoryStringSet(slot int, identifier string) {
	if slot >= 0 && slot < len(m.memory) {
		m.memory[slot] = Value{Type: ValueTypeString, StringVal: identifier}
	}
}

// MemoryStringGet retrieves a string identifier from a memory slot
func (m *MemoryManager) MemoryStringGet(slot int) string {
	if slot < 0 || slot >= len(m.memory) {
		return ""
	}
	if m.memory[slot].Type == ValueTypeString {
		return m.memory[slot].StringVal
	}
	return ""
}

// Reset clears both stack and memory
func (m *MemoryManager) Reset() {
	m.ClearStack()
	m.ClearAllMemory()
}

// Debug operations

// DumpStack returns a string representation of the current stack state
func (m *MemoryManager) DumpStack() string {
	if len(m.stack) == 0 {
		return "Stack: []"
	}

	result := "Stack: ["
	for i, v := range m.stack {
		if i > 0 {
			result += ", "
		}
		result += v.String()
	}
	result += "]"
	return result
}

// DumpMemory returns a string representation of memory slots that have values
func (m *MemoryManager) DumpMemory() string {
	var slots []string
	for i, v := range m.memory {
		if v.Type != ValueTypeUndefined {
			slots = append(slots, fmt.Sprintf("M[%d]=%s", i, v.String()))
		}
	}

	if len(slots) == 0 {
		return "Memory: all undefined"
	}

	result := "Memory: "
	for i, slot := range slots {
		if i > 0 {
			result += ", "
		}
		result += slot
	}
	return result
}
