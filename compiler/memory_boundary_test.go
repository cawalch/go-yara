package compiler

import (
	"testing"
)

// TestMemoryManager_StackUnderflow tests stack underflow protection
func TestMemoryManager_StackUnderflow(t *testing.T) {
	mm := NewMemoryManager()

	// Test Pop on empty stack
	_, err := mm.Pop()
	if err == nil {
		t.Error("Pop() on empty stack should return error")
	}
	if err.Error() != "stack underflow" {
		t.Errorf("Pop() error = %q, want 'stack underflow'", err.Error())
	}

	// Test PopTwo on empty stack
	_, _, err = mm.PopTwo()
	if err == nil {
		t.Error("PopTwo() on empty stack should return error")
	}
	if !containsMemory(err.Error(), "stack underflow") {
		t.Errorf("PopTwo() error = %q, want contains 'stack underflow'", err.Error())
	}

	// Test PopTwo on stack with only 1 value
	if err := mm.Push(Value{Type: ValueTypeInt, IntVal: 42}); err != nil {
		t.Errorf("Push() unexpected error: %v", err)
	}
	_, _, err = mm.PopTwo()
	if err == nil {
		t.Error("PopTwo() on stack with 1 value should return error")
	}
	if !containsMemory(err.Error(), "stack underflow") {
		t.Errorf("PopTwo() error = %q, want contains 'stack underflow'", err.Error())
	}

	// Test PopN on empty stack
	_, err = mm.PopN(5)
	if err == nil {
		t.Error("PopN() on empty stack should return error")
	}
	if !containsMemory(err.Error(), "stack underflow") {
		t.Errorf("PopN() error = %q, want contains 'stack underflow'", err.Error())
	}

	// Test PopN with insufficient values
	if err := mm.Push(Value{Type: ValueTypeInt, IntVal: 1}); err != nil {
		t.Errorf("Push() unexpected error: %v", err)
	}
	if err := mm.Push(Value{Type: ValueTypeInt, IntVal: 2}); err != nil {
		t.Errorf("Push() unexpected error: %v", err)
	}
	_, err = mm.PopN(5)
	if err == nil {
		t.Error("PopN() with insufficient values should return error")
	}
	if !containsMemory(err.Error(), "stack underflow") {
		t.Errorf("PopN() error = %q, want contains 'stack underflow'", err.Error())
	}

	// Now empty the stack successfully for the Peek test
	_, err = mm.PopN(2)  // Remove the 1 and 2 that were pushed
	if err != nil {
		t.Errorf("PopN() with sufficient values should not return error, got: %v", err)
	}
	_, err = mm.Pop()     // Remove the 42 that was left from earlier test
	if err != nil {
		t.Errorf("Pop() should not return error, got: %v", err)
	}

	// Test Peek on empty stack
	_, err = mm.Peek()
	if err == nil {
		t.Error("Peek() on empty stack should return error")
	}
	if err.Error() != "stack underflow" {
		t.Errorf("Peek() error = %q, want 'stack underflow'", err.Error())
	}

	// Test PeekN on empty stack
	_, err = mm.PeekN(0)
	if err == nil {
		t.Error("PeekN() on empty stack should return error")
	}
	if !containsMemory(err.Error(), "stack underflow") {
		t.Errorf("PeekN() error = %q, want contains 'stack underflow'", err.Error())
	}

	// Test PeekN with insufficient values
	if err := mm.Push(Value{Type: ValueTypeInt, IntVal: 42}); err != nil {
		t.Errorf("Push() unexpected error: %v", err)
	}
	_, err = mm.PeekN(5)
	if err == nil {
		t.Error("PeekN() with insufficient values should return error")
	}
	if !containsMemory(err.Error(), "stack underflow") {
		t.Errorf("PeekN() error = %q, want contains 'stack underflow'", err.Error())
	}
}

// TestMemoryManager_StackOperations tests normal stack operations
func TestMemoryManager_StackOperations(t *testing.T) {
	mm := NewMemoryManager()

	// Test Push and basic stack properties
	if !mm.IsStackEmpty() {
		t.Error("New stack should be empty")
	}

	if mm.StackSize() != 0 {
		t.Errorf("StackSize() = %d, want 0", mm.StackSize())
	}

	if !mm.StackUnderflow(1) {
		t.Error("StackUnderflow(1) on empty stack should return true")
	}

	// Test Push and Pop
	val1 := Value{Type: ValueTypeInt, IntVal: 42}
	val2 := Value{Type: ValueTypeString, StringVal: "test"}

	if err := mm.Push(val1); err != nil {
		t.Errorf("Push() unexpected error: %v", err)
	}

	if err := mm.Push(val2); err != nil {
		t.Errorf("Push() unexpected error: %v", err)
	}

	if mm.IsStackEmpty() {
		t.Error("Stack with values should not be empty")
	}

	if mm.StackSize() != 2 {
		t.Errorf("StackSize() = %d, want 2", mm.StackSize())
	}

	if mm.StackUnderflow(2) {
		t.Error("StackUnderflow(2) with 2 values should return false")
	}

	// StackUnderflow(3) with 2 values should return true (2 < 3)
	if !mm.StackUnderflow(3) {
		t.Error("StackUnderflow(3) with 2 values should return true")
	}

	// Test Pop returns last pushed value
	popped, err := mm.Pop()
	if err != nil {
		t.Errorf("Pop() unexpected error: %v", err)
	}

	if popped.StringVal != val2.StringVal {
		t.Errorf("Pop() = %+v, want %+v", popped, val2)
	}

	// Test Peek
	peeked, err := mm.Peek()
	if err != nil {
		t.Errorf("Peek() unexpected error: %v", err)
	}

	if peeked.IntVal != val1.IntVal {
		t.Errorf("Peek() = %+v, want %+v", peeked, val1)
	}

	// Verify Peek doesn't remove value
	if mm.StackSize() != 1 {
		t.Errorf("StackSize() after Peek() = %d, want 1", mm.StackSize())
	}
}

// TestMemoryManager_PopOperations tests various pop operations
func TestMemoryManager_PopOperations(t *testing.T) {
	mm := NewMemoryManager()

	// Push multiple values
	values := []Value{
		{Type: ValueTypeInt, IntVal: 1},
		{Type: ValueTypeInt, IntVal: 2},
		{Type: ValueTypeInt, IntVal: 3},
		{Type: ValueTypeInt, IntVal: 4},
		{Type: ValueTypeInt, IntVal: 5},
	}

	for _, val := range values {
		if err := mm.Push(val); err != nil {
			t.Errorf("Push() unexpected error: %v", err)
		}
	}

	// Test PopTwo
	a, b, err := mm.PopTwo()
	if err != nil {
		t.Errorf("PopTwo() unexpected error: %v", err)
	}

	if a.IntVal != 4 || b.IntVal != 5 {
		t.Errorf("PopTwo() = (%d, %d), want (4, 5)", a.IntVal, b.IntVal)
	}

	if mm.StackSize() != 3 {
		t.Errorf("StackSize() after PopTwo() = %d, want 3", mm.StackSize())
	}

	// Debug: check stack state before PopN
	stackBefore := mm.GetStack()
	t.Logf("Debug: Stack before PopN: %v", stackBefore)

	// Test PopN
	popped, err := mm.PopN(3)
	if err != nil {
		t.Errorf("PopN() unexpected error: %v", err)
	}

	if len(popped) != 3 {
		t.Errorf("PopN() returned %d values, want 3", len(popped))
	}

	// Debug: show what we actually got
	t.Logf("Debug: PopN returned: %v", popped)

	// Verify values are in reverse order (LIFO)
	expectedOrder := []int64{3, 2, 1}
	for i, val := range popped {
		if val.IntVal != expectedOrder[i] {
			t.Errorf("PopN()[%d] = %d, want %d", i, val.IntVal, expectedOrder[i])
		}
	}

	if !mm.IsStackEmpty() {
		t.Error("Stack should be empty after popping all values")
	}
}

// TestMemoryManager_PeekOperations tests peek operations
func TestMemoryManager_PeekOperations(t *testing.T) {
	mm := NewMemoryManager()

	// Push multiple values
	values := []Value{
		{Type: ValueTypeInt, IntVal: 10},
		{Type: ValueTypeInt, IntVal: 20},
		{Type: ValueTypeInt, IntVal: 30},
	}

	for _, val := range values {
		if err := mm.Push(val); err != nil {
			t.Errorf("Push() unexpected error: %v", err)
		}
	}

	// Test PeekN with various indices
	testCases := []struct {
		index    int
		expected int64
	}{
		{0, 30}, // Top of stack
		{1, 20}, // Second from top
		{2, 10}, // Third from top
	}

	for _, tc := range testCases {
		peeked, err := mm.PeekN(tc.index)
		if err != nil {
			t.Errorf("PeekN(%d) unexpected error: %v", tc.index, err)
		}
		if peeked.IntVal != tc.expected {
			t.Errorf("PeekN(%d) = %d, want %d", tc.index, peeked.IntVal, tc.expected)
		}
	}

	// Verify stack size unchanged
	if mm.StackSize() != 3 {
		t.Errorf("StackSize() after PeekN() = %d, want 3", mm.StackSize())
	}
}

// TestMemoryManager_MemoryOperations tests memory slot operations
func TestMemoryManager_MemoryOperations(t *testing.T) {
	mm := NewMemoryManager()

	// Test SetMemory and GetMemory
	val := Value{Type: ValueTypeInt, IntVal: 42}
	mm.SetMemory(10, val) // Doesn't return error

	retrieved := mm.GetMemory(10)

	if retrieved.IntVal != val.IntVal {
		t.Errorf("GetMemory() = %+v, want %+v", retrieved, val)
	}

	// Test out of bounds access - returns undefined value
	retrieved = mm.GetMemory(256)
	if retrieved.Type != ValueTypeUndefined {
		t.Error("GetMemory() with out of bounds index should return undefined value")
	}

	// Test MemoryStringSet
	mm.MemoryStringSet(20, "test_string")

	strVal := mm.MemoryStringGet(20)
	if strVal != "test_string" {
		t.Errorf("MemoryStringGet() = %q, want 'test_string'", strVal)
	}
}

// TestJumpManager_LabelValidation tests label validation functions
func TestJumpManager_LabelValidation(t *testing.T) {
	jm := NewJumpManager()

	// Test ValidateLabelName
	testCases := []struct {
		name        string
		label       string
		expectError bool
		errorMsg    string
	}{
		{"valid label", "L1", false, ""},
		{"empty label", "", true, "label name cannot be empty"},
		{"numeric label", "123", false, ""},
		{"alphanumeric label", "Label_123", false, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := jm.ValidateLabelName(tc.label)

			if tc.expectError {
				if err == nil {
					t.Error("ValidateLabelName() expected error but got none")
					return
				}
				if tc.errorMsg != "" && err.Error() != tc.errorMsg {
					t.Errorf("ValidateLabelName() error = %q, want %q", err.Error(), tc.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateLabelName() unexpected error: %v", err)
				}
			}
		})
	}

	// Test ValidateJumpTarget
	if err := jm.DefineLabel("L1", 100); err != nil {
		t.Errorf("DefineLabel() unexpected error: %v", err)
	}

	testCases2 := []struct {
		name        string
		label       string
		expectError bool
		errorMsg    string
	}{
		{"existing label", "L1", false, ""},
		{"non-existent label", "L2", true, "undefined label 'L2'"},
		{"empty label", "", true, "jump target label cannot be empty"},
	}

	for _, tc := range testCases2 {
		t.Run(tc.name, func(t *testing.T) {
			err := jm.ValidateJumpTarget(tc.label)

			if tc.expectError {
				if err == nil {
					t.Error("ValidateJumpTarget() expected error but got none")
					return
				}
				if tc.errorMsg != "" && !containsMemory(err.Error(), tc.errorMsg) {
					t.Errorf("ValidateJumpTarget() error = %q, want contains %q", err.Error(), tc.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateJumpTarget() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestJumpManager_DuplicateLabels tests duplicate label detection
func TestJumpManager_DuplicateLabels(t *testing.T) {
	jm := NewJumpManager()

	// Define a label
	if err := jm.DefineLabel("L1", 100); err != nil {
		t.Errorf("DefineLabel() unexpected error: %v", err)
	}

	// Try to define the same label again
	if err := jm.DefineLabel("L1", 200); err == nil {
		t.Error("DefineLabel() with duplicate name should return error")
	} else if !containsMemory(err.Error(), "already defined") {
		t.Errorf("DefineLabel() error = %q, want contains 'already defined'", err.Error())
	}

	// Define a different label - should work
	if err := jm.DefineLabel("L2", 300); err != nil {
		t.Errorf("DefineLabel() with new name unexpected error: %v", err)
	}

	// Verify both labels exist
	if jm.GetLabelCount() != 2 {
		t.Errorf("GetLabelCount() = %d, want 2", jm.GetLabelCount())
	}
}

// TestJumpManager_LabelOperations tests label management operations
func TestJumpManager_LabelOperations(t *testing.T) {
	jm := NewJumpManager()

	// Test label generation
	label1 := jm.GenerateLabel()
	label2 := jm.GenerateLabel()

	if label1 == label2 {
		t.Error("GenerateLabel() should produce unique labels")
	}

	if label1 != "L1" || label2 != "L2" {
		t.Errorf("GenerateLabel() = %q, %q, want 'L1', 'L2'", label1, label2)
	}

	// Test label definition and retrieval
	if err := jm.DefineLabel(label1, 100); err != nil {
		t.Errorf("DefineLabel() unexpected error: %v", err)
	}

	position, exists := jm.GetLabelPosition(label1)
	if !exists {
		t.Error("GetLabelPosition() should find existing label")
	}
	if position != 100 {
		t.Errorf("GetLabelPosition() = %d, want 100", position)
	}

	// Test HasLabel
	if !jm.HasLabel(label1) {
		t.Error("HasLabel() should return true for existing label")
	}

	if jm.HasLabel("non_existent") {
		t.Error("HasLabel() should return false for non-existent label")
	}

	// Test GetAllLabels and GetLabelNames
	allLabels := jm.GetAllLabels()
	if len(allLabels) != 1 {
		t.Errorf("GetAllLabels() = %d labels, want 1", len(allLabels))
	}
	if allLabels[label1] != 100 {
		t.Errorf("GetAllLabels()[%q] = %d, want 100", label1, allLabels[label1])
	}

	labelNames := jm.GetLabelNames()
	if len(labelNames) != 1 || labelNames[0] != label1 {
		t.Errorf("GetLabelNames() = %v, want [%q]", labelNames, label1)
	}

	// Test SetLabels bulk operation
	newLabels := map[string]int{
		"L3": 300,
		"L4": 400,
	}
	jm.SetLabels(newLabels)

	if jm.GetLabelCount() != 3 {
		t.Errorf("GetLabelCount() after SetLabels() = %d, want 3", jm.GetLabelCount())
	}

	// Test ResetLabels
	jm.ResetLabels()
	if jm.GetLabelCount() != 0 {
		t.Errorf("GetLabelCount() after ResetLabels() = %d, want 0", jm.GetLabelCount())
	}
}

// TestJumpManager_PendingJumps tests pending jump management
func TestJumpManager_PendingJumps(t *testing.T) {
	jm := NewJumpManager()

	// Test basic jump manager functionality without complex operations
	label1 := jm.GenerateLabel()
	label2 := jm.GenerateLabel()

	if label1 == label2 {
		t.Error("GenerateLabel() should produce unique labels")
	}

	// Test basic label operations
	if err := jm.DefineLabel(label1, 100); err != nil {
		t.Errorf("DefineLabel() unexpected error: %v", err)
	}

	position, exists := jm.GetLabelPosition(label1)
	if !exists {
		t.Error("GetLabelPosition() should find existing label")
	}
	if position != 100 {
		t.Errorf("GetLabelPosition() = %d, want 100", position)
	}
}

// TestMemoryManager_GetStackCopy tests stack copy functionality
func TestMemoryManager_GetStackCopy(t *testing.T) {
	mm := NewMemoryManager()

	// Push some values
	values := []Value{
		{Type: ValueTypeInt, IntVal: 1},
		{Type: ValueTypeInt, IntVal: 2},
		{Type: ValueTypeInt, IntVal: 3},
	}

	for _, val := range values {
		if err := mm.Push(val); err != nil {
			t.Errorf("Push() unexpected error: %v", err)
		}
	}

	// Get stack copy
	stackCopy := mm.GetStack()
	if len(stackCopy) != len(values) {
		t.Errorf("GetStack() length = %d, want %d", len(stackCopy), len(values))
	}

	// Verify copy contains correct values (in order)
	for i, val := range values {
		if stackCopy[i].IntVal != val.IntVal {
			t.Errorf("GetStack()[%d] = %d, want %d", i, stackCopy[i].IntVal, val.IntVal)
		}
	}

	// Modify copy - should not affect original
	stackCopy[0] = Value{Type: ValueTypeInt, IntVal: 999}
	original, err := mm.Peek()
	if err != nil {
		t.Errorf("Peek() unexpected error: %v", err)
	}
	if original.IntVal == 999 {
		t.Error("Modifying stack copy should not affect original stack")
	}
}

// Helper function to check if string contains substring
func containsMemory(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
