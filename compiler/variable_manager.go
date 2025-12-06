package compiler

import (
	"fmt"
)

// VariableManager handles variable mapping and indexing for the condition compiler
type VariableManager struct {
	variables         map[string]int
	externalVariables map[string]int
	ruleIndexMap      map[string]int
	nextVariableID    int
}

// NewVariableManager creates a new variable manager
func NewVariableManager() *VariableManager {
	return &VariableManager{
		variables:         make(map[string]int, 32), // Pre-allocate for typical rule count
		externalVariables: make(map[string]int, 16), // Pre-allocate for external variables
		ruleIndexMap:      make(map[string]int, 32), // Pre-allocate for rules
		nextVariableID:    0,                        // Start ID counter at 0
	}
}

// Variable Management

// GetVariableID returns the ID for a variable name, creating a new one if needed
func (vm *VariableManager) GetVariableID(name string) int {
	if id, exists := vm.variables[name]; exists {
		return id
	}

	// Create new variable ID
	vm.variables[name] = vm.nextVariableID
	vm.nextVariableID++
	return vm.variables[name]
}

// GetVariableIDIfExists returns the ID for a variable name, without creating new ones
func (vm *VariableManager) GetVariableIDIfExists(name string) (int, bool) {
	id, exists := vm.variables[name]
	return id, exists
}

// HasVariable checks if a variable exists
func (vm *VariableManager) HasVariable(name string) bool {
	_, exists := vm.variables[name]
	return exists
}

// GetAllVariables returns a copy of all variables
func (vm *VariableManager) GetAllVariables() map[string]int {
	result := make(map[string]int)
	for name, id := range vm.variables {
		result[name] = id
	}
	return result
}

// GetVariableCount returns the number of variables
func (vm *VariableManager) GetVariableCount() int {
	return len(vm.variables)
}

// GetVariableNames returns all variable names
func (vm *VariableManager) GetVariableNames() []string {
	names := make([]string, 0, len(vm.variables))
	for name := range vm.variables {
		names = append(names, name)
	}
	return names
}

// External Variable Management

// GetExternalVariableID returns the ID for an external variable name, creating a new one if needed
func (vm *VariableManager) GetExternalVariableID(name string) int {
	if id, exists := vm.externalVariables[name]; exists {
		return id
	}

	// Create new external variable ID
	vm.externalVariables[name] = vm.nextVariableID
	vm.nextVariableID++
	return vm.externalVariables[name]
}

// GetExternalVariableIDIfExists returns the ID for an external variable name, without creating new ones
func (vm *VariableManager) GetExternalVariableIDIfExists(name string) (int, bool) {
	id, exists := vm.externalVariables[name]
	return id, exists
}

// HasExternalVariable checks if an external variable exists
func (vm *VariableManager) HasExternalVariable(name string) bool {
	_, exists := vm.externalVariables[name]
	return exists
}

// GetAllExternalVariables returns a copy of all external variables
func (vm *VariableManager) GetAllExternalVariables() map[string]int {
	result := make(map[string]int)
	for name, id := range vm.externalVariables {
		result[name] = id
	}
	return result
}

// GetExternalVariableCount returns the number of external variables
func (vm *VariableManager) GetExternalVariableCount() int {
	return len(vm.externalVariables)
}

// GetExternalVariableNames returns all external variable names
func (vm *VariableManager) GetExternalVariableNames() []string {
	names := make([]string, 0, len(vm.externalVariables))
	for name := range vm.externalVariables {
		names = append(names, name)
	}
	return names
}

// Rule Index Management

// SetRuleIndex sets the index for a rule name
func (vm *VariableManager) SetRuleIndex(name string, index int) {
	vm.ruleIndexMap[name] = index
}

// GetRuleIndex returns the index for a rule name
func (vm *VariableManager) GetRuleIndex(name string) (int, bool) {
	index, exists := vm.ruleIndexMap[name]
	return index, exists
}

// HasRule checks if a rule exists
func (vm *VariableManager) HasRule(name string) bool {
	_, exists := vm.ruleIndexMap[name]
	return exists
}

// GetAllRules returns a copy of all rule indices
func (vm *VariableManager) GetAllRules() map[string]int {
	result := make(map[string]int)
	for name, index := range vm.ruleIndexMap {
		result[name] = index
	}
	return result
}

// GetRuleCount returns the number of rules
func (vm *VariableManager) GetRuleCount() int {
	return len(vm.ruleIndexMap)
}

// GetRuleNames returns all rule names
func (vm *VariableManager) GetRuleNames() []string {
	names := make([]string, 0, len(vm.ruleIndexMap))
	for name := range vm.ruleIndexMap {
		names = append(names, name)
	}
	return names
}

// Bulk Operations

// SetVariables sets multiple variables at once
func (vm *VariableManager) SetVariables(variables map[string]int) {
	for name, id := range variables {
		vm.variables[name] = id
		// Update next ID to avoid conflicts
		if id >= vm.nextVariableID {
			vm.nextVariableID = id + 1
		}
	}
}

// SetExternalVariables sets multiple external variables at once
func (vm *VariableManager) SetExternalVariables(variables map[string]int) {
	for name, id := range variables {
		vm.externalVariables[name] = id
		// Update next ID to avoid conflicts
		if id >= vm.nextVariableID {
			vm.nextVariableID = id + 1
		}
	}
}

// SetRules sets multiple rule indices at once
func (vm *VariableManager) SetRules(rules map[string]int) {
	for name, index := range rules {
		vm.ruleIndexMap[name] = index
	}
}

// State Management

// Reset clears all variable mappings
func (vm *VariableManager) Reset() {
	vm.variables = make(map[string]int)
	vm.externalVariables = make(map[string]int)
	vm.ruleIndexMap = make(map[string]int)
	vm.nextVariableID = 0
}

// ResetVariables clears only variable mappings (keeps external and rule mappings)
func (vm *VariableManager) ResetVariables() {
	vm.variables = make(map[string]int)
	vm.nextVariableID = 0
}

// ResetExternalVariables clears only external variable mappings
func (vm *VariableManager) ResetExternalVariables() {
	vm.externalVariables = make(map[string]int)
	// Note: We don't reset nextVariableID as external and regular variables share the same ID space
}

// ResetRules clears only rule mappings
func (vm *VariableManager) ResetRules() {
	vm.ruleIndexMap = make(map[string]int)
}

// Validation and Analysis

// ValidateVariableName checks if a variable name is valid
func (vm *VariableManager) ValidateVariableName(name string) error {
	if name == "" {
		return fmt.Errorf("variable name cannot be empty")
	}
	// Add more validation rules as needed (reserved words, etc.)
	return nil
}

// GetVariableStats returns statistics about variable usage
func (vm *VariableManager) GetVariableStats() map[string]interface{} {
	return map[string]interface{}{
		"variables_count": vm.GetVariableCount(),
		"external_count":  vm.GetExternalVariableCount(),
		"rules_count":     vm.GetRuleCount(),
		"next_id":         vm.nextVariableID,
	}
}

// Debug and Analysis Methods

// DumpVariables returns a string representation of all variables
func (vm *VariableManager) DumpVariables() string {
	if len(vm.variables) == 0 {
		return "No variables defined"
	}

	result := fmt.Sprintf("Variables (%d total):\n", len(vm.variables))
	for name, id := range vm.variables {
		result += fmt.Sprintf("  %s -> ID %d\n", name, id)
	}
	return result
}

// DumpExternalVariables returns a string representation of all external variables
func (vm *VariableManager) DumpExternalVariables() string {
	if len(vm.externalVariables) == 0 {
		return "No external variables defined"
	}

	result := fmt.Sprintf("External Variables (%d total):\n", len(vm.externalVariables))
	for name, id := range vm.externalVariables {
		result += fmt.Sprintf("  %s -> ID %d\n", name, id)
	}
	return result
}

// DumpRules returns a string representation of all rule indices
func (vm *VariableManager) DumpRules() string {
	if len(vm.ruleIndexMap) == 0 {
		return "No rules indexed"
	}

	result := fmt.Sprintf("Rule Indices (%d total):\n", len(vm.ruleIndexMap))
	for name, index := range vm.ruleIndexMap {
		result += fmt.Sprintf("  %s -> Index %d\n", name, index)
	}
	return result
}

// DumpAll returns a comprehensive dump of all variable manager state
func (vm *VariableManager) DumpAll() string {
	return fmt.Sprintf("%s\n\n%s\n\n%s",
		vm.DumpVariables(),
		vm.DumpExternalVariables(),
		vm.DumpRules())
}

// CheckConflicts checks for any naming conflicts between variable types
func (vm *VariableManager) CheckConflicts() []string {
	conflicts := make([]string, 0)

	// Check for conflicts between variables and external variables
	for name := range vm.variables {
		if _, exists := vm.externalVariables[name]; exists {
			conflicts = append(conflicts, fmt.Sprintf("Variable '%s' conflicts with external variable", name))
		}
	}

	// Check for conflicts between variables and rule names
	for name := range vm.variables {
		if _, exists := vm.ruleIndexMap[name]; exists {
			conflicts = append(conflicts, fmt.Sprintf("Variable '%s' conflicts with rule name", name))
		}
	}

	// Check for conflicts between external variables and rule names
	for name := range vm.externalVariables {
		if _, exists := vm.ruleIndexMap[name]; exists {
			conflicts = append(conflicts, fmt.Sprintf("External variable '%s' conflicts with rule name", name))
		}
	}

	return conflicts
}

// HasConflicts returns true if there are any naming conflicts
func (vm *VariableManager) HasConflicts() bool {
	return len(vm.CheckConflicts()) > 0
}
