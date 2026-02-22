package compiler

import (
	"fmt"
	"maps"
	"strings"
)

// JumpManager handles label generation and pending jump management for the condition compiler
type JumpManager struct {
	labelCounter int
	labels       map[string]int
	pendingJumps []PendingJump
}

// PendingJump is defined in condition_compiler.go

// NewJumpManager creates a new jump manager
func NewJumpManager() *JumpManager {
	return &JumpManager{
		labelCounter: 0,
		labels:       make(map[string]int),
		pendingJumps: make([]PendingJump, 0),
	}
}

// Label Management

// GenerateLabel creates a new unique label name
func (jm *JumpManager) GenerateLabel() string {
	jm.labelCounter++
	return fmt.Sprintf("L%d", jm.labelCounter)
}

// DefineLabel defines a label at the current position
func (jm *JumpManager) DefineLabel(name string, position int) error {
	if name == "" {
		return fmt.Errorf("label name cannot be empty")
	}

	if _, exists := jm.labels[name]; exists {
		return fmt.Errorf("label '%s' is already defined", name)
	}

	jm.labels[name] = position
	return nil
}

// GetLabelPosition returns the position of a label
func (jm *JumpManager) GetLabelPosition(name string) (int, bool) {
	position, exists := jm.labels[name]
	return position, exists
}

// HasLabel checks if a label exists
func (jm *JumpManager) HasLabel(name string) bool {
	_, exists := jm.labels[name]
	return exists
}

// GetAllLabels returns a copy of all labels
func (jm *JumpManager) GetAllLabels() map[string]int {
	result := make(map[string]int)
	maps.Copy(result, jm.labels)
	return result
}

// GetLabelCount returns the number of defined labels
func (jm *JumpManager) GetLabelCount() int {
	return len(jm.labels)
}

// GetLabelNames returns all label names
func (jm *JumpManager) GetLabelNames() []string {
	names := make([]string, 0, len(jm.labels))
	for name := range jm.labels {
		names = append(names, name)
	}
	return names
}

// Bulk Operations

// SetLabels sets multiple labels at once
func (jm *JumpManager) SetLabels(labels map[string]int) {
	maps.Copy(jm.labels, labels)
}

// ResetLabels clears all labels
func (jm *JumpManager) ResetLabels() {
	jm.labels = make(map[string]int)
}

// Pending Jump Management

// AddPendingJump adds a jump that needs to be resolved later
func (jm *JumpManager) AddPendingJump(opcode Opcode, label string, position int, line, column int) {
	jump := PendingJump{
		Opcode:   opcode,
		Label:    label,
		Position: position,
		Line:     line,
		Column:   column,
	}
	jm.pendingJumps = append(jm.pendingJumps, jump)
}

// AddPendingJumpAt adds a pending jump at a specific position (current bytecode position)
func (jm *JumpManager) AddPendingJumpAt(opcode Opcode, label string, line, column int, currentPosition int) {
	jm.AddPendingJump(opcode, label, currentPosition, line, column)
}

// GetPendingJumps returns a copy of all pending jumps
func (jm *JumpManager) GetPendingJumps() []PendingJump {
	result := make([]PendingJump, len(jm.pendingJumps))
	copy(result, jm.pendingJumps)
	return result
}

// GetPendingJumpCount returns the number of pending jumps
func (jm *JumpManager) GetPendingJumpCount() int {
	return len(jm.pendingJumps)
}

// HasPendingJumps returns true if there are any pending jumps
func (jm *JumpManager) HasPendingJumps() bool {
	return len(jm.pendingJumps) > 0
}

// ResolveJumps resolves all pending jumps using the current label positions
func (jm *JumpManager) ResolveJumps() []JumpResolution {
	resolutions := make([]JumpResolution, 0, len(jm.pendingJumps))

	for i := range jm.pendingJumps {
		jump := jm.pendingJumps[i]

		// Try to resolve the jump target
		if targetPos, exists := jm.labels[jump.Label]; exists {
			resolutions = append(resolutions, JumpResolution{
				PendingJump: jump,
				TargetPos:   targetPos,
				Resolved:    true,
			})
		} else {
			resolutions = append(resolutions, JumpResolution{
				PendingJump: jump,
				TargetPos:   -1,
				Resolved:    false,
				Error:       fmt.Sprintf("undefined label '%s'", jump.Label),
			})
		}
	}

	return resolutions
}

// ClearPendingJumps clears all pending jumps
func (jm *JumpManager) ClearPendingJumps() {
	jm.pendingJumps = jm.pendingJumps[:0]
}

// RemoveResolvedJumps removes jumps that have been resolved
func (jm *JumpManager) RemoveResolvedJumps(resolvedIndices []int) {
	// Sort indices in descending order to avoid index shifting
	for i := len(resolvedIndices) - 1; i >= 0; i-- {
		index := resolvedIndices[i]
		if index >= 0 && index < len(jm.pendingJumps) {
			jm.pendingJumps = append(jm.pendingJumps[:index], jm.pendingJumps[index+1:]...)
		}
	}
}

// State Management

// Reset clears all labels and pending jumps
func (jm *JumpManager) Reset() {
	jm.labelCounter = 0
	jm.labels = make(map[string]int)
	jm.pendingJumps = jm.pendingJumps[:0]
}

// ResetPendingJumps clears only pending jumps (keeps labels)
func (jm *JumpManager) ResetPendingJumps() {
	jm.pendingJumps = jm.pendingJumps[:0]
}

// Validation

// ValidateLabelName checks if a label name is valid
func (jm *JumpManager) ValidateLabelName(name string) error {
	if name == "" {
		return fmt.Errorf("label name cannot be empty")
	}
	// Add more validation rules as needed (reserved words, etc.)
	return nil
}

// ValidateJumpTarget checks if a jump target is valid
func (jm *JumpManager) ValidateJumpTarget(label string) error {
	if label == "" {
		return fmt.Errorf("jump target label cannot be empty")
	}

	if _, exists := jm.labels[label]; !exists {
		return fmt.Errorf("undefined label '%s'", label)
	}

	return nil
}

// JumpResolution represents the result of resolving a pending jump
type JumpResolution struct {
	PendingJump PendingJump
	TargetPos   int
	Resolved    bool
	Error       string
}

// IsResolved returns true if the jump was successfully resolved
func (jr *JumpResolution) IsResolved() bool {
	return jr.Resolved
}

// GetError returns the resolution error (if any)
func (jr *JumpResolution) GetError() string {
	return jr.Error
}

// Debug and Analysis Methods

// DumpLabels returns a string representation of all labels
func (jm *JumpManager) DumpLabels() string {
	if len(jm.labels) == 0 {
		return "No labels defined"
	}

	var result strings.Builder
	fmt.Fprintf(&result, "Labels (%d total):\n", len(jm.labels))
	for name, position := range jm.labels {
		fmt.Fprintf(&result, "  %s -> Position %d\n", name, position)
	}
	return result.String()
}

// DumpPendingJumps returns a string representation of all pending jumps
func (jm *JumpManager) DumpPendingJumps() string {
	if len(jm.pendingJumps) == 0 {
		return "No pending jumps"
	}

	var result strings.Builder
	fmt.Fprintf(&result, "Pending Jumps (%d total):\n", len(jm.pendingJumps))
	for i, jump := range jm.pendingJumps {
		fmt.Fprintf(&result, "  [%d] OP_%d -> %s (at position %d, line %d, col %d)\n",
			i, jump.Opcode, jump.Label, jump.Position, jump.Line, jump.Column)
	}
	return result.String()
}

// DumpAll returns a comprehensive dump of all jump manager state
func (jm *JumpManager) DumpAll() string {
	return fmt.Sprintf("%s\n\n%s",
		jm.DumpLabels(),
		jm.DumpPendingJumps())
}

// GetStats returns statistics about the jump manager state
func (jm *JumpManager) GetStats() map[string]any {
	return map[string]any{
		"label_count":        jm.GetLabelCount(),
		"pending_jump_count": jm.GetPendingJumpCount(),
		"next_label_number":  jm.labelCounter + 1,
	}
}

// Analysis Methods

// GetUnresolvedJumps returns all jumps that cannot be resolved
func (jm *JumpManager) GetUnresolvedJumps() []PendingJump {
	unresolved := make([]PendingJump, 0)
	for _, jump := range jm.pendingJumps {
		if _, exists := jm.labels[jump.Label]; !exists {
			unresolved = append(unresolved, jump)
		}
	}
	return unresolved
}

// HasUnresolvedJumps returns true if there are any jumps that cannot be resolved
func (jm *JumpManager) HasUnresolvedJumps() bool {
	return len(jm.GetUnresolvedJumps()) > 0
}

// FindJumpsByLabel returns all pending jumps targeting a specific label
func (jm *JumpManager) FindJumpsByLabel(targetLabel string) []PendingJump {
	jumps := make([]PendingJump, 0)
	for _, jump := range jm.pendingJumps {
		if jump.Label == targetLabel {
			jumps = append(jumps, jump)
		}
	}
	return jumps
}

// FindJumpsByOpcode returns all pending jumps with a specific opcode
func (jm *JumpManager) FindJumpsByOpcode(opcode Opcode) []PendingJump {
	jumps := make([]PendingJump, 0)
	for _, jump := range jm.pendingJumps {
		if jump.Opcode == opcode {
			jumps = append(jumps, jump)
		}
	}
	return jumps
}

// GetJumpComplexity returns metrics about jump complexity
func (jm *JumpManager) GetJumpComplexity() map[string]any {
	return map[string]any{
		"total_jumps":         jm.GetPendingJumpCount(),
		"unique_labels":       jm.GetLabelCount(),
		"max_jumps_per_label": 0,
		"jumps_by_opcode":     make(map[string]int),
	}
}
