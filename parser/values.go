package parser

import (
	"fmt"
	"math"

	"github.com/cawalch/go-yara/token"
)

// Position represents a position in source code with enhanced capabilities
type Position struct {
	Filename string
	Line     int
	Column   int
	Offset   int
}

// NewPosition creates a new position
func NewPosition(filename string, line, column, offset int) Position {
	return Position{
		Filename: filename,
		Line:     line,
		Column:   column,
		Offset:   offset,
	}
}

// FromTokenPosition creates a Position from a token.Position
func FromTokenPosition(pos token.Position) Position {
	return Position{
		Filename: pos.Filename,
		Line:     pos.Line,
		Column:   pos.Column,
		Offset:   pos.Offset,
	}
}

// ToTokenPosition converts a Position back to token.Position
func (p Position) ToTokenPosition() token.Position {
	return token.Position{
		Filename: p.Filename,
		Line:     p.Line,
		Column:   p.Column,
		Offset:   p.Offset,
	}
}

// String returns a string representation of the position
func (p Position) String() string {
	if p.Filename != "" {
		return fmt.Sprintf("%s:%d:%d", p.Filename, p.Line, p.Column)
	}
	return fmt.Sprintf("%d:%d", p.Line, p.Column)
}

// IsBefore returns true if this position is before another position
func (p Position) IsBefore(other Position) bool {
	if p.Line < other.Line {
		return true
	}
	if p.Line == other.Line && p.Column < other.Column {
		return true
	}
	return false
}

// IsAfter returns true if this position is after another position
func (p Position) IsAfter(other Position) bool {
	return other.IsBefore(p)
}

// Equals returns true if this position equals another position
func (p Position) Equals(other Position) bool {
	return p.Line == other.Line && p.Column == other.Column && p.Offset == other.Offset
}

// Distance calculates the distance between two positions
func (p Position) Distance(other Position) int {
	if p.Line == other.Line {
		return int(math.Abs(float64(p.Column - other.Column)))
	}
	// For different lines, calculate based on line difference + column difference
	return int(math.Abs(float64(p.Line-other.Line)))*1000 + int(math.Abs(float64(p.Column-other.Column)))
}

// PositionRange represents a range between two positions
type PositionRange struct {
	Start Position
	End   Position
}

// NewPositionRange creates a new position range
func NewPositionRange(start, end Position) PositionRange {
	return PositionRange{Start: start, End: end}
}

// Length returns the length of the range
func (pr PositionRange) Length() int {
	return pr.Start.Distance(pr.End)
}

// Contains returns true if the given position is within the range
func (pr PositionRange) Contains(pos Position) bool {
	return !pos.IsBefore(pr.Start) && !pos.IsAfter(pr.End)
}

// String returns a string representation of the range
func (pr PositionRange) String() string {
	return fmt.Sprintf("%s-%s", pr.Start.String(), pr.End.String())
}

// Opcode represents an opcode identifier (string-based to avoid compiler dependency)
type Opcode struct {
	Value    string
	Name     string
	Category OpcodeCategory
	Args     []OpcodeArg
	Position Position
}

// OpcodeCategory represents the category of an opcode
type OpcodeCategory int

const (
	// CategoryUnknown represents an unknown opcode category
	CategoryUnknown OpcodeCategory = iota
	// CategoryArithmetic represents arithmetic operations
	CategoryArithmetic
	// CategoryLogical represents logical operations
	CategoryLogical
	// CategoryComparison represents comparison operations
	CategoryComparison
	// CategoryBitwise represents bitwise operations
	CategoryBitwise
	// CategoryStack represents stack operations
	CategoryStack
	// CategoryFlow represents control flow operations
	CategoryFlow
	// CategoryMemory represents memory operations
	CategoryMemory
	// CategoryObject represents object operations
	CategoryObject
	// CategorySystem represents system operations
	CategorySystem
)

// OpcodeArg represents an argument to an opcode
type OpcodeArg struct {
	Type     OperandType
	Value    interface{}
	Required bool
	Position Position
}

// NewOpcode creates a new opcode with basic information
func NewOpcode(value string, name string, position Position) *Opcode {
	return &Opcode{
		Value:    value,
		Name:     name,
		Category: categorizeOpcode(value),
		Args:     make([]OpcodeArg, 0),
		Position: position,
	}
}

// AddArg adds an argument to the opcode
func (op *Opcode) AddArg(argType OperandType, value interface{}, required bool, position Position) {
	op.Args = append(op.Args, OpcodeArg{
		Type:     argType,
		Value:    value,
		Required: required,
		Position: position,
	})
}

// HasCategory returns true if the opcode belongs to the given category
func (op *Opcode) HasCategory(category OpcodeCategory) bool {
	return op.Category == category
}

// GetRequiredArgs returns all required arguments
func (op *Opcode) GetRequiredArgs() []OpcodeArg {
	var required []OpcodeArg
	for _, arg := range op.Args {
		if arg.Required {
			required = append(required, arg)
		}
	}
	return required
}

// GetOptionalArgs returns all optional arguments
func (op *Opcode) GetOptionalArgs() []OpcodeArg {
	var optional []OpcodeArg
	for _, arg := range op.Args {
		if !arg.Required {
			optional = append(optional, arg)
		}
	}
	return optional
}

// ValidateArgs validates that all required arguments are present
func (op *Opcode) ValidateArgs() error {
	for _, arg := range op.Args {
		if arg.Required && arg.Value == nil {
			return fmt.Errorf("required argument missing for opcode %s at %s", op.Name, arg.Position.String())
		}
	}
	return nil
}

// String returns a string representation of the opcode
func (op *Opcode) String() string {
	if len(op.Args) == 0 {
		return op.Name
	}
	return fmt.Sprintf("%s(%v)", op.Name, op.Args)
}

// categorizeOpcode determines the category of an opcode based on its string value
func categorizeOpcode(opcode string) OpcodeCategory {
	switch opcode {
	// Arithmetic operations
	case "INT_ADD", "INT_SUB", "INT_MUL", "INT_DIV", "DBL_ADD", "DBL_SUB", "DBL_MUL", "DBL_DIV",
		"INT_MINUS", "DBL_MINUS", "MOD":
		return CategoryArithmetic

	// Logical operations
	case "AND", "OR", "NOT":
		return CategoryLogical

	// Comparison operations
	case "INT_EQ", "INT_NEQ", "INT_LT", "INT_LE", "INT_GT", "INT_GE",
		"DBL_EQ", "DBL_NEQ", "DBL_LT", "DBL_LE", "DBL_GT", "DBL_GE",
		"CONTAINS", "ICONTAINS", "MATCHES":
		return CategoryComparison

	// Bitwise operations
	case "BITWISE_AND", "BITWISE_OR", "BITWISE_XOR", "SHL", "SHR", "BITWISE_NOT":
		return CategoryBitwise

	// Stack operations
	case "PUSH", "POP", "PUSH_8", "PUSH_16", "PUSH_32", "PUSH_U", "SWAP", "DUP":
		return CategoryStack

	// Control flow operations
	case "JZ", "JTRUE", "JFALSE", "JUMP":
		return CategoryFlow

	// Memory operations
	case "PUSH_M", "OBJ_LOAD", "OBJ_VALUE", "CLEAR_M", "INCR_M":
		return CategoryMemory

	// Object operations
	case "CALL", "OBJ_FIELD", "INDEX_ARRAY":
		return CategoryObject

	// System operations
	case "HALT", "ERROR", "NOP", "FOUND", "LENGTH", "COUNT", "OFFSET":
		return CategorySystem

	default:
		return CategoryUnknown
	}
}

// Operand represents an operand with enhanced type safety and validation
type Operand struct {
	Type     OperandType
	Value    interface{}
	Position Position
}

// OperandType represents the type of an operand
type OperandType int

const (
	// OperandNone represents no operand
	OperandNone OperandType = iota
	// OperandImmediate represents an immediate value
	OperandImmediate
	// OperandMemory represents a memory address
	OperandMemory
	// OperandRegister represents a register
	OperandRegister
	// OperandLabel represents a label reference
	OperandLabel
	// OperandImmediate8 represents an 8-bit immediate value
	OperandImmediate8
	// OperandImmediate16 represents a 16-bit immediate value
	OperandImmediate16
	// OperandImmediate32 represents a 32-bit immediate value
	OperandImmediate32
	// OperandImmediate64 represents a 64-bit immediate value
	OperandImmediate64
	// OperandRelative represents a relative offset
	OperandRelative
	// OperandAbsolute represents an absolute address
	OperandAbsolute
)

// NewOperand creates a new operand
func NewOperand(operandType OperandType, value interface{}, position Position) *Operand {
	return &Operand{
		Type:     operandType,
		Value:    value,
		Position: position,
	}
}

// NewImmediateOperand creates an immediate operand
func NewImmediateOperand(value uint64, position Position) *Operand {
	return NewOperand(OperandImmediate, value, position)
}

// NewImmediate8Operand creates an 8-bit immediate operand
func NewImmediate8Operand(value uint8, position Position) *Operand {
	return NewOperand(OperandImmediate8, value, position)
}

// NewImmediate16Operand creates a 16-bit immediate operand
func NewImmediate16Operand(value uint16, position Position) *Operand {
	return NewOperand(OperandImmediate16, value, position)
}

// NewImmediate32Operand creates a 32-bit immediate operand
func NewImmediate32Operand(value uint32, position Position) *Operand {
	return NewOperand(OperandImmediate32, value, position)
}

// NewImmediate64Operand creates a 64-bit immediate operand
func NewImmediate64Operand(value uint64, position Position) *Operand {
	return NewOperand(OperandImmediate64, value, position)
}

// NewMemoryOperand creates a memory operand
func NewMemoryOperand(address uint64, position Position) *Operand {
	return NewOperand(OperandMemory, address, position)
}

// NewLabelOperand creates a label operand
func NewLabelOperand(label string, position Position) *Operand {
	return NewOperand(OperandLabel, label, position)
}

// NewRelativeOperand creates a relative offset operand
func NewRelativeOperand(offset int32, position Position) *Operand {
	return NewOperand(OperandRelative, offset, position)
}

// IsImmediate returns true if the operand is an immediate value
func (op *Operand) IsImmediate() bool {
	switch op.Type {
	case OperandImmediate, OperandImmediate8, OperandImmediate16,
		OperandImmediate32, OperandImmediate64:
		return true
	default:
		return false
	}
}

// GetImmediateValue returns the immediate value if applicable
func (op *Operand) GetImmediateValue() (uint64, bool) {
	if !op.IsImmediate() {
		return 0, false
	}

	switch v := op.Value.(type) {
	case uint8:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint64:
		return v, true
	case int:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int8:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int16:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int32:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	default:
		return 0, false
	}
}

// Validate validates the operand value based on its type
func (op *Operand) Validate() error {
	switch op.Type {
	case OperandImmediate8:
		if val, ok := op.GetImmediateValue(); ok && val > 0xFF {
			return fmt.Errorf("8-bit immediate value %x out of range at %s", val, op.Position.String())
		}
	case OperandImmediate16:
		if val, ok := op.GetImmediateValue(); ok && val > 0xFFFF {
			return fmt.Errorf("16-bit immediate value %x out of range at %s", val, op.Position.String())
		}
	case OperandImmediate32:
		if val, ok := op.GetImmediateValue(); ok && val > 0xFFFFFFFF {
			return fmt.Errorf("32-bit immediate value %x out of range at %s", val, op.Position.String())
		}
	}
	return nil
}

// String returns a string representation of the operand
func (op *Operand) String() string {
	switch op.Type {
	case OperandImmediate, OperandImmediate8, OperandImmediate16,
		OperandImmediate32, OperandImmediate64:
		return fmt.Sprintf("0x%x", op.Value)
	case OperandMemory:
		return fmt.Sprintf("[%v]", op.Value)
	case OperandLabel:
		return fmt.Sprintf("label:%v", op.Value)
	case OperandRelative:
		return fmt.Sprintf("rel:%v", op.Value)
	case OperandAbsolute:
		return fmt.Sprintf("abs:%v", op.Value)
	default:
		return fmt.Sprintf("%T:%v", op.Type, op.Value)
	}
}
