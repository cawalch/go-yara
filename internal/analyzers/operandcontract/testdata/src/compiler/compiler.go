package compiler

type Opcode uint8

const (
	OpNoOperand Opcode = iota
	OpPush8
	OpPush16 // want "opcode OpPush16 requires a 2-byte operand but no interpreter consumption was found"
	OpPush32
	OpPushM
)

type OperandType uint8

const (
	OperandNone OperandType = iota
	OperandImmediate8
	OperandImmediate16
	OperandImmediate32
)

type Operand struct {
	Type  OperandType
	Value uint64
}

type Emitter struct{}

func (*Emitter) EmitOpcode(Opcode, int, int) {}

func (*Emitter) EmitOpcodeWithOperand(Opcode, Operand, int, int) {}

type Interpreter struct{}

func (*Interpreter) validateBytecodeBounds(Opcode, int) error { return nil }

func (i *Interpreter) readAndValidateMemorySlot(opcode Opcode) {
	_ = i.validateBytecodeBounds(opcode, 4)
}

func (i *Interpreter) consumeOperands() {
	_ = i.validateBytecodeBounds(OpPush8, 1)
	_ = i.validateBytecodeBounds(OpPush32, 4)
	i.readAndValidateMemorySlot(OpPushM)
	_ = i.validateBytecodeBounds(OpPush8, 4) // want "opcode OpPush8 consumes 4 operand bytes; contract requires 1"
}

func emitOperands(emitter *Emitter) {
	emitter.EmitOpcode(OpNoOperand, 1, 1)
	emitter.EmitOpcodeWithOperand(OpPush8, Operand{Type: OperandImmediate8}, 1, 1)
	emitter.EmitOpcodeWithOperand(OpPush32, Operand{Type: OperandImmediate32}, 1, 1)
	emitter.EmitOpcode(OpPush8, 1, 1)                                                  // want "opcode OpPush8 requires OperandImmediate8, not EmitOpcode"
	emitter.EmitOpcodeWithOperand(OpNoOperand, Operand{Type: OperandImmediate8}, 1, 1) // want "opcode OpNoOperand does not accept an operand"
	emitter.EmitOpcodeWithOperand(OpPushM, Operand{Type: OperandImmediate8}, 1, 1)     // want "opcode OpPushM requires OperandImmediate32, got OperandImmediate8"
}
