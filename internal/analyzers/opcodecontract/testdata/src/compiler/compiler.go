package compiler

type Opcode uint8

const (
	OpHandled Opcode = iota
	OpMissingName
	OpMissingHandler
	OpMissingJumpHandler
	OpHandledAlias = OpHandled
	OpIntBegin     = 10
	OpIntEq        = OpIntBegin
)

var opcodeNames = map[Opcode]string{
	OpHandled: "HANDLED",
}

var intOpNames = []string{"INT_EQ"}

type OpcodeHandler func()

var opcodeTable [256]OpcodeHandler

type OperandType uint8

const OperandNone OperandType = 20

func init() {
	opcodeTable[OpHandled] = handle
	opcodeTable[OpMissingName] = handle  // want "dispatched opcode OpMissingName has no opcodeNames entry"
	opcodeTable[OpHandledAlias] = handle // want "opcode value assigned more than once in opcodeTable"
	opcodeTable[OpIntEq] = handle
	opcodeTable[OperandNone] = handle // want "opcodeTable index must be an Opcode constant"
}

func handle() {}

type Emitter struct{}

func (e *Emitter) EmitOpcode(Opcode) {}

type JumpConfig struct {
	Opcode Opcode
}

func (e *Emitter) EmitJump(JumpConfig) {}

func emitMissingHandlers(emitter *Emitter) {
	emitter.EmitOpcode(OpMissingHandler) // want "emitted opcode OpMissingHandler has no opcodeTable dispatch handler"
	emitter.EmitJump(JumpConfig{
		Opcode: OpMissingJumpHandler, // want "emitted opcode OpMissingJumpHandler has no opcodeTable dispatch handler"
	})
}
