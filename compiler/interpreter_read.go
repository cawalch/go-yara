package compiler

import "fmt"

// executeReadIntOp executes integer reading operations (little-endian).
func (i *Interpreter) executeReadIntOp(size int, signed bool) error {
	if err := i.validateStackUnderflow(OpInt8); err != nil {
		return err
	}

	offsetVal := i.stack[len(i.stack)-1]
	if offsetVal.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer offset required"}
	}

	offset := offsetVal.IntVal
	val, err := i.executeReadInt(offset, size, signed)
	if err != nil {
		return err
	}

	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: val}
	return nil
}

// executeReadIntOpBE executes integer reading operations (big-endian).
func (i *Interpreter) executeReadIntOpBE(size int, signed bool) error {
	if err := i.validateStackUnderflow(OpInt8be); err != nil {
		return err
	}

	offsetVal := i.stack[len(i.stack)-1]
	if offsetVal.Type != ValueTypeInt {
		return &InterpreterError{Type: ErrorTypeMismatch, Message: "integer offset required"}
	}

	if i.matchContext == nil {
		return &InterpreterError{Type: ErrorRuntime, Message: "no match context available"}
	}

	offset := offsetVal.IntVal
	data, ok := i.matchContext.dataRange(offset, int64(size))
	if !ok {
		return &InterpreterError{Type: ErrorInvalidMemoryAccess, Message: "integer read extends beyond available data"}
	}

	if err := i.validateReadIntAccess(offset); err != nil {
		return err
	}

	val, err := i.readIntBE(data, 0, size, signed)
	if err != nil {
		return err
	}

	i.stack[len(i.stack)-1] = Value{Type: ValueTypeInt, IntVal: val}
	return nil
}

// readIntBE reads an integer in big-endian byte order.
//
//nolint:revive // argument-limit: API surface
func (i *Interpreter) readIntBE(data []byte, offset int64, size int, signed bool) (int64, error) {
	switch size {
	case 1:
		b := data[offset]
		return safeByteToInt64(b, signed), nil

	case 2:
		if err := i.validateBounds(data, offset, 1, "16-bit read"); err != nil {
			return 0, err
		}
		b1 := data[offset]
		b2 := data[offset+1]
		combined := uint16(b1)<<8 | uint16(b2)
		return safeUint16ToInt64(combined, !signed), nil

	case 4:
		if err := i.validateBounds(data, offset, 3, "32-bit read"); err != nil {
			return 0, err
		}
		b1 := data[offset]
		b2 := data[offset+1]
		b3 := data[offset+2]
		b4 := data[offset+3]
		combined := uint32(b1)<<24 | uint32(b2)<<16 | uint32(b3)<<8 | uint32(b4)
		return safeUint32ToInt64(combined, !signed), nil

	case 8:
		if err := i.validateBounds(data, offset, 7, "64-bit read"); err != nil {
			return 0, err
		}
		b1 := data[offset]
		b2 := data[offset+1]
		b3 := data[offset+2]
		b4 := data[offset+3]
		b5 := data[offset+4]
		b6 := data[offset+5]
		b7 := data[offset+6]
		b8 := data[offset+7]
		combined := uint64(b1)<<56 | uint64(b2)<<48 | uint64(b3)<<40 | uint64(b4)<<32 |
			uint64(b5)<<24 | uint64(b6)<<16 | uint64(b7)<<8 | uint64(b8)
		return safeUint64ToInt64(combined, !signed), nil

	default:
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: fmt.Sprintf("unsupported integer size: %d", size),
		}
	}
}

// validateBounds checks if a read operation is within data bounds.
//
//nolint:revive // argument-limit: compact validation helper
func (*Interpreter) validateBounds(data []byte, offset int64, extraBytes int, operation string) error {
	if offset+int64(extraBytes) >= int64(len(data)) {
		return &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: operation + " extends beyond data bounds",
		}
	}
	return nil
}

// executeReadInt reads an integer from the match context data (for testing).
func (i *Interpreter) executeReadInt(offset int64, size int, unsigned bool) (int64, error) {
	if err := i.validateReadIntAccess(offset); err != nil {
		return 0, err
	}

	data, ok := i.matchContext.dataRange(offset, int64(size))
	if !ok {
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: fmt.Sprintf("%d-bit read extends beyond available data", size*8),
		}
	}
	switch size {
	case 1:
		return i.readInt8(data, 0, unsigned)
	case 2:
		return i.readInt16(data, 0, unsigned)
	case 4:
		return i.readInt32(data, 0, unsigned)
	case 8:
		return i.readInt64(data, 0, unsigned)
	default:
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: fmt.Sprintf("unsupported integer size: %d", size),
		}
	}
}

// validateReadIntAccess validates that the offset is within bounds.
func (i *Interpreter) validateReadIntAccess(offset int64) error {
	if i.matchContext == nil {
		return &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: "no match context available for reading data",
		}
	}

	if offset < 0 {
		return &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: fmt.Sprintf("offset %d is out of bounds", offset),
		}
	}
	return nil
}

// readInt8 reads an 8-bit integer.
func (i *Interpreter) readInt8(data []byte, offset int64, unsigned bool) (int64, error) {
	val := data[offset]
	if unsigned {
		return int64(val), nil
	}
	return int64(int8(val)), nil
}

// readInt16 reads a 16-bit little-endian integer.
func (i *Interpreter) readInt16(data []byte, offset int64, unsigned bool) (int64, error) {
	if offset+1 >= int64(len(data)) {
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: "16-bit read extends beyond data bounds",
		}
	}
	val := uint16(data[offset]) | uint16(data[offset+1])<<8
	return safeUint16ToInt64(val, unsigned), nil
}

// readInt32 reads a 32-bit little-endian integer.
func (i *Interpreter) readInt32(data []byte, offset int64, unsigned bool) (int64, error) {
	if offset+3 >= int64(len(data)) {
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: "32-bit read extends beyond data bounds",
		}
	}
	val := uint32(data[offset]) | uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
	return safeUint32ToInt64(val, unsigned), nil
}

// readInt64 reads a 64-bit little-endian integer.
func (i *Interpreter) readInt64(data []byte, offset int64, unsigned bool) (int64, error) {
	if offset+7 >= int64(len(data)) {
		return 0, &InterpreterError{
			Type:    ErrorInvalidMemoryAccess,
			Message: "64-bit read extends beyond data bounds",
		}
	}
	val := uint64(data[offset]) | uint64(data[offset+1])<<8 |
		uint64(data[offset+2])<<16 | uint64(data[offset+3])<<24 |
		uint64(data[offset+4])<<32 | uint64(data[offset+5])<<40 |
		uint64(data[offset+6])<<48 | uint64(data[offset+7])<<56
	return safeUint64ToInt64(val, unsigned), nil
}

// Helper functions for safe integer conversions

// safeUint16ToInt64 converts uint16 to int64 with optional sign extension.
func safeUint16ToInt64(val uint16, unsigned bool) int64 {
	if unsigned {
		return int64(val)
	}
	if val&0x8000 != 0 {
		return int64(val) - 0x10000
	}
	return int64(val)
}

// safeUint32ToInt64 converts uint32 to int64 with optional sign extension.
func safeUint32ToInt64(val uint32, unsigned bool) int64 {
	if unsigned {
		return int64(val)
	}
	if val&0x80000000 != 0 {
		return int64(val) - 0x100000000
	}
	return int64(val)
}

// safeUint64ToInt64 converts uint64 to int64 with optional sign extension.
func safeUint64ToInt64(val uint64, unsigned bool) int64 {
	if unsigned {
		return int64(val)
	}
	if val&0x8000000000000000 != 0 {
		return int64(^val + 1)
	}
	return int64(val)
}

// safeByteToInt64 converts a byte to int64 with optional sign extension.
func safeByteToInt64(b byte, signed bool) int64 {
	if signed {
		if b&0x80 != 0 {
			return int64(b) - 0x100
		}
	}
	return int64(b)
}

// boolToInt converts a boolean to integer (1 for true, 0 for false).
func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// isTruthy determines if a value is considered truthy.
func (i *Interpreter) isTruthy(v Value) bool {
	switch v.Type {
	case ValueTypeInt:
		return v.IntVal != 0
	case ValueTypeDouble:
		return v.DoubleVal != 0
	case ValueTypeString:
		return i.getString(v) != ""
	default:
		return false
	}
}

// --- Read int operation wrappers ---

func (i *Interpreter) executeReadInt8() error   { return i.executeReadIntOp(1, true) }
func (i *Interpreter) executeReadInt16() error  { return i.executeReadIntOp(2, true) }
func (i *Interpreter) executeReadInt32() error  { return i.executeReadIntOp(4, true) }
func (i *Interpreter) executeReadInt64() error  { return i.executeReadIntOp(8, true) }
func (i *Interpreter) executeReadUint8() error  { return i.executeReadIntOp(1, false) }
func (i *Interpreter) executeReadUint16() error { return i.executeReadIntOp(2, false) }
func (i *Interpreter) executeReadUint32() error { return i.executeReadIntOp(4, false) }
func (i *Interpreter) executeReadUint64() error { return i.executeReadIntOp(8, false) }

func (i *Interpreter) executeReadInt8be() error   { return i.executeReadIntOpBE(1, true) }
func (i *Interpreter) executeReadInt16be() error  { return i.executeReadIntOpBE(2, true) }
func (i *Interpreter) executeReadInt32be() error  { return i.executeReadIntOpBE(4, true) }
func (i *Interpreter) executeReadInt64be() error  { return i.executeReadIntOpBE(8, true) }
func (i *Interpreter) executeReadUint8be() error  { return i.executeReadIntOpBE(1, false) }
func (i *Interpreter) executeReadUint16be() error { return i.executeReadIntOpBE(2, false) }
func (i *Interpreter) executeReadUint32be() error { return i.executeReadIntOpBE(4, false) }
func (i *Interpreter) executeReadUint64be() error { return i.executeReadIntOpBE(8, false) }
