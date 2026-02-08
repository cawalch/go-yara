package compiler

// builtinFunction identifies a built-in function executed via OpCall.
type builtinFunction uint8

const (
	builtinConcat builtinFunction = iota
	builtinToString
	builtinInt
	builtinMD5
	builtinSHA1
	builtinSHA256
)

const (
	builtinArgShift = 8
	builtinArgMask  = 0xFF
)

func encodeBuiltinCall(fn builtinFunction, argc int) uint64 {
	if argc < 0 {
		argc = 0
	}
	if argc > builtinArgMask {
		argc = builtinArgMask
	}
	return uint64(uint32(fn)<<builtinArgShift | uint32(argc))
}

func decodeBuiltinCall(encoded uint32) (builtinFunction, int) {
	fn := builtinFunction(encoded >> builtinArgShift)
	argc := int(encoded & builtinArgMask)
	return fn, argc
}
