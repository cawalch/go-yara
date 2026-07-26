package compiler

import "errors"

func unchecked(value int64) uint16 {
	return uint16(value) // want "conversion from int64 to uint16 may lose value"
}

func guarded(value int) (uint16, error) {
	if value < 0 || value > 65535 {
		return 0, errors.New("out of range")
	}
	return uint16(value), nil
}

func masked(value int) uint16 {
	return uint16(value & 0xffff)
}

func shifted(value uint16) byte {
	return byte(value >> 8)
}

func narrowedSigned(value int32) uint16 {
	return uint16(value) // want "conversion from int32 to uint16 may lose value"
}

func explicitlyIgnored(value int32) uint16 {
	return uint16(value) //checkednarrow:ignore low bits are intentionally preserved
}

func emptyIgnore(value int32) uint16 {
	//checkednarrow:ignore
	return uint16(value) // want "conversion from int32 to uint16 may lose value"
}

func unsignedToSigned(value uint64) int64 {
	return int64(value) // want "conversion from uint64 to int64 may lose value"
}

func safeWiden(value uint8) int64 {
	return int64(value)
}

func boundedLoop(start, end byte) []byte {
	var result []byte
	for value := int(start); value <= int(end); value++ {
		result = append(result, byte(value))
	}
	return result
}

func unboundedLoop() {
	for value := 0; ; value++ {
		_ = byte(value) // want "conversion from int to byte may lose value"
	}
}

func wrappingLoop() {
	for value := 0; ; value++ {
		if value <= 255 {
			_ = byte(value) // want "conversion from int to byte may lose value"
		}
	}
}
