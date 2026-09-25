//go:build go1.27 && goexperiment.simd && amd64

package compiler

import (
	"math/bits"
	"simd"
	"simd/archsimd"
)

func byteSIMDHardwareAvailable(value simd.Uint8s) bool {
	switch value.ToArch().(type) {
	case archsimd.Uint8x16, archsimd.Uint8x32, archsimd.Uint8x64:
		return true
	default:
		return false
	}
}

func firstMatchingByte(mask simd.Mask8s) int {
	var lanes uint64
	switch value := mask.ToInt8s().ToArch().(type) {
	case archsimd.Int8x16:
		lanes = uint64(value.ToMask().ToBits())
	case archsimd.Int8x32:
		lanes = uint64(value.ToMask().ToBits())
	case archsimd.Int8x64:
		lanes = value.ToMask().ToBits()
	default:
		return firstMatchingByteEmulated(mask)
	}
	if lanes == 0 {
		return -1
	}
	return bits.TrailingZeros64(lanes)
}
