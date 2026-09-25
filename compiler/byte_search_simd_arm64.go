//go:build go1.27 && goexperiment.simd && arm64

package compiler

import (
	"math/bits"
	"simd"
	"simd/archsimd"
)

func byteSIMDHardwareAvailable(value simd.Uint8s) bool {
	_, ok := value.ToArch().(archsimd.Uint8x16)
	return ok
}

func firstMatchingByte(mask simd.Mask8s) int {
	switch value := mask.ToInt8s().ToArch().(type) {
	case archsimd.Int8x16:
		words := value.ToBits().ReshapeToUint64s()
		if low := words.GetElem(0); low != 0 {
			return bits.TrailingZeros64(low) / 8
		}
		if high := words.GetElem(1); high != 0 {
			return 8 + bits.TrailingZeros64(high)/8
		}
		return -1
	default:
		return firstMatchingByteEmulated(mask)
	}
}
