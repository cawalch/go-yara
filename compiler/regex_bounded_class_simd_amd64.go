//go:build go1.27 && goexperiment.simd && amd64

package compiler

import (
	"math/bits"
	"simd"
	"simd/archsimd"
)

func countBoundedClass(data []byte, class *boundedClassSet) int {
	if len(data) < 32 || !archsimd.X86.AVX2() || !byteSIMDHardwareAvailable(simd.BroadcastUint8s(0)) {
		return countBoundedClassScalar(data, class)
	}
	bit := [32]byte{1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128,
		1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128}
	loTable, hiTable, bitsTable := archsimd.LoadUint8x32(class.low[:]), archsimd.LoadUint8x32(class.high[:]), archsimd.LoadUint8x32(bit[:])
	indexMask, sign, nibble := archsimd.BroadcastUint8x32(0x8f), archsimd.BroadcastUint8x32(0x80), archsimd.BroadcastUint8x32(15)
	pos := 0
	for ; pos+32 <= len(data); pos += 32 {
		v := archsimd.LoadUint8x32(data[pos : pos+32])
		lo := loTable.PermuteOrZeroGrouped(v.And(indexMask).BitsToInt8())
		hi := hiTable.PermuteOrZeroGrouped(v.Xor(sign).And(indexMask).BitsToInt8())
		indices := v.ReshapeToUint16s().ShiftAllRight(4).ReshapeToUint8s().And(nibble).BitsToInt8()
		valid := lo.Or(hi).And(bitsTable.PermuteOrZeroGrouped(indices))
		if invalid := valid.Equal(archsimd.BroadcastUint8x32(0)).ToBits(); invalid != 0 {
			return pos + bits.TrailingZeros32(invalid)
		}
	}
	return pos + countBoundedClassScalar(data[pos:], class)
}
