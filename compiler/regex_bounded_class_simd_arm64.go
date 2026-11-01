//go:build go1.27 && goexperiment.simd && arm64

package compiler

import (
	"simd"
	"simd/archsimd"
)

func countBoundedClass(data []byte, class *boundedClassSet) int {
	if len(data) < 16 || !byteSIMDHardwareAvailable(simd.BroadcastUint8s(0)) {
		return countBoundedClassScalar(data, class)
	}
	bit := [16]byte{1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128}
	loTable, hiTable, bitsTable := archsimd.LoadUint8x16(class.low[:16]), archsimd.LoadUint8x16(class.high[:16]), archsimd.LoadUint8x16(bit[:])
	indexMask, sign := archsimd.BroadcastUint8x16(0x8f), archsimd.BroadcastUint8x16(0x80)
	pos := 0
	for ; pos+16 <= len(data); pos += 16 {
		v := archsimd.LoadUint8x16(data[pos : pos+16])
		lo := loTable.LookupOrZero(v.And(indexMask))
		hi := hiTable.LookupOrZero(v.Xor(sign).And(indexMask))
		valid := lo.Or(hi).And(bitsTable.LookupOrZero(v.ShiftAllRight(4)))
		invalid := valid.Equal(archsimd.BroadcastUint8x16(0)).ToInt8x16().ToBits()
		if lane := firstMatchInUint64x2(invalid.ReshapeToUint64s()); lane >= 0 {
			return pos + lane
		}
	}
	return pos + countBoundedClassScalar(data[pos:], class)
}
