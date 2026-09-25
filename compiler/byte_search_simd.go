//go:build go1.27 && goexperiment.simd

package compiler

import "simd"

const byteSearchSIMDEnabled = true

// Probe an initial scalar prefix so short and dense searches do not pay SIMD
// dispatch and broadcast costs. Keep vector types out of these entry points so
// the compiler does not move the dispatch ahead of that probe.
func indexASCIIFoldByte(data []byte, want byte) int {
	if len(data) < 64 {
		return indexASCIIFoldByteScalar(data, want)
	}
	if index := indexASCIIFoldByteScalar(data[:16], want); index >= 0 {
		return index
	}
	if index := indexASCIIFoldByteSIMD(data[16:], want); index >= 0 {
		return 16 + index
	}
	return -1
}

func indexByteRange(data []byte, lower, upper byte) int {
	if len(data) < 64 {
		return indexByteRangeScalar(data, lower, upper)
	}
	if index := indexByteRangeScalar(data[:16], lower, upper); index >= 0 {
		return index
	}
	if index := indexByteRangeSIMD(data[16:], lower, upper); index >= 0 {
		return 16 + index
	}
	return -1
}

func indexASCIIFoldByteSIMD(data []byte, want byte) int {
	lower := simd.BroadcastUint8s(want)
	if !byteSIMDHardwareAvailable(lower) {
		return indexASCIIFoldByteScalar(data, want)
	}
	upper := simd.BroadcastUint8s(flipASCIICase(want))
	width := lower.Len()
	pos := 0
	for ; pos <= len(data)-width; pos += width {
		value := simd.LoadUint8s(data[pos : pos+width])
		mask := value.Equal(lower).Or(value.Equal(upper))
		if lane := firstMatchingByte(mask); lane >= 0 {
			return pos + lane
		}
	}
	if index := indexASCIIFoldByteScalar(data[pos:], want); index >= 0 {
		return pos + index
	}
	return -1
}

func indexByteRangeSIMD(data []byte, lower, upper byte) int {
	lo := simd.BroadcastUint8s(lower)
	if !byteSIMDHardwareAvailable(lo) {
		return indexByteRangeScalar(data, lower, upper)
	}
	span := simd.BroadcastUint8s(upper - lower)
	width := lo.Len()
	pos := 0
	for ; pos <= len(data)-width; pos += width {
		value := simd.LoadUint8s(data[pos : pos+width])
		if lane := firstMatchingByte(value.Sub(lo).Max(span).Equal(span)); lane >= 0 {
			return pos + lane
		}
	}
	if index := indexByteRangeScalar(data[pos:], lower, upper); index >= 0 {
		return pos + index
	}
	return -1
}

// Go 1.27 does not expose a portable first-true-lane operation. Hardware
// implementations use small archsimd bridges; this handles emulated vectors.
func firstMatchingByteEmulated(mask simd.Mask8s) int {
	value := mask.ToInt8s()
	lanes := make([]int8, value.Len())
	value.Store(lanes)
	for index, lane := range lanes {
		if lane != 0 {
			return index
		}
	}
	return -1
}
