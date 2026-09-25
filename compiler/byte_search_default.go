//go:build !go1.27 || !goexperiment.simd

package compiler

const byteSearchSIMDEnabled = false

func indexASCIIFoldByte(data []byte, want byte) int {
	return indexASCIIFoldByteScalar(data, want)
}

func indexByteRange(data []byte, lower, upper byte) int {
	return indexByteRangeScalar(data, lower, upper)
}
