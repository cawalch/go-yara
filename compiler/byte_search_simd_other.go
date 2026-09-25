//go:build go1.27 && goexperiment.simd && !arm64 && !amd64

package compiler

import "simd"

func byteSIMDHardwareAvailable(_ simd.Uint8s) bool {
	return false
}

func firstMatchingByte(mask simd.Mask8s) int {
	return firstMatchingByteEmulated(mask)
}
