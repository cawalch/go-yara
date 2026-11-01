//go:build !go1.27 || !goexperiment.simd || (!amd64 && !arm64)

package compiler

func countBoundedClass(data []byte, class *boundedClassSet) int {
	return countBoundedClassScalar(data, class)
}
