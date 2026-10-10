//go:build !go1.27 || !goexperiment.simd || (!arm64 && !amd64)

package compiler

const teddySIMDEnabled = false

func newTeddyPlatform(_ []acStringInfo) teddyPrefilter {
	return nil
}
