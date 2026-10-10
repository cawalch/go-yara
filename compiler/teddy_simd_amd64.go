//go:build go1.27 && goexperiment.simd && amd64

package compiler

import (
	"simd"
)

const teddySIMDEnabled = true

type teddyAMD64Prefilter struct {
	targets []simd.Uint8s
}

func newTeddyPlatform(strings []acStringInfo) teddyPrefilter {
	if len(strings) > 8 {
		return nil
	}

	var rootBytes []byte
	var seen [256]bool
	for _, s := range strings {
		prefix := extractPrefixInfo(s)
		if !seen[prefix.b0Lo] {
			seen[prefix.b0Lo] = true
			rootBytes = append(rootBytes, prefix.b0Lo)
		}
		if prefix.isFold0 && !seen[prefix.b0Hi] {
			seen[prefix.b0Hi] = true
			rootBytes = append(rootBytes, prefix.b0Hi)
		}
	}

	if len(rootBytes) == 0 || len(rootBytes) > 16 {
		return nil
	}

	targets := make([]simd.Uint8s, len(rootBytes))
	for i, b := range rootBytes {
		targets[i] = simd.BroadcastUint8s(b)
	}

	if !byteSIMDHardwareAvailable(targets[0]) {
		return nil
	}

	return &teddyAMD64Prefilter{targets: targets}
}

func (t *teddyAMD64Prefilter) findCandidate(data []byte, from int) int {
	if len(t.targets) == 0 {
		return -1
	}
	width := t.targets[0].Len()
	limit := len(data) - width

	pos := from
	for ; pos <= limit; pos += width {
		val := simd.LoadUint8s(data[pos : pos+width])
		mask := val.Equal(t.targets[0])
		for i := 1; i < len(t.targets); i++ {
			mask = mask.Or(val.Equal(t.targets[i]))
		}
		if lane := firstMatchingByte(mask); lane >= 0 {
			return pos + lane
		}
	}

	return -1
}

func (t *teddyAMD64Prefilter) findCandidateWithCancel(data []byte, from int, done <-chan struct{}) int {
	for pos := from; pos < len(data); pos += cancelableSearchWindow {
		if scanCanceled(done) {
			return -1
		}
		candidate := t.findCandidate(data, pos)
		if candidate < 0 {
			return -1
		}
		if candidate < pos+cancelableSearchWindow {
			return candidate
		}
		pos = candidate - (candidate % cancelableSearchWindow)
	}
	return -1
}
