//go:build go1.27 && goexperiment.simd && (arm64 || amd64)

package compiler

import (
	"github.com/cawalch/go-yara/regex"
)

// patternPrefixInfo holds normalized prefix bytes for Teddy construction.
type patternPrefixInfo struct {
	b0Lo, b0Hi byte
	b1Lo, b1Hi byte
	b2Lo, b2Hi byte
	hasByte1   bool
	hasByte2   bool
	isFold0    bool
	isFold1    bool
	isFold2    bool
}

func extractPrefixInfo(info acStringInfo) patternPrefixInfo {
	noCase := info.Flags&regex.FlagsNoCase != 0
	b0 := info.Data[0]
	res := patternPrefixInfo{
		b0Lo: b0,
		b0Hi: b0,
	}
	if noCase {
		folded := flipASCIICase(b0)
		if folded != b0 {
			res.isFold0 = true
			res.b0Hi = folded
		}
	}
	if len(info.Data) >= 2 {
		b1 := info.Data[1]
		res.hasByte1 = true
		res.b1Lo = b1
		res.b1Hi = b1
		if noCase {
			folded := flipASCIICase(b1)
			if folded != b1 {
				res.isFold1 = true
				res.b1Hi = folded
			}
		}
	}
	if len(info.Data) >= 3 {
		b2 := info.Data[2]
		res.hasByte2 = true
		res.b2Lo = b2
		res.b2Hi = b2
		if noCase {
			folded := flipASCIICase(b2)
			if folded != b2 {
				res.isFold2 = true
				res.b2Hi = folded
			}
		}
	}
	return res
}
