//go:build go1.27 && goexperiment.simd && amd64

package compiler

import (
	"math/bits"
	"simd"
	"simd/archsimd"

	"github.com/cawalch/go-yara/regex"
)

type teddyAVX2Bank struct {
	lo, hi [3]archsimd.Uint8x32
}

type teddyAVX2Corpus struct {
	banks     [2]teddyAVX2Bank
	prefixLen int
	twoBanks  bool
}

func newTeddyAVX2Corpus(strings []acStringInfo) teddyPrefilter {
	if !archsimd.X86.AVX2() || !byteSIMDHardwareAvailable(simd.BroadcastUint8s(0)) {
		return nil
	}
	cover := teddyPrefixCover(strings)
	if len(cover) == 0 {
		return nil
	}
	t := &teddyAVX2Corpus{prefixLen: len(cover[0].Data), twoBanks: len(cover) > 8}
	var lo, hi [2][3][32]byte
	for i, info := range cover {
		bank, bit := (i%16)/8, byte(1<<(i%8))
		for j, b := range info.Data {
			lo[bank][j][b&15] |= bit
			hi[bank][j][b>>4] |= bit
			if info.Flags&regex.FlagsNoCase != 0 {
				b = flipASCIICase(b)
				lo[bank][j][b&15] |= bit
				hi[bank][j][b>>4] |= bit
			}
		}
	}
	for bank := range t.banks {
		for j := range t.prefixLen {
			// VPSHUFB indexes each 128-bit lane independently.
			copy(lo[bank][j][16:], lo[bank][j][:16])
			copy(hi[bank][j][16:], hi[bank][j][:16])
			t.banks[bank].lo[j] = archsimd.LoadUint8x32(lo[bank][j][:])
			t.banks[bank].hi[j] = archsimd.LoadUint8x32(hi[bank][j][:])
		}
	}
	return &corpusTeddyPrefilter{t}
}

func (b *teddyAVX2Bank) candidates(data []byte, width int) archsimd.Uint8x32 {
	lowMask := archsimd.BroadcastUint8x32(15)
	result := archsimd.BroadcastUint8x32(255)
	for i := range width {
		v := archsimd.LoadUint8x32(data[i : i+32])
		lo := v.And(lowMask).BitsToInt8()
		hi := v.ReshapeToUint16s().ShiftAllRight(4).ReshapeToUint8s().And(lowMask).BitsToInt8()
		result = result.And(b.lo[i].PermuteOrZeroGrouped(lo).And(b.hi[i].PermuteOrZeroGrouped(hi)))
	}
	return result
}

func (t *teddyAVX2Corpus) findCandidate(data []byte, from int) int {
	for pos := from; pos <= len(data)-32-(t.prefixLen-1); pos += 32 {
		mask := t.banks[0].candidates(data[pos:], t.prefixLen)
		if t.twoBanks {
			mask = mask.Or(t.banks[1].candidates(data[pos:], t.prefixLen))
		}
		if lanes := ^mask.Equal(archsimd.BroadcastUint8x32(0)).ToBits(); lanes != 0 {
			return pos + bits.TrailingZeros32(lanes)
		}
	}
	return -1
}

func (t *teddyAVX2Corpus) tailMayMatch(data []byte) bool {
	// A 32-byte block with a three-byte prefix can leave 33 bytes. Two
	// padded blocks cover every remaining start; padding only adds candidates.
	var tail [96]byte
	copy(tail[:], data[max(0, len(data)-33):])
	return t.findCandidate(tail[:], 0) >= 0
}

func (t *teddyAVX2Corpus) findCandidateWithCancel(data []byte, from int, done <-chan struct{}) int {
	// The corpus wrapper owns cancellation checkpoints and exact scanning.
	if scanCanceled(done) {
		return -1
	}
	return t.findCandidate(data, from)
}
