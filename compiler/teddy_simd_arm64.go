//go:build go1.27 && goexperiment.simd && arm64

package compiler

import (
	"math"
	"math/bits"
	"simd/archsimd"
)

const teddySIMDEnabled = true

// firstMatchInUint64x2 returns the byte index (0..15) of the first non-zero byte
// in a 16-byte vector (split into two 64-bit words), or -1 if all bytes are zero.
func firstMatchInUint64x2(words archsimd.Uint64x2) int {
	w0 := words.GetElem(0)
	if w0 != 0 {
		return bits.TrailingZeros64(w0) >> 3
	}
	w1 := words.GetElem(1)
	if w1 != 0 {
		return 8 + (bits.TrailingZeros64(w1) >> 3)
	}
	return -1
}

type teddyNeon1Bank struct {
	mask0Lo   archsimd.Uint8x16
	mask0Hi   archsimd.Uint8x16
	mask1Lo   archsimd.Uint8x16
	mask1Hi   archsimd.Uint8x16
	mask2Lo   archsimd.Uint8x16
	mask2Hi   archsimd.Uint8x16
	prefixLen int
}

type teddyNeon2Bank struct {
	bank0Lo0, bank0Hi0 archsimd.Uint8x16
	bank0Lo1, bank0Hi1 archsimd.Uint8x16
	bank0Lo2, bank0Hi2 archsimd.Uint8x16

	bank1Lo0, bank1Hi0 archsimd.Uint8x16
	bank1Lo1, bank1Hi1 archsimd.Uint8x16
	bank1Lo2, bank1Hi2 archsimd.Uint8x16

	prefixLen int
}

func newTeddyPlatform(strings []acStringInfo) teddyPrefilter {
	minLen := math.MaxInt
	for _, s := range strings {
		if len(s.Data) < minLen {
			minLen = len(s.Data)
		}
	}
	prefixLen := min(3, minLen)
	if prefixLen < 1 {
		return nil
	}

	if len(strings) <= 8 {
		return newTeddyNeon1Bank(strings, prefixLen)
	}
	return newTeddyNeon2Bank(strings, prefixLen)
}

func newTeddyNeon1Bank(strings []acStringInfo, prefixLen int) *teddyNeon1Bank {
	var m0Lo, m0Hi, m1Lo, m1Hi, m2Lo, m2Hi [16]byte
	for i, s := range strings {
		bucket := i % 8
		bit := byte(1 << bucket)
		prefix := extractPrefixInfo(s)

		m0Lo[prefix.b0Lo&0x0F] |= bit
		m0Hi[prefix.b0Lo>>4] |= bit
		if prefix.isFold0 {
			m0Lo[prefix.b0Hi&0x0F] |= bit
			m0Hi[prefix.b0Hi>>4] |= bit
		}

		if prefixLen >= 2 && prefix.hasByte1 {
			m1Lo[prefix.b1Lo&0x0F] |= bit
			m1Hi[prefix.b1Lo>>4] |= bit
			if prefix.isFold1 {
				m1Lo[prefix.b1Hi&0x0F] |= bit
				m1Hi[prefix.b1Hi>>4] |= bit
			}
		}

		if prefixLen >= 3 && prefix.hasByte2 {
			m2Lo[prefix.b2Lo&0x0F] |= bit
			m2Hi[prefix.b2Lo>>4] |= bit
			if prefix.isFold2 {
				m2Lo[prefix.b2Hi&0x0F] |= bit
				m2Hi[prefix.b2Hi>>4] |= bit
			}
		}
	}

	return &teddyNeon1Bank{
		mask0Lo:   archsimd.LoadUint8x16(m0Lo[:]),
		mask0Hi:   archsimd.LoadUint8x16(m0Hi[:]),
		mask1Lo:   archsimd.LoadUint8x16(m1Lo[:]),
		mask1Hi:   archsimd.LoadUint8x16(m1Hi[:]),
		mask2Lo:   archsimd.LoadUint8x16(m2Lo[:]),
		mask2Hi:   archsimd.LoadUint8x16(m2Hi[:]),
		prefixLen: prefixLen,
	}
}

func (t *teddyNeon1Bank) findCandidate(data []byte, from int) int {
	lowMask := archsimd.BroadcastUint8x16(0x0F)
	mask0Lo := t.mask0Lo
	mask0Hi := t.mask0Hi
	mask1Lo := t.mask1Lo
	mask1Hi := t.mask1Hi
	mask2Lo := t.mask2Lo
	mask2Hi := t.mask2Hi

	offsetShift := t.prefixLen - 1
	limit32 := len(data) - 32 - offsetShift
	pos := from
	for ; pos <= limit32; pos += 32 {
		v0 := archsimd.LoadUint8x16(data[pos : pos+16])
		v0Lo := v0.And(lowMask)
		v0Hi := v0.ShiftAllRight(4)
		res0 := mask0Lo.LookupOrZero(v0Lo).And(mask0Hi.LookupOrZero(v0Hi))

		if t.prefixLen >= 2 {
			v1 := archsimd.LoadUint8x16(data[pos+1 : pos+17])
			v1Lo := v1.And(lowMask)
			v1Hi := v1.ShiftAllRight(4)
			res0 = res0.And(mask1Lo.LookupOrZero(v1Lo).And(mask1Hi.LookupOrZero(v1Hi)))
		}
		if t.prefixLen >= 3 {
			v2 := archsimd.LoadUint8x16(data[pos+2 : pos+18])
			v2Lo := v2.And(lowMask)
			v2Hi := v2.ShiftAllRight(4)
			res0 = res0.And(mask2Lo.LookupOrZero(v2Lo).And(mask2Hi.LookupOrZero(v2Hi)))
		}

		v0b := archsimd.LoadUint8x16(data[pos+16 : pos+32])
		v0bLo := v0b.And(lowMask)
		v0bHi := v0b.ShiftAllRight(4)
		res1 := mask0Lo.LookupOrZero(v0bLo).And(mask0Hi.LookupOrZero(v0bHi))

		if t.prefixLen >= 2 {
			v1b := archsimd.LoadUint8x16(data[pos+17 : pos+33])
			v1bLo := v1b.And(lowMask)
			v1bHi := v1b.ShiftAllRight(4)
			res1 = res1.And(mask1Lo.LookupOrZero(v1bLo).And(mask1Hi.LookupOrZero(v1bHi)))
		}
		if t.prefixLen >= 3 {
			v2b := archsimd.LoadUint8x16(data[pos+18 : pos+34])
			v2bLo := v2b.And(lowMask)
			v2bHi := v2b.ShiftAllRight(4)
			res1 = res1.And(mask2Lo.LookupOrZero(v2bLo).And(mask2Hi.LookupOrZero(v2bHi)))
		}

		combined := res0.Or(res1)
		wordsComb := combined.ReshapeToUint64s()
		if (wordsComb.GetElem(0) | wordsComb.GetElem(1)) == 0 {
			continue
		}

		if offset := firstMatchInUint64x2(res0.ReshapeToUint64s()); offset >= 0 {
			return pos + offset
		}
		return pos + 16 + firstMatchInUint64x2(res1.ReshapeToUint64s())
	}

	limit16 := len(data) - 16 - offsetShift
	for ; pos <= limit16; pos += 16 {
		v0 := archsimd.LoadUint8x16(data[pos : pos+16])
		v0Lo := v0.And(lowMask)
		v0Hi := v0.ShiftAllRight(4)
		m := mask0Lo.LookupOrZero(v0Lo).And(mask0Hi.LookupOrZero(v0Hi))

		if t.prefixLen >= 2 {
			v1 := archsimd.LoadUint8x16(data[pos+1 : pos+17])
			v1Lo := v1.And(lowMask)
			v1Hi := v1.ShiftAllRight(4)
			m = m.And(mask1Lo.LookupOrZero(v1Lo).And(mask1Hi.LookupOrZero(v1Hi)))
		}
		if t.prefixLen >= 3 {
			v2 := archsimd.LoadUint8x16(data[pos+2 : pos+18])
			v2Lo := v2.And(lowMask)
			v2Hi := v2.ShiftAllRight(4)
			m = m.And(mask2Lo.LookupOrZero(v2Lo).And(mask2Hi.LookupOrZero(v2Hi)))
		}

		if offset := firstMatchInUint64x2(m.ReshapeToUint64s()); offset >= 0 {
			return pos + offset
		}
	}

	return -1
}

func (t *teddyNeon1Bank) findCandidateWithCancel(data []byte, from int, done <-chan struct{}) int {
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

func newTeddyNeon2Bank(strings []acStringInfo, prefixLen int) *teddyNeon2Bank {
	var b0Lo0, b0Hi0, b0Lo1, b0Hi1, b0Lo2, b0Hi2 [16]byte
	var b1Lo0, b1Hi0, b1Lo1, b1Hi1, b1Lo2, b1Hi2 [16]byte

	for i, s := range strings {
		bucket := i % 16
		prefix := extractPrefixInfo(s)

		if bucket < 8 {
			bit := byte(1 << bucket)
			b0Lo0[prefix.b0Lo&0x0F] |= bit
			b0Hi0[prefix.b0Lo>>4] |= bit
			if prefix.isFold0 {
				b0Lo0[prefix.b0Hi&0x0F] |= bit
				b0Hi0[prefix.b0Hi>>4] |= bit
			}
			if prefixLen >= 2 && prefix.hasByte1 {
				b0Lo1[prefix.b1Lo&0x0F] |= bit
				b0Hi1[prefix.b1Lo>>4] |= bit
				if prefix.isFold1 {
					b0Lo1[prefix.b1Hi&0x0F] |= bit
					b0Hi1[prefix.b1Hi>>4] |= bit
				}
			}
			if prefixLen >= 3 && prefix.hasByte2 {
				b0Lo2[prefix.b2Lo&0x0F] |= bit
				b0Hi2[prefix.b2Lo>>4] |= bit
				if prefix.isFold2 {
					b0Lo2[prefix.b2Hi&0x0F] |= bit
					b0Hi2[prefix.b2Hi>>4] |= bit
				}
			}
		} else {
			bit := byte(1 << (bucket - 8))
			b1Lo0[prefix.b0Lo&0x0F] |= bit
			b1Hi0[prefix.b0Lo>>4] |= bit
			if prefix.isFold0 {
				b1Lo0[prefix.b0Hi&0x0F] |= bit
				b1Hi0[prefix.b0Hi>>4] |= bit
			}
			if prefixLen >= 2 && prefix.hasByte1 {
				b1Lo1[prefix.b1Lo&0x0F] |= bit
				b1Hi1[prefix.b1Lo>>4] |= bit
				if prefix.isFold1 {
					b1Lo1[prefix.b1Hi&0x0F] |= bit
					b1Hi1[prefix.b1Hi>>4] |= bit
				}
			}
			if prefixLen >= 3 && prefix.hasByte2 {
				b1Lo2[prefix.b2Lo&0x0F] |= bit
				b1Hi2[prefix.b2Lo>>4] |= bit
				if prefix.isFold2 {
					b1Lo2[prefix.b2Hi&0x0F] |= bit
					b1Hi2[prefix.b2Hi>>4] |= bit
				}
			}
		}
	}

	return &teddyNeon2Bank{
		bank0Lo0: archsimd.LoadUint8x16(b0Lo0[:]),
		bank0Hi0: archsimd.LoadUint8x16(b0Hi0[:]),
		bank0Lo1: archsimd.LoadUint8x16(b0Lo1[:]),
		bank0Hi1: archsimd.LoadUint8x16(b0Hi1[:]),
		bank0Lo2: archsimd.LoadUint8x16(b0Lo2[:]),
		bank0Hi2: archsimd.LoadUint8x16(b0Hi2[:]),

		bank1Lo0: archsimd.LoadUint8x16(b1Lo0[:]),
		bank1Hi0: archsimd.LoadUint8x16(b1Hi0[:]),
		bank1Lo1: archsimd.LoadUint8x16(b1Lo1[:]),
		bank1Hi1: archsimd.LoadUint8x16(b1Hi1[:]),
		bank1Lo2: archsimd.LoadUint8x16(b1Lo2[:]),
		bank1Hi2: archsimd.LoadUint8x16(b1Hi2[:]),

		prefixLen: prefixLen,
	}
}

func (t *teddyNeon2Bank) findCandidate(data []byte, from int) int {
	lowMask := archsimd.BroadcastUint8x16(0x0F)
	offsetShift := t.prefixLen - 1
	limit32 := len(data) - 32 - offsetShift

	pos := from
	for ; pos <= limit32; pos += 32 {
		v0 := archsimd.LoadUint8x16(data[pos : pos+16])
		v0Lo := v0.And(lowMask)
		v0Hi := v0.ShiftAllRight(4)
		res0A := t.bank0Lo0.LookupOrZero(v0Lo).And(t.bank0Hi0.LookupOrZero(v0Hi))
		res1A := t.bank1Lo0.LookupOrZero(v0Lo).And(t.bank1Hi0.LookupOrZero(v0Hi))

		if t.prefixLen >= 2 {
			v1 := archsimd.LoadUint8x16(data[pos+1 : pos+17])
			v1Lo := v1.And(lowMask)
			v1Hi := v1.ShiftAllRight(4)
			res0A = res0A.And(t.bank0Lo1.LookupOrZero(v1Lo).And(t.bank0Hi1.LookupOrZero(v1Hi)))
			res1A = res1A.And(t.bank1Lo1.LookupOrZero(v1Lo).And(t.bank1Hi1.LookupOrZero(v1Hi)))
		}
		if t.prefixLen >= 3 {
			v2 := archsimd.LoadUint8x16(data[pos+2 : pos+18])
			v2Lo := v2.And(lowMask)
			v2Hi := v2.ShiftAllRight(4)
			res0A = res0A.And(t.bank0Lo2.LookupOrZero(v2Lo).And(t.bank0Hi2.LookupOrZero(v2Hi)))
			res1A = res1A.And(t.bank1Lo2.LookupOrZero(v2Lo).And(t.bank1Hi2.LookupOrZero(v2Hi)))
		}
		combA := res0A.Or(res1A)

		v0b := archsimd.LoadUint8x16(data[pos+16 : pos+32])
		v0bLo := v0b.And(lowMask)
		v0bHi := v0b.ShiftAllRight(4)
		res0B := t.bank0Lo0.LookupOrZero(v0bLo).And(t.bank0Hi0.LookupOrZero(v0bHi))
		res1B := t.bank1Lo0.LookupOrZero(v0bLo).And(t.bank1Hi0.LookupOrZero(v0bHi))

		if t.prefixLen >= 2 {
			v1b := archsimd.LoadUint8x16(data[pos+17 : pos+33])
			v1bLo := v1b.And(lowMask)
			v1bHi := v1b.ShiftAllRight(4)
			res0B = res0B.And(t.bank0Lo1.LookupOrZero(v1bLo).And(t.bank0Hi1.LookupOrZero(v1bHi)))
			res1B = res1B.And(t.bank1Lo1.LookupOrZero(v1bLo).And(t.bank1Hi1.LookupOrZero(v1bHi)))
		}
		if t.prefixLen >= 3 {
			v2b := archsimd.LoadUint8x16(data[pos+18 : pos+34])
			v2bLo := v2b.And(lowMask)
			v2bHi := v2b.ShiftAllRight(4)
			res0B = res0B.And(t.bank0Lo2.LookupOrZero(v2bLo).And(t.bank0Hi2.LookupOrZero(v2bHi)))
			res1B = res1B.And(t.bank1Lo2.LookupOrZero(v2bLo).And(t.bank1Hi2.LookupOrZero(v2bHi)))
		}
		combB := res0B.Or(res1B)

		combined := combA.Or(combB)
		words := combined.ReshapeToUint64s()
		if (words.GetElem(0) | words.GetElem(1)) == 0 {
			continue
		}

		if offset := firstMatchInUint64x2(combA.ReshapeToUint64s()); offset >= 0 {
			return pos + offset
		}
		return pos + 16 + firstMatchInUint64x2(combB.ReshapeToUint64s())
	}

	limit16 := len(data) - 16 - offsetShift
	for ; pos <= limit16; pos += 16 {
		v0 := archsimd.LoadUint8x16(data[pos : pos+16])
		v0Lo := v0.And(lowMask)
		v0Hi := v0.ShiftAllRight(4)

		res0 := t.bank0Lo0.LookupOrZero(v0Lo).And(t.bank0Hi0.LookupOrZero(v0Hi))
		res1 := t.bank1Lo0.LookupOrZero(v0Lo).And(t.bank1Hi0.LookupOrZero(v0Hi))

		if t.prefixLen >= 2 {
			v1 := archsimd.LoadUint8x16(data[pos+1 : pos+17])
			v1Lo := v1.And(lowMask)
			v1Hi := v1.ShiftAllRight(4)

			res0 = res0.And(t.bank0Lo1.LookupOrZero(v1Lo).And(t.bank0Hi1.LookupOrZero(v1Hi)))
			res1 = res1.And(t.bank1Lo1.LookupOrZero(v1Lo).And(t.bank1Hi1.LookupOrZero(v1Hi)))
		}
		if t.prefixLen >= 3 {
			v2 := archsimd.LoadUint8x16(data[pos+2 : pos+18])
			v2Lo := v2.And(lowMask)
			v2Hi := v2.ShiftAllRight(4)

			res0 = res0.And(t.bank0Lo2.LookupOrZero(v2Lo).And(t.bank0Hi2.LookupOrZero(v2Hi)))
			res1 = res1.And(t.bank1Lo2.LookupOrZero(v2Lo).And(t.bank1Hi2.LookupOrZero(v2Hi)))
		}

		combined := res0.Or(res1)
		if offset := firstMatchInUint64x2(combined.ReshapeToUint64s()); offset >= 0 {
			return pos + offset
		}
	}

	return -1
}

func (t *teddyNeon2Bank) findCandidateWithCancel(data []byte, from int, done <-chan struct{}) int {
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
