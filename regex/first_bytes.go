package regex

import "math/bits"

const maxUsefulByteSetSize = 96

// ByteSet is a compact set of possible byte values.
type ByteSet struct {
	words [4]uint64
}

// ByteSetAtom describes a restrictive byte set that every regex match must
// consume. Offsets are measured in input characters before that byte.
type ByteSetAtom struct {
	Set       ByteSet
	MinOffset int
	MaxOffset int
}

// Contains reports whether value belongs to the set.
func (set ByteSet) Contains(value byte) bool {
	return set.words[value>>6]&(uint64(1)<<uint(value&63)) != 0
}

// Count returns the number of byte values in the set.
func (set ByteSet) Count() int {
	return bits.OnesCount64(set.words[0]) +
		bits.OnesCount64(set.words[1]) +
		bits.OnesCount64(set.words[2]) +
		bits.OnesCount64(set.words[3])
}

// ContiguousRange reports whether the set is one non-empty inclusive byte
// range and returns its bounds.
func (set ByteSet) ContiguousRange() (byte, byte, bool) {
	count := set.Count()
	if count == 0 {
		return 0, 0, false
	}
	lower := 0
	for lower < 256 && !set.Contains(byte(lower)) {
		lower++
	}
	upper := 255
	for upper >= 0 && !set.Contains(byte(upper)) {
		upper--
	}
	if upper-lower+1 != count {
		return 0, 0, false
	}
	return byte(lower), byte(upper), true
}

// ASCIIFolded returns a set expanded so either ASCII case is accepted whenever
// one case was already possible.
func (set ByteSet) ASCIIFolded() ByteSet {
	for lower := byte('a'); lower <= 'z'; lower++ {
		upper := lower - ('a' - 'A')
		if set.Contains(lower) || set.Contains(upper) {
			set.add(lower)
			set.add(upper)
		}
	}
	return set
}

// MandatoryByteSetAtoms returns restrictive byte sets that must be consumed by
// every match accepted by ast.
func MandatoryByteSetAtoms(ast *AST) []ByteSetAtom {
	if ast == nil || ast.Root == nil {
		return nil
	}
	return analyzeAtoms(ast.Root).byteAtoms
}

func classByteSet(class *Class) ByteSet {
	if class == nil {
		return fullByteSet()
	}
	var set ByteSet
	for value := 0; value < 256; value++ {
		member := class.Bitmap[value/8]&(byte(1)<<uint(value%8)) != 0
		if member != class.Negated {
			set.add(byte(value))
		}
	}
	return set
}

func maskedByteSet(value, mask byte, negated bool) ByteSet {
	var set ByteSet
	for candidate := 0; candidate < 256; candidate++ {
		matches := byte(candidate)&mask == value&mask
		if matches != negated {
			set.add(byte(candidate))
		}
	}
	return set
}

func predicateByteSet(predicate func(byte) bool) ByteSet {
	var set ByteSet
	for value := 0; value < 256; value++ {
		if predicate(byte(value)) {
			set.add(byte(value))
		}
	}
	return set
}

func byteSetOf(value byte) ByteSet {
	var set ByteSet
	set.add(value)
	return set
}

func fullByteSet() ByteSet {
	return ByteSet{words: [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}}
}

func usefulByteSetAtom(set ByteSet) []ByteSetAtom {
	count := set.Count()
	if count == 0 || count > maxUsefulByteSetSize {
		return nil
	}
	return []ByteSetAtom{{Set: set, MaxOffset: 0}}
}

func (set *ByteSet) add(value byte) {
	set.words[value>>6] |= uint64(1) << uint(value&63)
}

func (set *ByteSet) remove(value byte) {
	set.words[value>>6] &^= uint64(1) << uint(value&63)
}

func (set *ByteSet) union(other ByteSet) {
	for i := range set.words {
		set.words[i] |= other.words[i]
	}
}
