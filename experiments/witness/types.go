// Package witness is a research spike, not a supported matching API.
package witness

// A Rule requires every Pattern; a Pattern accepts any alternative sequence.
type Rule struct{ All []Pattern }
type Pattern struct{ Any []Sequence }
type Sequence []Term

// A term is either a literal or a bounded run of bytes from Set.
// Literal terms ignore Min/Max/Set; NoCase applies only to ASCII literals.
// Any-byte gaps use AllBytes().
type Term struct {
	Literal  []byte
	Set      [4]uint64
	Min, Max int
	NoCase   bool
}

func Literal(s string) Term { return Term{Literal: []byte(s)} }
func Bytes(minimum, maximum int, set [4]uint64) Term {
	return Term{Min: minimum, Max: maximum, Set: set}
}
func AllBytes() [4]uint64 { return [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)} }
func ByteRange(first, last byte) (set [4]uint64) {
	for b := int(first); b <= int(last); b++ {
		set[b/64] |= uint64(1) << (b % 64)
	}
	return
}
func Text(s string) Pattern { return Pattern{Any: []Sequence{{Literal(s)}}} }

type Decision uint8

const (
	NoMatch Decision = iota
	Match
	Unknown
)

type Stats struct{ Rules, Sequences, Signatures, Slots, TableBytes, Witnesses int }
