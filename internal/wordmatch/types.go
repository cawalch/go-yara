// Package wordmatch provides bounded Boolean matching for literal and byte-run rules.
package wordmatch

// A Rule requires every Pattern; a Pattern accepts any alternative sequence.
type Rule struct{ All []Pattern }
type Pattern struct{ Any []Sequence }
type Sequence []Term

// A term is either a literal or a bounded run of bytes from Set.
// Literal terms ignore Min/Max/Set; NoCase applies only to ASCII literals.
// An all-ones Set represents an any-byte gap.
type Term struct {
	Literal  []byte
	Set      [4]uint64
	Min, Max int
	NoCase   bool
}

type Decision uint8

const (
	NoMatch Decision = iota
	Match
	Unknown
)
