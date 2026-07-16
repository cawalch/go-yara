package compiler

import "github.com/cawalch/go-yara/regex"

// StringKind identifies the kind of pattern compiled for a string identifier.
type StringKind uint8

const (
	StringKindText StringKind = iota
	StringKindHex
	StringKindRegex
)

// RegexPattern holds compiled regex bytecode and flags.
type RegexPattern struct {
	Code              []byte
	Flags             regex.Flags
	prefix            []byte
	widePrefix        []byte
	atom              []byte
	wideAtom          []byte
	atomMinOffset     int
	atomMaxOffset     int
	byteSet           regex.ByteSet
	byteSetMinOffset  int
	byteSetMaxOffset  int
	byteSetCount      int
	byteSetLower      byte
	byteSetUpper      byte
	byteSetContiguous bool
	fixedByteSets     []regex.ByteSet
	anchored          bool
	cacheKey          string
	cacheIndex        int
}
