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
	Code                 []byte
	CaptureCode          []byte
	CaptureGroups        []int
	Flags                regex.Flags
	prefix               []byte
	widePrefix           []byte
	atom                 []byte
	wideAtom             []byte
	atomMinOffset        int
	atomMaxOffset        int
	alternativeAtoms     []regexPrefilterAtom
	wideAlternativeAtoms []regexPrefilterAtom
	leadingGap           *regexLeadingGapPlan
	byteSet              regex.ByteSet
	byteSetMinOffset     int
	byteSetMaxOffset     int
	byteSetCount         int
	byteSetLower         byte
	byteSetUpper         byte
	byteSetContiguous    bool
	byteSetValues        []byte
	fixedByteSets        []regex.ByteSet
	anchored             bool
	cacheKey             string
	cacheIndex           int
}

// EvidencePlan is the compiled form of an evidence declaration.
type EvidencePlan struct {
	Name   string
	Fields []string
	Anchor string
	Within int64
}

type regexLeadingGapPlan struct {
	leadingSet regex.ByteSet
	gapSet     regex.ByteSet
	gapMin     int
	gapMax     int
	atoms      []regexPrefilterAtom
}
