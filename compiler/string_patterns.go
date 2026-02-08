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
	Code  []byte
	Flags regex.Flags
}
