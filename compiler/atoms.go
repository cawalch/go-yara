// Package compiler provides bytecode generation and compilation for YARA rules.

package compiler

import (
	"github.com/cawalch/go-yara/ast"
)

const (
	// MaxAtomLength is the maximum length of an atom.
	MaxAtomLength = 4
	// MinAtomLength is the minimum length of an atom.
	MinAtomLength = 2
)

// Atom represents a fixed sequence of bytes extracted from a pattern.
type Atom struct {
	Data    []byte // The atom data
	Mask    []byte // The atom mask
	Offset  int    // Offset within the original pattern
	Length  int    // Length of the atom
	Quality int    // Quality score for optimization
}

// AtomQualityTableEntry represents an entry in the atom quality table.
type AtomQualityTableEntry struct {
	Atom    []byte
	Quality int
}

// AtomQualityTable is a table for looking up atom quality.
var AtomQualityTable []AtomQualityTableEntry

// calculateAtomQuality calculates the quality of an atom based on libyara's
// yr_atoms_heuristic_quality algorithm.
func calculateAtomQuality(atom *Atom) int {
	if atom.Length == 0 {
		return 0
	}

	quality := 0
	seenBytes := make(map[byte]bool)
	uniqueBytes := 0

	for i := 0; i < atom.Length; i++ {
		switch atom.Mask[i] {
		case 0x00:
			quality -= 10
		case 0x0F, 0xF0:
			quality += 4
		case 0xFF:
			b := atom.Data[i]
			switch b {
			case 0x00, 0x20, 0xCC, 0xFF:
				quality += 12 // Common bytes
			default:
				if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
					quality += 18 // Alphabetic
				} else {
					quality += 20 // Other
				}
			}
			if !seenBytes[b] {
				seenBytes[b] = true
				uniqueBytes++
			}
		}
	}

	quality += 2 * uniqueBytes

	// Penalize atoms with all equal and common bytes
	if uniqueBytes == 1 {
		b := atom.Data[0]
		if b == 0x00 || b == 0x20 || b == 0x90 || b == 0xCC || b == 0xFF {
			quality -= 10 * atom.Length
		}
	}

	return quality
}

// ExtractAtoms extracts atoms from a string pattern.
func ExtractAtoms(pattern ast.Pattern, modifiers []ast.StringModifier) []*Atom {
	switch p := pattern.(type) {
	case *ast.TextString:
		return ExtractFromTextString(p.Value, modifiers)
	case *ast.HexString:
		// TODO: Implement atom extraction for hex strings
		return nil
	case *ast.RegexPattern:
		// TODO: Implement atom extraction for regex patterns
		return nil
	default:
		return nil
	}
}

// ExtractFromTextString extracts atoms from a literal text string.
func ExtractFromTextString(s string, modifiers []ast.StringModifier) []*Atom {
	// For now, we'll extract a single, best-quality atom from the string,
	// similar to how yr_atoms_extract_from_string works for simple strings.

	if len(s) < MinAtomLength {
		return nil
	}

	var bestAtom *Atom
	maxQuality := -1

	// Iterate through all possible substrings of MaxAtomLength
	for i := 0; i <= len(s)-MaxAtomLength; i++ {
		substring := s[i : i+MaxAtomLength]
		atom := &Atom{
			Data:   []byte(substring),
			Mask:   make([]byte, MaxAtomLength),
			Offset: i,
			Length: MaxAtomLength,
		}
		for j := range atom.Mask {
			atom.Mask[j] = 0xFF // Fully defined bytes
		}

		quality := calculateAtomQuality(atom)
		if quality > maxQuality {
			maxQuality = quality
			bestAtom = atom
		}
	}

	// If the string is shorter than MaxAtomLength, use the whole string
	if bestAtom == nil && len(s) >= MinAtomLength {
		atom := &Atom{
			Data:   []byte(s),
			Mask:   make([]byte, len(s)),
			Offset: 0,
			Length: len(s),
		}
		for j := range atom.Mask {
			atom.Mask[j] = 0xFF
		}
		bestAtom = atom
		bestAtom.Quality = calculateAtomQuality(bestAtom)
	}

	if bestAtom != nil {
		return []*Atom{bestAtom}
	}

	return nil
}