package compiler

import (
	"errors"
	"fmt"

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

	// Calculate quality for each byte in the atom
	for i := range atom.Length {
		byteQuality, isUnique := calculateByteQuality(atom.Data[i], atom.Mask[i])
		quality += byteQuality

		if isUnique && !seenBytes[atom.Data[i]] {
			seenBytes[atom.Data[i]] = true
			uniqueBytes++
		}
	}

	// Apply unique byte bonus
	quality += 2 * uniqueBytes

	// Penalize atoms with all equal and common bytes
	quality = applyCommonBytePenalty(atom, quality, uniqueBytes)

	return quality
}

// calculateByteQuality calculates the quality contribution of a single byte
func calculateByteQuality(b, mask byte) (int, bool) {
	switch mask {
	case 0x00:
		return -10, false
	case 0x0F, 0xF0:
		return 4, false
	case 0xFF:
		return getFullyDefinedByteQuality(b), true
	default:
		return 0, false
	}
}

// getFullyDefinedByteQuality returns the quality for a fully defined byte
func getFullyDefinedByteQuality(b byte) int {
	switch b {
	case 0x00, 0x20, 0xCC, 0xFF:
		return 12 // Common bytes
	default:
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			return 18 // Alphabetic
		}
		return 20 // Other
	}
}

// applyCommonBytePenalty applies penalty for atoms with all equal and common bytes
func applyCommonBytePenalty(atom *Atom, quality, uniqueBytes int) int {
	if uniqueBytes == 1 {
		b := atom.Data[0]
		if isCommonByte(b) {
			quality -= 10 * atom.Length
		}
	}
	return quality
}

// isCommonByte checks if a byte is a common/low-entropy byte
func isCommonByte(b byte) bool {
	return b == 0x00 || b == 0x20 || b == 0x90 || b == 0xCC || b == 0xFF
}

// ExtractAtoms extracts atoms from a string pattern.
func ExtractAtoms(pattern ast.Pattern, modifiers []ast.StringModifier) []*Atom {
	switch p := pattern.(type) {
	case *ast.TextString:
		return ExtractFromTextString(p.Value, modifiers)
	case *ast.HexString:
		return ExtractFromHexString(p.Value, modifiers)
	case *ast.RegexPattern:
		return ExtractFromRegexPattern(p.Value, modifiers)
	default:
		return nil
	}
}

// ExtractFromTextString extracts atoms from a literal text string.
func ExtractFromTextString(s string, _ []ast.StringModifier) []*Atom {
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

// ExtractFromHexString extracts atoms from a hex string pattern.
// Hex strings can contain wildcards (??), alternatives, and fixed bytes.
func ExtractFromHexString(hexStr string, _ []ast.StringModifier) []*Atom {
	// Parse hex string - remove spaces and braces if present
	hexStr = cleanHexString(hexStr)

	if len(hexStr) < 2 {
		return nil
	}

	// Parse hex bytes and wildcards
	hexBytes, err := parseHexBytes(hexStr)
	if err != nil || len(hexBytes) == 0 {
		return nil
	}

	return extractAtomsFromHexBytes(hexBytes)
}

// extractAtomsFromHexBytes extracts atoms from parsed hex bytes
func extractAtomsFromHexBytes(hexBytes []HexByte) []*Atom {
	var atoms []*Atom
	currentSequence := make([]byte, 0)
	currentOffset := 0

	for i, hb := range hexBytes {
		if hb.IsWildcard {
			atoms = finalizeCurrentSequence(atoms, currentSequence, currentOffset)
			currentSequence = nil
			currentOffset = i + 1
		} else {
			currentSequence = append(currentSequence, hb.Value)
		}
	}

	// Don't forget the last sequence
	atoms = finalizeCurrentSequence(atoms, currentSequence, currentOffset)

	if len(atoms) == 0 {
		return nil
	}
	return atoms
}

// finalizeCurrentSequence creates an atom from the current byte sequence if long enough
func finalizeCurrentSequence(atoms []*Atom, sequence []byte, offset int) []*Atom {
	if len(sequence) >= MinAtomLength {
		atom := createAtom(sequence, offset)
		atoms = append(atoms, atom)
	}
	return atoms
}

// createAtom creates a new atom from a byte sequence
func createAtom(sequence []byte, offset int) *Atom {
	atom := &Atom{
		Data:   make([]byte, len(sequence)),
		Mask:   make([]byte, len(sequence)),
		Offset: offset,
		Length: len(sequence),
	}
	copy(atom.Data, sequence)
	for i := range atom.Mask {
		atom.Mask[i] = 0xFF // Fully defined bytes
	}
	atom.Quality = calculateAtomQuality(atom)
	return atom
}

// ExtractFromRegexPattern extracts atoms from a regex pattern.
// Extracts literal byte sequences from regex patterns for optimization.
func ExtractFromRegexPattern(regexStr string, _ []ast.StringModifier) []*Atom {
	// Remove regex delimiters and flags (e.g., "/pattern/i" -> "pattern")
	regexStr = cleanRegexPattern(regexStr)

	if len(regexStr) < MinAtomLength {
		return nil
	}

	// Extract literal sequences from the regex pattern
	literals := extractLiteralsFromRegex(regexStr)
	if len(literals) == 0 {
		return nil
	}

	// Convert literals to atoms using slices package
	var atoms []*Atom
	for _, literal := range literals {
		if len(literal) >= MinAtomLength {
			atom := &Atom{
				Data:   []byte(literal),
				Mask:   make([]byte, len(literal)),
				Offset: 0,
				Length: len(literal),
			}
			// Mark all bytes as fully defined
			for j := range atom.Mask {
				atom.Mask[j] = 0xFF
			}
			atom.Quality = calculateAtomQuality(atom)
			atoms = append(atoms, atom)
		}
	}

	// Return the best quality atom if we have any
	if len(atoms) > 0 {
		// Find the atom with maximum quality using manual loop
		bestAtom := atoms[0]
		for _, atom := range atoms[1:] {
			if atom.Quality > bestAtom.Quality {
				bestAtom = atom
			}
		}
		return []*Atom{bestAtom}
	}

	return nil
}

// cleanRegexPattern removes regex delimiters and flags
func cleanRegexPattern(regexStr string) string {
	// Remove leading and trailing slashes
	if len(regexStr) >= 2 && regexStr[0] == '/' {
		// Find the closing slash (accounting for escaped slashes)
		endIdx := len(regexStr) - 1
		for endIdx > 0 && regexStr[endIdx] != '/' {
			endIdx--
		}
		if endIdx > 0 {
			regexStr = regexStr[1:endIdx]
		}
	}
	return regexStr
}

// extractLiteralsFromRegex extracts literal byte sequences from a regex pattern
func extractLiteralsFromRegex(pattern string) []string {
	var literals []string
	var current []rune

	i := 0
	for i < len(pattern) {
		ch := rune(pattern[i])

		// Handle escape sequences
		if ch == '\\' && i+1 < len(pattern) {
			newCurrent, advance := parseRegexEscape(pattern, i, current, &literals)
			current = newCurrent
			i += advance
			continue
		}

		// Handle regex metacharacters that break literal sequences
		switch ch {
		case '.', '*', '+', '?', '|', '(', ')', '[', ']', '{', '}', '^', '$':
			// End current literal sequence
			if len(current) > 0 {
				literals = append(literals, string(current))
				current = nil
			}
			i++

		case ' ', '\t', '\n', '\r':
			// Whitespace breaks literal sequences
			if len(current) > 0 {
				literals = append(literals, string(current))
				current = nil
			}
			i++

		default:
			// Regular character - add to current literal
			current = append(current, ch)
			i++
		}
	}

	// Don't forget the last sequence
	if len(current) > 0 {
		literals = append(literals, string(current))
	}

	return literals
}

// parseRegexEscape parses an escape sequence in a regex pattern and updates the current sequence and literals list.
// Returns the updated current sequence and the number of characters consumed from pattern.
func parseRegexEscape(pattern string, i int, current []rune, literals *[]string) ([]rune, int) {
	next := pattern[i+1]

	if next == 'x' && i+3 < len(pattern) {
		if h1, ok1 := parseHexDigit(pattern[i+2]); ok1 {
			if h2, ok2 := parseHexDigit(pattern[i+3]); ok2 {
				current = append(current, rune((h1<<4)|h2))
				return current, 4
			}
		}
	}

	switch next {
	case 'w', 'W', 's', 'S', 'd', 'D', 'b', 'B':
		if len(current) > 0 {
			*literals = append(*literals, string(current))
			current = nil
		}
	case 'n':
		current = append(current, '\n')
	case 't':
		current = append(current, '\t')
	case 'r':
		current = append(current, '\r')
	case 'f':
		current = append(current, '\f')
	case 'a':
		current = append(current, '\a')
	default:
		current = append(current, rune(next))
	}

	return current, 2
}

// parseHexDigit parses a single hex digit (0-9, a-f, A-F)
func parseHexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// HexByte represents a byte in a hex string that can be fixed or wildcard
type HexByte struct {
	Value      byte
	IsWildcard bool
}

// cleanHexString removes spaces, braces, and other formatting from hex strings
func cleanHexString(hexStr string) string {
	// Remove braces if present
	if len(hexStr) > 2 && hexStr[0] == '{' && hexStr[len(hexStr)-1] == '}' {
		hexStr = hexStr[1 : len(hexStr)-1]
	}

	// Remove spaces and other whitespace
	var result []rune
	for _, r := range hexStr {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			result = append(result, r)
		}
	}

	return string(result)
}

// parseHexBytes parses a cleaned hex string into bytes and wildcards
func parseHexBytes(hexStr string) ([]HexByte, error) {
	if len(hexStr)%2 != 0 {
		return nil, errors.New("invalid hex string length")
	}

	var hexBytes []HexByte
	for i := 0; i < len(hexStr); i += 2 {
		pair := hexStr[i : i+2]

		if pair == "??" {
			hexBytes = append(hexBytes, HexByte{IsWildcard: true})
			continue
		}

		hb, err := parseSingleHexByte(pair)
		if err != nil {
			// Check for alternative syntax like "AA BB"
			if len(hexBytes) > 0 && hexBytes[len(hexBytes)-1].IsWildcard {
				// This might be an alternative, skip for now
				continue
			}
			return nil, err
		}
		hexBytes = append(hexBytes, hb)
	}

	return hexBytes, nil
}

// parseSingleHexByte parses a two-character hex pair into a HexByte.
func parseSingleHexByte(pair string) (HexByte, error) {
	var b byte
	if _, err := fmt.Sscanf(pair, "%02x", &b); err != nil {
		return HexByte{}, fmt.Errorf("invalid hex byte: %s", pair)
	}
	return HexByte{Value: b, IsWildcard: false}, nil
}
