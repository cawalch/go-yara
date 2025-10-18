// Package compiler provides bytecode generation and compilation for YARA rules.
package compiler

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/cawalch/go-yara/ast"
)

// Atom represents a fixed sequence of bytes extracted from a pattern
type Atom struct {
	Data     []byte // The atom data
	Offset   int    // Offset within the original pattern
	Length   int    // Length of the atom
	Quality  int    // Quality score for optimization
}

// StringCompiler handles compilation of string patterns to bytecode
type StringCompiler struct {
	emitter *Emitter
	// Maps for string identifiers to bytecode offsets
	stringOffsets map[string]int
	// Maps for pattern data
	patternData map[string][]byte
	// Extracted atoms for optimization
	atoms map[string][]Atom
}

// NewStringCompiler creates a new string compiler
func NewStringCompiler(emitter *Emitter) *StringCompiler {
	return &StringCompiler{
		emitter:       emitter,
		stringOffsets: make(map[string]int),
		patternData:   make(map[string][]byte),
		atoms:         make(map[string][]Atom),
	}
}

// CompileStrings compiles all strings in a rule to bytecode
func (sc *StringCompiler) CompileStrings(rule *ast.Rule) error {
	for _, str := range rule.Strings {
		if err := sc.compileString(str); err != nil {
			return fmt.Errorf("compiling string %s: %w", str.Identifier, err)
		}
	}
	return nil
}

// compileString compiles a single string pattern
func (sc *StringCompiler) compileString(str *ast.String) error {
	// Record the string offset for later reference
	offset := sc.emitter.EmitOpcode(OP_INIT_RULE, str.Pos.Line, str.Pos.Column)
	sc.stringOffsets[str.Identifier] = offset

	// Compile the pattern based on its type
	switch p := str.Pattern.(type) {
	case *ast.TextString:
		if err := sc.compileTextString(str.Identifier, p, str.Modifiers); err != nil {
			return err
		}
	case *ast.HexString:
		if err := sc.compileHexString(str.Identifier, p, str.Modifiers); err != nil {
			return err
		}
	case *ast.RegexPattern:
		if err := sc.compileRegexPattern(str.Identifier, p, str.Modifiers); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown pattern type")
	}

	return nil
}

// compileTextString compiles a text string pattern
func (sc *StringCompiler) compileTextString(identifier string, pattern *ast.TextString, modifiers []ast.StringModifier) error {
	text := pattern.Value

	// Apply modifiers
	encoded := sc.encodeTextString(text, modifiers)

	// Store pattern data
	sc.patternData[identifier] = encoded

	// Emit pattern matching instruction
	sc.emitter.EmitOpcode(OP_MATCHES, pattern.Pos.Line, pattern.Pos.Column)

	return nil
}

// compileHexString compiles a hex string pattern
func (sc *StringCompiler) compileHexString(identifier string, pattern *ast.HexString, modifiers []ast.StringModifier) error {
	// Parse hex string (simplified - would need full hex grammar parser)
	hexData := sc.parseHexString(pattern.Value)

	// Apply modifiers
	encoded := sc.encodeHexString(hexData, modifiers)

	// Store pattern data
	sc.patternData[identifier] = encoded

	// Emit pattern matching instruction
	sc.emitter.EmitOpcode(OP_MATCHES, pattern.Pos.Line, pattern.Pos.Column)

	return nil
}

// compileRegexPattern compiles a regular expression pattern
func (sc *StringCompiler) compileRegexPattern(identifier string, pattern *ast.RegexPattern, modifiers []ast.StringModifier) error {
	// Compile regex to internal format
	regexData := sc.compileRegex(pattern.Value, modifiers)

	// Store pattern data
	sc.patternData[identifier] = regexData

	// Emit pattern matching instruction
	sc.emitter.EmitOpcode(OP_MATCHES, pattern.Pos.Line, pattern.Pos.Column)

	return nil
}

// encodeTextString encodes a text string with modifiers applied
func (sc *StringCompiler) encodeTextString(text string, modifiers []ast.StringModifier) []byte {
	var result []byte

	// Check for wide modifier
	isWide := false
	for _, mod := range modifiers {
		if mod.Type == ast.StringModifierWide {
			isWide = true
			break
		}
	}

	if isWide {
		// Convert to UTF-16LE
		utf16Data := utf16.Encode([]rune(text))
		result = make([]byte, len(utf16Data)*2)
		for i, v := range utf16Data {
			result[i*2] = byte(v)
			result[i*2+1] = byte(v >> 8)
		}
	} else {
		// ASCII/UTF-8 encoding
		result = []byte(text)
	}

	// Apply case-insensitive modifier
	isNocase := false
	for _, mod := range modifiers {
		if mod.Type == ast.StringModifierNocase {
			isNocase = true
			break
		}
	}

	if isNocase {
		// For nocase, we need to create case-insensitive matching data
		// This is a simplified approach - real implementation would be more complex
		result = sc.applyNocaseModifier(result, isWide)
	}

	return result
}

// encodeHexString encodes a hex string with modifiers applied
func (sc *StringCompiler) encodeHexString(hexData []byte, modifiers []ast.StringModifier) []byte {
	// Apply XOR modifier if present
	for _, mod := range modifiers {
		if mod.Type == ast.StringModifierXor {
			if xorValue, ok := mod.Value.(int64); ok {
				for i := range hexData {
					hexData[i] ^= byte(xorValue)
				}
			}
		}
	}

	// Apply base64 modifiers if present
	for _, mod := range modifiers {
		if mod.Type == ast.StringModifierBase64 || mod.Type == ast.StringModifierBase64Wide {
			// Base64 decoding would happen here
			// This is simplified - real implementation would decode base64
		}
	}

	return hexData
}

// parseHexString parses a hex string pattern (simplified implementation)
func (sc *StringCompiler) parseHexString(hexStr string) []byte {
	// Remove spaces and comments
	clean := strings.ReplaceAll(hexStr, " ", "")
	clean = regexp.MustCompile(`/\*.*?\*/`).ReplaceAllString(clean, "")

	// Parse hex bytes (simplified - real implementation would handle full hex grammar)
	var result []byte
	for i := 0; i < len(clean)-1; i += 2 {
		if i+1 < len(clean) {
			// This is a very simplified hex parser
			// Real implementation would handle wildcards, jumps, alternatives, etc.
			if clean[i:i+2] == "??" {
				result = append(result, 0x00) // Wildcard
			} else {
				// Parse hex byte (simplified)
				result = append(result, 0x00) // Placeholder
			}
		}
	}

	return result
}

// compileRegex compiles a regex pattern to internal format
func (sc *StringCompiler) compileRegex(pattern string, modifiers []ast.StringModifier) []byte {
	// Compile regex to internal format
	// This is simplified - real implementation would compile to NFA/DFA

	// For now, just store the pattern string
	return []byte(pattern)
}

// applyNocaseModifier applies case-insensitive matching
func (sc *StringCompiler) applyNocaseModifier(data []byte, isWide bool) []byte {
	if isWide {
		// For wide strings, apply case-insensitive to UTF-16 data
		result := make([]byte, len(data))
		copy(result, data)

		// Convert ASCII letters to lowercase for case-insensitive matching
		for i := 0; i < len(result)-1; i += 2 {
			// Check if this is an ASCII letter in UTF-16LE
			if result[i] >= 'A' && result[i] <= 'Z' {
				result[i] = result[i] - 'A' + 'a'
			}
		}
		return result
	} else {
		// For ASCII strings, apply case-insensitive
		result := make([]byte, len(data))
		copy(result, data)

		// Convert ASCII letters to lowercase
		for i := range result {
			if result[i] >= 'A' && result[i] <= 'Z' {
				result[i] = result[i] - 'A' + 'a'
			}
		}
		return result
	}
}

// GetStringOffsets returns the bytecode offsets for all compiled strings
func (sc *StringCompiler) GetStringOffsets() map[string]int {
	return sc.stringOffsets
}

// GetPatternData returns the encoded pattern data for all strings
func (sc *StringCompiler) GetPatternData() map[string][]byte {
	return sc.patternData
}

// StringInfo holds information about a compiled string
type StringInfo struct {
	Identifier string
	Offset     int
	Pattern    []byte
	Modifiers  []ast.StringModifier
}

// GetStringInfo returns information about all compiled strings
func (sc *StringCompiler) GetStringInfo() []StringInfo {
	var info []StringInfo

	for identifier, offset := range sc.stringOffsets {
		pattern, exists := sc.patternData[identifier]
		if !exists {
			pattern = []byte{}
		}

		// We don't have the modifiers here, but in a real implementation
		// we'd store them during compilation
		info = append(info, StringInfo{
			Identifier: identifier,
			Offset:     offset,
			Pattern:    pattern,
			Modifiers:  []ast.StringModifier{}, // Would be populated during compilation
		})
	}

	return info
}

// ValidateStringModifiers validates that string modifiers are compatible
func (sc *StringCompiler) ValidateStringModifiers(modifiers []ast.StringModifier) error {
	hasWide := false
	hasASCII := false
	hasBase64 := false
	hasBase64Wide := false

	for _, mod := range modifiers {
		switch mod.Type {
		case ast.StringModifierWide:
			hasWide = true
		case ast.StringModifierASCII:
			hasASCII = true
		case ast.StringModifierBase64:
			hasBase64 = true
		case ast.StringModifierBase64Wide:
			hasBase64Wide = true
		}
	}

	// Check for incompatible modifiers
	if hasWide && hasASCII {
		return fmt.Errorf("cannot use both 'wide' and 'ascii' modifiers")
	}

	if hasBase64 && hasBase64Wide {
		return fmt.Errorf("cannot use both 'base64' and 'base64wide' modifiers")
	}

	return nil
}

// OptimizePattern optimizes a pattern for better matching performance
func (sc *StringCompiler) OptimizePattern(pattern []byte, modifiers []ast.StringModifier) []byte {
	// Apply various optimizations:
	// 1. Remove redundant bytes
	// 2. Optimize for alignment
	// 3. Apply modifier-specific optimizations

	optimized := make([]byte, len(pattern))
	copy(optimized, pattern)

	// Check for wide modifier
	isWide := false
	for _, mod := range modifiers {
		if mod.Type == ast.StringModifierWide {
			isWide = true
			break
		}
	}

	if isWide {
		// Optimize UTF-16 pattern
		optimized = sc.optimizeWidePattern(optimized)
	} else {
		// Optimize ASCII pattern
		optimized = sc.optimizeASCIIPattern(optimized)
	}

	return optimized
}

// optimizeWidePattern optimizes a UTF-16 encoded pattern
func (sc *StringCompiler) optimizeWidePattern(pattern []byte) []byte {
	if len(pattern)%2 != 0 {
		return pattern // Invalid wide string
	}

	// Remove null bytes that don't contribute to matching
	optimized := make([]byte, 0, len(pattern))
	for i := 0; i < len(pattern); i += 2 {
		// Keep non-null UTF-16 characters
		if pattern[i] != 0 || pattern[i+1] != 0 {
			optimized = append(optimized, pattern[i], pattern[i+1])
		}
	}

	return optimized
}

// optimizeASCIIPattern optimizes an ASCII pattern
func (sc *StringCompiler) optimizeASCIIPattern(pattern []byte) []byte {
	// Remove redundant sequences
	// This is a simplified optimization - real implementation would be more sophisticated

	optimized := make([]byte, 0, len(pattern))

	for i := 0; i < len(pattern); {
		// Skip consecutive identical bytes (simple run-length optimization)
		if i < len(pattern)-2 && pattern[i] == pattern[i+1] && pattern[i] == pattern[i+2] {
			// Found a run of 3+ identical bytes, optimize it
			optimized = append(optimized, pattern[i])
			i += 3
		} else {
			optimized = append(optimized, pattern[i])
			i++
		}
	}

	return optimized
}

// EstimatePatternComplexity estimates the complexity/quality of a pattern
// Based on libyara's yr_atoms_heuristic_quality algorithm
// Higher quality = better for pattern matching (less false positives)
// Used for optimization decisions and pattern selection
func (sc *StringCompiler) EstimatePatternComplexity(pattern []byte, modifiers []ast.StringModifier) int {
	if len(pattern) == 0 {
		return 0
	}

	quality := 0
	seenBytes := make(map[byte]bool)

	// Analyze each byte in the pattern
	for _, b := range pattern {
		// Track unique bytes
		if !seenBytes[b] {
			seenBytes[b] = true
		}

		// Score based on byte value (libyara heuristic)
		switch b {
		case 0x00, 0x20, 0xCC, 0xFF:
			// Common bytes contribute less (12 points)
			quality += 12
		case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
			// Alphabetic characters contribute 18 points
			quality += 18
		default:
			// Other bytes contribute 20 points
			quality += 20
		}
	}

	// Bonus for unique bytes (2x the number of unique bytes)
	quality += len(seenBytes) * 2

	// Adjust for modifiers
	for _, mod := range modifiers {
		switch mod.Type {
		case ast.StringModifierWide:
			// Wide strings are more complex (less common)
			quality = quality * 3 / 2
		case ast.StringModifierNocase:
			// Case-insensitive reduces quality (more matches)
			quality = quality * 2 / 3
		case ast.StringModifierASCII:
			// ASCII modifier slightly reduces quality
			quality = quality * 9 / 10
		}
	}

	return quality
}

// Debug printing functions

// PrintStringInfo prints information about all compiled strings
func (sc *StringCompiler) PrintStringInfo() {
	fmt.Println("Compiled String Information:")
	fmt.Printf("%-8s %-8s %-12s %-s\n", "ID", "Offset", "Size", "Pattern")
	fmt.Println("─────────────────────────────────────────")

	for _, info := range sc.GetStringInfo() {
		patternStr := fmt.Sprintf("%X", info.Pattern)
		if len(patternStr) > 20 {
			patternStr = patternStr[:17] + "..."
		}

		fmt.Printf("%-8s %-8d %-12d %-s\n",
			info.Identifier,
			info.Offset,
			len(info.Pattern),
			patternStr)
	}
}
// ExtractAtomsFromString extracts atoms from a string pattern
// Based on libyara's yr_atoms_extract_from_string function
func (sc *StringCompiler) ExtractAtomsFromString(pattern []byte, modifiers []ast.StringModifier) []Atom {
	var atoms []Atom

	if len(pattern) == 0 {
		return atoms
	}

	// Minimum atom length (libyara uses 2)
	minAtomLength := 2

	// Maximum atom length (libyara uses 4)
	maxAtomLength := 4

	// Extract atoms of different lengths
	for length := minAtomLength; length <= maxAtomLength && length <= len(pattern); length++ {
		for offset := 0; offset <= len(pattern)-length; offset++ {
			atomData := pattern[offset : offset+length]

			// Calculate quality for this atom
			quality := sc.calculateAtomQuality(atomData, modifiers)

			atom := Atom{
				Data:    make([]byte, len(atomData)),
				Offset:  offset,
				Length:  length,
				Quality: quality,
			}
			copy(atom.Data, atomData)

			atoms = append(atoms, atom)
		}
	}

	return atoms
}

// calculateAtomQuality calculates quality score for an atom
func (sc *StringCompiler) calculateAtomQuality(atomData []byte, modifiers []ast.StringModifier) int {
	if len(atomData) == 0 {
		return 0
	}

	quality := 0
	seenBytes := make(map[byte]bool)

	// Analyze each byte in the atom
	for _, b := range atomData {
		// Track unique bytes
		if !seenBytes[b] {
			seenBytes[b] = true
		}

		// Score based on byte value (libyara heuristic)
		switch b {
		case 0x00, 0x20, 0xCC, 0xFF:
			// Common bytes contribute less (12 points)
			quality += 12
		case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
			// Alphabetic characters contribute 18 points
			quality += 18
		default:
			// Other bytes contribute 20 points
			quality += 20
		}
	}

	// Bonus for unique bytes (2x the number of unique bytes)
	quality += len(seenBytes) * 2

	// Adjust for modifiers
	for _, mod := range modifiers {
		switch mod.Type {
		case ast.StringModifierWide:
			// Wide strings are more complex (less common)
			quality = quality * 3 / 2
		case ast.StringModifierNocase:
			// Case-insensitive reduces quality (more matches)
			quality = quality * 2 / 3
		case ast.StringModifierASCII:
			// ASCII modifier slightly reduces quality
			quality = quality * 9 / 10
		}
	}

	return quality
}

// ExtractAtomsFromRegex extracts atoms from a regex pattern
// This is a simplified implementation - real libyara would compile regex to NFA/DFA first
func (sc *StringCompiler) ExtractAtomsFromRegex(pattern string, modifiers []ast.StringModifier) []Atom {
	// For regex patterns, we extract literal strings from the regex
	// This is a simplified approach - real implementation would be more sophisticated

	// Simple regex literal extraction (not complete regex parsing)
	var atoms []Atom

	// Look for literal sequences in the regex (simplified)
	// In a real implementation, this would parse the regex properly

	// For now, return empty atoms for regex patterns
	// This would be implemented with proper regex parsing in production
	return atoms
}

// GetAtoms returns the extracted atoms for a string identifier
func (sc *StringCompiler) GetAtoms(identifier string) []Atom {
	return sc.atoms[identifier]
}

// GetAllAtoms returns all extracted atoms
func (sc *StringCompiler) GetAllAtoms() map[string][]Atom {
	return sc.atoms
}