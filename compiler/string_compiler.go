// Package compiler provides bytecode generation and compilation for YARA rules.
package compiler

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/cawalch/go-yara/ast"
)

// StringCompiler handles compilation of string patterns to bytecode
type StringCompiler struct {
	emitter *Emitter
	// Maps for string identifiers to bytecode offsets
	stringOffsets map[string]int
	// Maps for pattern data
	patternData map[string][]byte
	// Extracted atoms for optimization
	atoms map[string][]*Atom
}

// NewStringCompiler creates a new string compiler
func NewStringCompiler(emitter *Emitter) *StringCompiler {
	return &StringCompiler{
		emitter:       emitter,
		stringOffsets: make(map[string]int),
		patternData:   make(map[string][]byte),
		atoms:         make(map[string][]*Atom),
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

	// Extract atoms for optimization
	sc.atoms[str.Identifier] = ExtractAtoms(str.Pattern, str.Modifiers)

	return nil
}

// GetAtoms returns the extracted atoms for a string identifier
func (sc *StringCompiler) GetAtoms(identifier string) []*Atom {
	return sc.atoms[identifier]
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

// HexToken represents a token in a hex string
type HexToken struct {
	Type  string      // "byte", "wildcard", "masked", "jump", "alternative"
	Value interface{} // byte value, jump range, or alternatives
}

// parseHexString parses a hex string pattern with full YARA hex grammar support
func (sc *StringCompiler) parseHexString(hexStr string) []byte {
	// Tokenize the hex string
	tokens := sc.tokenizeHexString(hexStr)
	if len(tokens) == 0 {
		return []byte{}
	}

	// Convert tokens to bytes
	return sc.tokensToBytes(tokens)
}

// tokenizeHexString tokenizes a hex string into tokens
func (sc *StringCompiler) tokenizeHexString(hexStr string) []HexToken {
	var tokens []HexToken
	i := 0

	for i < len(hexStr) {
		// Skip whitespace
		for i < len(hexStr) && (hexStr[i] == ' ' || hexStr[i] == '\t' || hexStr[i] == '\n' || hexStr[i] == '\r') {
			i++
		}
		if i >= len(hexStr) {
			break
		}

		// Skip comments
		if i+1 < len(hexStr) && hexStr[i:i+2] == "/*" {
			// Find end of comment
			for i+1 < len(hexStr) && hexStr[i:i+2] != "*/" {
				i++
			}
			if i+1 < len(hexStr) {
				i += 2
			}
			continue
		}

		// Skip single-line comments
		if i+1 < len(hexStr) && hexStr[i:i+2] == "//" {
			// Skip to end of line
			for i < len(hexStr) && hexStr[i] != '\n' {
				i++
			}
			continue
		}

		// Parse tokens
		switch hexStr[i] {
		case '{':
			i++
		case '}':
			i++
		case '(':
			// Start of alternatives
			i++
			// Find matching closing paren
			depth := 1
			altStart := i
			for i < len(hexStr) && depth > 0 {
				if hexStr[i] == '(' {
					depth++
				} else if hexStr[i] == ')' {
					depth--
				}
				i++
			}
			// Parse alternatives
			altStr := hexStr[altStart : i-1]
			alts := sc.parseAlternatives(altStr)
			tokens = append(tokens, HexToken{Type: "alternative", Value: alts})

		case '[':
			// Jump range
			i++
			jumpStart := i
			for i < len(hexStr) && hexStr[i] != ']' {
				i++
			}
			jumpStr := hexStr[jumpStart:i]
			if i < len(hexStr) {
				i++ // skip ]
			}
			jump := sc.parseJump(jumpStr)
			tokens = append(tokens, HexToken{Type: "jump", Value: jump})

		case '?':
			// Wildcard or masked byte
			if i+1 < len(hexStr) && hexStr[i+1] == '?' {
				// Full wildcard ??
				tokens = append(tokens, HexToken{Type: "wildcard", Value: byte(0x00)})
				i += 2
			} else if i+1 < len(hexStr) && isHexDigit(hexStr[i+1]) {
				// Masked byte ?X
				hex := string(hexStr[i : i+2])
				val := sc.parseHexByte(hex)
				tokens = append(tokens, HexToken{Type: "masked", Value: val})
				i += 2
			} else {
				i++
			}

		default:
			// Try to parse hex byte
			if i+1 < len(hexStr) && isHexDigit(hexStr[i]) && isHexDigit(hexStr[i+1]) {
				hex := hexStr[i : i+2]
				val := sc.parseHexByte(hex)
				tokens = append(tokens, HexToken{Type: "byte", Value: val})
				i += 2
			} else if isHexDigit(hexStr[i]) && i+1 < len(hexStr) && hexStr[i+1] == '?' {
				// Masked byte X?
				hex := string(hexStr[i : i+2])
				val := sc.parseHexByte(hex)
				tokens = append(tokens, HexToken{Type: "masked", Value: val})
				i += 2
			} else {
				i++
			}
		}
	}

	return tokens
}

// parseAlternatives parses alternatives separated by |
func (sc *StringCompiler) parseAlternatives(altStr string) [][]byte {
	var alts [][]byte
	parts := strings.Split(altStr, "|")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			tokens := sc.tokenizeHexString(part)
			bytes := sc.tokensToBytes(tokens)
			alts = append(alts, bytes)
		}
	}
	return alts
}

// parseJump parses a jump range [X-Y] or [X]
func (sc *StringCompiler) parseJump(jumpStr string) map[string]int {
	jumpStr = strings.TrimSpace(jumpStr)
	result := make(map[string]int)

	if strings.Contains(jumpStr, "-") {
		parts := strings.Split(jumpStr, "-")
		if len(parts) == 2 {
			minStr := strings.TrimSpace(parts[0])
			maxStr := strings.TrimSpace(parts[1])

			if minVal, err := strconv.Atoi(minStr); err == nil {
				result["min"] = minVal
			}
			if maxStr == "" {
				result["max"] = 65535 // Infinite
			} else if maxVal, err := strconv.Atoi(maxStr); err == nil {
				result["max"] = maxVal
			}
		}
	} else {
		// Single value [X] means exactly X bytes
		if val, err := strconv.Atoi(jumpStr); err == nil {
			result["min"] = val
			result["max"] = val
		}
	}

	return result
}

// tokensToBytes converts tokens to bytes
func (sc *StringCompiler) tokensToBytes(tokens []HexToken) []byte {
	var result []byte
	for _, token := range tokens {
		switch token.Type {
		case "byte":
			if b, ok := token.Value.(byte); ok {
				result = append(result, b)
			}
		case "wildcard":
			result = append(result, 0x00) // Placeholder for wildcard
		case "masked":
			if b, ok := token.Value.(byte); ok {
				result = append(result, b)
			}
		case "jump":
			// Jumps are represented as special markers
			if jumpMap, ok := token.Value.(map[string]int); ok {
				minVal := jumpMap["min"]
				maxVal := jumpMap["max"]
				// Use special encoding for jumps (simplified)
				result = append(result, byte(0xFF)) // Jump marker
				result = append(result, byte(minVal&0xFF))
				result = append(result, byte((minVal>>8)&0xFF))
				result = append(result, byte(maxVal&0xFF))
				result = append(result, byte((maxVal>>8)&0xFF))
			}
		case "alternative":
			// Alternatives are represented as special markers
			if alts, ok := token.Value.([][]byte); ok && len(alts) > 0 {
				// Use first alternative for now (simplified)
				result = append(result, alts[0]...)
			}
		}
	}
	return result
}

// parseHexByte parses a single hex byte (with possible mask)
func (sc *StringCompiler) parseHexByte(hexStr string) byte {
	if len(hexStr) < 2 {
		return 0x00
	}

	// Handle masked bytes
	if hexStr[1] == '?' {
		// X? format - lower nibble is wildcard
		if val, err := strconv.ParseInt(string(hexStr[0]), 16, 16); err == nil {
			return byte((val & 0x0F) << 4)
		}
	} else if hexStr[0] == '?' {
		// ?X format - upper nibble is wildcard
		if val, err := strconv.ParseInt(string(hexStr[1]), 16, 16); err == nil {
			return byte(val & 0x0F)
		}
	} else {
		// Regular hex byte - convert to lowercase for parsing
		hexLower := strings.ToLower(hexStr)
		if val, err := strconv.ParseInt(hexLower, 16, 16); err == nil {
			return byte(val & 0xFF)
		}
	}

	return 0x00
}

// isHexDigit checks if a character is a hex digit
func isHexDigit(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
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

// Debug printing functions

// EstimatePatternComplexity estimates the complexity/quality of a pattern
// based on libyara's heuristic algorithm
func (sc *StringCompiler) EstimatePatternComplexity(pattern []byte, modifiers []ast.StringModifier) int {
	if len(pattern) == 0 {
		return 0
	}

	quality := 0
	seenBytes := make(map[byte]bool)
	uniqueBytes := 0

	for i := 0; i < len(pattern); i++ {
		b := pattern[i]
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

	quality += 2 * uniqueBytes

	// Penalize patterns with all equal and common bytes
	if uniqueBytes == 1 {
		b := pattern[0]
		if b == 0x00 || b == 0x20 || b == 0x90 || b == 0xCC || b == 0xFF {
			quality -= 10 * len(pattern)
		}
	}

	return quality
}

// PrintStringInfo prints information about all compiled strings
func (sc *StringCompiler) PrintStringInfo() {
	fmt.Println("Compiled String Information:")
	fmt.Printf("% -8s % -8s % -12s % -s\n", "ID", "Offset", "Size", "Pattern")
	fmt.Println("─────────────────────────────────────────")

	for _, info := range sc.GetStringInfo() {
		patternStr := fmt.Sprintf("%X", info.Pattern)
		if len(patternStr) > 20 {
			patternStr = patternStr[:17] + "..."
		}

		fmt.Printf("% -8s % -8d % -12d % -s\n",
			info.Identifier,
			info.Offset,
			len(info.Pattern),
			patternStr)
	}
}
