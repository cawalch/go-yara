package compiler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"unicode/utf16"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

// Optimized lookup table for ASCII case conversion
var (
	// Convert uppercase ASCII to lowercase in one operation
	toLowerTable = [256]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
		0x40, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
		'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
		0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
		0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
		0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
		0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
		0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
	}

	// Pre-computed table for checking if a character needs case conversion
	needsConversionTable = [256]bool{
		'A': true, 'B': true, 'C': true, 'D': true, 'E': true, 'F': true, 'G': true, 'H': true, 'I': true, 'J': true,
		'K': true, 'L': true, 'M': true, 'N': true, 'O': true, 'P': true, 'Q': true, 'R': true, 'S': true, 'T': true,
		'U': true, 'V': true, 'W': true, 'X': true, 'Y': true, 'Z': true,
	}
)

// Fast check for case conversion need - optimized for different string sizes
func fastNeedsConversion(data []byte) bool {
	switch len(data) {
	case 0:
		return false
	case 1:
		return needsConversionTable[data[0]]
	case 2:
		return needsConversionTable[data[0]] || needsConversionTable[data[1]]
	case 3:
		return needsConversionTable[data[0]] || needsConversionTable[data[1]] || needsConversionTable[data[2]]
	case 4:
		return needsConversionTable[data[0]] || needsConversionTable[data[1]] ||
			needsConversionTable[data[2]] || needsConversionTable[data[3]]
	default:
		// For larger strings, use unrolled loop for better performance
		dataLen := len(data)
		i := 0

		// Process 4 bytes at a time when possible
		for i+3 < dataLen {
			if needsConversionTable[data[i]] || needsConversionTable[data[i+1]] ||
				needsConversionTable[data[i+2]] || needsConversionTable[data[i+3]] {
				return true
			}
			i += 4
		}

		// Handle remaining bytes
		for i < dataLen {
			if needsConversionTable[data[i]] {
				return true
			}
			i++
		}
		return false
	}
}

// StringCompiler handles compilation of string patterns to bytecode
type stringCompiler struct {
	// Maps for string identifiers to automaton indices
	stringOffsets map[string]int
}

// NewStringCompiler creates a string compiler.
func newStringCompiler() *stringCompiler {
	return &stringCompiler{
		stringOffsets: make(map[string]int),
	}
}

// Reset clears per-rule compiler state so offsets and patterns don't leak between rules.
func (sc *stringCompiler) Reset() {
	sc.stringOffsets = make(map[string]int)
}

// hasModifier checks if a specific modifier type exists in the modifier list
func (sc *stringCompiler) hasModifier(modifiers []ast.StringModifier, modType ast.StringModifierType) bool {
	for _, mod := range modifiers {
		if mod.Type == modType {
			return true
		}
	}
	return false
}

// encodeTextBytes converts text to bytes with appropriate encoding
func (sc *stringCompiler) encodeTextBytes(text string, isWide bool) []byte {
	if isWide {
		// Optimized UTF-16LE encoding without intermediate []rune allocation
		runes := []rune(text)                // This allocation is unavoidable for proper Unicode handling
		result := make([]byte, len(runes)*2) // Pre-allocate exact size

		// Convert runes to UTF-16LE bytes in single pass
		for i, r := range runes {
			v := uint16(r) //checkednarrow:ignore existing wide-string encoding keeps the low UTF-16 code unit
			result[i*2] = byte(v & 0xff)
			result[i*2+1] = byte(v >> 8)
		}
		return result
	}

	// ASCII/UTF-8 encoding - optimize for common case
	result := make([]byte, len(text))
	copy(result, text)
	return result
}

// applyXorModifier applies XOR transformation to data
func (sc *stringCompiler) applyXorModifier(data []byte, modifiers []ast.StringModifier) []byte {
	key, ok := sc.singleXorKey(modifiers)
	if !ok {
		return data
	}
	for i := range data {
		data[i] ^= key
	}
	return data
}

// encodeToWideBytes converts a string to UTF-16LE encoded bytes
func (sc *stringCompiler) encodeToWideBytes(text string) []byte {
	utf16Data := utf16.Encode([]rune(text))
	result := make([]byte, len(utf16Data)*2)
	for i, v := range utf16Data {
		result[i*2] = byte(v & 0xff)
		result[i*2+1] = byte(v >> 8)
	}
	return result
}

// TextPattern holds encoded text pattern data with associated matching flags.
type TextPattern struct {
	Data  []byte
	Flags regex.Flags
}

// EncodeTextPatterns encodes text into one or more patterns based on modifiers.
func (sc *stringCompiler) EncodeTextPatterns(text string, modifiers []ast.StringModifier) ([]TextPattern, error) {
	hasWide := sc.hasModifier(modifiers, ast.StringModifierWide)
	hasASCII := sc.hasModifier(modifiers, ast.StringModifierASCII)
	isNocase := sc.hasModifier(modifiers, ast.StringModifierNocase)

	// nocaseFlag propagates FlagsNoCase into each TextPattern so downstream
	// stages (the Aho-Corasick automaton) know to match case-insensitively.
	// The pattern bytes are also lowercased below; both are required.
	nocaseFlag := regex.Flags(0)
	if isNocase {
		nocaseFlag = regex.FlagsNoCase
	}

	basePatterns := make([]TextPattern, 0, 2)

	switch {
	case hasWide && hasASCII:
		ascii := sc.encodeTextBytes(text, false)
		wide := sc.encodeTextBytes(text, true)
		if isNocase {
			ascii = sc.applyNocaseModifier(ascii, false)
			wide = sc.applyNocaseModifier(wide, true)
		}
		basePatterns = append(basePatterns,
			TextPattern{Data: ascii, Flags: nocaseFlag},
			TextPattern{Data: wide, Flags: regex.FlagsWide | nocaseFlag},
		)
	case hasWide:
		wide := sc.encodeTextBytes(text, true)
		if isNocase {
			wide = sc.applyNocaseModifier(wide, true)
		}
		basePatterns = append(basePatterns, TextPattern{Data: wide, Flags: regex.FlagsWide | nocaseFlag})
	default:
		ascii := sc.encodeTextBytes(text, false)
		if isNocase {
			ascii = sc.applyNocaseModifier(ascii, false)
		}
		basePatterns = append(basePatterns, TextPattern{Data: ascii, Flags: nocaseFlag})
	}

	patterns := basePatterns

	if keys, hasXor := sc.xorKeys(modifiers); hasXor {
		patterns = sc.applyXorKeysWithFlags(patterns, keys)
	}

	if mod, ok := sc.base64Modifier(modifiers); ok {
		alphabet, err := sc.base64Alphabet(mod)
		if err != nil {
			return nil, err
		}
		patterns = sc.applyBase64AlignmentWithFlags(patterns, alphabet, mod.Type == ast.StringModifierBase64Wide)
	}

	return sc.uniqueTextPatterns(patterns), nil
}

type xorRange struct {
	min int
	max int
}

func (sc *stringCompiler) xorKeys(modifiers []ast.StringModifier) ([]byte, bool) {
	for _, mod := range modifiers {
		if mod.Type != ast.StringModifierXor {
			continue
		}
		ranges := sc.normalizeXorModifier(mod.Value)
		if len(ranges) == 0 {
			return nil, false
		}
		keys := make([]byte, 0, 256)
		seen := make(map[byte]struct{})
		for _, r := range ranges {
			for k := r.min; k <= r.max; k++ {
				if k < 0 || k > 0xff {
					continue
				}
				b := byte(k)
				if _, ok := seen[b]; ok {
					continue
				}
				seen[b] = struct{}{}
				keys = append(keys, b)
			}
		}
		return keys, true
	}
	return nil, false
}

func (sc *stringCompiler) singleXorKey(modifiers []ast.StringModifier) (byte, bool) {
	keys, ok := sc.xorKeys(modifiers)
	if !ok || len(keys) != 1 {
		return 0, false
	}
	return keys[0], true
}

func (sc *stringCompiler) normalizeXorModifier(value any) []xorRange {
	if value == nil {
		return []xorRange{{min: 0, max: 255}}
	}
	switch v := value.(type) {
	case ast.XorRange:
		return []xorRange{sc.normalizeXorRange(int(v.Min), int(v.Max))}
	case *ast.XorRange:
		if v == nil {
			return []xorRange{{min: 0, max: 255}}
		}
		return []xorRange{sc.normalizeXorRange(int(v.Min), int(v.Max))}
	case int64:
		return []xorRange{sc.normalizeXorRange(int(v), int(v))}
	case int:
		return []xorRange{sc.normalizeXorRange(v, v)}
	default:
		return []xorRange{{min: 0, max: 255}}
	}
}

func (sc *stringCompiler) normalizeXorRange(min, max int) xorRange {
	if min < 0 {
		min = 0
	}
	if max < 0 {
		max = 0
	}
	if min > 255 {
		min = 255
	}
	if max > 255 {
		max = 255
	}
	if max < min {
		min, max = max, min
	}
	return xorRange{min: min, max: max}
}

func (sc *stringCompiler) applyXorKeysWithFlags(patterns []TextPattern, keys []byte) []TextPattern {
	if len(keys) == 0 {
		return patterns
	}
	out := make([]TextPattern, 0, len(patterns)*len(keys))
	for _, p := range patterns {
		for _, key := range keys {
			dup := make([]byte, len(p.Data))
			copy(dup, p.Data)
			for i := range dup {
				dup[i] ^= key
			}
			out = append(out, TextPattern{Data: dup, Flags: p.Flags})
		}
	}
	return out
}

func (sc *stringCompiler) base64Modifier(modifiers []ast.StringModifier) (ast.StringModifier, bool) {
	for _, mod := range modifiers {
		if mod.Type == ast.StringModifierBase64 || mod.Type == ast.StringModifierBase64Wide {
			return mod, true
		}
	}
	return ast.StringModifier{}, false
}

func (sc *stringCompiler) base64Alphabet(mod ast.StringModifier) (string, error) {
	if alphabet, ok := mod.Value.(string); ok && alphabet != "" {
		if len(alphabet) != 64 {
			return "", fmt.Errorf("invalid base64 alphabet length: expected 64, got %d", len(alphabet))
		}
		return alphabet, nil
	}
	return "", nil
}

func (sc *stringCompiler) applyBase64AlignmentWithFlags(patterns []TextPattern, alphabet string, wide bool) []TextPattern {
	out := make([]TextPattern, 0, len(patterns)*3)
	for _, p := range patterns {
		variants, err := sc.base64AlignedPatterns(p.Data, alphabet, wide)
		if err != nil {
			continue
		}
		flags := p.Flags
		if wide {
			flags |= regex.FlagsWide
		} else {
			flags &^= regex.FlagsWide
		}
		for _, v := range variants {
			out = append(out, TextPattern{Data: v, Flags: flags})
		}
	}
	return out
}

func (sc *stringCompiler) base64AlignedPatterns(data []byte, alphabet string, wide bool) ([][]byte, error) {
	enc := base64.StdEncoding
	if alphabet != "" {
		enc = base64.NewEncoding(alphabet)
	}

	var patterns [][]byte
	for i := 0; i <= 2; i++ {
		if i == 1 && len(data) == 1 {
			continue
		}
		pad := 0
		if (i+len(data))%3 != 0 {
			pad = 3 - ((i + len(data)) % 3)
		}

		tmp := make([]byte, i+len(data))
		for j := 0; j < i; j++ {
			tmp[j] = 'A'
		}
		copy(tmp[i:], data)

		encoded := enc.EncodeToString(tmp)
		leading := 0
		if i > 0 {
			leading = i + 1
		}
		trailing := 0
		if pad > 0 {
			trailing = pad + 1
		}
		if leading+trailing > len(encoded) {
			continue
		}
		trimmed := encoded[leading : len(encoded)-trailing]
		if wide {
			patterns = append(patterns, sc.encodeToWideBytes(trimmed))
		} else {
			patterns = append(patterns, []byte(trimmed))
		}
	}

	return patterns, nil
}

func (sc *stringCompiler) uniqueTextPatterns(patterns []TextPattern) []TextPattern {
	if len(patterns) <= 1 {
		return patterns
	}
	seen := make(map[string]struct{}, len(patterns))
	out := make([]TextPattern, 0, len(patterns))
	for _, p := range patterns {
		key := string(p.Data) + "|" + strconv.FormatUint(uint64(p.Flags), 10)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}

func (sc *stringCompiler) compileRegexWithAST(pattern string, _ []ast.StringModifier) ([]byte, *regex.AST, error) {
	// Remove delimiters and any inline flags; runtime flags (i/s) are propagated separately
	cleaned := cleanRegexPattern(pattern)

	p := regex.NewParser(0)
	astRe, err := p.Parse(cleaned)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing regex pattern: %w", err)
	}
	code, err := regex.Compile(astRe)
	if err != nil {
		return nil, nil, fmt.Errorf("compiling regex: %w", err)
	}
	return code, astRe, nil
}

// applyNocaseToWide converts wide UTF-16 strings to lowercase
func (sc *stringCompiler) applyNocaseToWide(data []byte) []byte {
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
}

// applyNocaseToLargeString handles case conversion for strings of any size
func (sc *stringCompiler) applyNocaseToLargeString(data []byte) []byte {
	// Fast check for case conversion need using lookup table
	if !fastNeedsConversion(data) {
		return data
	}

	// Optimized single-pass case conversion with pre-allocated capacity
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = toLowerTable[b] // Use lookup table directly
	}
	return result
}

// applyNocaseModifier applies case-insensitive transformation to string data
func (sc *stringCompiler) applyNocaseModifier(data []byte, isWide bool) []byte {
	if isWide {
		return sc.applyNocaseToWide(data)
	}
	return sc.applyNocaseToLargeString(data)
}

// GetStringOffsets returns an owned snapshot of compiled string offsets.
func (sc *stringCompiler) GetStringOffsets() map[string]int {
	return maps.Clone(sc.stringOffsets)
}

// ValidateStringModifiers validates that string modifiers are compatible
func (sc *stringCompiler) ValidateStringModifiers(modifiers []ast.StringModifier) error {
	hasWide := false
	hasASCII := false
	hasBase64 := false
	hasBase64Wide := false
	hasXor := false
	hasNocase := false
	hasFullword := false

	for _, mod := range modifiers {
		switch mod.Type {
		case ast.StringModifierWide:
			hasWide = true
		case ast.StringModifierASCII:
			hasASCII = true
		case ast.StringModifierBase64:
			hasBase64 = true
			if err := validateBase64Alphabet(mod.Value); err != nil {
				return err
			}
		case ast.StringModifierBase64Wide:
			hasBase64Wide = true
			if err := validateBase64Alphabet(mod.Value); err != nil {
				return err
			}
		case ast.StringModifierXor:
			hasXor = true
			if err := validateXorModifier(mod.Value); err != nil {
				return err
			}
		case ast.StringModifierNocase:
			hasNocase = true
		case ast.StringModifierFullword:
			hasFullword = true
		}
	}

	// Check for incompatible modifiers
	if hasBase64 && hasBase64Wide {
		return errors.New("cannot use both 'base64' and 'base64wide' modifiers")
	}

	if (hasBase64 || hasBase64Wide) && (hasXor || hasNocase || hasFullword) {
		return errors.New("base64 modifiers are incompatible with 'xor', 'nocase', or 'fullword'")
	}

	if (hasBase64 || hasBase64Wide) && (hasWide || hasASCII) {
		return errors.New("base64 modifiers are incompatible with 'wide' or 'ascii'")
	}

	return nil
}

func validateBase64Alphabet(value any) error {
	alphabet, ok := value.(string)
	if !ok || alphabet == "" {
		return nil
	}
	if len(alphabet) != 64 {
		return fmt.Errorf("invalid base64 alphabet length: expected 64, got %d", len(alphabet))
	}
	seen := make(map[byte]struct{}, 64)
	for i := 0; i < len(alphabet); i++ {
		ch := alphabet[i]
		if ch == '=' {
			return errors.New("invalid base64 alphabet: '=' is not allowed")
		}
		if _, exists := seen[ch]; exists {
			return errors.New("invalid base64 alphabet: duplicate characters")
		}
		seen[ch] = struct{}{}
	}
	return nil
}

func validateXorModifier(value any) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case ast.XorRange:
		return validateXorRange(v.Min, v.Max)
	case *ast.XorRange:
		if v == nil {
			return nil
		}
		return validateXorRange(v.Min, v.Max)
	case int64:
		return validateXorRange(v, v)
	case int:
		return validateXorRange(int64(v), int64(v))
	default:
		return nil
	}
}

func validateXorRange(min, max int64) error {
	if min < 0 || max < 0 || min > 255 || max > 255 {
		return errors.New("xor range must be within 0..255")
	}
	if max < min {
		return errors.New("xor range max must be >= min")
	}
	return nil
}

// OptimizePattern returns an owned copy of an exact text pattern. Repeated
// bytes and UTF-16 NUL code units are significant input, not redundant
// representation, so an optimization must never remove them.
func (sc *stringCompiler) OptimizePattern(pattern []byte, _ []ast.StringModifier) []byte {
	return slices.Clone(pattern)
}
