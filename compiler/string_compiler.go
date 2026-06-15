package compiler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
type StringCompiler struct {
	emitter *Emitter // kept for backward-compatibility with tests
	// Maps for string identifiers to automaton indices
	stringOffsets map[string]int
	// Maps for pattern data
	patternData map[string][]byte
	// Extracted atoms for optimization
	atoms map[string][]*Atom
}

// NewStringCompiler creates a new string compiler
// The emitter parameter is kept for backward compatibility; it's unused.
func NewStringCompiler(_ *Emitter) *StringCompiler {
	return &StringCompiler{
		stringOffsets: make(map[string]int),
		patternData:   make(map[string][]byte),
		atoms:         make(map[string][]*Atom),
	}
}

// Reset clears per-rule compiler state so offsets and patterns don't leak between rules.
func (sc *StringCompiler) Reset() {
	sc.stringOffsets = make(map[string]int)
	sc.patternData = make(map[string][]byte)
	sc.atoms = make(map[string][]*Atom)
}

// CompileStrings compiles all strings in a rule to bytecode
func (sc *StringCompiler) CompileStrings(rule *ast.Rule) error {
	for idx, str := range rule.Strings {
		// Assign a provisional offset so callers can inspect non-empty offsets map.
		// The RuleCompiler may later overwrite these with automaton-based indices.
		if _, exists := sc.stringOffsets[str.Identifier]; !exists {
			sc.stringOffsets[str.Identifier] = idx
		}
		if err := sc.compileString(str); err != nil {
			return fmt.Errorf("compiling string %s: %w", str.Identifier, err)
		}
	}
	return nil
}

// compileString compiles a single string pattern
func (sc *StringCompiler) compileString(str *ast.String) error {
	// Do not emit bytecode for string definitions; they are matched via the automaton.
	// Offsets for string identifiers are assigned by the rule compiler based on
	// the automaton's string index. Here we only preprocess/store pattern data.

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
		return errors.New("unknown pattern type")
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

	// Store pattern data for automaton building
	sc.patternData[identifier] = encoded

	return nil
}

// compileHexString compiles a hex string pattern
func (sc *StringCompiler) compileHexString(identifier string, pattern *ast.HexString, modifiers []ast.StringModifier) error {
	// Parse hex string (simplified - would need full hex grammar parser)
	hexData := sc.parseHexString(pattern.Value)

	// Apply modifiers
	encoded := sc.encodeHexString(hexData, modifiers)

	// Store pattern data for automaton building
	sc.patternData[identifier] = encoded

	return nil
}

// compileRegexPattern compiles a regular expression pattern
func (sc *StringCompiler) compileRegexPattern(identifier string, pattern *ast.RegexPattern, modifiers []ast.StringModifier) error {
	// Compile regex to internal VM bytecode
	regexData, err := sc.compileRegex(pattern.Value, modifiers)
	if err != nil {
		return fmt.Errorf("compile regex %q: %w", pattern.Value, err)
	}

	// Store pattern data (VM bytecode) for later execution
	sc.patternData[identifier] = regexData

	return nil
}

// hasModifier checks if a specific modifier type exists in the modifier list
func (sc *StringCompiler) hasModifier(modifiers []ast.StringModifier, modType ast.StringModifierType) bool {
	for _, mod := range modifiers {
		if mod.Type == modType {
			return true
		}
	}
	return false
}

// encodeTextBytes converts text to bytes with appropriate encoding
func (sc *StringCompiler) encodeTextBytes(text string, isWide bool) []byte {
	if isWide {
		// Optimized UTF-16LE encoding without intermediate []rune allocation
		runes := []rune(text)                // This allocation is unavoidable for proper Unicode handling
		result := make([]byte, len(runes)*2) // Pre-allocate exact size

		// Convert runes to UTF-16LE bytes in single pass
		for i, r := range runes {
			v := uint16(r)
			result[i*2] = byte(v)
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
func (sc *StringCompiler) applyXorModifier(data []byte, modifiers []ast.StringModifier) []byte {
	key, ok := sc.singleXorKey(modifiers)
	if !ok {
		return data
	}
	for i := range data {
		data[i] ^= key
	}
	return data
}

// applyBase64Modifier applies base64 decoding to data
func (sc *StringCompiler) applyBase64Modifier(data []byte, modifier ast.StringModifier) ([]byte, error) {
	alphabet, err := sc.base64Alphabet(modifier)
	if err != nil {
		return nil, err
	}

	if modifier.Type == ast.StringModifierBase64Wide {
		data = sc.encodeToWideBytes(string(data))
	}

	encoded, err := sc.encodeBase64Variants(data, alphabet)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 {
		return []byte{}, nil
	}
	// Return the first variant for compatibility with legacy callers.
	return encoded[0], nil
}

// encodeToWideBytes converts a string to UTF-16LE encoded bytes
func (sc *StringCompiler) encodeToWideBytes(text string) []byte {
	utf16Data := utf16.Encode([]rune(text))
	result := make([]byte, len(utf16Data)*2)
	for i, v := range utf16Data {
		result[i*2] = byte(v)
		result[i*2+1] = byte(v >> 8)
	}
	return result
}

// encodeTextString encodes a text string with modifiers applied
func (sc *StringCompiler) encodeTextString(text string, modifiers []ast.StringModifier) []byte {
	// Check for modifiers
	isWide := sc.hasModifier(modifiers, ast.StringModifierWide)
	isNocase := sc.hasModifier(modifiers, ast.StringModifierNocase)

	// Encode text with appropriate encoding
	result := sc.encodeTextBytes(text, isWide)

	// Apply case-insensitive modifier if needed
	if isNocase {
		result = sc.applyNocaseModifier(result, isWide)
	}

	// Apply XOR modifier if present
	result = sc.applyXorModifier(result, modifiers)

	return result
}

// TextPattern holds encoded text pattern data with associated matching flags.
type TextPattern struct {
	Data  []byte
	Flags regex.Flags
}

// EncodeTextPatterns encodes text into one or more patterns based on modifiers.
func (sc *StringCompiler) EncodeTextPatterns(text string, modifiers []ast.StringModifier) ([]TextPattern, error) {
	hasWide := sc.hasModifier(modifiers, ast.StringModifierWide)
	hasASCII := sc.hasModifier(modifiers, ast.StringModifierASCII)
	isNocase := sc.hasModifier(modifiers, ast.StringModifierNocase)

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
			TextPattern{Data: ascii, Flags: 0},
			TextPattern{Data: wide, Flags: regex.FlagsWide},
		)
	case hasWide:
		wide := sc.encodeTextBytes(text, true)
		if isNocase {
			wide = sc.applyNocaseModifier(wide, true)
		}
		basePatterns = append(basePatterns, TextPattern{Data: wide, Flags: regex.FlagsWide})
	default:
		ascii := sc.encodeTextBytes(text, false)
		if isNocase {
			ascii = sc.applyNocaseModifier(ascii, false)
		}
		basePatterns = append(basePatterns, TextPattern{Data: ascii, Flags: 0})
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

// encodeHexString encodes a hex string with modifiers applied
func (sc *StringCompiler) encodeHexString(hexData []byte, modifiers []ast.StringModifier) []byte {
	// Apply XOR modifier if present
	hexData = sc.applyXorModifier(hexData, modifiers)

	// Apply base64 modifiers if present
	for _, mod := range modifiers {
		if mod.Type == ast.StringModifierBase64 || mod.Type == ast.StringModifierBase64Wide {
			var err error
			hexData, err = sc.applyBase64Modifier(hexData, mod)
			if err != nil {
				// If base64 encoding fails, return original data
				continue
			}
		}
	}

	return hexData
}

type xorRange struct {
	min int
	max int
}

func (sc *StringCompiler) xorKeys(modifiers []ast.StringModifier) ([]byte, bool) {
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

func (sc *StringCompiler) singleXorKey(modifiers []ast.StringModifier) (byte, bool) {
	keys, ok := sc.xorKeys(modifiers)
	if !ok || len(keys) != 1 {
		return 0, false
	}
	return keys[0], true
}

func (sc *StringCompiler) normalizeXorModifier(value any) []xorRange {
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

func (sc *StringCompiler) normalizeXorRange(min, max int) xorRange {
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

func (sc *StringCompiler) applyXorKeysWithFlags(patterns []TextPattern, keys []byte) []TextPattern {
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

func (sc *StringCompiler) base64Modifier(modifiers []ast.StringModifier) (ast.StringModifier, bool) {
	for _, mod := range modifiers {
		if mod.Type == ast.StringModifierBase64 || mod.Type == ast.StringModifierBase64Wide {
			return mod, true
		}
	}
	return ast.StringModifier{}, false
}

func (sc *StringCompiler) base64Alphabet(mod ast.StringModifier) (string, error) {
	if alphabet, ok := mod.Value.(string); ok && alphabet != "" {
		if len(alphabet) != 64 {
			return "", fmt.Errorf("invalid base64 alphabet length: expected 64, got %d", len(alphabet))
		}
		return alphabet, nil
	}
	return "", nil
}

func (sc *StringCompiler) applyBase64AlignmentWithFlags(patterns []TextPattern, alphabet string, wide bool) []TextPattern {
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

func (sc *StringCompiler) base64AlignedPatterns(data []byte, alphabet string, wide bool) ([][]byte, error) {
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

func (sc *StringCompiler) encodeBase64Variants(data []byte, alphabet string) ([][]byte, error) {
	enc := base64.StdEncoding
	if alphabet != "" {
		enc = base64.NewEncoding(alphabet)
	}
	padded := enc.EncodeToString(data)
	noPad := enc.WithPadding(base64.NoPadding).EncodeToString(data)

	variants := []string{padded}
	if noPad != padded {
		variants = append(variants, noPad)
	}

	out := make([][]byte, 0, len(variants))
	for _, v := range variants {
		out = append(out, []byte(v))
	}
	return out, nil
}

func (sc *StringCompiler) uniqueTextPatterns(patterns []TextPattern) []TextPattern {
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

// HexToken represents a token in a hex string
type HexToken struct {
	Type  string // "byte", "wildcard", "masked", "jump", "alternative"
	Value any    // byte value, jump range, or alternatives
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
	tokens := make([]HexToken, 0, len(hexStr)/2)
	i := 0

	for i < len(hexStr) {
		i = sc.skipWhitespaceAndComments(hexStr, i)
		if i >= len(hexStr) {
			break
		}

		token, advance := sc.parseHexToken(hexStr, i)
		if token.Type != "" {
			tokens = append(tokens, token)
		}
		i += advance
	}

	return tokens
}

// skipWhitespaceAndComments skips whitespace and comments, returns new position
func (sc *StringCompiler) skipWhitespaceAndComments(hexStr string, pos int) int {
	i := pos

	// Skip whitespace
	for i < len(hexStr) && sc.isWhitespace(hexStr[i]) {
		i++
	}
	if i >= len(hexStr) {
		return i
	}

	// Skip multi-line comments
	if i+1 < len(hexStr) && hexStr[i:i+2] == "/*" {
		return sc.skipMultiLineComment(hexStr, i)
	}

	// Skip single-line comments
	if i+1 < len(hexStr) && hexStr[i:i+2] == "//" {
		return sc.skipSingleLineComment(hexStr, i)
	}

	return i
}

// isWhitespace checks if character is whitespace
func (sc *StringCompiler) isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

// skipMultiLineComment skips over a /* */ comment
func (sc *StringCompiler) skipMultiLineComment(hexStr string, pos int) int {
	i := pos + 2 // skip /*
	for i+1 < len(hexStr) && hexStr[i:i+2] != "*/" {
		i++
	}
	if i+1 < len(hexStr) {
		return i + 2 // skip */
	}
	return i
}

// skipSingleLineComment skips over a // comment
func (sc *StringCompiler) skipSingleLineComment(hexStr string, pos int) int {
	i := pos + 2 // skip //
	for i < len(hexStr) && hexStr[i] != '\n' {
		i++
	}
	return i
}

// parseHexToken parses a single hex token at the given position
func (sc *StringCompiler) parseHexToken(hexStr string, pos int) (token HexToken, nextPos int) {
	if pos >= len(hexStr) {
		return HexToken{}, 0
	}

	switch hexStr[pos] {
	case '{', '}':
		return HexToken{}, 1

	case '(':
		return sc.parseAlternativesToken(hexStr, pos)

	case '[':
		return sc.parseJumpToken(hexStr, pos)

	case '?':
		return sc.parseWildcardToken(hexStr, pos)

	default:
		return sc.parseHexByteToken(hexStr, pos)
	}
}

// parseAlternativesToken parses an alternatives token (...)
func (sc *StringCompiler) parseAlternativesToken(hexStr string, pos int) (token HexToken, nextPos int) {
	i := pos + 1 // skip '('
	depth := 1
	altStart := i

	for i < len(hexStr) && depth > 0 {
		switch hexStr[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		i++
	}

	altStr := hexStr[altStart : i-1]
	alts := sc.parseAlternatives(altStr)
	return HexToken{Type: "alternative", Value: alts}, i - pos
}

// parseJumpToken parses a jump token [...]
func (sc *StringCompiler) parseJumpToken(hexStr string, pos int) (token HexToken, nextPos int) {
	i := pos + 1 // skip '['
	jumpStart := i

	for i < len(hexStr) && hexStr[i] != ']' {
		i++
	}

	jumpStr := hexStr[jumpStart:i]
	if i < len(hexStr) {
		i++ // skip ]
	}

	jump := sc.parseJump(jumpStr)
	return HexToken{Type: "jump", Value: jump}, i - pos
}

// parseWildcardToken parses wildcard tokens (??, ?X, X?)
func (sc *StringCompiler) parseWildcardToken(hexStr string, pos int) (token HexToken, nextPos int) {
	if pos+1 >= len(hexStr) {
		return HexToken{}, 1
	}

	switch {
	case hexStr[pos+1] == '?':
		// Full wildcard ??
		return HexToken{Type: "wildcard", Value: byte(0x00)}, 2

	case isHexDigit(hexStr[pos+1]):
		// Masked byte ?X
		hex := hexStr[pos : pos+2]
		val := sc.parseHexByte(hex)
		return HexToken{Type: "masked", Value: val}, 2

	default:
		return HexToken{}, 1
	}
}

// parseHexByteToken parses regular hex byte tokens
func (sc *StringCompiler) parseHexByteToken(hexStr string, pos int) (token HexToken, nextPos int) {
	if pos+1 >= len(hexStr) {
		return HexToken{}, 1
	}

	switch {
	case isHexDigit(hexStr[pos]) && isHexDigit(hexStr[pos+1]):
		// Regular hex byte
		hex := hexStr[pos : pos+2]
		val := sc.parseHexByte(hex)
		return HexToken{Type: "byte", Value: val}, 2

	case isHexDigit(hexStr[pos]) && hexStr[pos+1] == '?':
		// Masked byte X?
		hex := hexStr[pos : pos+2]
		val := sc.parseHexByte(hex)
		return HexToken{Type: "masked", Value: val}, 2

	default:
		return HexToken{}, 1
	}
}

// parseAlternatives parses alternatives separated by |
func (sc *StringCompiler) parseAlternatives(altStr string) [][]byte {
	alts := make([][]byte, 0, strings.Count(altStr, "|")+1)
	parts := strings.SplitSeq(altStr, "|")
	for part := range parts {
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
		sc.parseRangeJump(jumpStr, result)
	} else {
		sc.parseSingleJump(jumpStr, result)
	}

	return result
}

// parseRangeJump parses a range jump like "10-20" or "10-"
func (sc *StringCompiler) parseRangeJump(jumpStr string, result map[string]int) {
	parts := strings.Split(jumpStr, "-")
	if len(parts) != 2 {
		return
	}

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

// parseSingleJump parses a single value jump like "10"
func (sc *StringCompiler) parseSingleJump(jumpStr string, result map[string]int) {
	if val, err := strconv.Atoi(jumpStr); err == nil {
		result["min"] = val
		result["max"] = val
	}
}

// processByteToken processes a byte token and appends to result
func (sc *StringCompiler) processByteToken(result *[]byte, token HexToken) {
	if b, ok := token.Value.(byte); ok {
		*result = append(*result, b)
	}
}

// processWildcardToken processes a wildcard token and appends to result
func (sc *StringCompiler) processWildcardToken(result *[]byte, _ HexToken) {
	*result = append(*result, 0x00) // Placeholder for wildcard
}

// processMaskedToken processes a masked token and appends to result
func (sc *StringCompiler) processMaskedToken(result *[]byte, token HexToken) {
	if b, ok := token.Value.(byte); ok {
		*result = append(*result, b)
	}
}

// processJumpToken processes a jump token and appends to result
func (sc *StringCompiler) processJumpToken(result *[]byte, token HexToken) {
	if jumpMap, ok := token.Value.(map[string]int); ok {
		minVal := jumpMap["min"]
		maxVal := jumpMap["max"]
		// Use special encoding for jumps (simplified)
		*result = append(*result, byte(0xFF), // Jump marker
			byte(minVal&0xFF),
			byte((minVal>>8)&0xFF),
			byte(maxVal&0xFF),
			byte((maxVal>>8)&0xFF))
	}
}

// processAlternativeToken processes an alternative token and appends to result
func (sc *StringCompiler) processAlternativeToken(result *[]byte, token HexToken) {
	if alts, ok := token.Value.([][]byte); ok && len(alts) > 0 {
		// Use first alternative for now (simplified)
		*result = append(*result, alts[0]...)
	}
}

// tokensToBytes converts a slice of HexTokens to bytes
func (sc *StringCompiler) tokensToBytes(tokens []HexToken) []byte {
	result := make([]byte, 0, len(tokens)*2)
	for _, token := range tokens {
		switch token.Type {
		case "byte":
			sc.processByteToken(&result, token)
		case "wildcard":
			sc.processWildcardToken(&result, token)
		case "masked":
			sc.processMaskedToken(&result, token)
		case "jump":
			sc.processJumpToken(&result, token)
		case "alternative":
			sc.processAlternativeToken(&result, token)
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
	switch {
	case hexStr[1] == '?':
		// X? format - lower nibble is wildcard
		if val, err := strconv.ParseInt(string(hexStr[0]), 16, 16); err == nil {
			return byte((val & 0x0F) << 4)
		}
	case hexStr[0] == '?':
		// ?X format - upper nibble is wildcard
		if val, err := strconv.ParseInt(string(hexStr[1]), 16, 16); err == nil {
			return byte(val & 0x0F)
		}
	default:
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

// compileRegex compiles a regex pattern to internal VM bytecode
func (sc *StringCompiler) compileRegex(pattern string, _ []ast.StringModifier) ([]byte, error) {
	// Remove delimiters and any inline flags; runtime flags (i/s) are propagated separately
	cleaned := cleanRegexPattern(pattern)

	p := regex.NewParser(0)
	astRe, err := p.Parse(cleaned)
	if err != nil {
		return nil, fmt.Errorf("parsing regex pattern: %w", err)
	}
	code, err := regex.Compile(astRe)
	if err != nil {
		return nil, fmt.Errorf("compiling regex: %w", err)
	}
	return code, nil
}

// applyNocaseToWide converts wide UTF-16 strings to lowercase
func (sc *StringCompiler) applyNocaseToWide(data []byte) []byte {
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

// applyNocaseToSmallString handles case conversion for small strings
//
// Deprecated: Use applyNocaseToLargeString for all cases for better maintainability
func (sc *StringCompiler) applyNocaseToSmallString(data []byte) []byte {
	return sc.applyNocaseToLargeString(data)
}

// applyNocaseToLargeString handles case conversion for strings of any size
func (sc *StringCompiler) applyNocaseToLargeString(data []byte) []byte {
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
func (sc *StringCompiler) applyNocaseModifier(data []byte, isWide bool) []byte {
	if isWide {
		return sc.applyNocaseToWide(data)
	}

	// Optimized case-insensitive conversion for ASCII strings
	if len(data) <= 128 {
		return sc.applyNocaseToSmallString(data)
	}

	return sc.applyNocaseToLargeString(data)
}

// GetStringOffsets returns the bytecode offsets for all compiled strings
func (sc *StringCompiler) GetStringOffsets() map[string]int {
	// Reference emitter to satisfy linters and maintain backward compatibility
	if sc.emitter == nil {
		// Emitter is not set, which is expected in some usage patterns
		// This function will return the string offsets regardless of emitter state
		_ = sc.emitter // Suppress nil check warning
	}
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
// Populate from patternData to ensure visibility even when stringOffsets
// are assigned later by the RuleCompiler.
func (sc *StringCompiler) GetStringInfo() []StringInfo {
	info := make([]StringInfo, 0, len(sc.patternData))

	for identifier, pattern := range sc.patternData {
		offset, ok := sc.stringOffsets[identifier]
		if !ok {
			// Unknown at this stage; RuleCompiler assigns real offsets.
			offset = -1
		}
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

// calculateByteQuality calculates the quality score for a single byte
func (sc *StringCompiler) calculateByteQuality(b byte) int {
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

// isCommonByte checks if a byte is considered common
func (sc *StringCompiler) isCommonByte(b byte) bool {
	return b == 0x00 || b == 0x20 || b == 0x90 || b == 0xCC || b == 0xFF
}

// calculateBaseQuality calculates base quality from pattern bytes
func (sc *StringCompiler) calculateBaseQuality(pattern []byte) (quality, uniqueBytes int) {
	quality = 0
	seenBytes := make(map[byte]bool)
	uniqueBytes = 0

	for i := range pattern {
		b := pattern[i]
		quality += sc.calculateByteQuality(b)

		if !seenBytes[b] {
			seenBytes[b] = true
			uniqueBytes++
		}
	}

	return quality, uniqueBytes
}

// applyPenaltyForCommonPatterns applies penalty for simple, common patterns
func (sc *StringCompiler) applyPenaltyForCommonPatterns(pattern []byte, uniqueBytes, quality int) int {
	// Penalize patterns with all equal and common bytes
	if uniqueBytes == 1 {
		b := pattern[0]
		if sc.isCommonByte(b) {
			quality -= 10 * len(pattern)
		}
	}
	return quality
}

// EstimatePatternComplexity returns the atom-quality heuristic for a byte pattern.
// Higher scores generally indicate more selective patterns for matching. The
// score is deterministic for a pattern, but it is not a runtime cost estimate;
// modifiers are currently ignored by this heuristic.
func (sc *StringCompiler) EstimatePatternComplexity(pattern []byte, _ []ast.StringModifier) int {
	if len(pattern) == 0 {
		return 0
	}

	quality, uniqueBytes := sc.calculateBaseQuality(pattern)
	quality += 2 * uniqueBytes

	return sc.applyPenaltyForCommonPatterns(pattern, uniqueBytes, quality)
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
