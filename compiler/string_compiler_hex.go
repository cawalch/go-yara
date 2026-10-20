package compiler

import (
	"strconv"
	"strings"
)

// hexToken represents a token in a hex string
type hexToken struct {
	Type  string // "byte", "wildcard", "masked", "jump", "alternative"
	Value any    // byte value, jump range, or alternatives
}

// parseHexString parses a hex string pattern with full YARA hex grammar support
func (sc *stringCompiler) parseHexString(hexStr string) []byte {
	// Tokenize the hex string
	tokens := sc.tokenizeHexString(hexStr)
	if len(tokens) == 0 {
		return []byte{}
	}

	// Convert tokens to bytes
	return sc.tokensToBytes(tokens)
}

// tokenizeHexString tokenizes a hex string into tokens
func (sc *stringCompiler) tokenizeHexString(hexStr string) []hexToken {
	tokens := make([]hexToken, 0, len(hexStr)/2)
	i := 0

	for i < len(hexStr) {
		i = sc.skipWhitespaceAndComments(hexStr, i)
		if i >= len(hexStr) {
			break
		}

		token, advance := sc.parsehexToken(hexStr, i)
		if token.Type != "" {
			tokens = append(tokens, token)
		}
		i += advance
	}

	return tokens
}

// skipWhitespaceAndComments skips whitespace and comments, returns new position
func (sc *stringCompiler) skipWhitespaceAndComments(hexStr string, pos int) int {
	i := pos
	for i < len(hexStr) && sc.isWhitespace(hexStr[i]) {
		i++
	}
	if i >= len(hexStr) {
		return i
	}
	if i+1 < len(hexStr) && hexStr[i:i+2] == "/*" {
		return sc.skipMultiLineComment(hexStr, i)
	}
	if i+1 < len(hexStr) && hexStr[i:i+2] == "//" {
		return sc.skipSingleLineComment(hexStr, i)
	}
	return i
}

// isWhitespace checks if character is whitespace
func (sc *stringCompiler) isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

// skipMultiLineComment skips over a /* */ comment
func (sc *stringCompiler) skipMultiLineComment(hexStr string, pos int) int {
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
func (sc *stringCompiler) skipSingleLineComment(hexStr string, pos int) int {
	i := pos + 2 // skip //
	for i < len(hexStr) && hexStr[i] != '\n' {
		i++
	}
	return i
}

// parsehexToken parses a single hex token at the given position
func (sc *stringCompiler) parsehexToken(hexStr string, pos int) (token hexToken, nextPos int) {
	if pos >= len(hexStr) {
		return hexToken{}, 0
	}

	switch hexStr[pos] {
	case '{', '}':
		return hexToken{}, 1
	case '(':
		return sc.parseAlternativesToken(hexStr, pos)
	case '[':
		return sc.parseJumpToken(hexStr, pos)
	case '?':
		return sc.parseWildcardToken(hexStr, pos)
	default:
		return sc.parsehexByteToken(hexStr, pos)
	}
}

// parseAlternativesToken parses an alternatives token (...)
func (sc *stringCompiler) parseAlternativesToken(hexStr string, pos int) (token hexToken, nextPos int) {
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

	if depth > 0 {
		return hexToken{}, i - pos
	}

	altStr := hexStr[altStart : i-1]
	alts := sc.parseAlternatives(altStr)
	return hexToken{Type: "alternative", Value: alts}, i - pos
}

// parseJumpToken parses a jump token [...]
func (sc *stringCompiler) parseJumpToken(hexStr string, pos int) (token hexToken, nextPos int) {
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
	return hexToken{Type: "jump", Value: jump}, i - pos
}

// parseWildcardToken parses wildcard tokens (??, ?X, X?)
func (sc *stringCompiler) parseWildcardToken(hexStr string, pos int) (token hexToken, nextPos int) {
	if pos+1 >= len(hexStr) {
		return hexToken{}, 1
	}

	switch {
	case hexStr[pos+1] == '?':
		return hexToken{Type: "wildcard", Value: byte(0x00)}, 2
	case isHexDigit(hexStr[pos+1]):
		hex := hexStr[pos : pos+2]
		val := sc.parsehexByte(hex)
		return hexToken{Type: "masked", Value: val}, 2
	default:
		return hexToken{}, 1
	}
}

// parsehexByteToken parses regular hex byte tokens
func (sc *stringCompiler) parsehexByteToken(hexStr string, pos int) (token hexToken, nextPos int) {
	if pos+1 >= len(hexStr) {
		return hexToken{}, 1
	}

	switch {
	case isHexDigit(hexStr[pos]) && isHexDigit(hexStr[pos+1]):
		hex := hexStr[pos : pos+2]
		val := sc.parsehexByte(hex)
		return hexToken{Type: "byte", Value: val}, 2
	case isHexDigit(hexStr[pos]) && hexStr[pos+1] == '?':
		hex := hexStr[pos : pos+2]
		val := sc.parsehexByte(hex)
		return hexToken{Type: "masked", Value: val}, 2
	default:
		return hexToken{}, 1
	}
}

// parseAlternatives parses alternatives separated by |
func (sc *stringCompiler) parseAlternatives(altStr string) [][]byte {
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
func (sc *stringCompiler) parseJump(jumpStr string) map[string]int {
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
func (sc *stringCompiler) parseRangeJump(jumpStr string, result map[string]int) {
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
func (sc *stringCompiler) parseSingleJump(jumpStr string, result map[string]int) {
	if val, err := strconv.Atoi(jumpStr); err == nil {
		result["min"] = val
		result["max"] = val
	}
}

// processByteToken processes a byte token and appends to result
func (sc *stringCompiler) processByteToken(result *[]byte, token hexToken) {
	if b, ok := token.Value.(byte); ok {
		*result = append(*result, b)
	}
}

// processWildcardToken processes a wildcard token and appends to result
func (sc *stringCompiler) processWildcardToken(result *[]byte, _ hexToken) {
	*result = append(*result, 0x00) // Placeholder for wildcard
}

// processMaskedToken processes a masked token and appends to result
func (sc *stringCompiler) processMaskedToken(result *[]byte, token hexToken) {
	if b, ok := token.Value.(byte); ok {
		*result = append(*result, b)
	}
}

// processJumpToken processes a jump token and appends to result
func (sc *stringCompiler) processJumpToken(result *[]byte, token hexToken) {
	if jumpMap, ok := token.Value.(map[string]int); ok {
		minVal := jumpMap["min"]
		maxVal := jumpMap["max"]
		*result = append(*result, byte(0xFF), // Jump marker
			byte(minVal&0xFF),
			byte((minVal>>8)&0xFF),
			byte(maxVal&0xFF),
			byte((maxVal>>8)&0xFF))
	}
}

// processAlternativeToken processes an alternative token and appends to result
func (sc *stringCompiler) processAlternativeToken(result *[]byte, token hexToken) {
	if alts, ok := token.Value.([][]byte); ok && len(alts) > 0 {
		*result = append(*result, alts[0]...)
	}
}

// tokensToBytes converts a slice of hexTokens to bytes
func (sc *stringCompiler) tokensToBytes(tokens []hexToken) []byte {
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

// parsehexByte parses a single hex byte (with possible mask)
func (sc *stringCompiler) parsehexByte(hexStr string) byte {
	if len(hexStr) < 2 {
		return 0x00
	}

	switch {
	case hexStr[1] == '?':
		if val, err := strconv.ParseInt(string(hexStr[0]), 16, 16); err == nil {
			return byte((val & 0x0F) << 4)
		}
	case hexStr[0] == '?':
		if val, err := strconv.ParseInt(string(hexStr[1]), 16, 16); err == nil {
			return byte(val & 0x0F)
		}
	default:
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
