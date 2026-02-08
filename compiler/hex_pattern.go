package compiler

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cawalch/go-yara/ast"
)

type HexTokenKind uint8

const (
	HexTokenByte HexTokenKind = iota
	HexTokenWildcard
	HexTokenMasked
	HexTokenJump
	HexTokenAlt
)

type HexPatternToken struct {
	Kind         HexTokenKind
	Value        byte
	Mask         byte
	Min          int
	Max          int
	Alternatives [][]HexPatternToken
	Negated      bool
}

type HexPattern struct {
	Tokens   []HexPatternToken
	XorKeys  []byte
	XorRange []ast.XorRange
}

func (p *HexPattern) Clone() *HexPattern {
	if p == nil {
		return nil
	}
	out := &HexPattern{
		Tokens:   cloneHexTokens(p.Tokens),
		XorKeys:  slices.Clone(p.XorKeys),
		XorRange: slices.Clone(p.XorRange),
	}
	return out
}

func cloneHexTokens(tokens []HexPatternToken) []HexPatternToken {
	out := make([]HexPatternToken, len(tokens))
	for i, t := range tokens {
		out[i] = t
		if t.Kind == HexTokenAlt {
			out[i].Alternatives = make([][]HexPatternToken, len(t.Alternatives))
			for j, alt := range t.Alternatives {
				out[i].Alternatives[j] = cloneHexTokens(alt)
			}
		}
	}
	return out
}

func (sc *StringCompiler) parseHexPattern(hexStr string) (*HexPattern, error) {
	content := stripHexBraces(hexStr)
	tokens, err := parseHexTokens(content)
	if err != nil {
		return nil, err
	}
	return &HexPattern{Tokens: tokens}, nil
}

func stripHexBraces(hexStr string) string {
	trimmed := strings.TrimSpace(hexStr)
	if strings.HasPrefix(trimmed, "{") {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "{"))
	}
	if strings.HasSuffix(trimmed, "}") {
		trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "}"))
	}
	return trimmed
}

func parseHexTokens(hexStr string) ([]HexPatternToken, error) {
	var tokens []HexPatternToken
	i := 0
	for i < len(hexStr) {
		i = skipHexWhitespaceAndComments(hexStr, i)
		if i >= len(hexStr) {
			break
		}
		ch := hexStr[i]
		switch ch {
		case '{', '}':
			i++
		case '(':
			alts, next, err := parseHexAlternatives(hexStr, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, HexPatternToken{Kind: HexTokenAlt, Alternatives: alts})
			i = next
		case '[':
			jump, next, err := parseHexJump(hexStr, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, jump)
			i = next
		case '~':
			token, next, err := parseHexAtom(hexStr, i+1)
			if err != nil {
				return nil, err
			}
			token.Negated = true
			tokens = append(tokens, token)
			i = next
		default:
			token, next, err := parseHexAtom(hexStr, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token)
			i = next
		}
	}
	return tokens, nil
}

func parseHexAtom(hexStr string, pos int) (HexPatternToken, int, error) {
	if pos >= len(hexStr) {
		return HexPatternToken{}, pos, fmt.Errorf("unexpected end of hex pattern")
	}
	ch := hexStr[pos]
	if ch == '?' {
		if pos+1 >= len(hexStr) {
			return HexPatternToken{}, pos, fmt.Errorf("incomplete wildcard")
		}
		if hexStr[pos+1] == '?' {
			return HexPatternToken{Kind: HexTokenWildcard}, pos + 2, nil
		}
		if isHexDigit(hexStr[pos+1]) {
			value := hexNibble(hexStr[pos+1])
			return HexPatternToken{Kind: HexTokenMasked, Value: value, Mask: 0x0F}, pos + 2, nil
		}
		return HexPatternToken{}, pos, fmt.Errorf("invalid wildcard token")
	}
	if isHexDigit(ch) {
		if pos+1 >= len(hexStr) {
			return HexPatternToken{}, pos, fmt.Errorf("incomplete byte token")
		}
		if hexStr[pos+1] == '?' {
			value := hexNibble(ch) << 4
			return HexPatternToken{Kind: HexTokenMasked, Value: value, Mask: 0xF0}, pos + 2, nil
		}
		if isHexDigit(hexStr[pos+1]) {
			value := hexByte(ch, hexStr[pos+1])
			return HexPatternToken{Kind: HexTokenByte, Value: value, Mask: 0xFF}, pos + 2, nil
		}
	}
	return HexPatternToken{}, pos, fmt.Errorf("invalid hex token at %d", pos)
}

func parseHexAlternatives(hexStr string, pos int) ([][]HexPatternToken, int, error) {
	start, end, err := extractHexGroup(hexStr, pos, '(', ')')
	if err != nil {
		return nil, pos, err
	}
	segments := splitHexAlternatives(hexStr[start:end])
	alts := make([][]HexPatternToken, 0, len(segments))
	for _, seg := range segments {
		tokens, err := parseHexTokens(seg)
		if err != nil {
			return nil, pos, err
		}
		alts = append(alts, tokens)
	}
	return alts, end + 1, nil
}

func splitHexAlternatives(content string) []string {
	var parts []string
	depth := 0
	last := 0
	for i := 0; i < len(content); i++ {
		switch content[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '|':
			if depth == 0 {
				parts = append(parts, content[last:i])
				last = i + 1
			}
		}
	}
	parts = append(parts, content[last:])
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func parseHexJump(hexStr string, pos int) (HexPatternToken, int, error) {
	start, end, err := extractHexGroup(hexStr, pos, '[', ']')
	if err != nil {
		return HexPatternToken{}, pos, err
	}
	content := strings.TrimSpace(hexStr[start:end])
	minVal, maxVal, err := parseHexJumpRange(content)
	if err != nil {
		return HexPatternToken{}, pos, err
	}
	return HexPatternToken{Kind: HexTokenJump, Min: minVal, Max: maxVal}, end + 1, nil
}

func parseHexJumpRange(content string) (int, int, error) {
	if content == "" || content == "-" {
		return 0, -1, nil
	}
	if strings.Contains(content, "-") {
		parts := strings.SplitN(content, "-", 2)
		minVal, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid jump min: %w", err)
		}
		if strings.TrimSpace(parts[1]) == "" {
			return minVal, -1, nil
		}
		maxVal, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid jump max: %w", err)
		}
		return minVal, maxVal, nil
	}
	val, err := strconv.Atoi(content)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid jump value: %w", err)
	}
	return val, val, nil
}

func extractHexGroup(hexStr string, pos int, open, close byte) (int, int, error) {
	if pos >= len(hexStr) || hexStr[pos] != open {
		return 0, 0, fmt.Errorf("expected %c at %d", open, pos)
	}
	depth := 1
	i := pos + 1
	for i < len(hexStr) && depth > 0 {
		switch hexStr[i] {
		case open:
			depth++
		case close:
			depth--
		}
		if depth == 0 {
			return pos + 1, i, nil
		}
		i++
	}
	return 0, 0, fmt.Errorf("unterminated %c", open)
}

func skipHexWhitespaceAndComments(hexStr string, pos int) int {
	i := pos
	for i < len(hexStr) {
		switch {
		case hexStr[i] == ' ' || hexStr[i] == '\t' || hexStr[i] == '\n' || hexStr[i] == '\r':
			i++
		case i+1 < len(hexStr) && hexStr[i] == '/' && hexStr[i+1] == '*':
			i += 2
			for i+1 < len(hexStr) && (hexStr[i] != '*' || hexStr[i+1] != '/') {
				i++
			}
			if i+1 < len(hexStr) {
				i += 2
			}
		case i+1 < len(hexStr) && hexStr[i] == '/' && hexStr[i+1] == '/':
			i += 2
			for i < len(hexStr) && hexStr[i] != '\n' {
				i++
			}
		default:
			return i
		}
	}
	return i
}

func hexNibble(ch byte) byte {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0'
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10
	default:
		return 0
	}
}

func hexByte(a, b byte) byte {
	return (hexNibble(a) << 4) | hexNibble(b)
}

// FindHexMatches returns all matches of the hex pattern in data.
func FindHexMatches(pattern *HexPattern, data []byte) []Match {
	if pattern == nil || len(pattern.Tokens) == 0 || len(data) == 0 {
		return nil
	}
	var matches []Match
	keys := pattern.XorKeys
	if len(keys) == 0 && len(pattern.XorRange) > 0 {
		keys = expandXorKeys(pattern.XorRange)
	}
	for start := 0; start < len(data); start++ {
		var ends []int
		if len(keys) == 0 {
			ends = matchHexTokens(pattern.Tokens, data, start)
		} else {
			for _, key := range keys {
				ends = append(ends, matchHexTokensXor(pattern.Tokens, data, start, key)...)
			}
		}
		for _, end := range ends {
			if end <= start {
				continue
			}
			matches = append(matches, Match{
				Offset: int64(start),
				Length: end - start,
			})
		}
	}
	return matches
}

func expandXorKeys(ranges []ast.XorRange) []byte {
	keys := make([]byte, 0, 256)
	seen := make(map[byte]struct{})
	for _, r := range ranges {
		min := int(r.Min)
		max := int(r.Max)
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
		for k := min; k <= max; k++ {
			b := byte(k)
			if _, ok := seen[b]; ok {
				continue
			}
			seen[b] = struct{}{}
			keys = append(keys, b)
		}
	}
	return keys
}

func matchHexTokens(tokens []HexPatternToken, data []byte, pos int) []int {
	if len(tokens) == 0 {
		return []int{pos}
	}
	if pos > len(data) {
		return nil
	}
	head := tokens[0]
	tail := tokens[1:]

	switch head.Kind {
	case HexTokenByte:
		if pos >= len(data) {
			return nil
		}
		ok := data[pos] == head.Value
		if head.Negated {
			ok = !ok
		}
		if ok {
			return matchHexTokens(tail, data, pos+1)
		}
		return nil
	case HexTokenMasked:
		if pos >= len(data) {
			return nil
		}
		ok := (data[pos] & head.Mask) == (head.Value & head.Mask)
		if head.Negated {
			ok = !ok
		}
		if ok {
			return matchHexTokens(tail, data, pos+1)
		}
		return nil
	case HexTokenWildcard:
		if head.Negated || pos >= len(data) {
			return nil
		}
		return matchHexTokens(tail, data, pos+1)
	case HexTokenJump:
		if head.Min < 0 {
			head.Min = 0
		}
		maxVal := head.Max
		if maxVal < 0 {
			maxVal = len(data) - pos
		}
		if maxVal < head.Min {
			return nil
		}
		var ends []int
		for jump := head.Min; jump <= maxVal; jump++ {
			ends = append(ends, matchHexTokens(tail, data, pos+jump)...)
		}
		return ends
	case HexTokenAlt:
		var ends []int
		for _, alt := range head.Alternatives {
			altEnds := matchHexTokens(alt, data, pos)
			for _, end := range altEnds {
				ends = append(ends, matchHexTokens(tail, data, end)...)
			}
		}
		return ends
	default:
		return nil
	}
}

func matchHexTokensXor(tokens []HexPatternToken, data []byte, pos int, key byte) []int {
	if len(tokens) == 0 {
		return []int{pos}
	}
	if pos > len(data) {
		return nil
	}
	head := tokens[0]
	tail := tokens[1:]

	switch head.Kind {
	case HexTokenByte:
		if pos >= len(data) {
			return nil
		}
		expected := head.Value ^ key
		ok := data[pos] == expected
		if head.Negated {
			ok = !ok
		}
		if ok {
			return matchHexTokensXor(tail, data, pos+1, key)
		}
		return nil
	case HexTokenMasked:
		if pos >= len(data) {
			return nil
		}
		expected := head.Value ^ (key & head.Mask)
		ok := (data[pos] & head.Mask) == (expected & head.Mask)
		if head.Negated {
			ok = !ok
		}
		if ok {
			return matchHexTokensXor(tail, data, pos+1, key)
		}
		return nil
	case HexTokenWildcard:
		if head.Negated || pos >= len(data) {
			return nil
		}
		return matchHexTokensXor(tail, data, pos+1, key)
	case HexTokenJump:
		if head.Min < 0 {
			head.Min = 0
		}
		maxVal := head.Max
		if maxVal < 0 {
			maxVal = len(data) - pos
		}
		if maxVal < head.Min {
			return nil
		}
		var ends []int
		for jump := head.Min; jump <= maxVal; jump++ {
			ends = append(ends, matchHexTokensXor(tail, data, pos+jump, key)...)
		}
		return ends
	case HexTokenAlt:
		var ends []int
		for _, alt := range head.Alternatives {
			altEnds := matchHexTokensXor(alt, data, pos, key)
			for _, end := range altEnds {
				ends = append(ends, matchHexTokensXor(tail, data, end, key)...)
			}
		}
		return ends
	default:
		return nil
	}
}
