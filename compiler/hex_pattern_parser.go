package compiler

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

const maxHexJumpBound = math.MaxInt32

func (sc *stringCompiler) parseHexPattern(hexStr string) (*HexPattern, error) {
	content := stripHexBraces(hexStr)
	tokens, err := parseHexTokens(content)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, errors.New("empty hex pattern")
	}
	if sc.strictLibyaraCompatibility && (tokens[0].Kind == HexTokenJump || tokens[len(tokens)-1].Kind == HexTokenJump) {
		return nil, errors.New("leading or trailing jump in hex string is not allowed in strict libyara compatibility mode")
	}
	return &HexPattern{Tokens: tokens}, nil
}

func stripHexBraces(hexStr string) string {
	trimmed := strings.TrimSpace(hexStr)
	if after, ok := strings.CutPrefix(trimmed, "{"); ok {
		trimmed = strings.TrimSpace(after)
	}
	if before, ok := strings.CutSuffix(trimmed, "}"); ok {
		trimmed = strings.TrimSpace(before)
	}
	return trimmed
}

func parseHexTokens(hexStr string) ([]HexPatternToken, error) {
	tokens := make([]HexPatternToken, 0, max(4, len(hexStr)/3))
	i := 0
	for i < len(hexStr) {
		var err error
		i, err = skipHexWhitespaceAndComments(hexStr, i)
		if err != nil {
			return nil, err
		}
		if i >= len(hexStr) {
			break
		}
		ch := hexStr[i]
		switch ch {
		case '{', '}':
			return nil, fmt.Errorf("unexpected %q in hex pattern at offset %d", ch, i)
		case '(':
			alts, next, err := parseHexAlternatives(hexStr, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, HexPatternToken{Kind: HexTokenAlt, Alternatives: alts})
			i = next
		case '[':
			if len(tokens) > 0 && tokens[len(tokens)-1].Kind == HexTokenJump {
				return nil, errors.New("consecutive jumps are not allowed in hex pattern")
			}
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
		return HexPatternToken{}, pos, errors.New("unexpected end of hex pattern")
	}
	ch := hexStr[pos]
	if ch == '?' {
		if pos+1 >= len(hexStr) {
			return HexPatternToken{}, pos, errors.New("incomplete wildcard")
		}
		if hexStr[pos+1] == '?' {
			return HexPatternToken{Kind: HexTokenWildcard}, pos + 2, nil
		}
		if isHexDigit(hexStr[pos+1]) {
			value := hexNibble(hexStr[pos+1])
			return HexPatternToken{Kind: HexTokenMasked, Value: value, Mask: 0x0F}, pos + 2, nil
		}
		return HexPatternToken{}, pos, errors.New("invalid wildcard token")
	}
	if isHexDigit(ch) {
		if pos+1 >= len(hexStr) {
			return HexPatternToken{}, pos, errors.New("incomplete byte token")
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
		// Upstream YARA's hex grammar requires every alternative branch to
		// contain at least one token ('alternatives : tokens | alternatives
		// '|' tokens'). Empty branches — from (), (|), (DE|), (|DE), or a
		// whitespace-only group — are invalid and previously compiled
		// silently into a degenerate HexTokenAlt with empty alternatives.
		if len(tokens) == 0 {
			return nil, pos, fmt.Errorf("empty alternative in hex group at offset %d", pos)
		}
		if tokens[0].Kind == HexTokenJump || tokens[len(tokens)-1].Kind == HexTokenJump {
			return nil, pos, errors.New("alternation branch cannot begin or end with a jump")
		}
		if hasUnboundedJump(tokens) {
			return nil, pos, errors.New("unbounded jumps not allowed inside alternation (|)")
		}
		alts = append(alts, tokens)
	}
	return alts, end + 1, nil
}

func hasUnboundedJump(tokens []HexPatternToken) bool {
	for _, tok := range tokens {
		if tok.Kind == HexTokenJump && tok.Max < 0 {
			return true
		}
		if tok.Kind == HexTokenAlt {
			if slices.ContainsFunc(tok.Alternatives, hasUnboundedJump) {
				return true
			}
		}
	}
	return false
}

func splitHexAlternatives(content string) []string {
	parts := make([]string, 0, 2)
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
	before, after, ok := strings.Cut(content, "-")
	if !ok {
		val, err := parseHexJumpBound(content, "invalid jump value")
		if err != nil {
			return 0, 0, err
		}
		return val, val, nil
	}
	minVal, err := parseHexJumpBound(strings.TrimSpace(before), "invalid jump min")
	if err != nil {
		return 0, 0, err
	}
	maxPart := strings.TrimSpace(after)
	if maxPart == "" {
		return minVal, -1, nil
	}
	maxVal, err := parseHexJumpBound(maxPart, "invalid jump max")
	if err != nil {
		return 0, 0, err
	}
	if minVal > maxVal {
		return 0, 0, errors.New("invalid jump range")
	}
	return minVal, maxVal, nil
}

func parseHexJumpBound(raw, invalidPrefix string) (int, error) {
	val, err := strconv.Atoi(raw)
	if errors.Is(err, strconv.ErrRange) {
		return 0, errors.New("jump length too large")
	}
	if err != nil {
		return 0, fmt.Errorf("%s: %w", invalidPrefix, err)
	}
	if val < 0 {
		return 0, errors.New("invalid jump range")
	}
	if val > maxHexJumpBound {
		return 0, errors.New("jump length too large")
	}
	return val, nil
}

//nolint:revive // argument-limit: internal helper
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

func skipHexWhitespaceAndComments(hexStr string, pos int) (int, error) {
	i := pos
	for i < len(hexStr) {
		switch {
		case hexStr[i] == ' ' || hexStr[i] == '\t' || hexStr[i] == '\n' || hexStr[i] == '\r':
			i++
		case i+1 < len(hexStr) && hexStr[i] == '/' && hexStr[i+1] == '*':
			i += 2
			closed := false
			for i+1 < len(hexStr) {
				if hexStr[i] == '*' && hexStr[i+1] == '/' {
					i += 2
					closed = true
					break
				}
				i++
			}
			if !closed {
				return i, errors.New("unterminated block comment in hex pattern")
			}
		case i+1 < len(hexStr) && hexStr[i] == '/' && hexStr[i+1] == '/':
			i += 2
			for i < len(hexStr) && hexStr[i] != '\n' {
				i++
			}
		default:
			return i, nil
		}
	}
	return i, nil
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

func isHexDigit(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}
