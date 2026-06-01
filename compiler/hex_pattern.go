package compiler

import (
	"bytes"
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
	if after, ok := strings.CutPrefix(trimmed, "{"); ok {
		trimmed = strings.TrimSpace(after)
	}
	if before, ok := strings.CutSuffix(trimmed, "}"); ok {
		trimmed = strings.TrimSpace(before)
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

// anchorInfo describes an anchor byte for skip-based matching.
type anchorInfo struct {
	byteVal byte // the definite literal byte value
	offset  int  // its position in the token sequence
	ok      bool // true if a usable anchor was found
}

// findAnchorByte scans the token list for the first definite, non-negated
// literal byte that can serve as an anchor for position skipping.
func findAnchorByte(tokens []HexPatternToken) anchorInfo {
	for i, tok := range tokens {
		switch tok.Kind {
		case HexTokenByte:
			if !tok.Negated {
				return anchorInfo{byteVal: tok.Value, offset: i, ok: true}
			}
		case HexTokenMasked:
			// A masked byte is only a definite anchor when the mask is 0xFF
			// (i.e. it's equivalent to a plain byte).
			if !tok.Negated && tok.Mask == 0xFF {
				return anchorInfo{byteVal: tok.Value, offset: i, ok: true}
			}
		case HexTokenWildcard:
			// Skip — no definite value
		case HexTokenJump:
			// Skip — variable length, but continue looking past it
		case HexTokenAlt:
			// Skip — alternatives are ambiguous, continue looking past them
		}
	}
	return anchorInfo{}
}

// FindHexMatches returns all matches of the hex pattern in data.
func FindHexMatches(pattern *HexPattern, data []byte) []Match {
	if pattern == nil || len(pattern.Tokens) == 0 || len(data) == 0 {
		return nil
	}
	keys := pattern.XorKeys
	if len(keys) == 0 && len(pattern.XorRange) > 0 {
		keys = expandXorKeys(pattern.XorRange)
	}

	// Try anchor-based skipping for the common case.
	anchor := findAnchorByte(pattern.Tokens)

	if len(keys) == 0 {
		if anchor.ok {
			return findHexMatchesAnchored(pattern.Tokens, data, anchor)
		}
		return findHexMatchesBruteForce(pattern.Tokens, data)
	}

	// XOR mode: for each key, compute the transformed anchor byte.
	if anchor.ok {
		return findHexMatchesXorAnchored(pattern.Tokens, data, keys, anchor)
	}
	return findHexMatchesXorBruteForce(pattern.Tokens, data, keys)
}

// findHexMatchesAnchored uses bytes.IndexByte to skip non-matching positions.
func findHexMatchesAnchored(tokens []HexPatternToken, data []byte, anchor anchorInfo) []Match {
	var matches []Match
	pos := 0
	for {
		idx := bytes.IndexByte(data[pos:], anchor.byteVal)
		if idx == -1 {
			break
		}
		candidateStart := pos + idx - anchor.offset
		pos = pos + idx + 1

		if candidateStart < 0 {
			continue
		}
		ends := matchHexTokensIterative(tokens, data, candidateStart)
		for _, end := range ends {
			if end <= candidateStart {
				continue
			}
			matches = append(matches, Match{
				Offset: int64(candidateStart),
				Length: end - candidateStart,
			})
		}
	}
	return matches
}

// findHexMatchesBruteForce is the fallback when no anchor byte exists.
func findHexMatchesBruteForce(tokens []HexPatternToken, data []byte) []Match {
	var matches []Match
	for start := range data {
		ends := matchHexTokensIterative(tokens, data, start)
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

// findHexMatchesXorAnchored uses per-key transformed anchor bytes for skip-based matching.
//
//nolint:revive // argument-limit: internal helper
func findHexMatchesXorAnchored(tokens []HexPatternToken, data []byte, keys []byte, anchor anchorInfo) []Match {
	var matches []Match
	for _, key := range keys {
		targetByte := anchor.byteVal ^ key
		pos := 0
		for {
			idx := bytes.IndexByte(data[pos:], targetByte)
			if idx == -1 {
				break
			}
			candidateStart := pos + idx - anchor.offset
			pos = pos + idx + 1

			if candidateStart < 0 {
				continue
			}
			ends := matchHexTokensIterativeXor(tokens, data, candidateStart, key)
			for _, end := range ends {
				if end <= candidateStart {
					continue
				}
				matches = append(matches, Match{
					Offset: int64(candidateStart),
					Length: end - candidateStart,
				})
			}
		}
	}
	return matches
}

// findHexMatchesXorBruteForce is the fallback for XOR patterns with no anchor.
func findHexMatchesXorBruteForce(tokens []HexPatternToken, data []byte, keys []byte) []Match {
	var matches []Match
	for start := range data {
		for _, key := range keys {
			ends := matchHexTokensIterativeXor(tokens, data, start, key)
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

// matchHexTokensIterative replaces the recursive matchHexTokens with an
// iterative approach. It handles linear tokens (byte, masked, wildcard)
// in a tight loop and only uses a worklist for branching tokens (jump, alt).
func matchHexTokensIterative(tokens []HexPatternToken, data []byte, pos int) []int {
	if pos > len(data) {
		return nil
	}
	return matchHexIter(tokens, data, pos, nil)
}

// matchHexIter processes tokens iteratively. The xorKey pointer selects
// between normal and XOR mode (nil = normal, non-nil = XOR with that key).
//
//nolint:revive // argument-limit: internal helper
func matchHexIter(tokens []HexPatternToken, data []byte, pos int, xorKey *byte) []int {
	var results []int
	// Each work item: tokens to match and the starting data position.
	type workItem struct {
		tokens  []HexPatternToken
		dataPos int
	}
	worklist := []workItem{{tokens, pos}}

	for len(worklist) > 0 {
		item := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]

		toks := item.tokens
		dp := item.dataPos

		// Fast linear path: consume non-branching tokens in a loop.
		for {
			if len(toks) == 0 {
				results = append(results, dp)
				goto nextItem
			}
			if dp > len(data) {
				goto nextItem
			}

			head := toks[0]
			switch head.Kind {
			case HexTokenByte:
				if dp >= len(data) {
					goto nextItem
				}
				var ok bool
				if xorKey != nil {
					ok = data[dp] == (head.Value ^ *xorKey)
				} else {
					ok = data[dp] == head.Value
				}
				if head.Negated {
					ok = !ok
				}
				if !ok {
					goto nextItem
				}
				toks = toks[1:]
				dp++

			case HexTokenMasked:
				if dp >= len(data) {
					goto nextItem
				}
				var ok bool
				if xorKey != nil {
					expected := head.Value ^ (*xorKey & head.Mask)
					ok = (data[dp] & head.Mask) == (expected & head.Mask)
				} else {
					ok = (data[dp] & head.Mask) == (head.Value & head.Mask)
				}
				if head.Negated {
					ok = !ok
				}
				if !ok {
					goto nextItem
				}
				toks = toks[1:]
				dp++

			case HexTokenWildcard:
				if head.Negated || dp >= len(data) {
					goto nextItem
				}
				toks = toks[1:]
				dp++

			case HexTokenJump:
				minJ := head.Min
				if minJ < 0 {
					minJ = 0
				}
				maxJ := head.Max
				if maxJ < 0 {
					maxJ = len(data) - dp
				}
				if maxJ < minJ {
					goto nextItem
				}
				tail := toks[1:]
				// Push branches in reverse order so smallest jump is processed first.
				for jump := maxJ; jump >= minJ; jump-- {
					worklist = append(worklist, workItem{tail, dp + jump})
				}
				goto nextItem

			case HexTokenAlt:
				tail := toks[1:]
				for _, alt := range head.Alternatives {
					// Build combined token slice: alt + tail
					combined := make([]HexPatternToken, len(alt)+len(tail))
					copy(combined, alt)
					copy(combined[len(alt):], tail)
					worklist = append(worklist, workItem{combined, dp})
				}
				goto nextItem

			default:
				goto nextItem
			}
		}

	nextItem:
	}

	return results
}

// matchHexTokensIterativeXor is the XOR variant of matchHexTokensIterative.
//
//nolint:revive // argument-limit: internal helper
func matchHexTokensIterativeXor(tokens []HexPatternToken, data []byte, pos int, key byte) []int {
	if pos > len(data) {
		return nil
	}
	return matchHexIter(tokens, data, pos, &key)
}
