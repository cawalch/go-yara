package compiler

import (
	"bytes"
	"encoding/binary"
	"slices"

	"github.com/cawalch/go-yara/ast"
)

// HexTokenKind identifies the syntactic kind of a token within a compiled hex pattern.
type HexTokenKind uint8

const (
	// HexTokenByte matches an exact single byte literal.
	HexTokenByte HexTokenKind = iota
	// HexTokenWildcard matches any single byte (??).
	HexTokenWildcard
	// HexTokenMasked matches a byte matching a high or low nibble mask (?A or A?).
	HexTokenMasked
	// HexTokenJump matches a variable-length jump interval ([-], [n-m]).
	HexTokenJump
	// HexTokenAlt matches an alternative sequence of tokens ((AA | BB)).
	HexTokenAlt
)

// HexPatternToken describes an individual token, jump, or alternative group within a HexPattern.
type HexPatternToken struct {
	Alternatives [][]HexPatternToken
	Min          int
	Max          int
	Kind         HexTokenKind
	Value        byte
	Mask         byte
	Negated      bool
}

// HexPattern represents a compiled hexadecimal pattern, consisting of an ordered sequence
// of tokens and optional XOR transformation configurations.
type HexPattern struct {
	Tokens     []HexPatternToken
	XorKeys    []byte
	XorRange   []ast.XorRange
	cacheKey   string
	cacheIndex int
}

// Clone creates a deep copy of the HexPattern and its token sequences.
func (p *HexPattern) Clone() *HexPattern {
	if p == nil {
		return nil
	}
	out := &HexPattern{
		Tokens:     cloneHexTokens(p.Tokens),
		XorKeys:    slices.Clone(p.XorKeys),
		XorRange:   slices.Clone(p.XorRange),
		cacheKey:   p.cacheKey,
		cacheIndex: p.cacheIndex,
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

// anchorInfo describes an anchor byte for skip-based matching.
type anchorInfo struct {
	offset    int  // min offset in bytes
	maxOffset int  // max offset in bytes
	byteVal   byte // the definite literal byte value
	ok        bool // true if a usable anchor was found
}

// findAnchorByte scans the token list for the first definite, non-negated
// literal byte that can serve as an anchor for position skipping.
func findAnchorByte(tokens []HexPatternToken) anchorInfo {
	minOffset := 0
	maxOffset := 0
	for _, tok := range tokens {
		switch tok.Kind {
		case HexTokenByte:
			if !tok.Negated {
				return anchorInfo{byteVal: tok.Value, offset: minOffset, maxOffset: maxOffset, ok: true}
			}
			minOffset++
			if maxOffset >= 0 {
				maxOffset++
			}
		case HexTokenMasked:
			// A masked byte is only a definite anchor when the mask is 0xFF
			// (i.e. it's equivalent to a plain byte).
			if !tok.Negated && tok.Mask == 0xFF {
				return anchorInfo{byteVal: tok.Value, offset: minOffset, maxOffset: maxOffset, ok: true}
			}
			minOffset++
			if maxOffset >= 0 {
				maxOffset++
			}
		case HexTokenWildcard:
			minOffset++
			if maxOffset >= 0 {
				maxOffset++
			}
		case HexTokenJump:
			if tok.Min > 0 {
				minOffset += tok.Min
			}
			if tok.Max < 0 || maxOffset < 0 {
				maxOffset = -1
			} else {
				maxOffset += tok.Max
			}
		case HexTokenAlt:
			altMin, altMax := hexTokensAlternativesLengthRange(tok.Alternatives)
			minOffset += altMin
			if altMax < 0 || maxOffset < 0 {
				maxOffset = -1
			} else {
				maxOffset += altMax
			}
		}
	}
	return anchorInfo{}
}

// xorDiffAnchor describes an XOR-invariant adjacent differential sequence for skip-based matching.
type xorDiffAnchor struct {
	offset   int
	byteVal0 byte
	diff     []byte
	ok       bool
}

// findXorDiffAnchor searches for the longest contiguous run of definite, non-negated literal bytes.
func findXorDiffAnchor(tokens []HexPatternToken) xorDiffAnchor {
	bestOffset := -1
	bestLen := 0
	currOffset := -1
	currLen := 0

	for i, tok := range tokens {
		isDefinite := (tok.Kind == HexTokenByte && !tok.Negated) ||
			(tok.Kind == HexTokenMasked && tok.Mask == 0xFF && !tok.Negated)
		if isDefinite {
			if currLen == 0 {
				currOffset = i
			}
			currLen++
			if currLen > bestLen {
				bestLen = currLen
				bestOffset = currOffset
			}
		} else {
			currLen = 0
			currOffset = -1
		}
	}

	if bestLen < 2 {
		return xorDiffAnchor{}
	}

	diff := make([]byte, bestLen-1)
	for j := 0; j < bestLen-1; j++ {
		b0 := tokens[bestOffset+j].Value
		b1 := tokens[bestOffset+j+1].Value
		diff[j] = b0 ^ b1
	}

	return xorDiffAnchor{
		offset:   bestOffset,
		byteVal0: tokens[bestOffset].Value,
		diff:     diff,
		ok:       true,
	}
}

type xorKeyMask [4]uint64

func makeXorKeyMask(keys []byte) xorKeyMask {
	var m xorKeyMask
	for _, k := range keys {
		m[k/64] |= uint64(1) << (k % 64)
	}
	return m
}

func (m *xorKeyMask) contains(k byte) bool {
	return (m[k/64] & (uint64(1) << (k % 64))) != 0
}

func (scratch *hexMatchScratch) ensureDiffData(data []byte) []byte {
	n := len(data) - 1
	if n <= 0 {
		return nil
	}
	if cap(scratch.diffBuf) < n {
		scratch.diffBuf = make([]byte, n)
	} else {
		scratch.diffBuf = scratch.diffBuf[:n]
	}
	diff := scratch.diffBuf
	i := 0
	for ; i+8 <= n; i += 8 {
		v0 := binary.LittleEndian.Uint64(data[i:])
		v1 := binary.LittleEndian.Uint64(data[i+1:])
		binary.LittleEndian.PutUint64(diff[i:], v0^v1)
	}
	for ; i < n; i++ {
		diff[i] = data[i] ^ data[i+1]
	}
	return diff
}

// FindHexMatches returns all matches of the hex pattern in data.
func FindHexMatches(pattern *HexPattern, data []byte) []Match {
	return findHexMatches(pattern, data, nil)
}

func findHexMatches(pattern *HexPattern, data []byte, done <-chan struct{}) []Match {
	var matches []Match
	var scratch hexMatchScratch
	findHexMatchesEach(pattern, data, done, &scratch, func(m Match) bool {
		matches = append(matches, m)
		return true
	})
	return matches
}

// findHexMatchesEach invokes onMatch for every hex pattern match found in data.
// It stops traversing immediately if onMatch returns false.
//
//nolint:revive // cancellation signal remains explicit on the matching hot path
func findHexMatchesEach(pattern *HexPattern, data []byte, done <-chan struct{}, scratch *hexMatchScratch, onMatch func(Match) bool) {
	if pattern == nil || len(pattern.Tokens) == 0 || len(data) == 0 {
		return
	}
	if scratch == nil {
		scratch = &hexMatchScratch{}
	}
	keys := pattern.XorKeys
	if len(keys) == 0 && len(pattern.XorRange) > 0 {
		keys = expandXorKeys(pattern.XorRange)
	}

	// Try anchor-based skipping for the common case.
	anchor := findAnchorByte(pattern.Tokens)

	if len(keys) == 0 {
		if anchor.ok && anchor.maxOffset >= 0 {
			findHexMatchesAnchoredEach(pattern.Tokens, data, anchor, done, scratch, onMatch)
			return
		}
		findHexMatchesBruteForceEach(pattern.Tokens, data, done, scratch, onMatch)
		return
	}

	if len(keys) == 1 {
		if anchor.ok && anchor.maxOffset >= 0 {
			findHexMatchesXorAnchoredEach(pattern.Tokens, data, keys, anchor, done, scratch, onMatch)
			return
		}
		findHexMatchesXorBruteForceEach(pattern.Tokens, data, keys, done, scratch, onMatch)
		return
	}

	// Multi-key XOR: use XOR-invariant differential anchor if a 2+ byte run exists.
	diffAnchor := findXorDiffAnchor(pattern.Tokens)
	if diffAnchor.ok {
		findHexMatchesXorDiffEach(pattern.Tokens, data, keys, diffAnchor, done, scratch, onMatch)
		return
	}

	if anchor.ok && anchor.maxOffset >= 0 {
		findHexMatchesXorAnchoredEach(pattern.Tokens, data, keys, anchor, done, scratch, onMatch)
		return
	}
	findHexMatchesXorBruteForceEach(pattern.Tokens, data, keys, done, scratch, onMatch)
}

// findHexMatchesXorDiffEach uses XOR 1st-order differential skipping for multi-key matching.
//
//nolint:revive // argument-limit: internal traversal helper with cancellation
func findHexMatchesXorDiffEach(
	tokens []HexPatternToken,
	data []byte,
	keys []byte,
	anchor xorDiffAnchor,
	done <-chan struct{},
	scratch *hexMatchScratch,
	onMatch func(Match) bool,
) {
	diffData := scratch.ensureDiffData(data)
	if len(diffData) < len(anchor.diff) {
		return
	}
	mask := makeXorKeyMask(keys)
	linear := isLinearHexPattern(tokens)
	checkpoint := 0
	pos := 0
	singleByteDiff := len(anchor.diff) == 1
	targetByte := anchor.diff[0]

	for {
		if scanCanceledAt(done, checkpoint) {
			return
		}
		checkpoint++

		var idx int
		if singleByteDiff {
			idx = bytes.IndexByte(diffData[pos:], targetByte)
		} else {
			idx = bytes.Index(diffData[pos:], anchor.diff)
		}
		if idx == -1 {
			break
		}
		diffPos := pos + idx
		candidateStart := diffPos - anchor.offset
		pos = diffPos + 1

		if candidateStart < 0 || candidateStart >= len(data) {
			continue
		}

		candidateKey := data[diffPos] ^ anchor.byteVal0
		if !mask.contains(candidateKey) {
			continue
		}

		if linear {
			if end, ok := matchLinearHexPattern(tokens, data, candidateStart, &candidateKey); ok {
				if !onMatch(Match{
					Offset: int64(candidateStart),
					Length: end - candidateStart,
				}) {
					return
				}
			}
			continue
		}

		if !scratch.matchEach(tokens, data, candidateStart, &candidateKey, func(end int) bool {
			if end <= candidateStart {
				return true
			}
			return onMatch(Match{
				Offset: int64(candidateStart),
				Length: end - candidateStart,
			})
		}) {
			return
		}
	}
}

// findHexMatchesAnchoredEach uses bytes.IndexByte to skip non-matching positions.
//
//nolint:revive // argument-limit: internal traversal helper with cancellation
func findHexMatchesAnchoredEach(
	tokens []HexPatternToken,
	data []byte,
	anchor anchorInfo,
	done <-chan struct{},
	scratch *hexMatchScratch,
	onMatch func(Match) bool,
) {
	linear := isLinearHexPattern(tokens)
	pos := 0
	checkpoint := 0
	for {
		if scanCanceledAt(done, checkpoint) {
			return
		}
		checkpoint++
		idx := bytes.IndexByte(data[pos:], anchor.byteVal)
		if idx == -1 {
			break
		}
		matchPos := pos + idx
		pos = matchPos + 1

		first := max(0, matchPos-anchor.maxOffset)
		last := min(len(data), matchPos-anchor.offset)
		for candidateStart := first; candidateStart <= last; candidateStart++ {
			if linear {
				if end, ok := matchLinearHexPattern(tokens, data, candidateStart, nil); ok {
					if !onMatch(Match{
						Offset: int64(candidateStart),
						Length: end - candidateStart,
					}) {
						return
					}
				}
				continue
			}
			if !scratch.matchEach(tokens, data, candidateStart, nil, func(end int) bool {
				if end <= candidateStart {
					return true
				}
				return onMatch(Match{
					Offset: int64(candidateStart),
					Length: end - candidateStart,
				})
			}) {
				return
			}
		}
	}
}

// findHexMatchesBruteForceEach is the fallback when no anchor byte exists.
//
//nolint:revive // argument-limit: internal traversal helper with cancellation
func findHexMatchesBruteForceEach(
	tokens []HexPatternToken,
	data []byte,
	done <-chan struct{},
	scratch *hexMatchScratch,
	onMatch func(Match) bool,
) {
	for start := range data {
		if scanCanceledAt(done, start) {
			return
		}
		if !scratch.matchEach(tokens, data, start, nil, func(end int) bool {
			if end <= start {
				return true
			}
			return onMatch(Match{
				Offset: int64(start),
				Length: end - start,
			})
		}) {
			return
		}
	}
}

// findHexMatchesXorAnchoredEach uses per-key transformed anchor bytes for skip-based matching.
//
//nolint:revive // argument-limit: internal traversal helper with cancellation
func findHexMatchesXorAnchoredEach(
	tokens []HexPatternToken,
	data []byte,
	keys []byte,
	anchor anchorInfo,
	done <-chan struct{},
	scratch *hexMatchScratch,
	onMatch func(Match) bool,
) {
	linear := isLinearHexPattern(tokens)
	checkpoint := 0
	for _, key := range keys {
		targetByte := anchor.byteVal ^ key
		pos := 0
		for {
			if scanCanceledAt(done, checkpoint) {
				return
			}
			checkpoint++
			idx := bytes.IndexByte(data[pos:], targetByte)
			if idx == -1 {
				break
			}
			matchPos := pos + idx
			pos = matchPos + 1

			first := max(0, matchPos-anchor.maxOffset)
			last := min(len(data), matchPos-anchor.offset)
			for candidateStart := first; candidateStart <= last; candidateStart++ {
				if linear {
					if end, ok := matchLinearHexPattern(tokens, data, candidateStart, &key); ok {
						if !onMatch(Match{
							Offset: int64(candidateStart),
							Length: end - candidateStart,
						}) {
							return
						}
					}
					continue
				}
				if !scratch.matchEach(tokens, data, candidateStart, &key, func(end int) bool {
					if end <= candidateStart {
						return true
					}
					return onMatch(Match{
						Offset: int64(candidateStart),
						Length: end - candidateStart,
					})
				}) {
					return
				}
			}
		}
	}
}

// findHexMatchesXorBruteForceEach is the fallback for XOR patterns with no anchor.
//
//nolint:revive // argument-limit: internal traversal helper with cancellation
func findHexMatchesXorBruteForceEach(
	tokens []HexPatternToken,
	data []byte,
	keys []byte,
	done <-chan struct{},
	scratch *hexMatchScratch,
	onMatch func(Match) bool,
) {
	for start := range data {
		if scanCanceledAt(done, start) {
			return
		}
		for _, key := range keys {
			if !scratch.matchEach(tokens, data, start, &key, func(end int) bool {
				if end <= start {
					return true
				}
				return onMatch(Match{
					Offset: int64(start),
					Length: end - start,
				})
			}) {
				return
			}
		}
	}
}

func isLinearHexPattern(tokens []HexPatternToken) bool {
	for _, token := range tokens {
		if token.Kind == HexTokenJump || token.Kind == HexTokenAlt {
			return false
		}
	}
	return true
}

//nolint:revive // argument-limit: hot path avoids allocating an options struct
func matchLinearHexPattern(tokens []HexPatternToken, data []byte, pos int, xorKey *byte) (int, bool) {
	if pos < 0 || len(tokens) > len(data)-pos {
		return 0, false
	}
	for _, token := range tokens {
		var ok bool
		switch token.Kind {
		case HexTokenByte:
			want := token.Value
			if xorKey != nil {
				want ^= *xorKey
			}
			ok = data[pos] == want
		case HexTokenMasked:
			want := token.Value
			if xorKey != nil {
				want ^= *xorKey & token.Mask
			}
			ok = data[pos]&token.Mask == want&token.Mask
		case HexTokenWildcard:
			ok = !token.Negated
		default:
			return 0, false
		}
		if token.Kind != HexTokenWildcard && token.Negated {
			ok = !ok
		}
		if !ok {
			return 0, false
		}
		pos++
	}
	return pos, true
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

type hexWorkItem struct {
	tokens  []HexPatternToken
	dataPos int
}

type hexMatchScratch struct {
	worklist   []hexWorkItem
	diffBuf    []byte
	inlineWork [16]hexWorkItem
}

func (scratch *hexMatchScratch) reset() {
	if scratch.worklist == nil {
		scratch.worklist = scratch.inlineWork[:0]
	} else {
		scratch.worklist = scratch.worklist[:0]
	}
}

// matchEach processes tokens iteratively while retaining branch buffers
// across anchor candidates in the same scan.
//
//nolint:revive // argument-limit: hot path avoids allocating an options struct
func (scratch *hexMatchScratch) matchEach(
	tokens []HexPatternToken,
	data []byte,
	pos int,
	xorKey *byte,
	onEnd func(int) bool,
) bool {
	scratch.reset()
	scratch.worklist = append(scratch.worklist, hexWorkItem{tokens, pos})

	for len(scratch.worklist) > 0 {
		item := scratch.worklist[len(scratch.worklist)-1]
		scratch.worklist = scratch.worklist[:len(scratch.worklist)-1]

		toks := item.tokens
		dp := item.dataPos

		// Fast linear path: consume non-branching tokens in a loop.
		for {
			if len(toks) == 0 {
				if !onEnd(dp) {
					return false
				}
				goto nextItem
			}
			if dp >= len(data) {
				head := toks[0]
				if (head.Kind != HexTokenJump && head.Kind != HexTokenAlt) || dp > len(data) || (head.Kind == HexTokenJump && head.Min > 0) {
					goto nextItem
				}
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
					scratch.worklist = append(scratch.worklist, hexWorkItem{tail, dp + jump})
				}
				goto nextItem

			case HexTokenAlt:
				tail := toks[1:]
				for _, alt := range head.Alternatives {
					if len(tail) == 0 {
						scratch.worklist = append(scratch.worklist, hexWorkItem{alt, dp})
						continue
					}
					// Build combined token slice: alt + tail
					combined := make([]HexPatternToken, len(alt)+len(tail))
					copy(combined, alt)
					copy(combined[len(alt):], tail)
					scratch.worklist = append(scratch.worklist, hexWorkItem{combined, dp})
				}
				goto nextItem

			default:
				goto nextItem
			}
		}

	nextItem:
	}

	return true
}
