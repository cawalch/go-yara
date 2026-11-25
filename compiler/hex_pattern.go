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
	Tokens       []HexPatternToken
	XorKeys      []byte
	XorRange     []ast.XorRange
	cacheKey     string
	cacheIndex   int
	scanMetadata *hexScanMetadata
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
	offset    int // min byte offset from pattern start
	maxOffset int // max byte offset from pattern start
	byteVal0  byte
	diff      []byte
	ok        bool
}

// findXorDiffAnchor searches for the longest contiguous run of definite, non-negated literal bytes
// at a bounded byte offset from the start of the pattern.
func findXorDiffAnchor(tokens []HexPatternToken) xorDiffAnchor {
	bestTokIdx := -1
	bestMinOffset := 0
	bestMaxOffset := 0
	bestLen := 0

	currTokIdx := -1
	currMinOffset := 0
	currMaxOffset := 0
	currLen := 0

	minByteOffset := 0
	maxByteOffset := 0

	for i, tok := range tokens {
		isDefinite := (tok.Kind == HexTokenByte && !tok.Negated) ||
			(tok.Kind == HexTokenMasked && tok.Mask == 0xFF && !tok.Negated)
		if isDefinite && maxByteOffset >= 0 {
			if currLen == 0 {
				currTokIdx = i
				currMinOffset = minByteOffset
				currMaxOffset = maxByteOffset
			}
			currLen++
			if currLen > bestLen {
				bestLen = currLen
				bestTokIdx = currTokIdx
				bestMinOffset = currMinOffset
				bestMaxOffset = currMaxOffset
			}
		} else {
			currLen = 0
			currTokIdx = -1
		}

		switch tok.Kind {
		case HexTokenByte, HexTokenMasked, HexTokenWildcard:
			minByteOffset++
			if maxByteOffset >= 0 {
				maxByteOffset++
			}
		case HexTokenJump:
			if tok.Min > 0 {
				minByteOffset += tok.Min
			}
			if tok.Max < 0 || maxByteOffset < 0 {
				maxByteOffset = -1
			} else {
				maxByteOffset += tok.Max
			}
		case HexTokenAlt:
			altMin, altMax := hexTokensAlternativesLengthRange(tok.Alternatives)
			minByteOffset += altMin
			if altMax < 0 || maxByteOffset < 0 {
				maxByteOffset = -1
			} else {
				maxByteOffset += altMax
			}
		}
	}

	if bestLen < 2 {
		return xorDiffAnchor{}
	}

	diff := make([]byte, bestLen-1)
	for j := 0; j < bestLen-1; j++ {
		b0 := tokens[bestTokIdx+j].Value
		b1 := tokens[bestTokIdx+j+1].Value
		diff[j] = b0 ^ b1
	}

	return xorDiffAnchor{
		offset:    bestMinOffset,
		maxOffset: bestMaxOffset,
		byteVal0:  tokens[bestTokIdx].Value,
		diff:      diff,
		ok:        true,
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

const maxPooledHexDiffBuf = 1 << 20 // 1 MiB cap on retained scratch diff buffer

func (scratch *hexMatchScratch) ensureDiffData(data []byte) []byte {
	n := len(data) - 1
	if n <= 0 {
		return nil
	}
	var diff []byte
	if n > maxPooledHexDiffBuf {
		diff = make([]byte, n)
	} else {
		if cap(scratch.diffBuf) < n {
			scratch.diffBuf = make([]byte, n)
		} else {
			scratch.diffBuf = scratch.diffBuf[:n]
		}
		diff = scratch.diffBuf
	}
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
	findHexMatchesEach(pattern, data, done, nil, func(m Match) bool {
		matches = append(matches, m)
		return true
	})
	return matches
}

// findHexMatchesEach invokes onMatch for every hex pattern match found in data.
// It stops traversing immediately if onMatch returns false.
//
// nolint:revive // cancellation signal remains explicit on the matching hot path
func findHexMatchesEach(pattern *HexPattern, data []byte, done <-chan struct{}, scratch *hexMatchScratch, onMatch func(Match) bool) {
	findHexMatchesWithMetadata(pattern, data, done, scratch, onMatch, nil)
}

//nolint:revive // argument-limit: scan state and immutable metadata stay explicit
func findHexMatchesWithMetadata(pattern *HexPattern, data []byte, done <-chan struct{}, scratch *hexMatchScratch, onMatch func(Match) bool, metadata *hexScanMetadata) {
	if pattern == nil || len(pattern.Tokens) == 0 || len(data) == 0 {
		return
	}
	if metadata == nil {
		minLength := hexTokensMinLengthCapped(pattern.Tokens, len(data)+1)
		if minLength > len(data) {
			return
		}
		dynamic := buildHexScanMetadata(pattern, minLength)
		metadata = &dynamic
	}
	if metadata.minLength > len(data) {
		return
	}
	keys := metadata.keys
	if metadata.hasLargeJump {
		if len(keys) == 0 && !hasAllMandatoryHexBytes(pattern.Tokens, data, nil) {
			return
		}
		if len(keys) == 1 && !hasAllMandatoryHexBytes(pattern.Tokens, data, &keys[0]) {
			return
		}
	}
	// Linear anchored scans do not need branch scratch at all.
	anchor := metadata.anchor
	if anchor.ok && anchor.maxOffset >= 0 && len(keys) <= 1 && metadata.linear {
		if scratch != nil {
			scratch.endJumpScan()
		}
		findHexMatchesAnchoredEach(pattern.Tokens, data, keys, metadata, done, nil, onMatch)
		return
	}
	if scratch == nil {
		scratch = &hexMatchScratch{}
	}
	scratch.prepareHexMetadata(pattern.Tokens, metadata)
	defer scratch.endJumpScan()

	// Multi-key XOR can use an invariant differential anchor for 2+ byte runs.
	if len(keys) > 1 {
		diffAnchor := metadata.diffAnchor
		if diffAnchor.ok {
			findHexMatchesXorDiffEach(pattern.Tokens, data, metadata, done, scratch, onMatch)
			return
		}
	}
	if anchor.ok && anchor.maxOffset >= 0 {
		findHexMatchesAnchoredEach(pattern.Tokens, data, keys, metadata, done, scratch, onMatch)
		return
	}
	findHexMatchesBruteForceEach(pattern.Tokens, data, keys, done, scratch, onMatch)
}

// findHexMatchesXorDiffEach uses XOR 1st-order differential skipping for multi-key matching.
//
//nolint:revive // argument-limit: internal traversal helper with cancellation
func findHexMatchesXorDiffEach(
	tokens []HexPatternToken,
	data []byte,
	metadata *hexScanMetadata,
	done <-chan struct{},
	scratch *hexMatchScratch,
	onMatch func(Match) bool,
) {
	anchor := metadata.diffAnchor
	diffData := scratch.ensureDiffData(data)
	if len(diffData) < len(anchor.diff) {
		return
	}
	mask := metadata.keyMask
	linear := metadata.linear
	checkpoint := 0
	pos := 0
	singleByteDiff := len(anchor.diff) == 1
	targetByte := anchor.diff[0]
	var lastChecked [256]int
	if anchor.maxOffset > anchor.offset {
		for i := range lastChecked {
			lastChecked[i] = -1
		}
	}

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
		pos = diffPos + 1

		candidateKey := data[diffPos] ^ anchor.byteVal0
		if !mask.contains(candidateKey) {
			continue
		}

		firstStart := max(0, diffPos-anchor.maxOffset)
		lastStart := min(len(data)-1, diffPos-anchor.offset)
		if anchor.maxOffset > anchor.offset {
			firstStart = max(firstStart, lastChecked[candidateKey]+1)
			if firstStart > lastStart {
				continue
			}
			lastChecked[candidateKey] = lastStart
		}
		for candidateStart := firstStart; candidateStart <= lastStart; candidateStart++ {
			if linear {
				end, ok := matchLinearHexPattern(tokens, data, candidateStart, &candidateKey)
				if !ok {
					continue
				}
				if !onMatch(Match{Offset: int64(candidateStart), Length: end - candidateStart}) {
					return
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
}

// findHexMatchesAnchoredEach scans in key-major order, or once without XOR for empty keys.
//
//nolint:revive // argument-limit: internal traversal helper with cancellation
func findHexMatchesAnchoredEach(
	tokens []HexPatternToken,
	data []byte,
	keys []byte,
	metadata *hexScanMetadata,
	done <-chan struct{},
	scratch *hexMatchScratch,
	onMatch func(Match) bool,
) {
	linear := metadata.linear
	anchor := metadata.anchor
	checkpoint := 0
	for keyIndex := range max(1, len(keys)) {
		var key *byte
		if len(keys) > 0 {
			key = &keys[keyIndex]
		}
		if !scanHexAnchorKey(tokens, data, anchor, key, linear, done, &checkpoint, scratch, onMatch) {
			return
		}
	}
}

// scanHexAnchorKey discovers and verifies candidates for one key. Keeping the
// linear verification here avoids a helper call for every candidate.
//
//nolint:revive // argument-limit: hot traversal keeps callback escape analysis precise
func scanHexAnchorKey(tokens []HexPatternToken, data []byte, anchor anchorInfo, key *byte,
	linear bool, done <-chan struct{}, checkpoint *int, scratch *hexMatchScratch, onMatch func(Match) bool,
) bool {
	targetByte := anchor.byteVal
	if key != nil {
		targetByte ^= *key
	}
	pos := 0
	lastChecked := -1
	for {
		if scanCanceledAt(done, *checkpoint) {
			return false
		}
		(*checkpoint)++
		idx := bytes.IndexByte(data[pos:], targetByte)
		if idx == -1 {
			return true
		}
		matchPos := pos + idx
		pos = matchPos + 1

		first := max(0, matchPos-anchor.maxOffset)
		last := min(len(data), matchPos-anchor.offset)
		if anchor.maxOffset > anchor.offset {
			first = max(first, lastChecked+1)
			if first > last {
				continue
			}
			lastChecked = last
		}
		for candidateStart := first; candidateStart <= last; candidateStart++ {
			if linear {
				end, ok := matchLinearHexPattern(tokens, data, candidateStart, key)
				if !ok {
					continue
				}
				if !onMatch(Match{Offset: int64(candidateStart), Length: end - candidateStart}) {
					return false
				}
				continue
			}
			if !scratch.matchEach(tokens, data, candidateStart, key, func(end int) bool {
				if end <= candidateStart {
					return true
				}
				return onMatch(Match{
					Offset: int64(candidateStart),
					Length: end - candidateStart,
				})
			}) {
				return false
			}
		}
	}
}

// findHexMatchesBruteForceEach scans in position-major order, with optional XOR keys.
//
//nolint:revive // argument-limit: internal traversal helper with cancellation
func findHexMatchesBruteForceEach(
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
		for keyIndex := range max(1, len(keys)) {
			var key *byte
			if len(keys) > 0 {
				key = &keys[keyIndex]
			}
			if !scratch.matchEach(tokens, data, start, key, func(end int) bool {
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
	var seen [256]bool
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
			if seen[b] {
				continue
			}
			seen[b] = true
			keys = append(keys, b)
		}
	}
	return keys
}

type hexWorkItem struct {
	tokens       []HexPatternToken
	dataPos      int
	continuation int
}

type jumpByteCacheEntry struct {
	byteVal      byte
	keyTag       int16
	primary      bool
	cacheStart   int
	nextHit      int
	scannedUntil int
}

type hexJumpCache struct {
	entries [8]jumpByteCacheEntry
	next    int
	active  bool
}

type hexMatchScratch struct {
	worklist            []hexWorkItem
	diffBuf             []byte
	inlineWork          [16]hexWorkItem
	jumpCache           *hexJumpCache
	continuations       []hexContinuation
	inlineContinuations [8]hexContinuation
	failed              map[hexFailureState]struct{}
	failureFrames       []hexFailureFrame
	planTokens          []HexPatternToken
	candidateStarts     []int
	fanoutCandidates    [][]int
	fanoutTouched       []int
	planPrefix          int
	planSingleJump      bool
	planMemoize         bool
}

// hexLargeJumpSpan is the jump-range threshold below which direct branch pushes
// are faster than indexed byte reachability probing.
const hexLargeJumpSpan = 16

func hexTokensHasLargeJump(tokens []HexPatternToken, maxSmallSpan int) bool {
	for _, tok := range tokens {
		switch tok.Kind {
		case HexTokenJump:
			if tok.Max < 0 || tok.Max-max(tok.Min, 0) > maxSmallSpan {
				return true
			}
		case HexTokenAlt:
			for _, alt := range tok.Alternatives {
				if hexTokensHasLargeJump(alt, maxSmallSpan) {
					return true
				}
			}
		}
	}
	return false
}

func (scratch *hexMatchScratch) beginJumpScan(_ *byte) {
	if scratch.jumpCache == nil {
		scratch.jumpCache = new(hexJumpCache)
	}
	scratch.jumpCache.active = true
	scratch.jumpCache.next = 0
	for i := range scratch.jumpCache.entries {
		scratch.jumpCache.entries[i].keyTag = -2
	}
}

func (scratch *hexMatchScratch) endJumpScan() {
	scratch.planTokens = nil
	if scratch.jumpCache != nil {
		scratch.jumpCache.active = false
	}
}

func (scratch *hexMatchScratch) reset() {
	if scratch.worklist == nil {
		scratch.worklist = scratch.inlineWork[:0]
	} else {
		scratch.worklist = scratch.worklist[:0]
	}
}

func hexXORKeyTag(xorKey *byte) int16 {
	if xorKey == nil {
		return -1
	}
	return int16(*xorKey)
}

func definiteHexByte(tok HexPatternToken, xorKey *byte) (byte, bool) {
	if tok.Negated {
		return 0, false
	}
	if tok.Kind != HexTokenByte && (tok.Kind != HexTokenMasked || tok.Mask != 0xFF) {
		return 0, false
	}
	b := tok.Value
	if xorKey != nil {
		b ^= *xorKey
	}
	return b, true
}

func hasAllMandatoryHexBytes(tokens []HexPatternToken, data []byte, xorKey *byte) bool {
	for _, tok := range tokens {
		if b, ok := definiteHexByte(tok, xorKey); ok {
			if bytes.IndexByte(data, b) == -1 {
				return false
			}
		}
	}
	return true
}

func hexTokensMinLengthCapped(tokens []HexPatternToken, limit int) int {
	total := 0
	for _, tok := range tokens {
		switch tok.Kind {
		case HexTokenByte, HexTokenMasked, HexTokenWildcard:
			total++
		case HexTokenJump:
			if tok.Min > 0 {
				if tok.Min >= limit-total {
					return limit
				}
				total += tok.Min
			}
		case HexTokenAlt:
			best := -1
			for _, alt := range tok.Alternatives {
				altMin := hexTokensMinLengthCapped(alt, limit-total)
				if best == -1 || altMin < best {
					best = altMin
				}
			}
			if best > 0 {
				total += best
			}
		}
		if total >= limit {
			return limit
		}
	}
	return total
}

//nolint:revive // argument-limit: hot path helper keeps state explicit
func (scratch *hexMatchScratch) lookupJumpCache(b byte, keyTag int16, lo, hi int, primary bool) (searchFrom, reuseIdx, cachedHit int, done bool) {
	searchFrom = lo
	reuseIdx = -1
	for idx := range scratch.jumpCache.entries {
		e := &scratch.jumpCache.entries[idx]
		if e.keyTag != keyTag || e.byteVal != b {
			continue
		}
		if e.primary == primary && (e.nextHit == -1 || e.nextHit < lo) {
			reuseIdx = idx
		}
		if lo < e.cacheStart {
			continue
		}
		if e.nextHit >= lo {
			if e.nextHit < hi {
				return 0, 0, e.nextHit, true
			}
			return 0, 0, -1, true
		}
		if lo < e.scannedUntil {
			if hi <= e.scannedUntil {
				return 0, 0, -1, true
			}
			searchFrom = max(searchFrom, e.scannedUntil)
		}
	}
	return searchFrom, reuseIdx, 0, false
}

//nolint:revive // argument-limit: hot path helper keeps state explicit
func (scratch *hexMatchScratch) findNextByte(data []byte, b byte, keyTag int16, lo, hi int, primary bool) int {
	if lo >= hi || lo >= len(data) {
		return -1
	}
	hi = min(hi, len(data))
	searchFrom := lo
	reuseIdx := -1

	jumpScanOn := scratch.jumpCache != nil && scratch.jumpCache.active
	if jumpScanOn {
		var cachedHit int
		var done bool
		searchFrom, reuseIdx, cachedHit, done = scratch.lookupJumpCache(b, keyTag, lo, hi, primary)
		if done {
			return cachedHit
		}
	}

	idx := bytes.IndexByte(data[searchFrom:hi], b)
	hit := -1
	if idx >= 0 {
		hit = searchFrom + idx
	}
	if jumpScanOn {
		if reuseIdx == -1 {
			reuseIdx = scratch.jumpCache.next
			scratch.jumpCache.next = (scratch.jumpCache.next + 1) % len(scratch.jumpCache.entries)
		}
		// bytes.IndexByte stops at the first match, so only [lo, hit+1) is known
		// when hit >= 0; the full [lo, hi) window is scanned only on a miss.
		scannedUntil := hi
		if hit >= 0 {
			scannedUntil = hit + 1
		}
		scratch.jumpCache.entries[reuseIdx] = jumpByteCacheEntry{
			byteVal:      b,
			keyTag:       keyTag,
			primary:      primary,
			cacheStart:   lo,
			nextHit:      hit,
			scannedUntil: scannedUntil,
		}
	}
	return hit
}

//nolint:revive // argument-limit: hot path helper
func (scratch *hexMatchScratch) tailAnchorCanReach(
	tail []HexPatternToken,
	data []byte,
	minPos, maxPos int,
	xorKey *byte,
) bool {
	anchor := findAnchorByte(tail)
	if !anchor.ok {
		return true
	}
	lo := minPos + anchor.offset
	if lo >= len(data) {
		return false
	}
	hi := len(data)
	if anchor.maxOffset >= 0 {
		hi = min(hi, maxPos+anchor.maxOffset+1)
	}
	b := anchor.byteVal
	if xorKey != nil {
		b ^= *xorKey
	}
	return scratch.findNextByte(data, b, hexXORKeyTag(xorKey), lo, hi, true) >= 0
}

//nolint:revive // argument-limit: hot path helper
func (scratch *hexMatchScratch) tailCanReachWindow(
	tail []HexPatternToken,
	data []byte,
	minPos, maxPos int,
	xorKey *byte,
) bool {
	keyTag := hexXORKeyTag(xorKey)
	for offset, tok := range tail {
		if tok.Kind == HexTokenJump || tok.Kind == HexTokenAlt {
			return scratch.tailAnchorCanReach(tail[offset:], data, minPos+offset, maxPos+offset, xorKey)
		}
		b, ok := definiteHexByte(tok, xorKey)
		if !ok {
			continue
		}
		lo := minPos + offset
		hi := min(len(data), maxPos+offset+1)
		if scratch.findNextByte(data, b, keyTag, lo, hi, true) < 0 {
			return false
		}
	}
	return true
}

//nolint:revive // argument-limit: hot path helper
func (scratch *hexMatchScratch) pushJumpByteMatches(
	nextTail []HexPatternToken,
	continuation int,
	data []byte,
	lo, hi int,
	targetByte byte,
	keyTag int16,
) {
	base := len(scratch.worklist)
	pos := scratch.findNextByte(data, targetByte, keyTag, lo, hi, true)
	for pos >= 0 {
		scratch.worklist = append(scratch.worklist, hexWorkItem{tokens: nextTail, dataPos: pos + 1, continuation: continuation})
		pos = scratch.findNextByte(data, targetByte, keyTag, pos+1, hi, false)
	}
	slices.Reverse(scratch.worklist[base:])
}

//go:noinline
//nolint:revive // argument-limit: cold large-jump fallback kept out of matchEach inline budget
func (scratch *hexMatchScratch) pushLargeJumpBranches(
	tail []HexPatternToken,
	continuation int,
	data []byte,
	dp, minJ, headMax int,
	xorKey *byte,
) {
	if scratch.jumpCache == nil || !scratch.jumpCache.active {
		scratch.beginJumpScan(nil)
	}
	tailMinLen := hexTokensMinLengthCapped(tail, len(data)-dp+1)
	maxJ := len(data) - dp - tailMinLen
	if headMax >= 0 && headMax < maxJ {
		maxJ = headMax
	}
	if maxJ < minJ {
		return
	}
	if len(tail) > 0 {
		if !scratch.tailCanReachWindow(tail, data, dp+minJ, dp+maxJ, xorKey) {
			return
		}
		if targetByte, hasByte := definiteHexByte(tail[0], xorKey); hasByte {
			scratch.pushJumpByteMatches(tail[1:], continuation, data, dp+minJ, dp+maxJ+1, targetByte, hexXORKeyTag(xorKey))
			return
		}
	}
	for jump := maxJ; jump >= minJ; jump-- {
		scratch.worklist = append(scratch.worklist, hexWorkItem{tokens: tail, dataPos: dp + jump, continuation: continuation})
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
	if len(tokens) == 0 {
		return onEnd(pos)
	}
	if len(scratch.planTokens) != len(tokens) || &scratch.planTokens[0] != &tokens[0] {
		scratch.prepareHex(tokens)
	}
	// Reject the common prefix before preparing per-candidate branch state.
	if scratch.planPrefix > 0 {
		end, ok := matchLinearHexPattern(tokens[:scratch.planPrefix], data, pos, xorKey)
		if !ok {
			return true
		}
		tokens, pos = tokens[scratch.planPrefix:], end
	}
	if len(tokens) == 0 {
		return onEnd(pos)
	}
	if scratch.planSingleJump {
		return scratch.matchSingleJump(tokens, data, pos, xorKey, onEnd)
	}
	scratch.reset()
	scratch.resetContinuations()
	memoize := scratch.planMemoize
	if memoize {
		clear(scratch.failed)
	}
	scratch.failureFrames = scratch.failureFrames[:0]
	var endCount uint64
	scratch.worklist = append(scratch.worklist, hexWorkItem{tokens: tokens, dataPos: pos})

	for {
		if memoize {
			scratch.finishFailures(len(scratch.worklist), endCount)
		}
		if len(scratch.worklist) == 0 {
			break
		}
		item := scratch.worklist[len(scratch.worklist)-1]
		scratch.worklist = scratch.worklist[:len(scratch.worklist)-1]

		if memoize {
			state := item.failureState()
			if _, failed := scratch.failed[state]; failed {
				continue
			}
			scratch.failureFrames = append(scratch.failureFrames, hexFailureFrame{state: state, depth: len(scratch.worklist), endCount: endCount})
		}

		toks := item.tokens
		dp := item.dataPos
		continuation := item.continuation

		// Fast linear path: consume non-branching tokens in a loop.
		for {
			if len(toks) == 0 {
				if dp > len(data) {
					goto nextItem
				}
				if continuation != 0 {
					tail := scratch.continuations[continuation-1]
					scratch.worklist = append(scratch.worklist, hexWorkItem{tokens: tail.tokens, dataPos: dp, continuation: tail.next})
					goto nextItem
				}
				endCount++
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
				minJ := max(head.Min, 0)
				maxJ := head.Max
				tail := toks[1:]
				if maxJ < 0 || maxJ-minJ > hexLargeJumpSpan {
					scratch.pushLargeJumpBranches(tail, continuation, data, dp, minJ, maxJ, xorKey)
					goto nextItem
				}
				maxJ = min(maxJ, len(data)-dp)
				if maxJ < minJ {
					goto nextItem
				}
				// Push branches in reverse order so smallest jump is processed first.
				for jump := maxJ; jump >= minJ; jump-- {
					scratch.worklist = append(scratch.worklist, hexWorkItem{tokens: tail, dataPos: dp + jump, continuation: continuation})
				}
				goto nextItem

			case HexTokenAlt:
				continuation = scratch.internContinuation(toks[1:], continuation)
				for _, alt := range head.Alternatives {
					scratch.worklist = append(scratch.worklist, hexWorkItem{tokens: alt, dataPos: dp, continuation: continuation})
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
