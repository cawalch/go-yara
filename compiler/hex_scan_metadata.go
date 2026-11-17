package compiler

import "math"

// hexScanMetadata belongs to an immutable compiled program. Standalone matching
// deliberately rebuilds it because callers may edit public HexPattern fields.
type hexScanMetadata struct {
	keys         []byte
	anchor       anchorInfo
	diffAnchor   xorDiffAnchor
	keyMask      xorKeyMask
	minLength    int
	prefix       int
	hasLargeJump bool
	linear       bool
	singleJump   bool
	memoize      bool
}

func prepareHexScanMetadata(pattern *HexPattern) *hexScanMetadata {
	metadata := buildHexScanMetadata(pattern, hexTokensMinLengthCapped(pattern.Tokens, math.MaxInt))
	return &metadata
}

func buildHexScanMetadata(pattern *HexPattern, minLength int) hexScanMetadata {
	keys := pattern.XorKeys
	if len(keys) == 0 && len(pattern.XorRange) > 0 {
		keys = expandXorKeys(pattern.XorRange)
	}
	metadata := hexScanMetadata{
		keys: keys, minLength: minLength,
		anchor:       findAnchorByte(pattern.Tokens),
		hasLargeJump: hexTokensHasLargeJump(pattern.Tokens, hexLargeJumpSpan),
	}
	if len(keys) > 1 {
		metadata.diffAnchor = findXorDiffAnchor(pattern.Tokens)
		metadata.keyMask = makeXorKeyMask(keys)
	}
	metadata.prefix, metadata.singleJump, metadata.memoize = classifyHexTokens(pattern.Tokens)
	metadata.linear = metadata.prefix == len(pattern.Tokens)
	return metadata
}

func (scratch *hexMatchScratch) prepareHexMetadata(tokens []HexPatternToken, metadata *hexScanMetadata) {
	scratch.planTokens = tokens
	scratch.planPrefix = metadata.prefix
	scratch.planSingleJump = metadata.singleJump
	scratch.planMemoize = metadata.memoize
}

// Prepared scanning is used only by the immutable program's internal scanners.
// Tests and caller-built rules without preparation retain the dynamic fallback.
//
//nolint:revive // argument-limit: preserve the scanner callback interface
func findPreparedHexMatchesEach(pattern *HexPattern, data []byte, done <-chan struct{}, scratch *hexMatchScratch, onMatch func(Match) bool) {
	var metadata *hexScanMetadata
	if pattern != nil {
		metadata = pattern.scanMetadata
	}
	findHexMatchesWithMetadata(pattern, data, done, scratch, onMatch, metadata)
}
