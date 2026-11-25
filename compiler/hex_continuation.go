package compiler

// A continuation names the shared tail after an alternative. Index zero means
// no tail; nonzero indices remain stable even if the backing slice grows.
type hexContinuation struct {
	tokens []HexPatternToken
	next   int
}

type hexFailureState struct {
	first        *HexPatternToken
	length       int
	dataPos      int
	continuation int
}

func (item hexWorkItem) failureState() hexFailureState {
	state := hexFailureState{length: len(item.tokens), dataPos: item.dataPos, continuation: item.continuation}
	if len(item.tokens) > 0 {
		state.first = &item.tokens[0]
	}
	return state
}

func (scratch *hexMatchScratch) resetContinuations() {
	if scratch.continuations == nil {
		scratch.continuations = scratch.inlineContinuations[:0]
	} else {
		scratch.continuations = scratch.continuations[:0]
	}
}

func (scratch *hexMatchScratch) internContinuation(tokens []HexPatternToken, next int) int {
	if len(tokens) == 0 {
		return next
	}
	// Canonical indices let converging branches share failure-cache entries.
	for i, tail := range scratch.continuations {
		if tail.next == next && len(tail.tokens) == len(tokens) && &tail.tokens[0] == &tokens[0] {
			return i + 1
		}
	}
	scratch.continuations = append(scratch.continuations, hexContinuation{tokens: tokens, next: next})
	return len(scratch.continuations)
}

// A single branch cannot revisit a suffix through multiple branch decisions.
// Avoid failure-cache overhead unless at least two branching tokens occur.
func hexBranchCount(tokens []HexPatternToken, limit int) int {
	count := 0
	for _, tok := range tokens {
		switch tok.Kind {
		case HexTokenJump:
			if tok.Max < 0 || tok.Max > max(tok.Min, 0) {
				count++
			}
		case HexTokenAlt:
			if len(tok.Alternatives) > 1 {
				count++
			}
			for _, alt := range tok.Alternatives {
				count += hexBranchCount(alt, limit-count)
				if count >= limit {
					return count
				}
			}
		}
		if count >= limit {
			return count
		}
	}
	return count
}

// A frame closes when all work pushed by its state has completed. Only failed
// states are cached: replaying successful states preserves callback multiplicity.
type hexFailureFrame struct {
	state    hexFailureState
	depth    int
	endCount uint64
}

func (scratch *hexMatchScratch) finishFailures(depth int, endCount uint64) {
	for len(scratch.failureFrames) > 0 {
		last := len(scratch.failureFrames) - 1
		frame := scratch.failureFrames[last]
		if frame.depth != depth {
			return
		}
		scratch.failureFrames = scratch.failureFrames[:last]
		if frame.endCount == endCount {
			if scratch.failed == nil {
				scratch.failed = make(map[hexFailureState]struct{})
			}
			scratch.failed[frame.state] = struct{}{}
		}
	}
}

// Keep ordinary single-gap patterns out of continuation/failure bookkeeping.
//
//nolint:revive // matching callback and XOR key remain explicit
func (scratch *hexMatchScratch) matchSingleJump(tokens []HexPatternToken, data []byte, pos int, xorKey *byte, onEnd func(int) bool) bool {
	head, tail := tokens[0], tokens[1:]
	if pos > len(data) || pos == len(data) && head.Min > 0 {
		return true
	}
	minJump := max(head.Min, 0)
	if head.Max < 0 || head.Max-minJump > hexLargeJumpSpan {
		return scratch.matchLargeSingleJump(head, tail, data, pos, minJump, xorKey, onEnd)
	}
	maxJump := min(head.Max, len(data)-pos)
	for jump := minJump; jump <= maxJump; jump++ {
		if len(tail) == 0 {
			if !onEnd(pos + jump) {
				return false
			}
		} else if end, ok := matchLinearHexPattern(tail, data, pos+jump, xorKey); ok && !onEnd(end) {
			return false
		}
		if jump == maxJump {
			break // Caller-built bounds may reach the platform's maximum int.
		}
	}
	return true
}

//nolint:revive // argument-limit: direct large-jump helper avoids heap allocation
func (scratch *hexMatchScratch) matchLargeSingleJump(
	head HexPatternToken,
	tail []HexPatternToken,
	data []byte,
	pos, minJump int,
	xorKey *byte,
	onEnd func(int) bool,
) bool {
	if len(tail) > 0 {
		if targetByte, hasByte := definiteHexByte(tail[0], xorKey); hasByte {
			return scratch.matchLargeJumpAnchored(head, tail, data, pos, minJump, targetByte, xorKey, onEnd)
		}
	}
	scratch.reset()
	scratch.pushLargeJumpBranches(tail, 0, data, pos, minJump, head.Max, xorKey)
	for len(scratch.worklist) > 0 {
		last := len(scratch.worklist) - 1
		item := scratch.worklist[last]
		scratch.worklist = scratch.worklist[:last]
		if end, ok := matchLinearHexPattern(item.tokens, data, item.dataPos, xorKey); ok && !onEnd(end) {
			return false
		}
	}
	return true
}

//nolint:revive // argument-limit: direct large-jump helper avoids heap allocation
func (scratch *hexMatchScratch) matchLargeJumpAnchored(
	head HexPatternToken,
	tail []HexPatternToken,
	data []byte,
	pos, minJump int,
	targetByte byte,
	xorKey *byte,
	onEnd func(int) bool,
) bool {
	if scratch.jumpCache == nil || !scratch.jumpCache.active {
		scratch.beginJumpScan(nil)
	}
	maxJ := len(data) - pos - len(tail)
	if head.Max >= 0 && head.Max < maxJ {
		maxJ = head.Max
	}
	if maxJ < minJump {
		return true
	}
	lo, hi := pos+minJump, pos+maxJ+1
	keyTag := hexXORKeyTag(xorKey)
	p := scratch.findNextByte(data, targetByte, keyTag, lo, hi, true)
	for p >= 0 {
		if end, ok := matchLinearHexPattern(tail[1:], data, p+1, xorKey); ok && !onEnd(end) {
			return false
		}
		p = scratch.findNextByte(data, targetByte, keyTag, p+1, hi, false)
	}
	return true
}

// Refresh the token classification at every scan boundary; caller-built public
// HexPatterns may be edited between scans. Anchor candidates reuse this plan.
func (scratch *hexMatchScratch) prepareHex(tokens []HexPatternToken) {
	scratch.planTokens = tokens
	scratch.planPrefix, scratch.planSingleJump, scratch.planMemoize = classifyHexTokens(tokens)
}

func classifyHexTokens(tokens []HexPatternToken) (prefix int, singleJump, memoize bool) {
	for prefix < len(tokens) && tokens[prefix].Kind != HexTokenJump && tokens[prefix].Kind != HexTokenAlt {
		prefix++
	}
	if prefix == len(tokens) {
		return prefix, false, false
	}
	singleJump = prefix < len(tokens) && tokens[prefix].Kind == HexTokenJump && isLinearHexPattern(tokens[prefix+1:])
	memoize = !singleJump && hexBranchCount(tokens, 2) >= 2
	return prefix, singleJump, memoize
}
