package compiler

// Preserve the original concatenating traversal as an order/multiplicity oracle.
//
//nolint:revive // matching oracle uses the production callback signature
func (scratch *hexMatchScratch) referenceMatchEach(
	tokens []HexPatternToken,
	data []byte,
	pos int,
	xorKey *byte,
	onEnd func(int) bool,
) bool {
	scratch.reset()
	scratch.worklist = append(scratch.worklist, hexWorkItem{tokens: tokens, dataPos: pos})

	for len(scratch.worklist) > 0 {
		item := scratch.worklist[len(scratch.worklist)-1]
		scratch.worklist = scratch.worklist[:len(scratch.worklist)-1]

		toks := item.tokens
		dp := item.dataPos

		// Fast linear path: consume non-branching tokens in a loop.
		for {
			if len(toks) == 0 {
				if dp > len(data) {
					goto nextItem
				}
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
					scratch.pushLargeJumpBranches(tail, 0, data, dp, minJ, maxJ, xorKey)
					goto nextItem
				}
				maxJ = min(maxJ, len(data)-dp)
				if maxJ < minJ {
					goto nextItem
				}
				// Push branches in reverse order so smallest jump is processed first.
				for jump := maxJ; jump >= minJ; jump-- {
					scratch.worklist = append(scratch.worklist, hexWorkItem{tokens: tail, dataPos: dp + jump})
				}
				goto nextItem

			case HexTokenAlt:
				tail := toks[1:]
				for _, alt := range head.Alternatives {
					if len(tail) == 0 {
						scratch.worklist = append(scratch.worklist, hexWorkItem{tokens: alt, dataPos: dp})
						continue
					}
					// Build combined token slice: alt + tail
					combined := make([]HexPatternToken, len(alt)+len(tail))
					copy(combined, alt)
					copy(combined[len(alt):], tail)
					scratch.worklist = append(scratch.worklist, hexWorkItem{tokens: combined, dataPos: dp})
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
