package compiler

import (
	"slices"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

type regexVerifiedSpan struct {
	end   int
	order boundedAtomOrder
}

// Verify each atom occurrence once in each direction. The backward VM emits
// all starts together instead of rerunning the whole expression at each start.
// Only the winning occurrence per start is retained, regardless of how many
// overlapping atoms verify it.
//
//nolint:revive // scanner context and pattern metadata stay explicit
func addBoundedRegexVerifications(ctx *MatchContext, id string, pattern RegexPattern, data []byte, modifiers []ast.StringModifier) {
	best := make(map[int]regexVerifiedSpan)
	bs := ctx.acquireRegexBatch(len(pattern.Code))
	wide := hasModifier(modifiers, ast.StringModifierWide)
	ascii := hasModifier(modifiers, ast.StringModifierASCII)
	encodings, count := regexEncodingOrder(pattern.Flags, wide, ascii)
	greedy := pattern.Flags&regex.FlagsGreedy != 0
	for _, isWide := range encodings[:count] {
		flags := pattern.Flags &^ (regex.FlagsWide | regex.FlagsExhaustive | regex.FlagsFullwordEnd | regex.FlagsBackwards)
		step := 1
		if isWide {
			flags |= regex.FlagsWide
			step = 2
		}
		for index, atom := range pattern.verification.Atoms {
			guard := regexVerificationWordGuard{enabled: hasModifier(modifiers, ast.StringModifierFullword), wide: isWide && flags&regexASCIIWordBoundary == 0, lastStart: [2]int{-1, -1}}
			width := min(len(atom.Bytes), 4/step)
			// Search the known prefix without expanding wildcard/case variants.
			var literal [4]byte
			size := 0
			for i := range width {
				if atom.Mask[i] != 255 {
					break
				}
				literal[size] = atom.Bytes[i]
				size += step
			}
			searcher := newRegexLiteralSearcher(data, literal[:size], flags)
			anchoredStart := pattern.Flags&regexStartAtomEntries != 0 && slices.Contains(atom.Backward, regex.OpMatchAtStart)
			limit := len(data)
			if anchoredStart {
				limit = min(limit, 1)
			}

			for at := 0; at < limit; at++ {
				if scanCanceled(ctx.cancelDone) {
					return
				}
				if width > 0 && !anchoredStart {
					at = searcher.index(at)
					if at < 0 {
						break
					}
				}
				if !guard.allows(data, at, ctx.cancelDone) {
					continue
				}
				order, ok := verificationAtomOrder(atom, data, at, index, step, flags)
				if !ok {
					continue
				}
				// A lower-priority atom cannot replace an already accepted start.
				if greedy && pattern.Flags&regexStartAtomEntries != 0 {
					if previous, exists := best[at]; exists && order.before(previous.order) {
						continue
					}
				}
				// New match-start plans have only assertions behind the atom.
				// Check them before a potentially long forward attempt; a failed
				// anchor must not rescan the suffix at every later atom hit.
				if pattern.Flags&regexStartAtomEntries != 0 && len(atom.Backward) > 1 {
					starts, err := regex.ExecVerifyBatchWithCancel(bs, atom.Backward, data, flags|regex.FlagsBackwards, at, 0, ctx.cancelDone)
					if err != nil {
						return
					}
					if len(starts) == 0 {
						continue
					}
				}
				ends, err := regex.ExecVerifyBatchWithCancel(bs, atom.Forward, data, flags, at, regexVerificationDistance, ctx.cancelDone)
				if err != nil {
					return
				}
				if len(ends) == 0 {
					continue
				}
				end := ends[0]
				if ctx.maxMatchSpan <= 0 && hasModifier(modifiers, ast.StringModifierFullword) && !isFullwordMatch(data, 0, end, isWide && flags&regexASCIIWordBoundary == 0) {
					continue
				}
				starts := []int{at}
				if len(atom.Backward) > 1 && pattern.Flags&regexStartAtomEntries == 0 {
					starts, err = regex.ExecVerifyBatchWithCancel(bs, atom.Backward, data, flags|regex.FlagsBackwards, at, regexVerificationDistance, ctx.cancelDone)
					if err != nil {
						return
					}
				}
				for _, start := range starts {
					candidateEnd := end
					if ctx.maxMatchSpan > 0 && candidateEnd-start > ctx.maxMatchSpan {
						limit := start + ctx.maxMatchSpan
						if at > limit {
							continue
						}
						capped, err := regex.ExecVerifyBatchWithCancel(nil, atom.Forward, data[:limit], flags, at, min(regexVerificationDistance, limit-at), ctx.cancelDone)
						if err != nil {
							return
						}
						if len(capped) == 0 {
							continue
						}
						candidateEnd = capped[0]
					}
					match := Match{Pattern: id, Offset: int64(start), Length: candidateEnd - start}
					if !matchPassesModifiers(data, match, modifiers, isWide && flags&regexASCIIWordBoundary == 0) {
						continue
					}
					previous, exists := best[start]
					if !exists || greedy != order.before(previous.order) {
						best[start] = regexVerifiedSpan{candidateEnd, order}
					}
				}
			}
		}
	}
	starts := make([]int, 0, len(best))
	for start := range best {
		starts = append(starts, start)
	}
	slices.Sort(starts)
	for _, start := range starts {
		ctx.AddMatch(Match{Pattern: id, Offset: int64(start), Length: best[start].end - start})
	}
}

//nolint:revive // atom position and encoding determine AC order
func verificationAtomOrder(atom regexVerificationAtom, data []byte, at, index, step int, flags regex.Flags) (boundedAtomOrder, bool) {
	width := min(len(atom.Bytes), 4/step)
	order := boundedAtomOrder{end: at + width*step, length: width * step, index: index, wide: step == 2}
	if width == 0 {
		// Atomless callbacks verify ASCII then wide at each input position.
		order.wide = false
		order.index = step - 1
	} else if step == 2 {
		order.index = -index
	}
	if order.end > len(data) {
		return order, false
	}
	for i := range width {
		got, want := data[at+i*step], atom.Bytes[i]
		mask := atom.Mask[i]
		if mask == 0 && flags&regex.FlagsNoCase != 0 && toLowerTable[got] >= 'a' && toLowerTable[got] <= 'z' {
			order.variant = true
		}
		if mask != 0 && got&mask != want {
			if flags&regex.FlagsNoCase == 0 || toLowerTable[got]&mask != toLowerTable[want] {
				return order, false
			}
			order.variant = true
		}
		if step == 2 && data[at+i*step+1] != 0 {
			return order, false
		}
	}
	if order.variant {
		order.index = -order.index
	}
	return order, true
}

func needsBoundedRegexVerification(pattern RegexPattern, data []byte, maxSpan int) bool {
	plan := pattern.verification
	if plan != nil && pattern.Flags&regexStartAtomEntries != 0 {
		return true
	}
	if plan == nil || plan.ForwardOnly || len(data) <= regexVerificationDistance || maxSpan > 0 && maxSpan <= regexVerificationDistance {
		return false
	}
	// Any match longer than the budget crosses one of these grid points.
	// Prove short runs locally around the grid, avoiding a full-buffer walk
	// for sparse or separator-rich inputs. Long runs stop this check early.
	for at := regexVerificationDistance; at < len(data); at += regexVerificationDistance {
		if !plan.Allowed[data[at]] {
			continue
		}
		left, right := at, at+1
		for left > 0 && right-left <= regexVerificationDistance && plan.Allowed[data[left-1]] {
			left--
		}
		for right < len(data) && right-left <= regexVerificationDistance && plan.Allowed[data[right]] {
			right++
		}
		if right-left > regexVerificationDistance {
			return true
		}
	}
	return false
}

// Fullword boundaries rule out atom positions before either VM runs. Cursors
// advance monotonically, so a long word costs one boundary walk rather than
// a separate backwards search at each overlapping atom.
type regexVerificationWordGuard struct {
	enabled, wide      bool
	startCursor        int
	lastStart, nextEnd [2]int
}

func (guard *regexVerificationWordGuard) allows(data []byte, at int, done <-chan struct{}) bool {
	if !guard.enabled {
		return true
	}
	for guard.startCursor <= at {
		if scanCanceledAt(done, guard.startCursor) {
			return false
		}
		if isFullwordStart(data, guard.startCursor, guard.wide) {
			alignment := 0
			if guard.wide {
				alignment = guard.startCursor & 1
			}
			guard.lastStart[alignment] = guard.startCursor
		}
		guard.startCursor++
	}
	alignment, step := 0, 1
	if guard.wide {
		alignment, step = at&1, 2
	}
	if guard.lastStart[alignment] < at-regexVerificationDistance {
		return false
	}
	guard.nextEnd[alignment] = max(guard.nextEnd[alignment], at)
	for !isFullwordMatch(data, 0, guard.nextEnd[alignment], guard.wide) {
		if scanCanceledAt(done, guard.nextEnd[alignment]) {
			return false
		}
		guard.nextEnd[alignment] += step
	}
	return guard.nextEnd[alignment] <= at+regexVerificationDistance
}
