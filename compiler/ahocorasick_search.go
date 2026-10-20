package compiler

import (
	"bytes"
	"iter"

	"github.com/cawalch/go-yara/regex"
)

func (ac *acAutomaton) rootIsDense16(data []byte) bool {
	sample := data
	if len(sample) > 256 {
		sample = sample[:256]
	}
	rootTransitions := &ac.transitions16[0]
	hits := 0
	for _, b := range sample {
		if rootTransitions[b] != 0 {
			hits++
			if hits > 16 {
				return true
			}
		}
	}
	return false
}

const (
	maxSparseRootTransitions = 4
	rootCandidateExhausted   = -1
	rootCandidateUnsearched  = -2
)

type rootLane struct {
	value  byte
	isFold bool
}

// rootCandidateCursor keeps one next-occurrence cursor per root transition.
// Every lane advances monotonically, so an absent root byte is searched once
// instead of rescanning the remaining input at every candidate from another
// lane.
type rootCandidateCursor struct {
	lanes     []rootLane
	positions [maxSparseRootTransitions]int
}

func newRootCandidateCursor(lanes []rootLane) rootCandidateCursor {
	cursor := rootCandidateCursor{lanes: lanes}
	for index := range cursor.positions {
		cursor.positions[index] = rootCandidateUnsearched
	}
	return cursor
}

func (cursor *rootCandidateCursor) next(data []byte, from int) int {
	best := -1
	for index, lane := range cursor.lanes {
		position := cursor.positions[index]
		if position == rootCandidateExhausted {
			continue
		}
		if position < from {
			var relative int
			if lane.isFold {
				relative = indexASCIIFoldByte(data[from:], lane.value)
			} else {
				relative = bytes.IndexByte(data[from:], lane.value)
			}
			if relative < 0 {
				cursor.positions[index] = rootCandidateExhausted
				continue
			}
			position = from + relative
			cursor.positions[index] = position
		}
		if best < 0 || position < best {
			best = position
		}
	}
	return best
}

func (cursor *rootCandidateCursor) nextWithCancel(data []byte, from int, done <-chan struct{}) int {
	best := -1
	for index, lane := range cursor.lanes {
		position := cursor.positions[index]
		if position == rootCandidateExhausted {
			continue
		}
		if position < from {
			var positionFound int
			if lane.isFold {
				positionFound = indexASCIIFoldByteWithCancel(data, from, lane.value, done)
			} else {
				positionFound = indexByteWithCancel(data, from, lane.value, done)
			}
			if positionFound < 0 {
				cursor.positions[index] = rootCandidateExhausted
				continue
			}
			position = positionFound
			cursor.positions[index] = position
		}
		if best < 0 || position < best {
			best = position
		}
	}
	return best
}

//nolint:revive // cancellation-aware hot path avoids an options allocation
func indexByteWithCancel(data []byte, from int, value byte, done <-chan struct{}) int {
	for windowStart := from; windowStart < len(data); windowStart += cancelableSearchWindow {
		if scanCanceled(done) {
			return -1
		}
		windowEnd := min(windowStart+cancelableSearchWindow, len(data))
		if relative := bytes.IndexByte(data[windowStart:windowEnd], value); relative >= 0 {
			return windowStart + relative
		}
	}
	return -1
}

//nolint:revive // cancellation-aware hot path avoids an options allocation
func indexASCIIFoldByteWithCancel(data []byte, from int, value byte, done <-chan struct{}) int {
	for windowStart := from; windowStart < len(data); windowStart += cancelableSearchWindow {
		if scanCanceled(done) {
			return -1
		}
		windowEnd := min(windowStart+cancelableSearchWindow, len(data))
		if relative := indexASCIIFoldByte(data[windowStart:windowEnd], value); relative >= 0 {
			return windowStart + relative
		}
	}
	return -1
}

func (ac *acAutomaton) yieldMatches(state int32, offset int, yield func(acMatch) bool) bool {
	outputStart := ac.states[state].outputStart
	outputEnd := ac.states[state].outputEnd
	for idx := outputStart; idx < outputEnd; idx++ {
		stringIndex := ac.outputs[idx]
		if stringIndex < 0 || int(stringIndex) >= len(ac.strings) {
			continue
		}
		stringInfo := ac.strings[stringIndex]
		if !yield(acMatch{
			StringIndex: int(stringIndex),
			StringID:    stringInfo.Identifier,
			Backtrack:   offset + 1 - stringInfo.Length,
		}) {
			return false
		}
	}
	return true
}

func indexSinglePattern(data []byte, pattern []byte, noCase bool) int {
	if len(pattern) == 0 || len(pattern) > len(data) {
		return -1
	}
	if !noCase {
		return bytes.Index(data, pattern)
	}

	if len(pattern) == 1 {
		return indexASCIIFoldByte(data, pattern[0])
	}

	last := len(data) - len(pattern)
	for pos := 0; pos <= last; {
		rel := indexASCIIFoldByte(data[pos:last+1], pattern[0])
		if rel < 0 {
			return -1
		}
		candidate := pos + rel
		matched := true
		for idx := 1; idx < len(pattern); idx++ {
			if toLowerTable[data[candidate+idx]] != toLowerTable[pattern[idx]] {
				matched = false
				break
			}
		}
		if matched {
			return candidate
		}
		pos = candidate + 1
	}
	return -1
}

func singlePatternIsDense(data []byte, pattern []byte, noCase bool) bool {
	const sampleSize = 256
	if len(data) > sampleSize {
		data = data[:sampleSize]
	}
	matches := 0
	for pos := 0; pos <= len(data)-len(pattern); {
		rel := indexSinglePattern(data[pos:], pattern, noCase)
		if rel < 0 {
			return false
		}
		matches++
		if matches == 8 {
			return true
		}
		pos += rel + 1
	}
	return false
}

func (ac *acAutomaton) rootIsDense(data []byte) bool {
	sample := data
	if len(sample) > 256 {
		sample = sample[:256]
	}
	rootTransitions := &ac.states[0].transitions
	hits := 0
	for _, b := range sample {
		if rootTransitions[b] != 0 {
			hits++
			if hits > 16 {
				return true
			}
		}
	}
	return false
}

// searchSinglePattern uses the platform byte-search primitives when an
// automaton contains only one concrete pattern. This avoids walking the AC
// state machine for the common one-rule/one-string case while preserving
// overlapping matches and nocase semantics.
func (ac *acAutomaton) searchSinglePattern(data []byte, yield func(acMatch) bool) {
	info := ac.strings[0]
	noCase := info.Flags&regex.FlagsNoCase != 0
	for pos := 0; pos <= len(data)-len(info.Data); {
		rel := indexSinglePattern(data[pos:], info.Data, noCase)
		if rel < 0 {
			return
		}
		start := pos + rel
		if !yield(acMatch{
			StringIndex: 0,
			StringID:    info.Identifier,
			Backtrack:   start,
		}) {
			return
		}
		pos = start + 1
	}
}

func (ac *acAutomaton) searchSinglePatternWithCancel(
	data []byte,
	yield func(acMatch) bool,
	done <-chan struct{},
) {
	info := ac.strings[0]
	noCase := info.Flags&regex.FlagsNoCase != 0
	for pos := 0; pos <= len(data)-len(info.Data); {
		rel := indexSinglePatternWithCancel(data[pos:], info.Data, noCase, done)
		if rel < 0 {
			return
		}
		start := pos + rel
		if !yield(acMatch{
			StringIndex: 0,
			StringID:    info.Identifier,
			Backtrack:   start,
		}) {
			return
		}
		pos = start + 1
	}
}

//nolint:revive // cancellation-aware hot path avoids an options allocation
func indexSinglePatternWithCancel(data, pattern []byte, noCase bool, done <-chan struct{}) int {
	if len(pattern) == 0 || len(pattern) > len(data) {
		return -1
	}
	lastStart := len(data) - len(pattern)
	for windowStart := 0; windowStart <= lastStart; windowStart += cancelableSearchWindow {
		if scanCanceled(done) {
			return -1
		}
		windowEnd := min(windowStart+cancelableSearchWindow, lastStart+1)
		searchEnd := windowEnd + len(pattern) - 1
		if relative := indexSinglePattern(data[windowStart:searchEnd], pattern, noCase); relative >= 0 {
			return windowStart + relative
		}
	}
	return -1
}

// SearchWithCancel searches for pattern matches while checking done for cancellation.
func (ac *acAutomaton) SearchWithCancel(data []byte, done <-chan struct{}, yield func(acMatch) bool) {
	if !ac.compiled || len(data) == 0 || scanCanceled(done) {
		return
	}
	if len(ac.strings) == 1 {
		info := ac.strings[0]
		if len(info.Data) > 0 {
			noCase := info.Flags&regex.FlagsNoCase != 0
			if !singlePatternIsDense(data, info.Data, noCase) {
				ac.searchSinglePatternWithCancel(data, yield, done)
				return
			}
		}
	}

	if len(ac.transitions16) > 0 {
		ac.searchWithCancel16(data, done, yield)
		return
	}
	ac.searchWithCancel32(data, done, yield)
}

//nolint:nestif // mirrors Search with bounded cancellation checkpoints
func (ac *acAutomaton) searchWithCancel16(data []byte, done <-chan struct{}, yield func(acMatch) bool) {
	trans := ac.transitions16
	rootTransitions := &trans[0]
	hasOutput := ac.hasOutput
	currentState := uint16(0)
	rootHasNoOutput := !hasOutput[0]

	if rootHasNoOutput && ac.teddy != nil && len(data) >= 256 {
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if i&(scanCancellationInterval-1) == 0 && scanCanceled(done) {
				return
			}
			if currentState == 0 && i >= linearUntil && len(data)-i >= 32 {
				candidate := ac.teddy.findCandidateWithCancel(data, i, done)
				if candidate < 0 {
					i = max(i, len(data)-31)
					if i >= len(data) {
						return
					}
				} else {
					if candidate-i < 64 {
						linearUntil = candidate + 256
					}
					i = candidate
				}
			}
			if currentState == 0 {
				currentState = rootTransitions[data[i]]
				if currentState == 0 {
					continue
				}
			} else {
				currentState = trans[currentState][data[i]]
			}
			if hasOutput[currentState] &&
				!ac.yieldMatchesWithCancel(int32(currentState), i, yield, done) {
				return
			}
		}
		return
	}

	if rootHasNoOutput && len(data) >= 256 && len(ac.rootLanes) > 0 && len(ac.rootLanes) <= maxSparseRootTransitions && !ac.rootIsDense16(data) {
		rootCursor := newRootCandidateCursor(ac.rootLanes)
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if i&(scanCancellationInterval-1) == 0 && scanCanceled(done) {
				return
			}
			if currentState == 0 && i >= linearUntil && len(data)-i >= 256 {
				candidate := rootCursor.nextWithCancel(data, i, done)
				if candidate < 0 {
					return
				}
				if candidate-i < 64 {
					linearUntil = candidate + 256
				}
				i = candidate
			}
			if currentState == 0 {
				currentState = rootTransitions[data[i]]
				if currentState == 0 {
					continue
				}
			} else {
				currentState = trans[currentState][data[i]]
			}
			if hasOutput[currentState] &&
				!ac.yieldMatchesWithCancel(int32(currentState), i, yield, done) {
				return
			}
		}
		return
	}

	for blockStart := 0; blockStart < len(data); blockStart += scanCancellationInterval {
		if scanCanceled(done) {
			return
		}
		blockEnd := min(blockStart+scanCancellationInterval, len(data))
		for relative, b := range data[blockStart:blockEnd] {
			if currentState == 0 {
				currentState = rootTransitions[b]
				if currentState == 0 {
					continue
				}
			} else {
				currentState = trans[currentState][b]
			}
			if hasOutput[currentState] &&
				!ac.yieldMatchesWithCancel(int32(currentState), blockStart+relative, yield, done) {
				return
			}
		}
	}
}

//nolint:nestif // mirrors Search with bounded cancellation checkpoints
func (ac *acAutomaton) searchWithCancel32(data []byte, done <-chan struct{}, yield func(acMatch) bool) {
	trans := ac.transitions32
	rootTransitions := &trans[0]
	hasOutput := ac.hasOutput
	currentState := int32(0)
	rootHasNoOutput := !hasOutput[0]

	if rootHasNoOutput && ac.teddy != nil && len(data) >= 256 {
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if i&(scanCancellationInterval-1) == 0 && scanCanceled(done) {
				return
			}
			if currentState == 0 && i >= linearUntil && len(data)-i >= 32 {
				candidate := ac.teddy.findCandidateWithCancel(data, i, done)
				if candidate < 0 {
					i = max(i, len(data)-31)
					if i >= len(data) {
						return
					}
				} else {
					if candidate-i < 64 {
						linearUntil = candidate + 256
					}
					i = candidate
				}
			}
			if currentState == 0 {
				currentState = rootTransitions[data[i]]
				if currentState == 0 {
					continue
				}
			} else {
				currentState = trans[currentState][data[i]]
			}
			if hasOutput[currentState] &&
				!ac.yieldMatchesWithCancel(currentState, i, yield, done) {
				return
			}
		}
		return
	}

	if rootHasNoOutput && len(data) >= 256 && len(ac.rootLanes) > 0 && len(ac.rootLanes) <= maxSparseRootTransitions && !ac.rootIsDense(data) {
		rootCursor := newRootCandidateCursor(ac.rootLanes)
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if i&(scanCancellationInterval-1) == 0 && scanCanceled(done) {
				return
			}
			if currentState == 0 && i >= linearUntil && len(data)-i >= 256 {
				candidate := rootCursor.nextWithCancel(data, i, done)
				if candidate < 0 {
					return
				}
				if candidate-i < 64 {
					linearUntil = candidate + 256
				}
				i = candidate
			}
			if currentState == 0 {
				currentState = rootTransitions[data[i]]
				if currentState == 0 {
					continue
				}
			} else {
				currentState = trans[currentState][data[i]]
			}
			if hasOutput[currentState] &&
				!ac.yieldMatchesWithCancel(currentState, i, yield, done) {
				return
			}
		}
		return
	}

	for blockStart := 0; blockStart < len(data); blockStart += scanCancellationInterval {
		if scanCanceled(done) {
			return
		}
		blockEnd := min(blockStart+scanCancellationInterval, len(data))
		for relative, b := range data[blockStart:blockEnd] {
			if currentState == 0 {
				currentState = rootTransitions[b]
				if currentState == 0 {
					continue
				}
			} else {
				currentState = trans[currentState][b]
			}
			if hasOutput[currentState] &&
				!ac.yieldMatchesWithCancel(currentState, blockStart+relative, yield, done) {
				return
			}
		}
	}
}

func (ac *acAutomaton) searchIterWithCancel(data []byte, done <-chan struct{}) iter.Seq[acMatch] {
	return func(yield func(acMatch) bool) {
		ac.SearchWithCancel(data, done, yield)
	}
}

//nolint:revive // iterator callback and cancellation signal stay on the hot path
func (ac *acAutomaton) yieldMatchesWithCancel(
	state int32,
	offset int,
	yield func(acMatch) bool,
	done <-chan struct{},
) bool {
	outputStart := ac.states[state].outputStart
	outputEnd := ac.states[state].outputEnd
	for idx := outputStart; idx < outputEnd; idx++ {
		relative := int(idx - outputStart)
		if relative > 0 && relative&(scanCancellationInterval-1) == 0 && scanCanceled(done) {
			return false
		}
		stringIndex := ac.outputs[idx]
		if stringIndex < 0 || int(stringIndex) >= len(ac.strings) {
			continue
		}
		stringInfo := ac.strings[stringIndex]
		if !yield(acMatch{
			StringIndex: int(stringIndex),
			StringID:    stringInfo.Identifier,
			Backtrack:   offset + 1 - stringInfo.Length,
		}) {
			return false
		}
	}
	return true
}

// Search performs optimized pattern matching, directly yielding matches via callback.
func (ac *acAutomaton) Search(data []byte, yield func(acMatch) bool) {
	if !ac.compiled || len(data) == 0 {
		return
	}
	if len(ac.strings) == 1 {
		info := ac.strings[0]
		if len(info.Data) > 0 {
			noCase := info.Flags&regex.FlagsNoCase != 0
			if !singlePatternIsDense(data, info.Data, noCase) {
				ac.searchSinglePattern(data, yield)
				return
			}
		}
	}

	if len(ac.transitions16) > 0 {
		ac.search16(data, yield)
		return
	}
	ac.search32(data, yield)
}

//nolint:nestif // the sparse-root and general loops are intentionally separate hot paths
func (ac *acAutomaton) search16(data []byte, yield func(acMatch) bool) {
	trans := ac.transitions16
	rootTransitions := &trans[0]
	hasOutput := ac.hasOutput
	currentState := uint16(0)
	rootHasNoOutput := !hasOutput[0]

	if rootHasNoOutput && ac.teddy != nil && len(data) >= 256 {
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if currentState == 0 && i >= linearUntil && len(data)-i >= 32 {
				candidate := ac.teddy.findCandidate(data, i)
				if candidate < 0 {
					i = max(i, len(data)-31)
					if i >= len(data) {
						return
					}
				} else {
					if candidate-i < 64 {
						linearUntil = candidate + 256
					}
					i = candidate
				}
			}
			if currentState == 0 {
				currentState = rootTransitions[data[i]]
				if currentState == 0 {
					continue
				}
			} else {
				currentState = trans[currentState][data[i]]
			}
			if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
				return
			}
		}
		return
	}

	if rootHasNoOutput && len(data) >= 256 && len(ac.rootLanes) > 0 && len(ac.rootLanes) <= maxSparseRootTransitions && !ac.rootIsDense16(data) {
		rootCursor := newRootCandidateCursor(ac.rootLanes)
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if currentState == 0 && i >= linearUntil && len(data)-i >= 256 {
				candidate := rootCursor.next(data, i)
				if candidate < 0 {
					return
				}
				if candidate-i < 64 {
					linearUntil = candidate + 256
				}
				i = candidate
			}
			if currentState == 0 {
				currentState = rootTransitions[data[i]]
				if currentState == 0 {
					continue
				}
			} else {
				currentState = trans[currentState][data[i]]
			}
			if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
				return
			}
		}
		return
	}

	for i, b := range data {
		if currentState == 0 {
			currentState = rootTransitions[b]
			if currentState == 0 {
				continue
			}
		} else {
			currentState = trans[currentState][b]
		}
		if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
			return
		}
	}
}

//nolint:nestif // the sparse-root and general loops are intentionally separate hot paths
func (ac *acAutomaton) search32(data []byte, yield func(acMatch) bool) {
	trans := ac.transitions32
	rootTransitions := &trans[0]
	hasOutput := ac.hasOutput
	currentState := int32(0)
	rootHasNoOutput := !hasOutput[0]

	if rootHasNoOutput && ac.teddy != nil && len(data) >= 256 {
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if currentState == 0 && i >= linearUntil && len(data)-i >= 32 {
				candidate := ac.teddy.findCandidate(data, i)
				if candidate < 0 {
					i = max(i, len(data)-31)
					if i >= len(data) {
						return
					}
				} else {
					if candidate-i < 64 {
						linearUntil = candidate + 256
					}
					i = candidate
				}
			}
			if currentState == 0 {
				currentState = rootTransitions[data[i]]
				if currentState == 0 {
					continue
				}
			} else {
				currentState = trans[currentState][data[i]]
			}
			if hasOutput[currentState] && !ac.yieldMatches(currentState, i, yield) {
				return
			}
		}
		return
	}

	if rootHasNoOutput && len(data) >= 256 && len(ac.rootLanes) > 0 && len(ac.rootLanes) <= maxSparseRootTransitions && !ac.rootIsDense(data) {
		rootCursor := newRootCandidateCursor(ac.rootLanes)
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if currentState == 0 && i >= linearUntil && len(data)-i >= 256 {
				candidate := rootCursor.next(data, i)
				if candidate < 0 {
					return
				}
				if candidate-i < 64 {
					linearUntil = candidate + 256
				}
				i = candidate
			}
			if currentState == 0 {
				currentState = rootTransitions[data[i]]
				if currentState == 0 {
					continue
				}
			} else {
				currentState = trans[currentState][data[i]]
			}
			if hasOutput[currentState] && !ac.yieldMatches(currentState, i, yield) {
				return
			}
		}
		return
	}

	for i, b := range data {
		if currentState == 0 {
			currentState = rootTransitions[b]
			if currentState == 0 {
				continue
			}
		} else {
			currentState = trans[currentState][b]
		}
		if hasOutput[currentState] && !ac.yieldMatches(currentState, i, yield) {
			return
		}
	}
}

// SearchIter performs optimized pattern matching yielding matches via an iter.Seq iterator.
func (ac *acAutomaton) SearchIter(data []byte) iter.Seq[acMatch] {
	return func(yield func(acMatch) bool) {
		ac.Search(data, yield)
	}
}
