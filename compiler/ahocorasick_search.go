package compiler

import (
	"bytes"
	"iter"

	"github.com/cawalch/go-yara/regex"
)

// rootRowIsDense reports whether a root goto row is dense enough that a
// sparse-root candidate cursor would add more cursor overhead than it saves.
// It samples the first 256 input bytes and counts root hits. Rows come from
// compiled flat tables, where a closed miss reads back as 0.
func rootRowIsDense[S ~uint16 | ~int32](rootTransitions *[256]S, data []byte) bool {
	sample := data
	if len(sample) > 256 {
		sample = sample[:256]
	}
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

// rootHasEdge reports whether the automaton's closed root goto table has a
// transition for byte b. Misses read back as 0 after closure, so 0 means "no
// root edge"; an automaton without any built table reports no edges.
func (ac *acAutomaton) rootHasEdge(b byte) bool {
	if len(ac.transitions16) > 0 {
		return ac.transitions16[0][b] != 0
	}
	if len(ac.transitions32) > 0 {
		return ac.transitions32[0][b] != 0
	}
	if ac.classRoot16 != nil {
		return ac.classRoot16[b] != 0
	}
	if ac.classRoot32 != nil {
		return ac.classRoot32[b] != 0
	}
	if ac.trieRoot != nil {
		return ac.trieRoot[b] != -1
	}
	if len(ac.states) > 0 {
		return ac.states[0].transitions[b] != 0
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
	outputRange := ac.outputRanges[state]
	outputStart := outputRange[0]
	outputEnd := outputRange[1]
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

// rootIsDense and rootIsDense16 sample the root goto row through whichever
// table is populated: the 32-bit kernel calls rootIsDense, the 16-bit kernel
// rootIsDense16, and tests may probe either on any width.
func (ac *acAutomaton) rootIsDense16(data []byte) bool {
	if len(ac.transitions16) > 0 {
		return rootRowIsDense(&ac.transitions16[0], data)
	}
	if ac.classRoot16 != nil {
		return rootRowIsDense(ac.classRoot16, data)
	}
	return false
}

func (ac *acAutomaton) rootIsDense(data []byte) bool {
	switch {
	case len(ac.transitions32) > 0:
		return rootRowIsDense(&ac.transitions32[0], data)
	case len(ac.transitions16) > 0:
		return rootRowIsDense(&ac.transitions16[0], data)
	case ac.classRoot32 != nil:
		return rootRowIsDense(ac.classRoot32, data)
	case ac.classRoot16 != nil:
		return rootRowIsDense(ac.classRoot16, data)
	case ac.trieRoot != nil:
		return rootRowIsDense(ac.trieRoot, data)
	case len(ac.states) > 0:
		return rootRowIsDense(&ac.states[0].transitions, data)
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
	ac.searchWithCancel(data, done, false, yield)
}

//nolint:revive // hot path avoids struct allocation
func (ac *acAutomaton) searchWithCancel(data []byte, done <-chan struct{}, skipGate bool, yield func(acMatch) bool) {
	ac.ensureCompiled()
	if !ac.compiled || len(data) == 0 || scanCanceled(done) {
		return
	}
	if !skipGate && teddySIMDEnabled && ac.teddyGate != nil && len(data) >= 256 && len(data) <= 512 && !ac.teddyGate.mayMatch(data, done) {
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
		searchTableWithCancel(ac, ac.transitions16, data, done, yield)
		return
	}
	if len(ac.flatClass16) > 0 {
		searchClassTableWithCancel(ac, ac.classRoot16, ac.flatClass16, data, done, yield)
		return
	}
	if len(ac.flatClass32) > 0 {
		searchClassTableWithCancel(ac, ac.classRoot32, ac.flatClass32, data, done, yield)
		return
	}
	searchTableWithCancel(ac, ac.transitions32, data, done, yield)
}

//nolint:nestif,revive // mirrors searchTableWithCancel for byte-class compressed tables
func searchClassTableWithCancel[S ~uint16 | ~int32](ac *acAutomaton, rootTransitions *[256]S, flat []S, data []byte, done <-chan struct{}, yield func(acMatch) bool) {
	classMap := &ac.classMap
	shift := ac.classShift
	hasOutput := ac.hasOutput
	var currentState S
	rootHasNoOutput := !hasOutput[0]

	if rootHasNoOutput && ac.teddy != nil && len(data) >= 256 {
		tailBytes := ac.teddy.tailBytes()
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if i&(scanCancellationInterval-1) == 0 && scanCanceled(done) {
				return
			}
			if currentState == 0 && i >= linearUntil && len(data)-i > tailBytes {
				candidate := ac.teddy.findCandidateWithCancel(data, i, done)
				if candidate < 0 {
					i = max(i, len(data)-tailBytes)
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
				currentState = flat[(int(currentState)<<shift)+int(classMap[data[i]])]
			}
			if hasOutput[currentState] &&
				!ac.yieldMatchesWithCancel(int32(currentState), i, yield, done) {
				return
			}
		}
		return
	}

	if rootHasNoOutput && len(data) > 256 && len(ac.rootLanes) > 0 && len(ac.rootLanes) <= maxSparseRootTransitions && !rootRowIsDense(rootTransitions, data) {
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
				currentState = flat[(int(currentState)<<shift)+int(classMap[data[i]])]
			}
			if hasOutput[currentState] &&
				!ac.yieldMatchesWithCancel(int32(currentState), i, yield, done) {
				return
			}
		}
		return
	}

	for i := 0; i < len(data); i++ {
		if i&(scanCancellationInterval-1) == 0 && scanCanceled(done) {
			return
		}
		if currentState == 0 {
			for {
				currentState = rootTransitions[data[i]]
				if currentState != 0 {
					break
				}
				i++
				if i == len(data) {
					return
				}
				if i&(scanCancellationInterval-1) == 0 && scanCanceled(done) {
					return
				}
			}
		} else {
			currentState = flat[(int(currentState)<<shift)+int(classMap[data[i]])]
		}
		if hasOutput[currentState] &&
			!ac.yieldMatchesWithCancel(int32(currentState), i, yield, done) {
			return
		}
	}
}

//nolint:nestif,revive // mirrors Search with bounded cancellation checkpoints
func searchTableWithCancel[S ~uint16 | ~int32](ac *acAutomaton, trans [][256]S, data []byte, done <-chan struct{}, yield func(acMatch) bool) {
	rootTransitions := &trans[0]
	hasOutput := ac.hasOutput
	var currentState S
	rootHasNoOutput := !hasOutput[0]

	if rootHasNoOutput && ac.teddy != nil && len(data) >= 256 {
		tailBytes := ac.teddy.tailBytes()
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if i&(scanCancellationInterval-1) == 0 && scanCanceled(done) {
				return
			}
			if currentState == 0 && i >= linearUntil && len(data)-i > tailBytes {
				candidate := ac.teddy.findCandidateWithCancel(data, i, done)
				if candidate < 0 {
					i = max(i, len(data)-tailBytes)
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

	if rootHasNoOutput && len(data) > 256 && len(ac.rootLanes) > 0 && len(ac.rootLanes) <= maxSparseRootTransitions && !rootRowIsDense(rootTransitions, data) {
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

//nolint:revive // iterator callback and cancellation signal stay on the hot path
func (ac *acAutomaton) yieldMatchesWithCancel(
	state int32,
	offset int,
	yield func(acMatch) bool,
	done <-chan struct{},
) bool {
	outputRange := ac.outputRanges[state]
	outputStart := outputRange[0]
	outputEnd := outputRange[1]
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
	ac.search(data, false, yield)
}

func (ac *acAutomaton) search(data []byte, skipGate bool, yield func(acMatch) bool) {
	ac.ensureCompiled()
	if !ac.compiled || len(data) == 0 {
		return
	}
	if !skipGate && teddySIMDEnabled && ac.teddyGate != nil && len(data) >= 256 && len(data) <= 512 && !ac.teddyGate.mayMatch(data, nil) {
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
		searchTable(ac, ac.transitions16, data, yield)
		return
	}
	if len(ac.flatClass16) > 0 {
		searchClassTable(ac, ac.classRoot16, ac.flatClass16, data, yield)
		return
	}
	if len(ac.flatClass32) > 0 {
		searchClassTable(ac, ac.classRoot32, ac.flatClass32, data, yield)
		return
	}
	searchTable(ac, ac.transitions32, data, yield)
}

//nolint:nestif,revive // mirrors searchTable for byte-class compressed tables
func searchClassTable[S ~uint16 | ~int32](ac *acAutomaton, rootTransitions *[256]S, flat []S, data []byte, yield func(acMatch) bool) {
	classMap := &ac.classMap
	shift := ac.classShift
	hasOutput := ac.hasOutput
	var currentState S
	rootHasNoOutput := !hasOutput[0]

	if rootHasNoOutput && ac.teddy != nil && len(data) >= 256 {
		tailBytes := ac.teddy.tailBytes()
		linearUntil := 0
		for i := 0; i < len(data); i++ {
			if currentState == 0 && i >= linearUntil && len(data)-i > tailBytes {
				candidate := ac.teddy.findCandidate(data, i)
				if candidate < 0 {
					i = max(i, len(data)-tailBytes)
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
				currentState = flat[(int(currentState)<<shift)+int(classMap[data[i]])]
			}
			if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
				return
			}
		}
		return
	}

	if rootHasNoOutput && len(data) > 256 && len(ac.rootLanes) > 0 && len(ac.rootLanes) <= maxSparseRootTransitions && !rootRowIsDense(rootTransitions, data) {
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
				currentState = flat[(int(currentState)<<shift)+int(classMap[data[i]])]
			}
			if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
				return
			}
		}
		return
	}

	if rootHasNoOutput {
		for i := 0; i < len(data); i++ {
			currentState = rootTransitions[data[i]]
			if currentState == 0 {
				continue
			}
			if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
				return
			}
			for i++; i < len(data); i++ {
				currentState = flat[(int(currentState)<<shift)+int(classMap[data[i]])]
				if currentState == 0 {
					break
				}
				if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
					return
				}
			}
		}
		return
	}

	for i := range data {
		if currentState == 0 {
			currentState = rootTransitions[data[i]]
		} else {
			currentState = flat[(int(currentState)<<shift)+int(classMap[data[i]])]
		}
		if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
			return
		}
	}
}

//nolint:revive // argument-limit: hot path avoids struct allocation
func searchTable[S ~uint16 | ~int32](ac *acAutomaton, trans [][256]S, data []byte, yield func(acMatch) bool) {
	rootTransitions := &trans[0]
	hasOutput := ac.hasOutput
	rootHasNoOutput := !hasOutput[0]

	if rootHasNoOutput && ac.teddy != nil && len(data) >= 256 {
		searchTableTeddy(ac, trans, data, yield)
		return
	}

	if rootHasNoOutput && len(data) > 256 && len(ac.rootLanes) > 0 && len(ac.rootLanes) <= maxSparseRootTransitions && !rootRowIsDense(rootTransitions, data) {
		searchTableRootLanes(ac, trans, data, yield)
		return
	}

	if rootHasNoOutput && len(data) >= 512 && !rootRowIsDense(rootTransitions, data) {
		searchTableSparseScalar(ac, trans, data, yield)
		return
	}

	var currentState S
	for i := 0; i < len(data); i++ {
		if currentState == 0 {
			// Stay in the root-miss loop until a transition consumes a prefix.
			for {
				currentState = rootTransitions[data[i]]
				if currentState != 0 {
					break
				}
				i++
				if i == len(data) {
					return
				}
			}
		} else {
			currentState = trans[currentState][data[i]]
		}
		if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
			return
		}
	}
}

//nolint:revive // argument-limit: hot path avoids struct allocation
func searchTableTeddy[S ~uint16 | ~int32](ac *acAutomaton, trans [][256]S, data []byte, yield func(acMatch) bool) {
	rootTransitions := &trans[0]
	hasOutput := ac.hasOutput
	tailBytes := ac.teddy.tailBytes()
	var currentState S
	linearUntil := 0
	denseWindow := 256
	for i := 0; i < len(data); {
		if currentState != 0 {
			currentState = trans[currentState][data[i]]
			if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
				return
			}
			i++
			continue
		}
		if i >= linearUntil && len(data)-i > tailBytes {
			i = advanceTeddyCandidate(ac.teddy, data, i, tailBytes, &linearUntil, &denseWindow)
			if i >= len(data) {
				return
			}
		}
		for {
			currentState = rootTransitions[data[i]]
			if currentState != 0 {
				break
			}
			i++
			if i == len(data) {
				return
			}
			if i >= linearUntil && len(data)-i > tailBytes {
				break
			}
		}
		if currentState == 0 {
			continue
		}
		if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
			return
		}
		i++
	}
}

//nolint:revive // argument-limit: hot path avoids struct allocation
func advanceTeddyCandidate(teddy teddyPrefilter, data []byte, i, tailBytes int, linearUntil, denseWindow *int) int {
	candidate := teddy.findCandidate(data, i)
	if candidate < 0 {
		return max(i, len(data)-tailBytes)
	}
	if candidate-i < 64 {
		*linearUntil = candidate + *denseWindow
		if *denseWindow < 8192 {
			*denseWindow <<= 1
		}
	} else {
		*denseWindow = 256
	}
	return candidate
}

//nolint:revive // argument-limit: hot path avoids struct allocation
func searchTableRootLanes[S ~uint16 | ~int32](ac *acAutomaton, trans [][256]S, data []byte, yield func(acMatch) bool) {
	rootTransitions := &trans[0]
	hasOutput := ac.hasOutput
	var currentState S
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
}

//nolint:revive // argument-limit: hot path avoids struct allocation
func searchTableSparseScalar[S ~uint16 | ~int32](ac *acAutomaton, trans [][256]S, data []byte, yield func(acMatch) bool) {
	rootTransitions := &trans[0]
	hasOutput := ac.hasOutput
	var currentState S
	for i := 0; i < len(data); i++ {
		if currentState != 0 {
			currentState = trans[currentState][data[i]]
			if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
				return
			}
			continue
		}
		i = skipSparseRoot8(rootTransitions, data, i)
		if i == len(data) {
			return
		}
		for {
			currentState = rootTransitions[data[i]]
			if currentState != 0 {
				break
			}
			i++
			if i == len(data) {
				return
			}
		}
		if hasOutput[currentState] && !ac.yieldMatches(int32(currentState), i, yield) {
			return
		}
	}
}

func skipSparseRoot8[S ~uint16 | ~int32](root *[256]S, data []byte, i int) int {
	for i+8 <= len(data) {
		w := data[i : i+8]
		if root[w[0]]|root[w[1]]|root[w[2]]|root[w[3]]|
			root[w[4]]|root[w[5]]|root[w[6]]|root[w[7]] != 0 {
			break
		}
		i += 8
	}
	return i
}

// SearchIter performs optimized pattern matching yielding matches via an iter.Seq iterator.
func (ac *acAutomaton) SearchIter(data []byte) iter.Seq[acMatch] {
	return func(yield func(acMatch) bool) {
		ac.Search(data, yield)
	}
}
