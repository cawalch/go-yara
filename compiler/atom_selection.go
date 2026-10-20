package compiler

import (
	"github.com/cawalch/go-yara/regex"
)

// selectLiteralAtom chooses a bounded, high-information window from a literal
// prefix. Later windows win ties because generated rule families commonly
// share their leading bytes and vary near the end of the prefix.
func selectLiteralAtom(literal []byte) (prefilterAtom, bool) {
	if len(literal) < minPrefilterAtomLength {
		return prefilterAtom{}, false
	}
	width := min(len(literal), maxPrefilterAtomLength)
	best := prefilterAtom{score: -1}
	for offset := 0; offset+width <= len(literal); offset++ {
		data := literal[offset : offset+width]
		score := prefilterAtomScore(data)
		if score >= best.score {
			best = prefilterAtom{data: data, offset: offset, score: score}
		}
	}
	return best, true
}

func selectMandatoryRegexAtom(atoms []regex.LiteralAtom) (regexPrefilterAtom, bool) {
	return selectRegexAtom(atoms, false, false)
}

func selectMandatoryASCIIFoldedRegexAtom(atoms []regex.LiteralAtom) (regexPrefilterAtom, bool) {
	return selectRegexAtom(atoms, false, true)
}

func selectBoundedMandatoryRegexAtom(atoms []regex.LiteralAtom) (regexPrefilterAtom, bool) {
	return selectRegexAtom(atoms, true, false)
}

func selectRegexAtom(atoms []regex.LiteralAtom, boundedOnly, asciiNoCase bool) (regexPrefilterAtom, bool) {
	best := regexPrefilterAtom{score: -1}
	for _, candidate := range atoms {
		if boundedOnly && candidate.MaxOffset < 0 {
			continue
		}
		atom, ok := selectLiteralAtom(candidate.Data)
		if !ok {
			continue
		}
		minOffset := candidate.MinOffset + atom.offset
		maxOffset := candidate.MaxOffset
		if maxOffset >= 0 {
			maxOffset += atom.offset
		}
		candidateAtom := regexPrefilterAtom{
			data:        atom.data,
			minOffset:   minOffset,
			maxOffset:   maxOffset,
			score:       atom.score,
			asciiNoCase: asciiNoCase,
		}
		if betterRegexPrefilterAtom(candidateAtom, best) {
			best = candidateAtom
		}
	}
	return best, len(best.data) >= minPrefilterAtomLength
}

// selectAlternativeRegexAtoms keeps one mandatory atom for every cover group.
// Bounded atoms are preferred, but an unbounded atom can still prove its branch
// cannot match when the atom is absent. The set is all-or-nothing: omitting a
// group would make the candidate scan unsound and could hide a valid match.
func selectAlternativeRegexAtoms(alternatives [][]regex.LiteralAtom) ([]regexPrefilterAtom, bool) {
	if len(alternatives) < 2 {
		return nil, false
	}
	atoms := make([]regexPrefilterAtom, 0, len(alternatives))
	seen := make(map[regexAlternativeDedupKey]struct{}, len(alternatives))
	for _, alternative := range alternatives {
		atom, ok := selectBoundedMandatoryRegexAtom(alternative)
		if !ok {
			atom, ok = selectMandatoryRegexAtom(alternative)
		}
		if !ok {
			return nil, false
		}
		key := regexAlternativeDedupKey{
			data:        string(atom.data),
			minOffset:   atom.minOffset,
			maxOffset:   atom.maxOffset,
			asciiNoCase: atom.asciiNoCase,
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		atoms = append(atoms, atom)
	}
	return atoms, len(atoms) > 0
}

func selectLeadingGapRegexPlan(plan regex.LeadingByteGapPlan) (*regexLeadingGapPlan, bool) {
	if len(plan.AtomGroups) == 0 || plan.GapSet.Count() > maxRegexByteSetSize {
		return nil, false
	}
	atoms := make([]regexPrefilterAtom, 0, len(plan.AtomGroups))
	seen := make(map[regexAlternativeDedupKey]struct{}, len(plan.AtomGroups))
	for _, group := range plan.AtomGroups {
		atom, ok := selectBoundedMandatoryRegexAtom(group)
		if !ok {
			return nil, false
		}
		if atom.maxOffset-atom.minOffset > maxLeadingGapAtomOffsetWidth {
			return nil, false
		}
		key := regexAlternativeDedupKey{
			data:        string(atom.data),
			minOffset:   atom.minOffset,
			maxOffset:   atom.maxOffset,
			asciiNoCase: atom.asciiNoCase,
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		atoms = append(atoms, atom)
	}
	if len(atoms) == 0 {
		return nil, false
	}
	return &regexLeadingGapPlan{
		leadingSet: plan.LeadingSet,
		gapSet:     plan.GapSet,
		gapMin:     plan.GapMin,
		gapMax:     plan.GapMax,
		atoms:      atoms,
	}, true
}

func cloneLeadingGapRegexPlan(plan *regexLeadingGapPlan) *regexLeadingGapPlan {
	if plan == nil {
		return nil
	}
	return &regexLeadingGapPlan{
		leadingSet: plan.leadingSet,
		gapSet:     plan.gapSet,
		gapMin:     plan.gapMin,
		gapMax:     plan.gapMax,
		atoms:      cloneRegexPrefilterAtoms(plan.atoms),
	}
}

func cloneRegexPrefilterAtoms(atoms []regexPrefilterAtom) []regexPrefilterAtom {
	if len(atoms) == 0 {
		return nil
	}
	cloned := make([]regexPrefilterAtom, len(atoms))
	for index, atom := range atoms {
		cloned[index] = atom
		cloned[index].data = append([]byte(nil), atom.data...)
	}
	return cloned
}

func widenRegexPrefilterAtoms(atoms []regexPrefilterAtom) []regexPrefilterAtom {
	if len(atoms) == 0 {
		return nil
	}
	wide := make([]regexPrefilterAtom, len(atoms))
	for index, atom := range atoms {
		wide[index] = atom
		wide[index].data = widenRegexPrefix(atom.data)
		wide[index].minOffset *= 2
		if wide[index].maxOffset >= 0 {
			wide[index].maxOffset *= 2
		}
	}
	return wide
}

func betterRegexPrefilterAtom(candidate, current regexPrefilterAtom) bool {
	if len(candidate.data) != len(current.data) {
		return len(candidate.data) > len(current.data)
	}
	candidateBounded := candidate.maxOffset >= 0
	currentBounded := current.maxOffset >= 0
	if candidateBounded != currentBounded {
		return candidateBounded
	}
	if candidate.score != current.score {
		return candidate.score > current.score
	}
	if candidateBounded {
		candidateWidth := candidate.maxOffset - candidate.minOffset
		currentWidth := current.maxOffset - current.minOffset
		if candidateWidth != currentWidth {
			return candidateWidth < currentWidth
		}
	}
	return true
}

func selectMandatoryRegexByteSetAtom(atoms []regex.ByteSetAtom, flags regex.Flags) (regexByteSetPrefilter, bool) {
	var best regexByteSetPrefilter
	found := false
	for _, atom := range atoms {
		set := atom.Set
		if flags&regex.FlagsNoCase != 0 {
			set = set.ASCIIFolded()
		}
		count := set.Count()
		if count == 0 || count > maxRegexByteSetSize {
			continue
		}
		candidate := regexByteSetPrefilter{
			set:       set,
			minOffset: atom.MinOffset,
			maxOffset: atom.MaxOffset,
			count:     count,
		}
		if !found || betterRegexByteSetPrefilter(candidate, best) {
			best = candidate
			found = true
		}
	}
	return best, found
}

func betterRegexByteSetPrefilter(candidate, current regexByteSetPrefilter) bool {
	candidateBounded := candidate.maxOffset >= 0
	currentBounded := current.maxOffset >= 0
	if candidateBounded != currentBounded {
		return candidateBounded
	}
	if candidate.count != current.count {
		return candidate.count < current.count
	}
	if candidateBounded {
		candidateWidth := candidate.maxOffset - candidate.minOffset
		currentWidth := current.maxOffset - current.minOffset
		if candidateWidth != currentWidth {
			return candidateWidth < currentWidth
		}
	}
	return true
}

func alternativeAtomsBeatPrefix(atoms []regexPrefilterAtom, prefix []byte) bool {
	if len(atoms) < 2 || hasUnboundedRegexAlternative(atoms) {
		return false
	}
	prefixAtom, ok := selectLiteralAtom(prefix)
	if !ok {
		return true
	}
	current := regexPrefilterAtom{
		data:      prefixAtom.data,
		minOffset: prefixAtom.offset,
		maxOffset: prefixAtom.offset,
		score:     prefixAtom.score,
	}
	for _, atom := range atoms {
		if !betterRegexPrefilterAtom(atom, current) {
			return false
		}
	}
	return true
}

func selectSharedRegexAtoms(pattern RegexPattern) []regexPrefilterAtom {
	if pattern.atomASCIINoCase && len(pattern.atom) >= minPrefilterAtomLength && len(pattern.prefix) < minPrefilterAtomLength {
		return []regexPrefilterAtom{{
			data:        pattern.atom,
			minOffset:   pattern.atomMinOffset,
			maxOffset:   pattern.atomMaxOffset,
			score:       prefilterAtomScore(pattern.atom),
			asciiNoCase: true,
		}}
	}
	if alternativeAtomsBeatPrefix(pattern.alternativeAtoms, pattern.prefix) {
		// Prefer a complete OR-cover when every branch atom is bounded and more
		// selective than the common prefix (or when no usable prefix exists).
		return pattern.alternativeAtoms
	}
	if atom, ok := selectLiteralAtom(pattern.prefix); ok {
		return []regexPrefilterAtom{{
			data:      atom.data,
			minOffset: atom.offset,
			maxOffset: atom.offset,
			score:     atom.score,
		}}
	}
	if len(pattern.atom) >= minPrefilterAtomLength {
		return []regexPrefilterAtom{{
			data:        pattern.atom,
			minOffset:   pattern.atomMinOffset,
			maxOffset:   pattern.atomMaxOffset,
			score:       prefilterAtomScore(pattern.atom),
			asciiNoCase: pattern.atomASCIINoCase,
		}}
	}
	return nil
}

func prefilterAtomScore(atom []byte) int {
	score := 0
	var seen [256]bool
	for _, b := range atom {
		switch {
		case b == 0 || b >= 0x80:
			score += 6
		case b >= '0' && b <= '9':
			score += 3
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z':
			score += 2
		default:
			score += 4
		}
		if !seen[b] {
			score++
			seen[b] = true
		}
	}
	return score
}

// selectHexAtom chooses the best literal run whose byte offset from the start
// is statically known. Variable jumps and alternatives end the safe region;
// patterns without a useful atom remain on the existing matcher path.
func selectHexAtom(tokens []HexPatternToken) (prefilterAtom, bool) {
	best := prefilterAtom{score: -1}
	fixedOffset := 0
	runOffset := 0
	var run []byte

	considerRun := func() {
		atom, ok := selectLiteralAtom(run)
		if ok {
			atom.offset += runOffset
			if len(atom.data) > len(best.data) || (len(atom.data) == len(best.data) && atom.score >= best.score) {
				best = atom
			}
		}
		run = nil
	}

	for _, token := range tokens {
		exact := token.Kind == HexTokenByte && !token.Negated
		if token.Kind == HexTokenMasked && token.Mask == 0xFF && !token.Negated {
			exact = true
		}
		if exact {
			if len(run) == 0 {
				runOffset = fixedOffset
			}
			run = append(run, token.Value)
			fixedOffset++
			continue
		}

		considerRun()
		switch token.Kind {
		case HexTokenByte, HexTokenMasked, HexTokenWildcard:
			fixedOffset++
		case HexTokenJump:
			if token.Min < 0 || token.Min != token.Max {
				return best, len(best.data) >= minPrefilterAtomLength
			}
			fixedOffset += token.Min
		case HexTokenAlt:
			return best, len(best.data) >= minPrefilterAtomLength
		}
	}
	considerRun()
	return best, len(best.data) >= minPrefilterAtomLength
}
