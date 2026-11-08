package compiler

import (
	"math/bits"
)

// corpusSharedAtoms also considers the verifier's proven mandatory literal
// after a prefix. Keep fixed offsets and at least the existing atom quality;
// only trade the prefix when the internal candidate's frequency across eligible
// verifiers is at most half that of the existing prefilter candidate.
func corpusSharedAtoms(rules []*CompiledRule) map[string]regexPrefilterAtom {
	selected := corpusPrefixAtoms(rules)
	type choice struct{ current, internal regexPrefilterAtom }
	choices := make(map[string]choice)
	for _, rule := range rules {
		if rule.IsDead {
			continue
		}
		for id, pattern := range rule.RegexPatterns {
			if rule.IsStringDead(id) || pattern.cacheKey == "" || len(pattern.prefix) < minPrefilterAtomLength ||
				pattern.atomMinOffset < len(pattern.prefix) || pattern.atomMinOffset != pattern.atomMaxOffset {
				continue
			}
			atoms := selectSharedRegexAtoms(pattern)
			if len(atoms) != 1 {
				continue
			}
			current := atoms[0]
			if atom, ok := selected[pattern.cacheKey]; ok {
				current = atom
			}
			internal := regexPrefilterAtom{
				data:        pattern.atom,
				minOffset:   pattern.atomMinOffset,
				maxOffset:   pattern.atomMaxOffset,
				score:       prefilterAtomScore(pattern.atom),
				asciiNoCase: pattern.atomASCIINoCase,
			}
			if current.minOffset != current.maxOffset || len(internal.data) < len(current.data) || internal.score < current.score {
				continue
			}
			choices[pattern.cacheKey] = choice{current, internal}
		}
	}
	// Below this threshold, new root bytes could disable the shared pass.
	if len(choices) < minSharedNonTextEntries {
		return selected
	}
	// Length distinguishes short prefixes from eight-byte atoms padded with NULs.
	type atomKey struct {
		data [maxPrefilterAtomLength]byte
		size int
	}
	keyFor := func(data []byte) atomKey { return atomKey{corpusAtomKey(data), len(data)} }
	counts := make(map[atomKey]int)
	for _, choice := range choices {
		current, internal := keyFor(choice.current.data), keyFor(choice.internal.data)
		counts[current]++
		if internal != current {
			counts[internal]++
		}
	}
	updates := make(map[string]regexPrefilterAtom)
	for key, choice := range choices {
		if counts[keyFor(choice.internal.data)] <= counts[keyFor(choice.current.data)]/2 {
			updates[key] = choice.internal
		}
	}
	if len(updates) == 0 || corpusAtomsLoseSparseRoots(rules, selected, updates) {
		return selected
	}
	if selected == nil {
		return updates
	}
	for key, atom := range updates {
		selected[key] = atom
	}
	return selected
}

// More selective atoms must not turn a sparse-root byte search into a full
// DFA walk. Include unchanged text/hex entries and count ASCII case pairs as
// one lane, just as collectRootBytes does. Eligible corpora guarantee shared scans.
func corpusAtomsLoseSparseRoots(rules []*CompiledRule, selected, updates map[string]regexPrefilterAtom) bool {
	var before, after [256]bool
	oldCount, newCount := 0, 0
	add := func(roots *[256]bool, count *int, value byte) {
		value = toLowerTable[value]
		if !roots[value] {
			roots[value] = true
			*count++
		}
	}
	addBoth := func(value byte) {
		add(&before, &oldCount, value)
		add(&after, &newCount, value)
	}
	for _, rule := range rules {
		if rule.IsDead {
			continue
		}
		if rule.automaton != nil {
			for _, info := range rule.automaton.strings {
				if !rule.IsStringDead(info.Identifier) && rule.StringKinds[info.Identifier] == StringKindText && len(info.Data) > 0 {
					addBoth(info.Data[0])
				}
			}
		}
		for id, pattern := range rule.RegexPatterns {
			if rule.IsStringDead(id) || pattern.cacheKey == "" {
				continue
			}
			atoms := selectSharedRegexAtoms(pattern)
			if atom, ok := selected[pattern.cacheKey]; ok {
				atoms = []regexPrefilterAtom{atom}
			}
			for _, atom := range atoms {
				add(&before, &oldCount, atom.data[0])
			}
			if atom, ok := updates[pattern.cacheKey]; ok {
				atoms = []regexPrefilterAtom{atom}
			}
			for _, atom := range atoms {
				add(&after, &newCount, atom.data[0])
			}
		}
		for id, pattern := range rule.HexPatterns {
			if rule.IsStringDead(id) || pattern == nil || pattern.cacheKey == "" || len(pattern.XorKeys) > 1 || len(pattern.XorRange) > 0 {
				continue
			}
			if atom, ok := selectHexAtom(pattern.Tokens); ok {
				root := atom.data[0]
				if len(pattern.XorKeys) == 1 {
					root ^= pattern.XorKeys[0]
				}
				addBoth(root)
			}
		}
		if oldCount > maxSparseRootTransitions {
			return false
		}
	}
	return newCount > maxSparseRootTransitions
}

// corpusPrefixAtoms breaks equal-quality prefix-window ties using the number
// of distinct eligible regex prefixes containing each window. Only the shared
// prefilter changes; verification atoms and match-selection policies stay intact.
func corpusPrefixAtoms(rules []*CompiledRule) map[string]regexPrefilterAtom {
	type prefixChoice struct {
		prefix []byte
		atom   regexPrefilterAtom
	}
	choices := make(map[string]prefixChoice)
	for _, rule := range rules {
		if rule.IsDead {
			continue
		}
		for id, pattern := range rule.RegexPatterns {
			if rule.IsStringDead(id) || pattern.cacheKey == "" || len(pattern.prefix) <= maxPrefilterAtomLength {
				continue
			}
			atoms := selectSharedRegexAtoms(pattern)
			// Alternative covers and internal atoms keep their existing policy.
			if len(atoms) != 1 || atoms[0].asciiNoCase || atoms[0].minOffset != atoms[0].maxOffset {
				continue
			}
			prefix, _ := selectLiteralAtom(pattern.prefix)
			if atoms[0].minOffset != prefix.offset || string(atoms[0].data) != string(prefix.data) {
				continue
			}
			choices[pattern.cacheKey] = prefixChoice{pattern.prefix, atoms[0]}
		}
	}
	if len(choices) < 2 {
		return nil
	}
	type frequency struct {
		count int
		last  string
	}
	counts := make(map[[maxPrefilterAtomLength]byte]frequency)
	for key, choice := range choices {
		for offset := 0; offset+maxPrefilterAtomLength <= len(choice.prefix); offset++ {
			window := choice.prefix[offset : offset+maxPrefilterAtomLength]
			atomKey := corpusAtomKey(window)
			f := counts[atomKey]
			if f.last != key {
				counts[atomKey] = frequency{f.count + 1, key}
			}
		}
	}
	selected := make(map[string]regexPrefilterAtom)
	for key, choice := range choices {
		best := choice.atom
		frequency := counts[corpusAtomKey(best.data)].count
		target := frequency / 2
		largeCorpus := len(choices) > minSharedNonTextEntries
		// Prefer later windows and stop after halving fanout for small corpora.
		// For large corpora, find the minimum-frequency, highest-entropy atom.
		for offset := len(choice.prefix) - maxPrefilterAtomLength; offset >= 0; offset-- {
			if !largeCorpus && frequency <= max(1, target) {
				break
			}
			window := choice.prefix[offset : offset+maxPrefilterAtomLength]
			score := prefilterAtomScore(window)
			if !largeCorpus {
				if score != best.score {
					continue
				}
			} else {
				if score < 20 || score < best.score-4 {
					continue
				}
			}
			count := counts[corpusAtomKey(window)].count
			entropy := atomEntropy(window)
			bestEntropy := atomEntropy(best.data)
			better := count < frequency || (count == frequency && (score > best.score || (score == best.score && entropy > bestEntropy)))
			if better {
				best.data, best.minOffset, best.maxOffset, best.score = window, offset, offset, score
				frequency = count
			}
		}
		if best.minOffset != choice.atom.minOffset {
			selected[key] = best
		}
	}
	return selected
}

// Fold ASCII for scoring so case variants do not look artificially rare.
func corpusAtomKey(data []byte) (key [maxPrefilterAtomLength]byte) {
	copy(key[:], data)
	for i, b := range key {
		if b >= 'A' && b <= 'Z' {
			key[i] = b + ('a' - 'A')
		}
	}
	return key
}

// atomEntropy computes an integer Shannon entropy and character diversity score
// for a candidate atom window. Higher scores indicate richer information content,
// mixed character classes (e.g. uppercase, lowercase, digits, symbols), and lower
// repetition, making the atom less likely to collide with common text in logs.
func atomEntropy(atom []byte) int {
	if len(atom) == 0 {
		return 0
	}
	var counts [256]uint8
	distinct := 0
	var classes uint8 // bit 0: lower, bit 1: upper, bit 2: digit, bit 3: punct, bit 4: non-ascii/zero
	for _, b := range atom {
		if counts[b] == 0 {
			distinct++
			switch {
			case b == 0 || b >= 0x80:
				classes |= 1 << 4
			case b >= '0' && b <= '9':
				classes |= 1 << 2
			case b >= 'A' && b <= 'Z':
				classes |= 1 << 1
			case b >= 'a' && b <= 'z':
				classes |= 1 << 0
			default:
				classes |= 1 << 3
			}
		}
		counts[b]++
	}
	var cLogCTable = [...]int{0, 0, 16, 38, 64, 93, 124, 157, 192}
	n := len(atom)
	nLogN := n * 24
	sumCLogC := 0
	for _, c := range counts {
		if c > 0 && int(c) < len(cLogCTable) {
			sumCLogC += cLogCTable[c]
		}
	}
	entropy := nLogN - sumCLogC
	if entropy < 0 {
		entropy = 0
	}
	classCount := bits.OnesCount8(classes)
	return (entropy >> 3) + distinct*2 + classCount*4
}
