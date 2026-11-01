package compiler

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
		// Prefer later windows and stop after halving fanout. Chasing unique
		// windows can inflate the automaton for little additional scan benefit.
		for offset := len(choice.prefix) - maxPrefilterAtomLength; offset >= 0 && frequency > max(1, target); offset-- {
			window := choice.prefix[offset : offset+maxPrefilterAtomLength]
			if prefilterAtomScore(window) != best.score {
				continue
			}
			if count := counts[corpusAtomKey(window)].count; count < frequency {
				best.data, best.minOffset, best.maxOffset = window, offset, offset
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
