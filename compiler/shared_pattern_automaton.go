package compiler

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

type sharedPrefilterSpec struct {
	identifier  string
	data        []byte
	isHex       bool
	isRegex     bool
	flags       regex.Flags
	forceShared bool
	entry       SharedAutomatonEntry
}

type sharedPatternAutomatonBuilder struct {
	automaton      *ACAutomaton
	lookup         []SharedAutomatonEntry
	seen           map[prefilterDedupKey]struct{}
	prefilterSpecs []sharedPrefilterSpec
}

func newSharedPatternAutomatonBuilder(rules []*CompiledRule) *sharedPatternAutomatonBuilder {
	totalEntries := 0
	for _, rule := range rules {
		if rule.Automaton != nil {
			totalEntries += len(rule.Automaton.strings)
		}
		for _, pattern := range rule.RegexPatterns {
			totalEntries += max(2, len(pattern.alternativeAtoms)*2)
		}
		totalEntries += len(rule.HexPatterns)
	}

	automaton := NewACAutomaton()
	automaton.ReserveStrings(totalEntries)
	return &sharedPatternAutomatonBuilder{
		automaton:      automaton,
		lookup:         make([]SharedAutomatonEntry, 0, totalEntries),
		seen:           make(map[prefilterDedupKey]struct{}),
		prefilterSpecs: make([]sharedPrefilterSpec, 0, totalEntries),
	}
}

// buildSharedPatternAutomaton combines text strings and safe regex/hex atoms
// into one global candidate pass. Non-text entries are exact-verified after
// the automaton reports their candidate offsets.
func buildSharedPatternAutomaton(rules []*CompiledRule) (*ACAutomaton, []SharedAutomatonEntry, error) {
	builder := newSharedPatternAutomatonBuilder(rules)
	for ruleIndex, rule := range rules {
		if err := builder.addRule(ruleIndex, rule); err != nil {
			return nil, nil, err
		}
	}
	if err := builder.addDeferredPrefilters(); err != nil {
		return nil, nil, err
	}
	if err := builder.automaton.Compile(); err != nil {
		return nil, nil, fmt.Errorf("compiling shared automaton: %w", err)
	}
	return builder.automaton, builder.lookup, nil
}

func sharedNonTextCacheCoverage(size int, lookup []SharedAutomatonEntry) []bool {
	covered := make([]bool, size)
	// Non-text specs are emitted as complete mandatory-atom covers: the builder
	// either adds every deferred spec, adds every forced alternative/case spec,
	// or adds none. Deduplicated specs share the same exact-match cache key.
	for _, entry := range lookup {
		if entry.Kind == StringKindText || entry.CacheIndex < 0 || entry.CacheIndex >= size {
			continue
		}
		covered[entry.CacheIndex] = true
	}
	return covered
}

func sharedNonTextCacheRuleLookup(rules []*CompiledRule, covered []bool) [][]int {
	lookup := make([][]int, len(covered))
	for ruleIndex, rule := range rules {
		for _, info := range rule.prefilterStrings {
			if info.class != prefilterStringNonText || info.cacheIndex < 0 ||
				info.cacheIndex >= len(covered) || !covered[info.cacheIndex] {
				continue
			}
			ruleIndices := lookup[info.cacheIndex]
			if len(ruleIndices) == 0 || ruleIndices[len(ruleIndices)-1] != ruleIndex {
				lookup[info.cacheIndex] = append(ruleIndices, ruleIndex)
			}
		}
	}
	return lookup
}

func (builder *sharedPatternAutomatonBuilder) addRule(ruleIndex int, rule *CompiledRule) error {
	if err := builder.addTextPatterns(ruleIndex, rule); err != nil {
		return err
	}
	builder.addRegexPrefilters(ruleIndex, rule)
	builder.addHexPrefilters(ruleIndex, rule)
	return nil
}

func (builder *sharedPatternAutomatonBuilder) addTextPatterns(ruleIndex int, rule *CompiledRule) error {
	if rule.Automaton == nil {
		return nil
	}
	for _, info := range rule.Automaton.strings {
		strID := info.Identifier
		if rule.StringKinds[strID] != StringKindText {
			continue
		}
		globalID := fmt.Sprintf("%s:%s", rule.Name, strID)
		if err := builder.automaton.AddStringWithFlags(globalID, info.Data, false, false, info.Flags); err != nil {
			return fmt.Errorf("adding %s to shared automaton: %w", globalID, err)
		}
		builder.lookup = append(builder.lookup, SharedAutomatonEntry{
			RuleIndex: ruleIndex,
			StringIdx: rule.ResolveStringIndex(strID),
			Kind:      StringKindText,
		})
	}
	return nil
}

func (builder *sharedPatternAutomatonBuilder) addRegexPrefilters(ruleIndex int, rule *CompiledRule) {
	for _, strID := range sortedPatternIDs(rule.RegexPatterns) {
		pattern := rule.RegexPatterns[strID]
		atoms := selectSharedRegexAtoms(pattern)
		if len(atoms) == 0 || pattern.cacheKey == "" {
			continue
		}

		modifiers := rule.StringModifiers[strID]
		hasWide := hasModifier(modifiers, ast.StringModifierWide)
		hasASCII := hasModifier(modifiers, ast.StringModifierASCII)
		encodings := []bool{false}
		switch {
		case hasWide && hasASCII:
			// Preserve the existing matcher order: wide, then ASCII.
			encodings = []bool{true, false}
		case hasWide:
			encodings = []bool{true}
		}

		// A bounded alternative cover is all-or-nothing: omitting even one
		// member would make the prefilter unsound. Keep the complete cover in
		// the shared automaton even when its root fanout crosses the normal
		// density threshold.
		forceAlternativeCover := len(atoms) > 1
		for _, wide := range encodings {
			for atomIndex, atom := range atoms {
				forceShared := atom.asciiNoCase || forceAlternativeCover
				key := prefilterDedupKey{
					kind:          StringKindRegex,
					cacheKey:      pattern.cacheKey,
					wide:          wide,
					atomData:      string(atom.data),
					atomMinOffset: atom.minOffset,
					atomMaxOffset: atom.maxOffset,
					atomNoCase:    atom.asciiNoCase,
				}
				if _, exists := builder.seen[key]; exists {
					continue
				}
				builder.seen[key] = struct{}{}

				atomData := atom.data
				atomMinOffset := atom.minOffset
				atomMaxOffset := atom.maxOffset
				flags := pattern.Flags &^ regex.FlagsWide
				if atom.asciiNoCase {
					flags |= regex.FlagsNoCase
				}
				if wide {
					atomData = widenRegexPrefix(atomData)
					atomMinOffset *= 2
					if atomMaxOffset >= 0 {
						atomMaxOffset *= 2
					}
					flags |= regex.FlagsWide
				}
				builder.prefilterSpecs = append(builder.prefilterSpecs, sharedPrefilterSpec{
					identifier:  fmt.Sprintf("%s:%s:regex:%t:%d", rule.Name, strID, wide, atomIndex),
					data:        atomData,
					isRegex:     true,
					flags:       flags,
					forceShared: forceShared,
					entry: SharedAutomatonEntry{
						RuleIndex:       ruleIndex,
						StringIdx:       rule.ResolveStringIndex(strID),
						Kind:            StringKindRegex,
						AtomOffset:      atomMinOffset,
						AtomMaxOffset:   atomMaxOffset,
						alternativeAtom: len(atoms) > 1,
						forceShared:     forceShared,
						IsWide:          wide,
						CacheIndex:      pattern.cacheIndex,
					},
				})
			}
		}
	}
}

func (builder *sharedPatternAutomatonBuilder) addHexPrefilters(ruleIndex int, rule *CompiledRule) {
	for _, strID := range sortedPatternIDs(rule.HexPatterns) {
		pattern := rule.HexPatterns[strID]
		if pattern == nil || pattern.cacheKey == "" || len(pattern.XorKeys) > 0 || len(pattern.XorRange) > 0 {
			continue
		}
		atom, ok := selectHexAtom(pattern.Tokens)
		if !ok {
			continue
		}
		key := prefilterDedupKey{kind: StringKindHex, cacheKey: pattern.cacheKey}
		if _, exists := builder.seen[key]; exists {
			continue
		}
		builder.seen[key] = struct{}{}

		builder.prefilterSpecs = append(builder.prefilterSpecs, sharedPrefilterSpec{
			identifier: fmt.Sprintf("%s:%s:hex", rule.Name, strID),
			data:       atom.data,
			isHex:      true,
			entry: SharedAutomatonEntry{
				RuleIndex:     ruleIndex,
				StringIdx:     rule.ResolveStringIndex(strID),
				Kind:          StringKindHex,
				AtomOffset:    atom.offset,
				AtomMaxOffset: atom.offset,
				CacheIndex:    pattern.cacheIndex,
			},
		})
	}
}

func (builder *sharedPatternAutomatonBuilder) addDeferredPrefilters() error {
	addAll := shouldAddSharedNonTextPrefilters(builder.automaton, builder.prefilterSpecs)
	for _, spec := range builder.prefilterSpecs {
		if !addAll && !spec.forceShared {
			continue
		}
		if err := builder.automaton.AddStringWithFlags(
			spec.identifier,
			spec.data,
			spec.isHex,
			spec.isRegex,
			spec.flags,
		); err != nil {
			return fmt.Errorf("adding %s atom to shared automaton: %w", spec.identifier, err)
		}
		builder.lookup = append(builder.lookup, spec.entry)
	}
	return nil
}

func shouldAddSharedNonTextPrefilters(automaton *ACAutomaton, specs []sharedPrefilterSpec) bool {
	if len(specs) >= minSharedNonTextEntries {
		return true
	}
	if len(specs) < minSparseSharedNonTextEntries {
		return false
	}

	var rootBytes [256]bool
	rootCount := 0
	addRootByte := func(value byte) bool {
		if !rootBytes[value] {
			rootBytes[value] = true
			rootCount++
		}
		return rootCount <= maxSparseRootTransitions
	}
	for value, nextState := range automaton.states[0].transitions {
		if nextState != -1 && !addRootByte(byte(value)) {
			return false
		}
	}
	for _, spec := range specs {
		if len(spec.data) == 0 {
			continue
		}
		first := spec.data[0]
		if !addRootByte(first) {
			return false
		}
		if spec.flags&regex.FlagsNoCase != 0 && !addRootByte(flipASCIICase(first)) {
			return false
		}
	}
	return true
}
