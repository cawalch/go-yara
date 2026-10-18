package compiler

import (
	"context"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

func TestResolvePrefilterStringNilHexPattern(t *testing.T) {
	rule := &CompiledRule{
		StringKinds:     map[string]StringKind{"$h": StringKindHex},
		HexPatterns:     map[string]*HexPattern{"$h": nil},
		RegexPatterns:   map[string]RegexPattern{},
		IndexToStringID: []string{"$h"},
	}
	if got := resolvePrefilterString(rule, "$h"); got.class != prefilterStringUnresolved {
		t.Fatalf("resolvePrefilterString(nil hex) = %+v, want unresolved", got)
	}
}

func fixedDispatchTestPattern(byteSet regex.ByteSet, cacheKey string, cacheIndex int) RegexPattern {
	return RegexPattern{
		fixedByteSets:    []regex.ByteSet{byteSet, byteSet, byteSet, byteSet},
		byteSet:          byteSet,
		byteSetCount:     1,
		byteSetMinOffset: 0,
		byteSetMaxOffset: 0,
		cacheKey:         cacheKey,
		cacheIndex:       cacheIndex,
	}
}

func TestBuildFixedRegexDispatchBoundaries(t *testing.T) {
	// Include byte 0 so the loop-bound mutant (value <= 256) indexes buckets[256]
	// via byte(256) == 0 and panics.
	byteSet := regex.NewByteSet([]byte{0, 'a'})
	rule := &CompiledRule{
		RegexPatterns: map[string]RegexPattern{
			"$a": fixedDispatchTestPattern(byteSet, "a", 0),
			"$b": fixedDispatchTestPattern(byteSet, "b", 1),
			"$c": fixedDispatchTestPattern(byteSet, "c", 2),
		},
		StringModifiers: map[string][]ast.StringModifier{
			"$a": {{Type: ast.StringModifierWide}, {Type: ast.StringModifierASCII}},
		},
	}
	dispatch := buildFixedRegexDispatch([]*CompiledRule{rule})
	if dispatch == nil {
		t.Fatal("dispatch with exactly minSharedFixedRegexEntries entries was not built")
	}
	if len(dispatch.cacheOrder) != 1 {
		t.Fatalf("cacheOrder = %+v, want exactly one wide entry", dispatch.cacheOrder)
	}
	if dispatch.cacheOrder[0].wideLength != 8 {
		t.Fatalf("cacheOrder[0].wideLength = %d, want 8", dispatch.cacheOrder[0].wideLength)
	}
}

func TestPopulateNonTextPrefilterCacheNilMatchCtx(t *testing.T) {
	s := &Scanner{program: &CompiledProgram{
		nonTextCacheSize: 1,
		sharedLookup:     []sharedAutomatonEntry{{Kind: StringKindText}},
	}}
	s.touchedPrefilterCandidates = []int{0}
	var cache nonTextMatchCache
	cache.reset(1)
	if err := s.populateNonTextPrefilterCache(context.Background(), nil, &cache); err != nil {
		t.Fatalf("populateNonTextPrefilterCache = %v, want nil", err)
	}
}

func TestPopulateNonTextPrefilterCacheLookupBounds(t *testing.T) {
	s := &Scanner{program: &CompiledProgram{
		nonTextCacheSize: 1,
		sharedLookup:     []sharedAutomatonEntry{{Kind: StringKindText}},
	}}
	s.touchedPrefilterCandidates = []int{1} // == len(sharedLookup)
	var cache nonTextMatchCache
	cache.reset(1)
	if err := s.populateNonTextPrefilterCache(context.Background(), nil, &cache); err != nil {
		t.Fatalf("populateNonTextPrefilterCache = %v, want nil", err)
	}
}

func TestPopulateNonTextPrefilterCacheCacheIndexBounds(t *testing.T) {
	rule := &CompiledRule{IndexToStringID: []string{"$x"}}
	s := &Scanner{program: &CompiledProgram{
		nonTextCacheSize: 1,
		Rules:            []*CompiledRule{rule},
		sharedLookup: []sharedAutomatonEntry{{
			Kind:       StringKindRegex,
			CacheIndex: 1, // == len(cache.matches)
			RuleIndex:  0,
			StringIdx:  0,
		}},
	}}
	s.touchedPrefilterCandidates = []int{0}
	var cache nonTextMatchCache
	cache.reset(1)
	if err := s.populateNonTextPrefilterCache(context.Background(), nil, &cache); err != nil {
		t.Fatalf("populateNonTextPrefilterCache = %v, want nil", err)
	}
}

func TestPopulateNonTextPrefilterCacheRuleIndexBounds(t *testing.T) {
	rule := &CompiledRule{IndexToStringID: []string{"$x"}}
	s := &Scanner{program: &CompiledProgram{
		nonTextCacheSize: 1,
		Rules:            []*CompiledRule{rule},
		sharedLookup: []sharedAutomatonEntry{{
			Kind:       StringKindRegex,
			CacheIndex: 0,
			RuleIndex:  1, // == len(Rules)
			StringIdx:  0,
		}},
	}}
	s.touchedPrefilterCandidates = []int{0}
	var cache nonTextMatchCache
	cache.reset(1)
	if err := s.populateNonTextPrefilterCache(context.Background(), nil, &cache); err != nil {
		t.Fatalf("populateNonTextPrefilterCache = %v, want nil", err)
	}
}

func TestPopulateNonTextPrefilterCacheStringIdxBounds(t *testing.T) {
	rule := &CompiledRule{IndexToStringID: []string{"$x"}}
	s := &Scanner{program: &CompiledProgram{
		nonTextCacheSize: 1,
		Rules:            []*CompiledRule{rule},
		sharedLookup: []sharedAutomatonEntry{{
			Kind:       StringKindRegex,
			CacheIndex: 0,
			RuleIndex:  0,
			StringIdx:  1, // == len(rule.IndexToStringID)
		}},
	}}
	s.touchedPrefilterCandidates = []int{0}
	var cache nonTextMatchCache
	cache.reset(1)
	if err := s.populateNonTextPrefilterCache(context.Background(), nil, &cache); err != nil {
		t.Fatalf("populateNonTextPrefilterCache = %v, want nil", err)
	}
}

func TestCanSkipSharedNonTextEntryHookMask(t *testing.T) {
	s := &Scanner{skipUnmatchedNonText: true}
	s.globalMatches = make([][]globalMatchEntry, 1)
	rule := &CompiledRule{
		Index:            0,
		requiredStrings:  []string{"$x"},
		StringIDToIndex:  map[string]int{"$x": 0},
		prefilterStrings: []prefilterStringInfo{{class: prefilterStringText}},
	}
	entry := sharedAutomatonEntry{singleRuleCache: true}
	if !s.canSkipSharedNonTextEntry(entry, rule, nil) {
		t.Fatal("canSkipSharedNonTextEntry = false with zero hook mask, want true")
	}
}

func TestAppendRegexFallbackMatchesNilContext(t *testing.T) {
	rule := &CompiledRule{StringModifiers: map[string][]ast.StringModifier{}}
	if got := appendRegexFallbackMatches(nil, rule, "$x", RegexPattern{}, []byte("abc"), 0, false, nil, nil); len(got) != 0 {
		t.Fatalf("appendRegexFallbackMatches = %v, want no matches", got)
	}
}

func TestAppendHexPrefilterMatchesLinearLastStart(t *testing.T) {
	rule := &CompiledRule{HexPatterns: map[string]*HexPattern{
		"$h": {Tokens: []HexPatternToken{{Kind: HexTokenByte, Value: 0xAA}}},
	}}
	entry := sharedAutomatonEntry{AtomOffset: 0}
	data := []byte{0x00, 0xAA}
	got := appendHexPrefilterMatches(nil, rule, "$h", entry, data, []int{1}, nil, nil)
	if len(got) != 1 || got[0].Offset != 1 || got[0].Length != 1 {
		t.Fatalf("appendHexPrefilterMatches = %v, want one match at offset 1", got)
	}
}

func TestAppendHexPrefilterMatchesNilScratchAndEmptyEnd(t *testing.T) {
	// A non-linear pattern (zero-length jump) forces the scratch path and
	// yields end == start, which must be skipped.
	rule := &CompiledRule{HexPatterns: map[string]*HexPattern{
		"$h": {Tokens: []HexPatternToken{{Kind: HexTokenJump, Min: 0, Max: 0}}},
	}}
	entry := sharedAutomatonEntry{AtomOffset: 0}
	data := []byte{0x00, 0xAA}
	if got := appendHexPrefilterMatches(nil, rule, "$h", entry, data, []int{1}, nil, nil); len(got) != 0 {
		t.Fatalf("appendHexPrefilterMatches(zero-length) = %v, want no matches", got)
	}
}

func TestAppendHexPrefilterMatchesLinearEmptyEnd(t *testing.T) {
	// An empty linear token list matches with end == start, which must be skipped.
	rule := &CompiledRule{HexPatterns: map[string]*HexPattern{"$h": {}}}
	entry := sharedAutomatonEntry{AtomOffset: 0}
	data := []byte{0x00, 0xAA}
	if got := appendHexPrefilterMatches(nil, rule, "$h", entry, data, []int{1}, nil, nil); len(got) != 0 {
		t.Fatalf("appendHexPrefilterMatches(linear zero-length) = %v, want no matches", got)
	}
}
