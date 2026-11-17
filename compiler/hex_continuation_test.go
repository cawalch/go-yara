package compiler

import (
	"bytes"
	"slices"
	"testing"
)

//nolint:revive // differential oracle needs explicit input, key, and callback limit
func checkHexContinuationParity(t *testing.T, scratch *hexMatchScratch, tokens []HexPatternToken, data []byte, key *byte, stop int) {
	t.Helper()
	scratch.endJumpScan() // Jump-byte caches are scoped to one input scan.
	var want, got []int
	var reference hexMatchScratch
	wantComplete := reference.referenceMatchEach(tokens, data, 0, key, func(end int) bool {
		want = append(want, end)
		return stop == 0 || len(want) < stop
	})
	complete := scratch.matchEach(tokens, data, 0, key, func(end int) bool {
		got = append(got, end)
		return stop == 0 || len(got) < stop
	})
	if complete != wantComplete || !slices.Equal(got, want) {
		t.Fatalf("got %v (complete=%v), want %v (complete=%v)", got, complete, want, wantComplete)
	}
}

func TestHexContinuationOrderAndReuse(t *testing.T) {
	patterns := []string{
		`{ 41 ( 42 | 42 43 | 42 ) 44 }`,
		`{ ( 41 | 41 42 ) ( 42 | 43 ) 44 }`,
		`{ 41 ( ( 42 | 43 ) [0-3] 44 | 42 [0-2] 44 ) 45 }`,
		`{ 41 [0-64] ( 42 | 43 ) [0-64] 44 }`,
		`{ 41 ( 42 [0-2] 43 | 42 [0-3] 44 ) 45 }`,
		`{ 41 [0-2] ?? [0-2] ~42 }`,
	}
	var scratch hexMatchScratch
	for _, source := range patterns {
		pattern, err := newStringCompiler().parseHexPattern(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, plain := range [][]byte{[]byte("ABD"), []byte("ABCD"), []byte("ABBCDE"), []byte("ACBDDE"), []byte("AAAABCD"), []byte("ABDD"), []byte("AAAAAA")} {
			for _, key := range []byte{0, 0x55, 0xff} {
				data := bytes.Clone(plain)
				for i := range data {
					data[i] ^= key
				}
				for _, stop := range []int{0, 1, 2} {
					checkHexContinuationParity(t, &scratch, pattern.Tokens, data, &key, stop)
				}
			}
		}
	}
}

func TestHexContinuationGrowth(t *testing.T) {
	tokens := []HexPatternToken{{Kind: HexTokenByte, Value: 'A'}}
	for range 24 {
		tokens = []HexPatternToken{{Kind: HexTokenAlt, Alternatives: [][]HexPatternToken{tokens}}, {Kind: HexTokenByte, Value: 'A'}}
	}
	var scratch hexMatchScratch
	checkHexContinuationParity(t, &scratch, tokens, bytes.Repeat([]byte{'A'}, 25), nil, 0)
	if len(scratch.continuations) <= len(scratch.inlineContinuations) {
		t.Fatal("test did not exercise continuation-buffer growth")
	}
	// Reusing the same scratch with a different pattern/data must clear failures.
	checkHexContinuationParity(t, &scratch, []HexPatternToken{{Kind: HexTokenByte, Value: 'B'}}, []byte{'B'}, nil, 0)
}

func repeatedFailureTokens(count int) []HexPatternToken {
	var tokens []HexPatternToken
	for range count {
		tokens = append(tokens, HexPatternToken{Kind: HexTokenJump, Max: 8}, HexPatternToken{Kind: HexTokenWildcard})
	}
	return append(tokens, HexPatternToken{Kind: HexTokenByte, Value: 'B'})
}

func TestHexRepeatedFailureMemoization(t *testing.T) {
	tokens := repeatedFailureTokens(12)
	data := bytes.Repeat([]byte{'A'}, 128)
	var scratch hexMatchScratch
	if !scratch.matchEach(tokens, data, 0, nil, func(int) bool {
		t.Fatal("unexpected match")
		return false
	}) {
		t.Fatal("matching did not complete")
	}
	if len(scratch.failed) == 0 || len(scratch.failed) > len(tokens)*(len(data)+1) {
		t.Fatalf("unexpected failed-state count: %d", len(scratch.failed))
	}
	// A successful tail after a failed attempt must not be suppressed.
	data[15] = 'B'
	checkHexContinuationParity(t, &scratch, repeatedFailureTokens(3), data[:16], nil, 1)
}

func TestHexRepeatedAlternativeFailureMemoization(t *testing.T) {
	var tokens []HexPatternToken
	for range 24 {
		tokens = append(tokens, HexPatternToken{Kind: HexTokenAlt, Alternatives: [][]HexPatternToken{
			{{Kind: HexTokenByte, Value: 'A'}},
			{{Kind: HexTokenByte, Value: 'A'}, {Kind: HexTokenByte, Value: 'A'}},
		}})
	}
	tokens = append(tokens, HexPatternToken{Kind: HexTokenByte, Value: 'B'})
	data := bytes.Repeat([]byte{'A'}, 64)
	var scratch hexMatchScratch
	if !scratch.matchEach(tokens, data, 0, nil, func(int) bool {
		t.Fatal("unexpected match")
		return false
	}) {
		t.Fatal("matching did not complete")
	}
	if len(scratch.failed) == 0 || len(scratch.failed) > 5*len(tokens)*(len(data)+1) {
		t.Fatalf("unexpected failed-state count: %d", len(scratch.failed))
	}
}

func FuzzHexContinuationParity(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 0, 1}, byte(0), uint8(0))
	f.Add([]byte{2, 2, 2}, []byte{0, 0, 0, 0, 0, 0}, byte(0x55), uint8(1))
	f.Fuzz(func(t *testing.T, operations, data []byte, key byte, stop uint8) {
		if len(operations) > 6 || len(data) > 24 {
			return
		}
		var tokens []HexPatternToken
		for _, op := range operations {
			value := op & 3
			switch op % 6 {
			case 0:
				tokens = append(tokens, HexPatternToken{Kind: HexTokenByte, Value: value, Negated: op&8 != 0})
			case 1:
				tokens = append(tokens, HexPatternToken{Kind: HexTokenJump, Max: 3})
			case 2:
				tokens = append(tokens, HexPatternToken{Kind: HexTokenAlt, Alternatives: [][]HexPatternToken{
					{{Kind: HexTokenByte, Value: value}},
					{{Kind: HexTokenWildcard}, {Kind: HexTokenByte, Value: value}},
				}})
			case 3:
				tokens = append(tokens, HexPatternToken{Kind: HexTokenMasked, Mask: 1, Value: value & 1, Negated: op&8 != 0})
			case 4:
				tokens = append(tokens, HexPatternToken{Kind: HexTokenWildcard})
			case 5:
				tokens = append(tokens, HexPatternToken{Kind: HexTokenAlt, Alternatives: [][]HexPatternToken{nil, {{Kind: HexTokenWildcard}}}})
			}
		}
		encoded := bytes.Clone(data)
		for i := range encoded {
			encoded[i] = encoded[i]&3 ^ key
		}
		var scratch hexMatchScratch
		checkHexContinuationParity(t, &scratch, tokens, encoded, &key, int(stop%4))
	})
}

func TestHexPlanRefreshBetweenScans(t *testing.T) {
	pattern := &HexPattern{Tokens: []HexPatternToken{
		{Kind: HexTokenByte, Value: 'A'},
		{Kind: HexTokenJump, Max: 1},
		{Kind: HexTokenByte, Value: 'B'},
	}}
	var scratch hexMatchScratch
	collect := func(data []byte) []Match {
		var matches []Match
		findHexMatchesEach(pattern, data, nil, &scratch, func(match Match) bool {
			matches = append(matches, match)
			return true
		})
		return matches
	}
	if matches := collect([]byte("AB")); len(matches) != 1 || matches[0].Length != 2 {
		t.Fatalf("initial scan: %v", matches)
	}
	// Change the same backing token array from a single gap to alternatives.
	pattern.Tokens[1] = HexPatternToken{Kind: HexTokenAlt, Alternatives: [][]HexPatternToken{{{Kind: HexTokenByte, Value: 'C'}}}}
	if matches := collect([]byte("ACB")); len(matches) != 1 || matches[0].Length != 3 {
		t.Fatalf("edited pattern scan: %v", matches)
	}
	if matches := collect([]byte("ADB")); len(matches) != 0 {
		t.Fatalf("changed input scan: %v", matches)
	}
}

func TestHexAlternationAllocationBound(t *testing.T) {
	pattern, err := newStringCompiler().parseHexPattern(`{ 0A ( 1A | 2A | 3A ) 0B }`)
	if err != nil {
		t.Fatal(err)
	}
	data := generateData(100_000)
	if matches := FindHexMatches(pattern, data); len(matches) != 0 {
		t.Fatal("allocation test requires no result-slice allocations")
	}
	allocs := testing.AllocsPerRun(20, func() { FindHexMatches(pattern, data) })
	if allocs > 1 {
		t.Fatalf("alternation scan allocated %.1f times, want at most one scratch allocation", allocs)
	}
}

func TestHexSingleJumpMaximumInt(t *testing.T) {
	limit := int(^uint(0) >> 1)
	for _, tail := range [][]HexPatternToken{nil, {{Kind: HexTokenByte, Value: 'B'}}} {
		tokens := append([]HexPatternToken{{Kind: HexTokenJump, Min: limit, Max: limit}}, tail...)
		var scratch hexMatchScratch
		checkHexContinuationParity(t, &scratch, tokens, []byte("AB"), nil, 0)
	}
}
