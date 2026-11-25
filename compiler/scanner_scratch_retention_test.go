package compiler

import "testing"

// A single dense scan must not pin occurrence buffers proportional to its
// transient match count in a reusable Scanner.
func TestScannerDropsOversizedOccurrenceBuffers(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule dense { strings: $a = "a" condition: $a }`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()

	data := make([]byte, 4*maxRetainedOccurrences)
	for i := range data {
		data[i] = 'a'
	}
	first, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Matches["dense"]["$a"]) != len(data) {
		t.Fatalf("dense matches = %d, want %d", len(first.Matches["dense"]["$a"]), len(data))
	}
	if cap(scanner.globalMatches[0]) <= maxRetainedOccurrences || cap(scanner.matchCtx.spansByIndex[0]) <= maxRetainedOccurrences {
		t.Fatalf("dense scan did not populate occurrence buffers: global=%d spans=%d",
			cap(scanner.globalMatches[0]), cap(scanner.matchCtx.spansByIndex[0]))
	}

	// A rejected scan still resets per-scan state, so the dense buffers must be
	// dropped even though no rule reaches condition evaluation.
	if _, err := scanner.Scan([]byte("b")); err != nil {
		t.Fatal(err)
	}
	if got := cap(scanner.globalMatches[0]); got > maxRetainedOccurrences {
		t.Fatalf("retained global match buffer cap = %d, want <= %d", got, maxRetainedOccurrences)
	}
	if got := cap(scanner.matchCtx.spansByIndex[0]); got > maxRetainedOccurrences {
		t.Fatalf("retained span buffer cap = %d, want <= %d", got, maxRetainedOccurrences)
	}

	// Results are materialized independently of scanner scratch buffers.
	matches := first.Matches["dense"]["$a"]
	if len(matches) != len(data) || matches[0].Offset != 0 || matches[len(matches)-1].Offset != int64(len(data)-1) {
		t.Fatalf("first scan result was invalidated by the following scan")
	}
}

// The pooled convenience path returns its scanner before the caller observes
// the result, so trimming must not invalidate owned result slices.
func TestPooledScanResultSurvivesScratchTrim(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule dense { strings: $a = "a" condition: $a }`)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 2*maxRetainedOccurrences)
	for i := range data {
		data[i] = 'a'
	}
	first, err := program.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := program.Scan([]byte("b")); err != nil {
		t.Fatal(err)
	}
	matches := first.Matches["dense"]["$a"]
	if len(matches) != len(data) || matches[len(matches)-1].Offset != int64(len(data)-1) {
		t.Fatalf("pooled scan result was invalidated after trimming: len=%d", len(matches))
	}
}

func TestNonTextScratchBuffersAreBounded(t *testing.T) {
	scanner := &Scanner{
		prefilterCandidates:        make([][]int, 1),
		touchedPrefilterCandidates: []int{0},
		nonTextCache: nonTextMatchCache{
			matches: make([][]matchSpan, 1),
			ready:   make([]bool, 1),
			touched: []int{0},
		},
	}
	scanner.prefilterCandidates[0] = make([]int, maxRetainedOccurrences+1)
	scanner.nonTextCache.matches[0] = make([]matchSpan, maxRetainedOccurrences+1)
	scanner.hexScratch.candidateStarts = make([]int, maxRetainedOccurrences+1)
	scanner.hexScratch.fanoutCandidates = [][]int{make([]int, maxRetainedOccurrences+1)}
	scanner.hexScratch.failed = make(map[hexFailureState]struct{}, maxRetainedOccurrences+1)
	for i := 0; i <= maxRetainedOccurrences; i++ {
		scanner.hexScratch.failed[hexFailureState{dataPos: i}] = struct{}{}
	}

	scanner.resetPrefilterCandidates(1)
	scanner.nonTextCache.reset(1)
	scanner.trimRetainedScratch()

	if got := cap(scanner.prefilterCandidates[0]); got > maxRetainedOccurrences {
		t.Fatalf("retained prefilter buffer cap = %d, want <= %d", got, maxRetainedOccurrences)
	}
	if got := cap(scanner.nonTextCache.matches[0]); got > maxRetainedOccurrences {
		t.Fatalf("retained non-text buffer cap = %d, want <= %d", got, maxRetainedOccurrences)
	}
	if got := cap(scanner.hexScratch.candidateStarts); got > maxRetainedOccurrences {
		t.Fatalf("retained hex candidate buffer cap = %d, want <= %d", got, maxRetainedOccurrences)
	}
	if got := cap(scanner.hexScratch.fanoutCandidates[0]); got > maxRetainedOccurrences {
		t.Fatalf("retained hex fanout buffer cap = %d, want <= %d", got, maxRetainedOccurrences)
	}
	if scanner.hexScratch.failed != nil {
		t.Fatalf("retained hex failure cache with %d entries", len(scanner.hexScratch.failed))
	}
}
