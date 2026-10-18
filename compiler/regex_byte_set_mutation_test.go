package compiler

import (
	"bytes"
	"slices"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

// Residual gremlins survivors for regex_byte_set.go are classified at the
// bottom of this file per the #311 acceptance criteria.

func TestShouldUseSparseRegexByteSetSearch(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		values []byte
		wide   bool
		want   bool
	}{
		{name: "wide", data: bytes.Repeat([]byte("z"), 128), values: []byte{'a'}, wide: true, want: false},
		{name: "empty values", data: bytes.Repeat([]byte("z"), 128), values: nil, want: false},
		{name: "short data", data: bytes.Repeat([]byte("z"), 63), values: []byte{'a'}, want: false},
		{name: "64-byte sparse", data: bytes.Repeat([]byte("z"), 64), values: []byte{'a'}, want: true},
		{name: "all value dense", data: bytes.Repeat([]byte("a"), 512), values: []byte{'a'}, want: false},
		{name: "eight matches dense", data: append(bytes.Repeat([]byte("a"), 8), bytes.Repeat([]byte("z"), 120)...), values: []byte{'a'}, want: false},
		{name: "one match sparse", data: append([]byte("a"), bytes.Repeat([]byte("z"), 127)...), values: []byte{'a'}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldUseSparseRegexByteSetSearch(tt.data, tt.values, tt.wide); got != tt.want {
				t.Fatalf("shouldUseSparseRegexByteSetSearch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegexCandidateStartRanges(t *testing.T) {
	search := regexByteSetSearch{
		data:    make([]byte, 100),
		pattern: RegexPattern{byteSetMinOffset: 1, byteSetMaxOffset: 3},
	}
	ranges := newRegexCandidateStartRanges(search)
	if first, last, ok := ranges.next(10); !ok || first != 7 || last != 9 {
		t.Fatalf("next(10) = (%d,%d,%v), want (7,9,true)", first, last, ok)
	}
	if first, last, ok := ranges.next(12); !ok || first != 10 || last != 11 {
		t.Fatalf("next(12) = (%d,%d,%v), want (10,11,true)", first, last, ok)
	}
	if _, _, ok := ranges.next(12); ok {
		t.Fatal("next(12) again returned a range, want none")
	}
}

func TestRegexCandidateStartCounterAdd(t *testing.T) {
	search := regexByteSetSearch{
		data:    make([]byte, 100),
		pattern: RegexPattern{byteSetMinOffset: 1, byteSetMaxOffset: 3},
	}
	counter := newRegexCandidateStartCounter(search, 3)
	if !counter.add(10) {
		t.Fatal("add(10) = false, want true")
	}
	if counter.count != 3 {
		t.Fatalf("count = %d, want 3", counter.count)
	}
	if counter.add(20) {
		t.Fatal("add(20) = true past limit, want false")
	}
}

func TestCollectRegexCandidateStartsInto(t *testing.T) {
	starts, ok := collectRegexCandidateStarts([]int{10}, 1, 3, false, 100, 100)
	if !ok || !slices.Equal(starts, []int{7, 8, 9}) {
		t.Fatalf("collect = %v, %v, want [7 8 9] true", starts, ok)
	}
	starts, ok = collectRegexCandidateStarts([]int{10, 11}, 1, 3, false, 100, 100)
	if !ok || !slices.Equal(starts, []int{7, 8, 9, 10}) {
		t.Fatalf("collect dedup = %v, %v, want [7 8 9 10] true", starts, ok)
	}
	starts, ok = collectRegexCandidateStarts([]int{10, 8}, 1, 1, false, 100, 100)
	if !ok || !slices.Equal(starts, []int{7, 9}) {
		t.Fatalf("collect sort = %v, %v, want [7 9] true", starts, ok)
	}
	if _, ok := collectRegexCandidateStarts([]int{10}, 0, 10, false, 100, 5); ok {
		t.Fatal("collect exceeded limit but returned ok")
	}
	// Exactly at the limit must still succeed.
	starts, ok = collectRegexCandidateStarts([]int{10}, 0, 0, false, 100, 1)
	if !ok || !slices.Equal(starts, []int{10}) {
		t.Fatalf("collect at limit = %v, %v, want [10] true", starts, ok)
	}
}

func TestRegexByteSetSearchIndex(t *testing.T) {
	contiguous := regexByteSetSearch{
		data:    []byte{0x10, 0x11, 0x12, 0x13},
		pattern: RegexPattern{byteSetContiguous: true, byteSetLower: 0x11, byteSetUpper: 0x12},
	}
	if got := contiguous.index(0); got != 1 {
		t.Fatalf("indexContiguous = %d, want 1", got)
	}
	if got := contiguous.index(2); got != 2 {
		t.Fatalf("indexContiguous(2) = %d, want 2", got)
	}
	general := regexByteSetSearch{
		data:    []byte{0x10, 0x20, 0x11},
		pattern: RegexPattern{byteSet: regex.NewByteSet([]byte{0x11})},
	}
	if got := general.index(0); got != 2 {
		t.Fatalf("indexGeneral = %d, want 2", got)
	}
	sparse := regexByteSetSearch{
		data:            []byte{0x10, 0x20, 0x11},
		pattern:         RegexPattern{byteSetValues: []byte{0x11, 0x30}},
		useSparseValues: true,
	}
	if got := sparse.index(0); got != 2 {
		t.Fatalf("indexSparse = %d, want 2", got)
	}
	// Wide forces the scalar range path, whose match sits at the last index.
	wide := regexByteSetSearch{
		data:    []byte{0x30, 0x00, 0x12, 0x00},
		pattern: RegexPattern{byteSetContiguous: true, byteSetLower: 0x10, byteSetUpper: 0x12},
		wide:    true,
	}
	if got := wide.index(0); got != 2 {
		t.Fatalf("indexContiguous(wide last) = %d, want 2", got)
	}
	// Equal bounds take the single-byte fast path.
	equal := regexByteSetSearch{
		data:    []byte{0x10, 0x11},
		pattern: RegexPattern{byteSetContiguous: true, byteSetLower: 0x11, byteSetUpper: 0x11},
	}
	if got := equal.index(0); got != 1 {
		t.Fatalf("indexContiguous(equal bounds) = %d, want 1", got)
	}
	missing := regexByteSetSearch{
		data:    []byte{0x10, 0x11},
		pattern: RegexPattern{byteSetContiguous: true, byteSetLower: 0x99, byteSetUpper: 0x99},
	}
	if got := missing.index(0); got != -1 {
		t.Fatalf("indexContiguous(miss) = %d, want -1", got)
	}
}

func TestIndexSparseRegexByteSet(t *testing.T) {
	data := []byte{0x11, 0x99, 0x30}
	if got := indexSparseRegexByteSet(data, 0, []byte{0x11, 0x30}); got != 0 {
		t.Fatalf("indexSparseRegexByteSet = %d, want 0", got)
	}
	if got := indexSparseRegexByteSet(data, 0, []byte{0x99}); got != 1 {
		t.Fatalf("indexSparseRegexByteSet(single) = %d, want 1", got)
	}
	if got := indexSparseRegexByteSet(data, 0, []byte{0x77}); got != -1 {
		t.Fatalf("indexSparseRegexByteSet(miss) = %d, want -1", got)
	}
}

func TestSelectStaticRegexLiteralAnchor(t *testing.T) {
	if got := selectStaticRegexLiteralAnchor([]byte("abc!"), false); got != 3 {
		t.Fatalf("anchor = %d, want 3", got)
	}
	if got := selectStaticRegexLiteralAnchor([]byte("abc"), false); got != 0 {
		t.Fatalf("anchor tie = %d, want 0", got)
	}
	wide := []byte{'a', 0, 'b', 0, 'c', 0, '!', 0}
	if got := selectStaticRegexLiteralAnchor(wide, true); got != 6 {
		t.Fatalf("wide anchor = %d, want 6", got)
	}
}

func TestRegexLiteralSearcherNoCase(t *testing.T) {
	if got := indexRegexLiteral([]byte("xxABxx"), 0, []byte("ab"), regex.FlagsNoCase, false); got != 2 {
		t.Fatalf("indexRegexLiteral = %d, want 2", got)
	}
	if got := indexRegexLiteral([]byte("xxABxx"), 0, nil, regex.FlagsNoCase, false); got != -1 {
		t.Fatalf("indexRegexLiteral(empty literal) = %d, want -1", got)
	}
	searcher := newRegexLiteralSearcher([]byte("zzab"), []byte("ab"), 0)
	if got := searcher.index(0); got != 2 {
		t.Fatalf("case-sensitive index = %d, want 2", got)
	}
}

func TestSelectRegexLiteralSearchAnchor(t *testing.T) {
	data := bytes.Repeat([]byte("a"), 128)
	if got := selectRegexLiteralSearchAnchor(data, []byte("abc"), false); got != 1 {
		t.Fatalf("anchor = %d, want 1", got)
	}
	if got := selectRegexLiteralSearchAnchor(bytes.Repeat([]byte("a"), 64), []byte("ab"), false); got != 1 {
		t.Fatalf("anchor(64-byte data) = %d, want 1", got)
	}
	if got := selectRegexLiteralSearchAnchor(data, []byte("aa"), false); got != 0 {
		t.Fatalf("anchor(duplicate literal) = %d, want 0", got)
	}
	// Equal frequencies: the higher-scoring later byte wins.
	alternating := bytes.Repeat([]byte("a!"), 64)
	if got := selectRegexLiteralSearchAnchor(alternating, []byte("a!"), false); got != 1 {
		t.Fatalf("anchor(score tie-break) = %d, want 1", got)
	}
}

func TestASCIIFoldByteCursor(t *testing.T) {
	cursor := newASCIIFoldByteCursor('a')
	if got := cursor.next([]byte("zzAzz"), 0); got != 2 {
		t.Fatalf("next = %d, want 2", got)
	}
	cursor = newASCIIFoldByteCursor('a')
	if got := cursor.next([]byte("zzzzz"), 0); got != -1 {
		t.Fatalf("next(miss) = %d, want -1", got)
	}
	// A rewind resets the per-value cursors.
	cursor = newASCIIFoldByteCursor('a')
	_ = cursor.next([]byte("zzAzz"), 0)
	if got := cursor.next([]byte("zzAzz"), 0); got != 2 {
		t.Fatalf("next(rewind) = %d, want 2", got)
	}
}

func TestIndexASCIIFoldByteScalar(t *testing.T) {
	if got := indexASCIIFoldByteScalar([]byte("zzAzz"), 'a'); got != 2 {
		t.Fatalf("fold upper = %d, want 2", got)
	}
	if got := indexASCIIFoldByteScalar([]byte("zzazz"), 'A'); got != 2 {
		t.Fatalf("fold lower = %d, want 2", got)
	}
	if got := indexASCIIFoldByteScalar([]byte("zzzzz"), 'a'); got != -1 {
		t.Fatalf("miss = %d, want -1", got)
	}
	if got := indexASCIIFoldByteScalar([]byte("0123"), '5'); got != -1 {
		t.Fatalf("non-letter miss = %d, want -1", got)
	}
}

func TestIndexByteRangeScalar(t *testing.T) {
	if got := indexByteRangeScalar([]byte{0x10, 0x20, 0x30}, 0x20, 0x2F); got != 1 {
		t.Fatalf("range = %d, want 1", got)
	}
	if got := indexByteRangeScalar([]byte{0x20, 0x30}, 0x20, 0x21); got != 0 {
		t.Fatalf("width-1 at zero = %d, want 0", got)
	}
	if got := indexByteRangeScalar([]byte{0x10, 0x20}, 0x20, 0x20); got != 1 {
		t.Fatalf("equal bounds = %d, want 1", got)
	}
	if got := indexByteRangeScalar([]byte{0x10, 0x20}, 0x30, 0x40); got != -1 {
		t.Fatalf("miss = %d, want -1", got)
	}
}

func TestEqualRegexPrefixFold(t *testing.T) {
	if !equalRegexPrefixFold([]byte("AB"), []byte("ab"), false) {
		t.Fatal("folded prefix did not match")
	}
	if equalRegexPrefixFold([]byte("Ax"), []byte("ab"), false) {
		t.Fatal("mismatched prefix matched")
	}
	if !equalRegexPrefixFold([]byte{'A', 0, 'B', 0}, []byte{'a', 0, 'b', 0}, true) {
		t.Fatal("wide folded prefix did not match")
	}
}

func TestRegexByteSetCandidatePlan(t *testing.T) {
	search := regexByteSetSearch{
		data:    []byte{0x10, 0x11, 0x10, 0x11},
		pattern: RegexPattern{byteSet: regex.NewByteSet([]byte{0x11}), byteSetMinOffset: 0, byteSetMaxOffset: 0},
		cache:   &regexByteSetCandidateCache{},
	}
	plan, ok := search.candidatePlan()
	if !ok {
		t.Fatal("candidatePlan reported cancellation")
	}
	if !slices.Equal(plan.positions, []int{1, 3}) {
		t.Fatalf("positions = %v, want [1 3]", plan.positions)
	}
}

func TestRegexByteSetPlanCachedPositions(t *testing.T) {
	search := regexByteSetSearch{
		data:    make([]byte, 100),
		pattern: RegexPattern{byteSet: regex.NewByteSet([]byte{0x11})},
		cache:   &regexByteSetCandidateCache{},
	}
	entry := search.cacheEntry()
	entry.positions = []int{10, 20}
	entry.ready = true
	entry.complete = true
	plan, ok := search.candidatePlan()
	if !ok || !plan.useCached || plan.count == 0 {
		t.Fatalf("candidatePlan cached = %+v, %v, want cached plan with count", plan, ok)
	}
}

func TestRegexByteSetUnboundedPlanAtZero(t *testing.T) {
	search := regexByteSetSearch{
		data:    []byte{0x11, 0x22},
		pattern: RegexPattern{byteSet: regex.NewByteSet([]byte{0x11}), byteSetMaxOffset: -1},
		cache:   &regexByteSetCandidateCache{},
	}
	plan, ok := search.candidatePlan()
	if ok {
		t.Fatalf("candidatePlan(byte at 0) = (%+v, true), want handled=false", plan)
	}
}

func TestRegexByteSetCachePositionLimit(t *testing.T) {
	data := make([]byte, maxCachedRegexByteSetPositions+1)
	for i := range data {
		data[i] = 0x11
	}
	search := regexByteSetSearch{
		data:    data,
		pattern: RegexPattern{byteSet: regex.NewByteSet([]byte{0x11})},
		cache:   &regexByteSetCandidateCache{},
	}
	plan, ok := search.candidatePlan()
	if !ok {
		t.Fatal("candidatePlan reported cancellation")
	}
	if plan.positions != nil {
		t.Fatalf("plan.positions = %v, want nil when the cache overflows", plan.positions)
	}
}

func TestRegexCandidateStartRangesInitialCovered(t *testing.T) {
	// The initial covered bound is -1 (or -2/-1 for wide); a start range must not
	// be pushed forward past its natural first offset.
	narrow := regexByteSetSearch{
		data:    make([]byte, 100),
		pattern: RegexPattern{byteSetMinOffset: 0, byteSetMaxOffset: 10},
	}
	ranges := newRegexCandidateStartRanges(narrow)
	if first, _, ok := ranges.next(5); !ok || first != 0 {
		t.Fatalf("narrow next(5) first = %d, want 0", first)
	}

	wide := regexByteSetSearch{
		data:    make([]byte, 100),
		pattern: RegexPattern{byteSetMinOffset: 0, byteSetMaxOffset: 10},
		wide:    true,
	}
	wideRanges := newRegexCandidateStartRanges(wide)
	if first, _, ok := wideRanges.next(4); !ok || first != 0 {
		t.Fatalf("wide next(4) first = %d, want 0", first)
	}
}

// Residual gremlins survivors for regex_byte_set.go (gremlins v0.6.0,
// workers=1, timeout-coefficient=30), classified per #311:
//
// LIVED / equivalent-mode:
//
//	94:37,347:53   capacity arithmetic (limit / make cap) is not observable.
//	145:49,491:17  loop bounds whose extra final iteration scans an empty range
//	               and returns -1.
//	145:80,163:14  checkpoint++ is a no-op when done is nil.
//	234:23,253:23, (last-first)/step -> *step is identical for step == 1.
//	358:24
//	346:17         cap(starts) == 0 -> nil-vs-empty slice, both appendable.
//	359:12         count <= 0 is unreachable (count >= 1 whenever first <= last).
//	465:15         resampleAnchor returning false is a no-op.
//	476:41         pos > len(data) at equality: bytes.Index on an empty tail
//	               returns -1 either way.
//	586:46,614:25, guarded bounds where the boundary variant cannot change the
//	683:10,693:15, selected range.
//	702:11,702:27
//	674:14         lastFrom: -1 sentinel; from < lastFrom is false initially.
//	634:28         uint16 frequency underflow preserves the comparison order.
//
// NOT COVERED / unfixable-by-tests:
//
//	451:*,453:*,455:*  prefilterByteScore `switch { case ... }` arms; Go emits
//	                   no coverage block for a case expression.
//	664:30,665:30      const declarations emit no coverage block.
//
// NOT COVERED / not exercised:
//
//	103:103,116:11,121:52  unbounded cache-entry hit paths.
//	246:9,356:9            wide `first++` lane alignment.
//	524:12,527:122,528:17,530:10  SIMD indexContiguous guards, short-circuited
//	                       by byteSearchSIMDEnabled on this platform.
//
// TIMED OUT / non-terminating:
//
//	150:15,166:25,280:32,305:23,482:11,494:11,506:27,508:9,546:9,568:60,
//	574:9,580:11,687:10  negated loop bounds and `return -1` -> 1 make the scan
//	cursor walk backwards or never advance.
