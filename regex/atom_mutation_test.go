package regex

import (
	"math"
	"reflect"
	"testing"
)

func mustParseAtom(t *testing.T, pattern string) *AST {
	t.Helper()
	ast, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(pattern)
	if err != nil {
		t.Fatalf("parse %q: %v", pattern, err)
	}
	return ast
}

func TestAtomAddLength(t *testing.T) {
	tests := []struct {
		left, right, want int
	}{
		{0, 0, 0},
		{2, 3, 5},
		{-1, 5, -1},
		{5, -1, -1},
		{math.MaxInt - 1, 1, math.MaxInt},
		{math.MaxInt, 1, -1},
	}
	for _, tt := range tests {
		if got := addLength(tt.left, tt.right); got != tt.want {
			t.Fatalf("addLength(%d, %d) = %d, want %d", tt.left, tt.right, got, tt.want)
		}
	}
}

func TestAtomMultiplyLength(t *testing.T) {
	tests := []struct {
		length, count, want int
	}{
		{0, 5, 0},
		{2, 3, 6},
		{-1, 3, -1},
		{2, 1, 2},
		{2, math.MaxInt / 2, math.MaxInt - 1},
		{2, math.MaxInt/2 + 1, -1},
	}
	for _, tt := range tests {
		if got := multiplyLength(tt.length, tt.count); got != tt.want {
			t.Fatalf("multiplyLength(%d, %d) = %d, want %d", tt.length, tt.count, got, tt.want)
		}
	}
}

func TestAtomMaxLength(t *testing.T) {
	tests := []struct {
		left, right, want int
	}{
		{0, 5, 5},
		{5, 0, 5},
		{-1, 5, -1},
		{5, -1, -1},
		{3, 7, 7},
	}
	for _, tt := range tests {
		if got := maxLength(tt.left, tt.right); got != tt.want {
			t.Fatalf("maxLength(%d, %d) = %d, want %d", tt.left, tt.right, got, tt.want)
		}
	}
}

func TestRepeatLiteralBounds(t *testing.T) {
	if got := repeatLiteral(nil, 3); got != nil {
		t.Fatalf("repeatLiteral(nil, 3) = %v, want nil", got)
	}
	if got := repeatLiteral([]byte("ab"), 0); got != nil {
		t.Fatalf("repeatLiteral(ab, 0) = %v, want nil", got)
	}
	if got := repeatLiteral([]byte("ab"), -1); got != nil {
		t.Fatalf("repeatLiteral(ab, -1) = %v, want nil", got)
	}
	if got := string(repeatLiteral([]byte("ab"), 1)); got != "ab" {
		t.Fatalf("repeatLiteral(ab, 1) = %q, want ab", got)
	}
	if got := string(repeatLiteral([]byte("ab"), 3)); got != "ababab" {
		t.Fatalf("repeatLiteral(ab, 3) = %q, want ababab", got)
	}
	if got := repeatLiteral([]byte("ab"), math.MaxInt/2+1); got != nil {
		t.Fatalf("repeatLiteral(ab, overflow) = %v, want nil", got)
	}
}

func TestLiteralAtomOffsetWidth(t *testing.T) {
	if got := literalAtomOffsetWidth(LiteralAtom{MinOffset: 0, MaxOffset: 0}); got != 0 {
		t.Fatalf("literalAtomOffsetWidth(width 0) = %d, want 0", got)
	}
	if got := literalAtomOffsetWidth(LiteralAtom{MinOffset: 1, MaxOffset: 5}); got != 4 {
		t.Fatalf("literalAtomOffsetWidth(1..5) = %d, want 4", got)
	}
	if got := literalAtomOffsetWidth(LiteralAtom{MaxOffset: -1}); got != math.MaxInt {
		t.Fatalf("literalAtomOffsetWidth(unbounded) = %d, want MaxInt", got)
	}
}

func TestBetterByteSetAtomOrdering(t *testing.T) {
	two := NewByteSet([]byte{'a', 'b'})
	one := NewByteSet([]byte{'a'})
	tests := []struct {
		name      string
		candidate ByteSetAtom
		current   ByteSetAtom
		want      bool
	}{
		{
			name:      "bounded beats unbounded",
			candidate: ByteSetAtom{Set: two, MinOffset: 0, MaxOffset: 0},
			current:   ByteSetAtom{Set: one, MaxOffset: -1},
			want:      true,
		},
		{
			name:      "unbounded loses to bounded",
			candidate: ByteSetAtom{Set: one, MaxOffset: -1},
			current:   ByteSetAtom{Set: two, MinOffset: 0, MaxOffset: 0},
			want:      false,
		},
		{
			name:      "narrower width wins on equal count",
			candidate: ByteSetAtom{Set: two, MinOffset: 0, MaxOffset: 1},
			current:   ByteSetAtom{Set: two, MinOffset: 0, MaxOffset: 5},
			want:      true,
		},
		{
			name:      "width arithmetic distinguishes 4 from 5",
			candidate: ByteSetAtom{Set: two, MinOffset: 1, MaxOffset: 5},
			current:   ByteSetAtom{Set: two, MinOffset: 0, MaxOffset: 5},
			want:      true,
		},
		{
			name:      "wider loses",
			candidate: ByteSetAtom{Set: two, MinOffset: 0, MaxOffset: 5},
			current:   ByteSetAtom{Set: two, MinOffset: 0, MaxOffset: 1},
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := betterByteSetAtom(tt.candidate, tt.current); got != tt.want {
				t.Fatalf("betterByteSetAtom() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewLiteralAtomCoverPlanBounds(t *testing.T) {
	if cover, ok := newLiteralAtomCoverPlan(nil); ok || cover.fullyBounded {
		t.Fatalf("newLiteralAtomCoverPlan(nil) = (%+v, %v), want (unbounded, false)", cover, ok)
	}

	bounded, ok := newLiteralAtomCoverPlan([][]LiteralAtom{{{Data: []byte("ab"), MaxOffset: 0}}})
	if !ok || !bounded.fullyBounded {
		t.Fatalf("newLiteralAtomCoverPlan(MaxOffset 0) = (%+v, %v), want fullyBounded true", bounded, ok)
	}

	atCap, ok := newLiteralAtomCoverPlan([][]LiteralAtom{{{Data: make([]byte, maxLiteralAlternativeBytes)}}})
	if !ok || len(atCap.groups) != 1 {
		t.Fatalf("newLiteralAtomCoverPlan(totalBytes == cap) = (%+v, %v), want one group", atCap, ok)
	}
	if _, ok := newLiteralAtomCoverPlan([][]LiteralAtom{{{Data: make([]byte, maxLiteralAlternativeBytes+1)}}}); ok {
		t.Fatal("newLiteralAtomCoverPlan(totalBytes > cap) = true, want false")
	}
}

func TestBetterLiteralAtomCoverOrdering(t *testing.T) {
	candidate := literalAtomCoverPlan{groups: make([][]LiteralAtom, 4), fullyBounded: true, score: 1}
	current := literalAtomCoverPlan{groups: make([][]LiteralAtom, 2), fullyBounded: true, score: 3}
	if betterLiteralAtomCover(candidate, current) {
		t.Fatal("betterLiteralAtomCover(1x4, 3x2) = true, want false")
	}

	equalScoreCandidate := literalAtomCoverPlan{groups: make([][]LiteralAtom, 2), fullyBounded: true, score: 2, totalBytes: 10}
	equalScoreCurrent := literalAtomCoverPlan{groups: make([][]LiteralAtom, 2), fullyBounded: true, score: 2, totalBytes: 5}
	if betterLiteralAtomCover(equalScoreCandidate, equalScoreCurrent) {
		t.Fatal("betterLiteralAtomCover(equal score, more bytes) = true, want false")
	}

	bounded := literalAtomCoverPlan{fullyBounded: true}
	unbounded := literalAtomCoverPlan{fullyBounded: false}
	if !betterLiteralAtomCover(bounded, unbounded) || betterLiteralAtomCover(unbounded, bounded) {
		t.Fatal("betterLiteralAtomCover must prefer fullyBounded")
	}
}

func TestIntersectMandatoryAtomsWidths(t *testing.T) {
	common := intersectMandatoryAtoms([]atomAnalysis{
		{atoms: []LiteralAtom{{Data: []byte("xaay")}}},
		{atoms: []LiteralAtom{{Data: []byte("zaaw")}}},
	})
	if len(common) == 0 || string(common[0].Data) != "aa" {
		t.Fatalf("intersectMandatoryAtoms(2-byte common) = %+v, want window \"aa\"", common)
	}

	atCap := []atomAnalysis{
		{atoms: []LiteralAtom{{Data: make([]byte, maxLiteralAlternativeBytes/2)}}},
		{atoms: []LiteralAtom{{Data: make([]byte, maxLiteralAlternativeBytes/2)}}},
	}
	if got := intersectMandatoryAtoms(atCap); len(got) == 0 {
		t.Fatal("intersectMandatoryAtoms(totalBytes == 16KB) = nil, want common window")
	}

	if got := intersectMandatoryAtoms([]atomAnalysis{
		{atoms: []LiteralAtom{{Data: []byte("ab")}}},
		{atoms: []LiteralAtom{{Data: []byte("cd")}}},
	}); got != nil {
		t.Fatalf("intersectMandatoryAtoms(no common) = %+v, want nil", got)
	}
}

func TestMandatoryAtomWindowsOffset(t *testing.T) {
	windows := mandatoryAtomWindows([]LiteralAtom{
		{Data: []byte("ab"), MinOffset: 0, MaxOffset: 0},
		{Data: []byte("ab"), MinOffset: 3, MaxOffset: 3},
	}, 2)
	window, ok := windows["ab"]
	if !ok {
		t.Fatal("mandatoryAtomWindows missing key \"ab\"")
	}
	if window.MinOffset != 0 {
		t.Fatalf("mandatoryAtomWindows kept MinOffset %d, want first (0)", window.MinOffset)
	}
}

func TestMergeAlternativeByteSetAtomsCap(t *testing.T) {
	first := make([]byte, 0, 48)
	second := make([]byte, 0, 48)
	for value := range 48 {
		first = append(first, byte(value))
		second = append(second, byte(value+48))
	}
	merged := mergeAlternativeByteSetAtoms([]atomAnalysis{
		{byteAtoms: []ByteSetAtom{{Set: NewByteSet(first), MaxOffset: 0}}},
		{byteAtoms: []ByteSetAtom{{Set: NewByteSet(second), MaxOffset: 0}}},
	})
	if len(merged) != 1 || merged[0].Set.Count() != maxUsefulByteSetSize {
		t.Fatalf("mergeAlternativeByteSetAtoms(at cap) = %+v, want one %d-byte atom", merged, maxUsefulByteSetSize)
	}
}

func TestAsciiCasePairValueBoundary(t *testing.T) {
	ast := mustParseAtom(t, "[zZ]")
	value, ok := asciiCasePairValue(ast.Root)
	if !ok || value != 'z' {
		t.Fatalf("asciiCasePairValue([zZ]) = (%q, %v), want ('z', true)", value, ok)
	}
}

func TestLiteralAtomCoverFromAlternativesMinimum(t *testing.T) {
	if _, ok := literalAtomCoverFromAlternatives([][]LiteralAtom{{{Data: []byte("ab")}}}, 1); ok {
		t.Fatal("literalAtomCoverFromAlternatives(1 alternative) = true, want false")
	}
	if _, ok := literalAtomCoverFromAlternatives([][]LiteralAtom{
		{{Data: []byte("ab")}},
		{{Data: []byte("cd")}},
	}, 1); !ok {
		t.Fatal("literalAtomCoverFromAlternatives(2 alternatives) = false, want true")
	}
}

func TestLiteralAtomCoverFromMandatoryMinimum(t *testing.T) {
	if _, ok := literalAtomCoverFromMandatory([]LiteralAtom{{Data: []byte("ab")}}, 2); !ok {
		t.Fatal("literalAtomCoverFromMandatory(len == minimumLength) = false, want true")
	}
	if _, ok := literalAtomCoverFromMandatory([]LiteralAtom{{Data: []byte("a")}}, 2); ok {
		t.Fatal("literalAtomCoverFromMandatory(len < minimumLength) = true, want false")
	}
}

func TestAnalyzePlusAtomsUnboundedAndZeroWidth(t *testing.T) {
	unbounded := analyzePlusAtoms(&Node{Kind: NodePlus, Children: []*Node{{Kind: NodeLiteral, Value: 'a'}}})
	if unbounded.maxLength != -1 {
		t.Fatalf("analyzePlusAtoms(literal).maxLength = %d, want -1", unbounded.maxLength)
	}
	if len(unbounded.atoms) == 0 {
		t.Fatal("analyzePlusAtoms(literal) dropped the exact atom")
	}

	zeroWidth := analyzePlusAtoms(&Node{Kind: NodePlus, Children: []*Node{{Kind: NodeAnchorStart}}})
	if zeroWidth.maxLength != 0 {
		t.Fatalf("analyzePlusAtoms(zero-width).maxLength = %d, want 0", zeroWidth.maxLength)
	}
	if len(zeroWidth.atoms) != 0 {
		t.Fatalf("analyzePlusAtoms(zero-width).atoms = %+v, want none", zeroWidth.atoms)
	}
}

func TestAnalyzeRangeAtomsExactness(t *testing.T) {
	unboundedZero := analyzeRangeAtoms(&Node{
		Kind: NodeRange, Start: 0, End: math.MaxUint16,
		Children: []*Node{{Kind: NodeAnchorStart}},
	})
	if unboundedZero.maxLength != 0 {
		t.Fatalf("analyzeRangeAtoms(unbounded zero-width).maxLength = %d, want 0", unboundedZero.maxLength)
	}

	unbounded := analyzeRangeAtoms(&Node{
		Kind: NodeRange, Start: 0, End: math.MaxUint16,
		Children: []*Node{{Kind: NodeLiteral, Value: 'a'}},
	})
	if unbounded.maxLength != -1 {
		t.Fatalf("analyzeRangeAtoms(unbounded literal).maxLength = %d, want -1", unbounded.maxLength)
	}

	exact := analyzeRangeAtoms(&Node{
		Kind: NodeRange, Start: 2, End: 2,
		Children: []*Node{{Kind: NodeLiteral, Value: 'a'}},
	})
	if string(exact.exact) != "aa" || !exact.isExact {
		t.Fatalf("analyzeRangeAtoms(a{2}).exact = %q/%v, want \"aa\"/true", exact.exact, exact.isExact)
	}
	found := false
	for _, atom := range exact.atoms {
		if string(atom.Data) == "aa" {
			found = true
		}
	}
	if !found {
		t.Fatalf("analyzeRangeAtoms(a{2}).atoms = %+v, want repeated literal", exact.atoms)
	}
}

func TestAnalyzeAltAtomsExactAtoms(t *testing.T) {
	empty := analyzeAltAtoms([]*Node{{Kind: NodeEmpty}, {Kind: NodeEmpty}})
	if len(empty.atoms) != 0 {
		t.Fatalf("analyzeAltAtoms(empty, empty).atoms = %+v, want none", empty.atoms)
	}

	same := analyzeAltAtoms([]*Node{
		{Kind: NodeLiteral, Value: 'a'},
		{Kind: NodeLiteral, Value: 'a'},
	})
	if !reflect.DeepEqual(same.atoms, []LiteralAtom{{Data: []byte("a"), MaxOffset: 0}}) {
		t.Fatalf("analyzeAltAtoms(a, a).atoms = %+v, want exact \"a\"", same.atoms)
	}
}

// Mutation-test classification for regex/atom.go (gremlins v0.6.0, --workers 1):
//
// Equivalent-mode (no test can distinguish them):
//   - 100:40 (len(children)-index in a make cap) and 345:44/1206:37 (make
//     capacities): slice capacity is not observable.
//   - 113:28 (runValid && len(run) > 0): the run loop always executes at least
//     once, and a failed asciiCasePairValue clears runValid, so the
//     len(run) == 0 case is unreachable.
//   - 267:50 (maxLiteralAlternatives-len(cover.groups) -> +): appendAlternativeLeaves
//     already caps at maxLiteralAlternatives, so the widened comparison is never
//     the deciding term.
//   - 341:20 (len(expanded)*len(childBranches) -> +): a successful run needs a
//     trailing exact child, and once expanded reaches 16 the sum form
//     (expanded+1) also exceeds maxExpandedConcatBranches, so both reject.
//   - 473:19 (len(children) > 3): wrapping a single suffix child in a concat
//     yields the same atom analysis as the child itself.
//   - 538:29 (len(groups) > 0): every leaf must produce a non-empty group or
//     the function returns early, so groups is never empty here.
//   - 690:27 and 693:32 (quality/group-count comparisons): each is only
//     evaluated when its guard (candidateQuality != currentQuality, group
//     counts differ) is true, where < and <= coincide.
//   - 752:16 (len(*dst) >= maxLiteralAlternatives): the same over-cap leaves are
//     rejected by the downstream group-budget check.
//   - 1071:32 (count < count) and 1077:26 (width < width): only evaluated when
//     the compared values differ, where < and <= coincide.
//   - 1075:37 (current.MaxOffset - current.MinOffset -> +): MinOffset is
//     non-negative, so the mutated width is never smaller and cannot flip the
//     comparison.
//
// Impractical: 1203:11 (repeatLiteral count == MaxInt/len) would allocate a
// MaxInt-sized slice to reach the boundary.
//
// Non-terminating (gremlins TIMED OUT): 101:14, 111:10, 325:9, 336:13 and
// 1099:42 invert a loop counter.

func literalConcatNode(n int) *Node {
	children := make([]*Node, n)
	for i := range children {
		children[i] = &Node{Kind: NodeLiteral, Value: 'a'}
	}
	return &Node{Kind: NodeConcat, Children: children}
}

func literalAltNode(n int) *Node {
	children := make([]*Node, n)
	for i := range children {
		children[i] = &Node{Kind: NodeLiteral, Value: byte('a' + i%26)}
	}
	return &Node{Kind: NodeAlt, Children: children}
}

func TestBetterByteSetAtomCountOrdering(t *testing.T) {
	one := NewByteSet([]byte{'a'})
	two := NewByteSet([]byte{'a', 'b'})
	if !betterByteSetAtom(
		ByteSetAtom{Set: one, MinOffset: 0, MaxOffset: 0},
		ByteSetAtom{Set: two, MinOffset: 0, MaxOffset: 0},
	) {
		t.Fatal("betterByteSetAtom(smaller set) = false, want true")
	}
}

func TestBetterLiteralAtomCoverCountAndBytes(t *testing.T) {
	// Equal scores and group counts: the total-bytes tie-break decides, and the
	// group-count equality must not short-circuit it.
	smallBytes := literalAtomCoverPlan{groups: make([][]LiteralAtom, 2), fullyBounded: true, score: 2, totalBytes: 3}
	largeBytes := literalAtomCoverPlan{groups: make([][]LiteralAtom, 2), fullyBounded: true, score: 2, totalBytes: 9}
	if !betterLiteralAtomCover(smallBytes, largeBytes) {
		t.Fatal("betterLiteralAtomCover(fewer bytes) = false, want true")
	}
	equalBytes := literalAtomCoverPlan{groups: make([][]LiteralAtom, 2), fullyBounded: true, score: 2, totalBytes: 9}
	if betterLiteralAtomCover(equalBytes, largeBytes) {
		t.Fatal("betterLiteralAtomCover(equal bytes) = true, want false")
	}
}

func TestAnalyzeRangeAtomsExactEmptyAtMinimum(t *testing.T) {
	result := analyzeRangeAtoms(&Node{
		Kind: NodeRange, Start: 1, End: 1,
		Children: []*Node{{Kind: NodeEmpty}},
	})
	if len(result.atoms) != 0 {
		t.Fatalf("analyzeRangeAtoms(empty{1}).atoms = %+v, want none", result.atoms)
	}
}

func TestLiteralAlternativeAtomCoverCap(t *testing.T) {
	if _, ok := literalAlternativeAtomCover(literalAltNode(256).Children, 1); !ok {
		t.Fatal("literalAlternativeAtomCover(256) = false, want true")
	}
	if _, ok := literalAlternativeAtomCover(literalAltNode(257).Children, 1); ok {
		t.Fatal("literalAlternativeAtomCover(257) = true, want false")
	}
}

func TestRequiredLiteralAlternationCoverCap(t *testing.T) {
	if _, ok := requiredLiteralAlternationCover(literalAltNode(256), 1); !ok {
		t.Fatal("requiredLiteralAlternationCover(256) = false, want true")
	}
	if _, ok := requiredLiteralAlternationCover(literalAltNode(257), 1); ok {
		t.Fatal("requiredLiteralAlternationCover(257) = true, want false")
	}
}

func TestLiteralAlternativesByteCap(t *testing.T) {
	ast := &AST{Root: &Node{Kind: NodeAlt, Children: []*Node{literalConcatNode(8192), literalConcatNode(8192)}}}
	if got := LiteralAlternatives(ast); len(got) != 2 {
		t.Fatalf("LiteralAlternatives(at byte cap) = %d alternatives, want 2", len(got))
	}
}

func TestAlternativeMandatoryLiteralAtomsByteCap(t *testing.T) {
	// A concat of 8192 literals yields 8192 single-byte atoms plus the merged
	// 8192-byte run, i.e. exactly maxLiteralAlternativeBytes of atom data.
	ast := &AST{Root: &Node{Kind: NodeAlt, Children: []*Node{literalConcatNode(8192)}}}
	if got := AlternativeMandatoryLiteralAtoms(ast); len(got) != 1 {
		t.Fatalf("AlternativeMandatoryLiteralAtoms(at byte cap) = %d groups, want 1", len(got))
	}
}

func TestExpandBoundedConcatAlternationCoverBounds(t *testing.T) {
	// A run that reaches exactly maxExpandedConcatBranches must stay valid.
	atCap := mustParseAtom(t, "[ab][cd][ef][gh]x")
	if _, ok := expandBoundedConcatAlternationCover(atCap.Root.Children, 1); !ok {
		t.Fatal("expandBoundedConcatAlternationCover(exactly 16 branches) = false, want true")
	}
	// Three 3-way classes overflow the branch budget, so the run is rejected.
	over := mustParseAtom(t, "[abc][def][ghi]x")
	if _, ok := expandBoundedConcatAlternationCover(over.Root.Children, 1); ok {
		t.Fatal("expandBoundedConcatAlternationCover(27 branches) = true, want false")
	}
	// A branch whose length equals minimumLength must still be kept.
	exact := mustParseAtom(t, "[ab]x")
	if _, ok := expandBoundedConcatAlternationCover(exact.Root.Children, 2); !ok {
		t.Fatal("expandBoundedConcatAlternationCover(len == minimumLength) = false, want true")
	}
}

func TestExactConcatChildBranchesBounds(t *testing.T) {
	emptyRange := &Node{Kind: NodeRange, Start: 0, End: 1, Children: []*Node{{Kind: NodeEmpty}}}
	if _, _, ok := exactConcatChildBranches(emptyRange); ok {
		t.Fatal("exactConcatChildBranches(empty optional) = true, want false")
	}

	twoClass := &Node{Kind: NodeClass, Class: &Class{}}
	classSet(twoClass.Class, 'a')
	classSet(twoClass.Class, 'b')
	if _, multi, ok := exactConcatChildBranches(twoClass); !ok || !multi {
		t.Fatal("exactConcatChildBranches(2-member class) = false, want multi-branch")
	}

	eightClass := &Node{Kind: NodeClass, Class: &Class{}}
	for _, value := range []byte{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'} {
		classSet(eightClass.Class, value)
	}
	if _, _, ok := exactConcatChildBranches(eightClass); !ok {
		t.Fatal("exactConcatChildBranches(8-member class) = false, want true")
	}

	sixteen := literalAltNode(16)
	if _, _, ok := exactConcatChildBranches(sixteen); !ok {
		t.Fatal("exactConcatChildBranches(16 leaves) = false, want true")
	}
	if _, _, ok := exactConcatChildBranches(literalAltNode(17)); ok {
		t.Fatal("exactConcatChildBranches(17 leaves) = true, want false")
	}
}

func TestLeadingByteGapAtomCover(t *testing.T) {
	tests := []struct {
		pattern string
		gapMin  int
		gapMax  int
		wantOK  bool
	}{
		{pattern: `a\d+bcd`, gapMin: 1, gapMax: -1, wantOK: true},
		{pattern: `a[0-9]{2,3}xyz`, gapMin: 2, gapMax: 3, wantOK: true},
		{pattern: `a[0-9]*x`, gapMin: 0, gapMax: -1, wantOK: true},
		{pattern: `a[0-9]{2,}b`, gapMin: 2, gapMax: -1, wantOK: true},
		{pattern: `a\d+b`, gapMin: 1, gapMax: -1, wantOK: true},
		{pattern: `a\d+`, wantOK: false},
		{pattern: `ab`, wantOK: false},
		{pattern: `^a\d+b`, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			ast, err := NewParser(ParserFlagEnableStrictEscapeSequences).Parse(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			plan, ok := LeadingByteGapAtomCover(ast, 0, 1)
			if ok != tt.wantOK {
				t.Fatalf("LeadingByteGapAtomCover(%q) ok = %v, want %v", tt.pattern, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if plan.LeadingSet.Count() != 1 || !plan.LeadingSet.Contains('a') {
				t.Fatalf("LeadingSet = count %d, want single 'a'", plan.LeadingSet.Count())
			}
			if plan.GapSet.Count() != 10 {
				t.Fatalf("GapSet count = %d, want 10", plan.GapSet.Count())
			}
			if plan.GapMin != tt.gapMin || plan.GapMax != tt.gapMax {
				t.Fatalf("gap = [%d,%d], want [%d,%d]", plan.GapMin, plan.GapMax, tt.gapMin, tt.gapMax)
			}
			if len(plan.AtomGroups) == 0 {
				t.Fatal("AtomGroups empty")
			}
		})
	}

	if _, ok := LeadingByteGapAtomCover(nil, 0, 1); ok {
		t.Fatal("LeadingByteGapAtomCover(nil) = true, want false")
	}

	ast := mustParseAtom(t, `a\d+bcd`)
	plan, ok := LeadingByteGapAtomCover(ast, 0, 3)
	if !ok || len(plan.AtomGroups) != 1 || len(plan.AtomGroups[0]) != 1 || string(plan.AtomGroups[0][0].Data) != "bcd" {
		t.Fatalf("LeadingByteGapAtomCover(minlen=3) = (%+v, %v), want just \"bcd\"", plan.AtomGroups, ok)
	}
}

func TestAnalyzeAtomsRangeAnyAndDefault(t *testing.T) {
	unbounded := analyzeAtoms(&Node{Kind: NodeRangeAny, Start: 0, End: math.MaxUint16})
	if unbounded.maxLength != -1 {
		t.Fatalf("analyzeAtoms(unbounded RangeAny).maxLength = %d, want -1", unbounded.maxLength)
	}
	bounded := analyzeAtoms(&Node{Kind: NodeRangeAny, Start: 2, End: 5})
	if bounded.minLength != 2 || bounded.maxLength != 5 {
		t.Fatalf("analyzeAtoms(RangeAny 2..5) = [%d,%d], want [2,5]", bounded.minLength, bounded.maxLength)
	}
	unknown := analyzeAtoms(&Node{Kind: NodeKind(99)})
	if unknown.maxLength != -1 {
		t.Fatalf("analyzeAtoms(unknown).maxLength = %d, want -1", unknown.maxLength)
	}
}

func TestBetterLiteralAtomCoverGroupCountTieBreak(t *testing.T) {
	candidate := literalAtomCoverPlan{groups: make([][]LiteralAtom, 2), fullyBounded: true, score: 4}
	current := literalAtomCoverPlan{groups: make([][]LiteralAtom, 3), fullyBounded: true, score: 6}
	// candidateQuality = 4*3 = 12, currentQuality = 6*2 = 12 (equal), then 2 < 3.
	if !betterLiteralAtomCover(candidate, current) {
		t.Fatal("betterLiteralAtomCover(fewer groups at equal quality) = false, want true")
	}
}
