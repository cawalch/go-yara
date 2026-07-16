package compiler

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestSelectHexAtomUsesOnlyFixedOffsets(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		want       []byte
		wantOffset int
		wantOK     bool
	}{
		{name: "literal", pattern: "DE AD BE EF", want: []byte{0xDE, 0xAD, 0xBE, 0xEF}, wantOK: true},
		{name: "leading wildcard", pattern: "?? 11 22 33", want: []byte{0x11, 0x22, 0x33}, wantOffset: 1, wantOK: true},
		{name: "fixed jump", pattern: "44 [2] 55 66 77", want: []byte{0x55, 0x66, 0x77}, wantOffset: 3, wantOK: true},
		{name: "before variable jump", pattern: "AA BB [1-3] CC DD", want: []byte{0xAA, 0xBB}, wantOK: true},
		{name: "after variable jump", pattern: "?? [1-3] CC DD", wantOK: false},
		{name: "after alternative", pattern: "AA (BB | CC) DD EE", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := parseHexTokens(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			atom, ok := selectHexAtom(tokens)
			if ok != tt.wantOK {
				t.Fatalf("selectHexAtom ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if !bytes.Equal(atom.data, tt.want) || atom.offset != tt.wantOffset {
				t.Fatalf("selectHexAtom = (% X, %d), want (% X, %d)", atom.data, atom.offset, tt.want, tt.wantOffset)
			}
		})
	}
}

func TestCompiledRegexCarriesMandatoryInternalAtom(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule internal_atom {
			strings:
				$pattern = /[a-z]{1,8}family_marker/
			condition:
				$pattern
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	pattern := program.Rules[0].RegexPatterns["$pattern"]
	if len(pattern.prefix) != 0 {
		t.Fatalf("literal prefix = %q, want none", pattern.prefix)
	}
	if string(pattern.atom) != "ly_marke" {
		t.Fatalf("mandatory atom = %q, want %q", pattern.atom, "ly_marke")
	}
	if pattern.atomMinOffset != 5 || pattern.atomMaxOffset != 12 {
		t.Fatalf("mandatory atom offsets = [%d,%d], want [5,12]", pattern.atomMinOffset, pattern.atomMaxOffset)
	}
}

func TestCompiledRegexCarriesLiteralAlternativeAtoms(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule literal_alternatives {
			strings:
				$pattern = /(cardholder|nameoncard|expiry|expiration)\b/
			condition:
				$pattern
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	pattern := program.Rules[0].RegexPatterns["$pattern"]
	if len(pattern.atom) != 0 {
		t.Fatalf("mandatory atom = %q, want none", pattern.atom)
	}
	if len(pattern.alternativeAtoms) != 4 || len(pattern.wideAlternativeAtoms) != 4 {
		t.Fatalf("alternative atom counts = ascii:%d wide:%d, want 4 each",
			len(pattern.alternativeAtoms), len(pattern.wideAlternativeAtoms))
	}
	for index, atom := range pattern.alternativeAtoms {
		if len(atom.data) < minPrefilterAtomLength || atom.minOffset != atom.maxOffset {
			t.Errorf("alternative atom %d = %+v, want a useful exact-offset atom", index, atom)
		}
		wide := pattern.wideAlternativeAtoms[index]
		if wide.minOffset != atom.minOffset*2 || wide.maxOffset != atom.maxOffset*2 {
			t.Errorf("wide alternative atom %d offsets = [%d,%d], want [%d,%d]",
				index, wide.minOffset, wide.maxOffset, atom.minOffset*2, atom.maxOffset*2)
		}
	}
}

func TestLiteralAlternativeRegexAtomsMatchLinearScan(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule literal_alternatives {
			strings:
				$issue = /(cardholder|nameoncard|expiry|expiration)\b/
				$nocase = /(alpha_marker|beta_token|gamma_value)/ nocase
				$wide = /(wide_alpha|wide_beta|wide_gamma)/ wide
				$both = /(dual_alpha|dual_beta|dual_gamma)/ ascii wide
				$leading_assertion = /\b(boundary_alpha|boundary_beta)/
				$offset_window = /(abcdefghij|klmnopqrst|uvwxyzabcd)/
			condition:
				any of them
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	rule := program.Rules[0]
	dataSets := [][]byte{
		make([]byte, 1024),
		[]byte("cardholder nameoncardx expiry expiration! ALPHA_MARKER beta_token gamma_value boundary_alpha xboundary_beta abcdefghij klmnopqrst uvwxyzabcd"),
		append([]byte("dual_alpha "), widenRegexPrefix([]byte("wide_beta dual_gamma"))...),
	}
	for dataIndex, data := range dataSets {
		optimized := BuildMatchContext(rule, data)
		linear := buildLinearRegexContext(rule, data)
		for _, id := range sortedPatternIDs(rule.RegexPatterns) {
			got := matchRangesInOrder(optimized.Matches[id])
			want := matchRangesInOrder(linear.Matches[id])
			if !slices.Equal(got, want) {
				t.Errorf("data %d, %s ranges = %v, linear scan = %v", dataIndex, id, got, want)
			}
		}
		optimized.Release()
		linear.Release()
	}
}

func TestCompiledRegexRejectsIncompleteLiteralAlternatives(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule incomplete_alternatives {
			strings:
				$prefix = /prefix(foo|bar)/
				$suffix = /(foo|bar)suffix/
				$mixed = /(foo|b.r)/
				$short = /(a|bar)/
			condition:
				any of them
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	for id, pattern := range program.Rules[0].RegexPatterns {
		if len(pattern.alternativeAtoms) != 0 {
			t.Errorf("%s alternative atoms = %+v, want none", id, pattern.alternativeAtoms)
		}
	}
}

func TestCompiledRegexPrefersBoundedMandatoryAtom(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule bounded_atom {
			strings:
				$pattern = /[a-z]{1,2}bounded_marker.*unbounded_entropy/
			condition:
				$pattern
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	pattern := program.Rules[0].RegexPatterns["$pattern"]
	if len(pattern.atom) == 0 || pattern.atomMaxOffset < 0 {
		t.Fatalf("selected atom = %q at [%d,%d], want a bounded atom", pattern.atom, pattern.atomMinOffset, pattern.atomMaxOffset)
	}
}

func TestCompiledRegexCarriesMandatoryByteSet(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule byte_set_atom {
			strings:
				$pattern = /.{2}[a-z]{2}/
			condition:
				$pattern
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	pattern := program.Rules[0].RegexPatterns["$pattern"]
	if pattern.byteSetCount != 26 || !pattern.byteSetContiguous {
		t.Fatalf("byte set count = %d, contiguous = %v", pattern.byteSetCount, pattern.byteSetContiguous)
	}
	if pattern.byteSetLower != 'a' || pattern.byteSetUpper != 'z' {
		t.Fatalf("byte set bounds = [%#x,%#x], want ['a','z']", pattern.byteSetLower, pattern.byteSetUpper)
	}
	if pattern.byteSetMinOffset != 2 || pattern.byteSetMaxOffset != 2 {
		t.Fatalf("byte set offsets = [%d,%d], want [2,2]", pattern.byteSetMinOffset, pattern.byteSetMaxOffset)
	}
}

func TestCompiledRegexCarriesFixedByteSets(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule fixed_byte_sets {
			strings:
				$singleton = /[a]{2}[0-9]/
				$classes = /[ab]{2}[0-9]/
			condition:
				any of them
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	singleton := program.Rules[0].RegexPatterns["$singleton"]
	if string(singleton.atom) != "aa" || singleton.atomMinOffset != 0 || singleton.atomMaxOffset != 0 {
		t.Fatalf("singleton atom = %q at [%d,%d], want aa at [0,0]", singleton.atom, singleton.atomMinOffset, singleton.atomMaxOffset)
	}
	classes := program.Rules[0].RegexPatterns["$classes"]
	if len(classes.fixedByteSets) != 3 {
		t.Fatalf("fixed byte sets = %d, want 3", len(classes.fixedByteSets))
	}
	if classes.fixedByteSets[0].Count() != 2 || classes.fixedByteSets[2].Count() != 10 {
		t.Fatalf("fixed byte-set counts = [%d,%d,%d], want [2,2,10]",
			classes.fixedByteSets[0].Count(), classes.fixedByteSets[1].Count(), classes.fixedByteSets[2].Count())
	}
}

func TestIndexRegexLiteralNoCaseUsesEitherASCIICase(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		literal []byte
		wide    bool
		want    int
	}{
		{name: "lowercase literal", data: []byte("xxEXPyy"), literal: []byte("exp"), want: 2},
		{name: "uppercase literal", data: []byte("xxexpyy"), literal: []byte("EXP"), want: 2},
		{name: "frequent first byte absent", data: []byte(strings.Repeat("e", 256)), literal: []byte("exp"), want: -1},
		{name: "nonletter first byte", data: []byte("xx_0Xyy"), literal: []byte("_0x"), want: 2},
		{name: "wide", data: widenRegexPrefix([]byte("EXP")), literal: widenRegexPrefix([]byte("exp")), wide: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := indexRegexLiteral(tt.data, 0, tt.literal, regex.FlagsNoCase, tt.wide)
			if got != tt.want {
				t.Fatalf("indexRegexLiteral() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestMandatoryRegexAtomMatchesLinearScan(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule internal_atoms {
			strings:
				$bounded = /[a-z]{1,8}family_marker/
				$zero_width = /.{0,8}family_marker/
				$unbounded = /.*family_marker/
				$alternation = /alpha_marker|beta_marker/
				$branch_prefix = /(x|long)family_marker/
				$nocase = /[a-z]{1,3}case_marker/i
				$wide = /[a-z]{1,3}wide_marker/ wide
				$both = /[a-z]{1,3}dual_marker/ ascii wide
				$overlap = /[a-z]{1,2}aba/
				$optional = /(family_marker)?/
				$anchored = /^[a-z]{1,8}anchored_marker/
				$atomless = /[a-z]{2,4}[0-9]{2}/
				$atomless_nocase = /[a-z]{2}[0-9]{2}/i
				$atomless_wide = /[a-z]{2}[0-9]{2}/ wide
				$optional_first = /[a-z]?[0-9]{2}/
				$later_fixed = /.{2}[a-z]{2}/
				$later_variable = /.{1,3}[a-z]{2}/
				$alt_classes = /([a-c]|[x-z])[0-9]/
				$alt_offsets = /[a-c]|..[x-z]/
				$plus_class = /[a-z]+[0-9]{2}/
			condition:
				any of them
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	rule := program.Rules[0]
	wideData := widenRegexPrefix([]byte("xywide_marker zzdual_marker ab12"))
	dataSets := [][]byte{
		make([]byte, 128),
		[]byte("xfamily_marker longfamily_marker alpha_marker beta_marker xxCASE_MARKER zaba zzaba"),
		[]byte("abcdefghanchored_marker and later abcanchored_marker"),
		append([]byte("ascii xydual_marker "), wideData...),
		[]byte("family_markerfamily_marker"),
		[]byte("ab12 z99 AB34 12 xxab z7 xyz99"),
	}

	for dataIndex, data := range dataSets {
		optimized := BuildMatchContext(rule, data)
		linear := buildLinearRegexContext(rule, data)
		for _, id := range sortedPatternIDs(rule.RegexPatterns) {
			got := matchRangesInOrder(optimized.Matches[id])
			want := matchRangesInOrder(linear.Matches[id])
			if !slices.Equal(got, want) {
				t.Errorf("data %d, %s ranges = %v, linear scan = %v", dataIndex, id, got, want)
			}
		}
		optimized.Release()
		linear.Release()
	}
}

func TestScannerReusesMandatoryByteSetPositions(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule reused_byte_set {
			strings:
				$first = /.{1,2}[a-z]{2}/
				$second = /.{3,4}[a-z]{2}/
			condition:
				any of them
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	if _, err := scanner.Scan(make([]byte, 128)); err != nil {
		t.Fatal(err)
	}
	if len(scanner.regexByteSetCache.entries) != 1 {
		t.Fatalf("byte-set cache entries = %d, want 1", len(scanner.regexByteSetCache.entries))
	}

	data := []byte("00ab 0000cd")
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	linear := buildLinearRegexContext(program.Rules[0], data)
	defer linear.Release()
	for _, id := range []string{"$first", "$second"} {
		got := matchRangesInOrder(result.Matches["reused_byte_set"][id])
		want := matchRangesInOrder(linear.Matches[id])
		if !slices.Equal(got, want) {
			t.Errorf("%s cached ranges = %v, linear scan = %v", id, got, want)
		}
	}
}

func TestRegexByteSetCandidateIteratorMatchesCollectedStarts(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule byte_set_candidates {
			strings:
				$fixed = /.{2}[a-z]{2}/
				$variable = /.{1,3}[a-z]{2}/
				$alternative = /[a-c]|..[x-z]/
				$optional = /[a-z]?[0-9]{2}/
				$wide = /.{1,2}[a-z]{2}/ wide
			condition:
				any of them
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	rule := program.Rules[0]
	data := append([]byte("00ab xz z99 12 "), widenRegexPrefix([]byte("00ab xz"))...)

	for _, cached := range []bool{false, true} {
		var cache regexByteSetCandidateCache
		for _, id := range sortedPatternIDs(rule.RegexPatterns) {
			pattern := rule.RegexPatterns[id]
			wide := id == "$wide"
			search := regexByteSetSearch{data: data, pattern: pattern, wide: wide}
			if cached {
				search.cache = &cache
			}

			positions := make([]int, 0)
			for searchFrom := 0; searchFrom <= len(data); {
				position := search.index(searchFrom)
				if position < 0 {
					break
				}
				positions = append(positions, position)
				searchFrom = position + 1
			}
			minOffset := pattern.byteSetMinOffset
			maxOffset := pattern.byteSetMaxOffset
			if wide {
				minOffset *= 2
				maxOffset *= 2
			}
			limit := max(1024, len(data)/4)
			want, wantHandled := collectRegexCandidateStarts(positions, minOffset, maxOffset, wide, len(data), limit)

			plan, handled := search.candidatePlan()
			if handled != wantHandled {
				t.Fatalf("cached=%v %s handled=%v, want %v", cached, id, handled, wantHandled)
			}
			if !handled {
				continue
			}
			got := make([]int, 0, plan.count)
			iterator := search.candidateIterator(plan)
			for start, ok := iterator.next(); ok; start, ok = iterator.next() {
				got = append(got, start)
			}
			if !slices.Equal(got, want) {
				t.Errorf("cached=%v %s starts=%v, want %v", cached, id, got, want)
			}
		}
	}
}

func TestSharedMandatoryRegexAtomsMatchLinearScan(t *testing.T) {
	var source strings.Builder
	source.WriteString("rule shared_internal_atoms {\nstrings:\n")
	for i := range 40 {
		switch i {
		case 0:
			fmt.Fprintln(&source, "$pattern_00 = /[a-z]{1,3}wide_marker_00/ wide")
		case 1:
			fmt.Fprintln(&source, "$pattern_01 = /[a-z]{1,3}case_marker_01/i")
		default:
			fmt.Fprintf(&source, "$pattern_%02d = /[a-z]{0,3}family_marker_%02d/\n", i, i)
		}
	}
	source.WriteString("condition: any of them\n}\n")
	program, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		t.Fatal(err)
	}
	regexEntries := 0
	for _, entry := range program.SharedLookup {
		if entry.Kind == StringKindRegex {
			regexEntries++
		}
	}
	if regexEntries < 40 {
		t.Fatalf("shared regex entries = %d, want at least 40", regexEntries)
	}

	data := []byte("abfamily_marker_05 FAMILY_MARKER_01 xyzfamily_marker_37 ")
	data = append(data, widenRegexPrefix([]byte("xywide_marker_00"))...)
	scanner := NewScanner(program)
	defer scanner.Close()
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	rule := program.Rules[0]
	linear := buildLinearRegexContext(rule, data)
	defer linear.Release()
	for _, id := range sortedPatternIDs(rule.RegexPatterns) {
		got := matchRangesInOrder(result.Matches[rule.Name][id])
		want := matchRangesInOrder(linear.Matches[id])
		if !slices.Equal(got, want) {
			t.Errorf("%s shared ranges = %v, linear scan = %v", id, got, want)
		}
	}
}

func TestFixedRegexDispatchMatchesLinearScan(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule fixed_dispatch {
			strings:
				$a = /[ab]{2}[0-9]/
				$b = /[cd]{2}[0-9]/ nocase
				$c = /[ef]{2}[0-9]/ wide
				$d = /[gh]{2}[0-9]/ ascii wide
				$e = /[ij]{2}[0-9]/
				$f = /[kl]{2}[0-9]/ fullword
				$g = /.[mn]/
				$h = /.[op]/s
				$negated = /[^q]{2}[0-9]/ nocase
			condition:
				any of them
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	if program.fixedRegexScan == nil {
		t.Fatal("fixed regex dispatch was not built")
	}
	if shouldUseFixedRegexDispatch(make([]byte, 4096), program.fixedRegexScan) {
		t.Fatal("fixed regex dispatch selected for a no-candidate sample")
	}
	if !shouldUseFixedRegexDispatch(bytes.Repeat([]byte("a0c0e0g0"), 512), program.fixedRegexScan) {
		t.Fatal("fixed regex dispatch not selected for a candidate-rich sample")
	}

	data := []byte("aa1 CC2 gg4 xkk6x kk6 \nm \np qq1 rr2 ")
	data = append(data, widenRegexPrefix([]byte("ee3 hh5"))...)
	scanner := NewScanner(program)
	defer scanner.Close()
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	rule := program.Rules[0]
	linear := buildLinearRegexContext(rule, data)
	defer linear.Release()
	for _, id := range sortedPatternIDs(rule.RegexPatterns) {
		got := matchRangesInOrder(result.Matches[rule.Name][id])
		want := matchRangesInOrder(linear.Matches[id])
		if !slices.Equal(got, want) {
			t.Errorf("%s dispatch ranges = %v, linear scan = %v", id, got, want)
		}
	}
}

func buildLinearRegexContext(rule *CompiledRule, data []byte) *MatchContext {
	ctx := matchContextPool.Get().(*MatchContext)
	ctx.Reset(data)
	for id, pattern := range rule.RegexPatterns {
		pattern.prefix = nil
		pattern.widePrefix = nil
		pattern.atom = nil
		pattern.wideAtom = nil
		pattern.alternativeAtoms = nil
		pattern.wideAlternativeAtoms = nil
		pattern.byteSetCount = 0
		pattern.fixedByteSets = nil
		modifiers := rule.StringModifiers[id]
		addRegexMatchesWithModifiers(ctx, id, pattern, data, modifiers)
	}
	return ctx
}

func matchRangesInOrder(matches []Match) []matchRange {
	ranges := make([]matchRange, len(matches))
	for i, match := range matches {
		ranges[i] = matchRange{offset: match.Offset, length: match.Length}
	}
	return ranges
}

func TestSharedNonTextPrefilterMatchesLocalEngines(t *testing.T) {
	var source strings.Builder
	source.WriteString(`
		rule prefilter_all {
			strings:
				$regex_ascii = /family_[a-z]{1,2}\.exe/i
				$regex_window = /common_prefix_variant_[0-9]+/
				$regex_wide = /wide_marker_[a-z]+/ wide
				$regex_both = /dual_marker_[a-z]+/i ascii wide
				$regex_anchor = /^anchored_prefix_[a-z]+/
				$regex_overlap = /aba/
				$hex_linear = { DE AD BE EF }
				$hex_jump = { 0A 0B [2-4] 0C 0D }
				$hex_offset = { ?? 11 22 33 }
				$hex_fixed_jump = { 44 [2] 55 66 77 }
				$hex_alt = { 88 99 ( AA | BB ) }
				$fallback_short = /a[0-9]+/
				$fallback_atomless = /[a-z]+_tail/
				$fallback_hex = { ?? [1-3] DE AD }
				$fallback_xor = { AB CD EF } xor(1)
	`)
	// Keep the integration test above the compile-time crossover so it
	// exercises the shared non-text path even if the threshold is retuned.
	for i := range 80 {
		fmt.Fprintf(&source, "\t\t\t\t$filler_%d = /never_%02d_prefix_[0-9]+/\n", i, i)
	}
	source.WriteString(`
			condition:
				any of them
		}
		rule duplicate_a {
			strings:
				$regex_a = /family_[a-z]{1,2}\.exe/i
				$hex_a = { DE AD BE EF }
			condition:
				$regex_a and $hex_a
		}
		rule duplicate_b {
			strings:
				$regex_b = /family_[a-z]{1,2}\.exe/i
				$hex_b = { DE AD BE EF }
			condition:
				$regex_b and $hex_b
		}
	`)

	program, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		t.Fatal(err)
	}
	var regexEntries, hexEntries int
	for _, entry := range program.SharedLookup {
		switch entry.Kind {
		case StringKindRegex:
			regexEntries++
		case StringKindHex:
			hexEntries++
		}
	}
	if regexEntries == 0 || hexEntries == 0 {
		t.Fatalf("shared prefilter entries: regex=%d hex=%d", regexEntries, hexEntries)
	}

	data := []byte("anchored_prefix_yes family_AB.exe common_prefix_variant_42 aba ababa dual_marker_ascii hello_tail ")
	data = append(data, widenRegexPrefix([]byte("wide_marker_test"))...)
	data = append(data, ' ')
	data = append(data, widenRegexPrefix([]byte("DUAL_MARKER_WIDE"))...)
	data = append(data,
		0xDE, 0xAD, 0xBE, 0xEF,
		0x0A, 0x0B, 0x00, 0x00, 0x00, 0x0C, 0x0D,
		0x00, 0x11, 0x22, 0x33,
		0x44, 0xAA, 0xBB, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xBB,
		0x00, 0x00, 0xDE, 0xAD,
		0xAA, 0xCC, 0xEE,
	)

	scanner := NewScanner(program)
	defer scanner.Close()
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}

	rule := program.Rules[0]
	local := BuildMatchContext(rule, data)
	defer local.Release()
	for _, id := range rule.StringIdentifiers() {
		got := normalizedMatchRanges(result.Matches[rule.Name][id])
		want := normalizedMatchRanges(local.Matches[id])
		if !slices.Equal(got, want) {
			t.Errorf("%s ranges = %v, local matcher = %v", id, got, want)
		}
	}
	for _, duplicate := range []struct {
		rule    string
		regexID string
		hexID   string
	}{
		{rule: "duplicate_a", regexID: "$regex_a", hexID: "$hex_a"},
		{rule: "duplicate_b", regexID: "$regex_b", hexID: "$hex_b"},
	} {
		if !result.RuleResults[duplicate.rule] ||
			len(result.Matches[duplicate.rule][duplicate.regexID]) == 0 ||
			len(result.Matches[duplicate.rule][duplicate.hexID]) == 0 {
			t.Errorf("deduplicated matches missing for %s: %v", duplicate.rule, result.Matches[duplicate.rule])
		}
	}

	cleanData := []byte("a clean payload without any configured atoms")
	cleanResult, err := scanner.Scan(cleanData)
	if err != nil {
		t.Fatal(err)
	}
	cleanLocal := BuildMatchContext(rule, cleanData)
	defer cleanLocal.Release()
	for _, id := range rule.StringIdentifiers() {
		got := normalizedMatchRanges(cleanResult.Matches[rule.Name][id])
		want := normalizedMatchRanges(cleanLocal.Matches[id])
		if !slices.Equal(got, want) {
			t.Errorf("clean scan %s ranges = %v, local matcher = %v", id, got, want)
		}
	}
	if cleanResult.RuleResults["duplicate_a"] || cleanResult.RuleResults["duplicate_b"] {
		t.Fatalf("clean rescan reused stale cache results: %v", cleanResult.RuleResults)
	}
}

type matchRange struct {
	offset int64
	length int
}

func normalizedMatchRanges(matches []Match) []matchRange {
	ranges := make([]matchRange, len(matches))
	for i, match := range matches {
		ranges[i] = matchRange{offset: match.Offset, length: match.Length}
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].offset != ranges[j].offset {
			return ranges[i].offset < ranges[j].offset
		}
		return ranges[i].length < ranges[j].length
	})
	return ranges
}

func BenchmarkSharedNonTextPrefilterScale(b *testing.B) {
	for _, numRules := range []int{20, 50, 100, 500} {
		b.Run(fmt.Sprintf("rules_%d", numRules), func(b *testing.B) {
			var source strings.Builder
			for i := range numRules {
				if i%2 == 0 {
					fmt.Fprintf(&source, `
						rule unique_hex_%d {
							strings: $hex = { %02X %02X 0C 0D }
							condition: $hex
						}
					`, i, i%255+1, i/255+1)
				} else {
					fmt.Fprintf(&source, `
						rule unique_regex_%d {
							strings: $re = /family_%d_[a-z]{1,2}\.exe/i
							condition: $re
						}
					`, i, i)
				}
			}

			program, err := NewCompiler().CompileSource(source.String())
			if err != nil {
				b.Fatal(err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()
			data := make([]byte, 100*1024)

			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := scanner.Scan(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
