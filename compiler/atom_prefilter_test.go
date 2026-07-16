package compiler

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
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
