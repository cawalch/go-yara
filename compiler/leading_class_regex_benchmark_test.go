package compiler

import (
	"bytes"
	"slices"
	"testing"
)

const (
	leadingClassRegexRule = `rule r {
	strings:
		$c = /["'#.\[]\s*(cardnumber|cvv|cardholder)\b/ nocase
	condition:
		$c
}`
	noLeadingClassRegexRule = `rule r {
	strings:
		$c = /(cardnumber|cvv|cardholder)\b/ nocase
	condition:
		$c
}`
)

func fillRegexBenchmarkData(chunk string) []byte {
	buffer := bytes.NewBuffer(nil)
	for buffer.Len() < 1<<20 {
		buffer.WriteString(chunk)
	}
	return buffer.Bytes()
}

func BenchmarkLeadingClassRegexAtoms(b *testing.B) {
	dense := fillRegexBenchmarkData(`a.b['c']="d";x.y("z");`)
	sparse := fillRegexBenchmarkData(" benignFillerCode123")
	for _, benchmark := range []struct {
		name string
		rule string
		data []byte
	}{
		{name: "with_class/dense", rule: leadingClassRegexRule, data: dense},
		{name: "with_class/sparse", rule: leadingClassRegexRule, data: sparse},
		{name: "without_class/dense", rule: noLeadingClassRegexRule, data: dense},
		{name: "without_class/sparse", rule: noLeadingClassRegexRule, data: sparse},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			program, err := NewCompiler().CompileSource(benchmark.rule)
			if err != nil {
				b.Fatal(err)
			}
			scanner := NewScanner(program)
			defer scanner.Close()

			b.SetBytes(int64(len(benchmark.data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, scanErr := scanner.Scan(benchmark.data); scanErr != nil {
					b.Fatal(scanErr)
				}
			}
		})
	}
}

func TestLeadingClassRegexMatches(t *testing.T) {
	program, err := NewCompiler().CompileSource(leadingClassRegexRule)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	pattern := program.Rules[0].RegexPatterns["$c"]
	if len(pattern.alternativeAtoms) != 3 {
		t.Fatalf("alternative atoms = %+v, want 3", pattern.alternativeAtoms)
	}
	for index, atom := range pattern.alternativeAtoms {
		if atom.minOffset < 1 || atom.maxOffset != -1 {
			t.Errorf("alternative atom %d offsets = [%d,%d], want min >= 1 and max -1", index, atom.minOffset, atom.maxOffset)
		}
		if wide := pattern.wideAlternativeAtoms[index]; wide.minOffset != atom.minOffset*2 || wide.maxOffset != -1 {
			t.Errorf("wide alternative atom %d offsets = [%d,%d], want [%d,-1]",
				index, wide.minOffset, wide.maxOffset, atom.minOffset*2)
		}
	}

	data := []byte(`prefix .   CARDNUMBER suffix 'cvv [ cardholder`)
	result, err := scanner.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	matches := result.Matches["r"]["$c"]
	if len(matches) != 3 {
		t.Fatalf("matches = %+v, want 3", matches)
	}
}

func TestNestedAlternativeAtomCoverMatchesLinearScan(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
		rule nested_alternatives {
			strings:
				$leading = /["'#.\[]\s*(cardnumber|cvv|cardholder)\b/ nocase
				$mixed = /(alphaone|.*zulu_two)/ nocase
				$bounded = /[x]?(alpha_token|beta_value)/
				$repeat = /(left_token|right_value)+/
				$wide = /["']\s*(wide_alpha|wide_beta)/ nocase wide
			condition:
				any of them
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	rule := program.Rules[0]
	wide := widenRegexPrefix([]byte(`'  WIDE_ALPHA "wide_beta`))
	dataSets := [][]byte{
		[]byte(`a.b['c']="d";x.y("z");`),
		[]byte(`prefix .   CARDNUMBER suffix 'cvv [ cardholder`),
		[]byte(`alphaone prefix zulu_two xalpha_token beta_value left_tokenright_value`),
		[]byte(`cardnumber without a leading selector and unrelated zulu`),
		wide,
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
