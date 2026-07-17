package compiler

import (
	"bytes"
	"testing"
)

const regexMatchDensityRules = `
private rule card_fields {
    strings:
        $c1 = /["'#.\[]\s*(card[-_ ]?number|cardnum|ccnumber|pan)\b/ nocase
        $c2 = /["'#.\[]\s*(cvv|cvc|cvv2|securitycode)\b/ nocase
        $c3 = /(exp[-_ ]?date|expir(y|ation))\b/ nocase
        $c4 = /(cardholder|nameoncard)\b/ nocase
    condition: 2 of ($c*)
}
rule harvest {
    strings: $b = "sendBeacon"
    condition: card_fields and $b
}`

func regexMatchDensityBody(header string, size int) []byte {
	buffer := bytes.NewBufferString(header)
	for buffer.Len() < size {
		buffer.WriteString(" benignFillerCode123")
	}
	return buffer.Bytes()
}

func BenchmarkRegexMatchDensity(b *testing.B) {
	benchmarks := []struct {
		name   string
		header string
	}{
		{
			name:   "few_matches",
			header: `{"card_number":"x","cvv":"y"} sendBeacon; `,
		},
		{
			name: "many_matches",
			header: `d={"card_number":q('#cardnumber').v,"cvv":q('input[name="cvv"]').v,` +
				`"exp_date":q('#expiry').v,"cardholder":q('#nameoncard').v,"cvc":q('#card-cvc').v}; sendBeacon; `,
		},
	}
	program, err := NewCompiler().CompileSource(regexMatchDensityRules)
	if err != nil {
		b.Fatal(err)
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			scanner := NewScanner(program)
			defer scanner.Close()
			data := regexMatchDensityBody(benchmark.header, 1<<20)

			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, scanErr := scanner.Scan(data); scanErr != nil {
					b.Fatal(scanErr)
				}
			}
		})
	}
}

func TestRegexMatchDensityPreservesAllMatches(t *testing.T) {
	program, err := NewCompiler().CompileSource(regexMatchDensityRules)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(program)
	defer scanner.Close()
	for _, sample := range []struct {
		name        string
		header      string
		matchCounts map[string]int
	}{
		{
			name:        "few",
			header:      `{"card_number":"x","cvv":"y"} sendBeacon; `,
			matchCounts: map[string]int{"$c1": 1, "$c2": 1, "$c3": 0, "$c4": 0},
		},
		{
			name: "many",
			header: `d={"card_number":q('#cardnumber').v,"cvv":q('input[name="cvv"]').v,` +
				`"exp_date":q('#expiry').v,"cardholder":q('#nameoncard').v,"cvc":q('#card-cvc').v}; sendBeacon; `,
			matchCounts: map[string]int{"$c1": 2, "$c2": 3, "$c3": 2, "$c4": 2},
		},
	} {
		t.Run(sample.name, func(t *testing.T) {
			data := regexMatchDensityBody(sample.header, 4096)
			result, scanErr := scanner.Scan(data)
			if scanErr != nil {
				t.Fatal(scanErr)
			}
			if !result.RuleResults["card_fields"] || !result.RuleResults["harvest"] {
				t.Fatalf("rule results = %v, want both rules to match", result.RuleResults)
			}
			for pattern, want := range sample.matchCounts {
				if got := len(result.Matches["card_fields"][pattern]); got != want {
					t.Errorf("%s matches = %d, want %d", pattern, got, want)
				}
			}
		})
	}
}
