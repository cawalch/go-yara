package compiler

import (
	"bytes"
	"fmt"
	"testing"
)

// A plain text paragraph followed by one terminated record. Each span setting
// returns the same small set of occurrences.
func BenchmarkRegexMaxMatchSpan(b *testing.B) {
	data := append(bytes.Repeat([]byte("A short record with ordinary text. "), 160), []byte("\nrecord complete;")...)
	p, err := NewCompiler().CompileSource("rule records { strings: $line = /.+;/ condition: $line }")
	if err != nil {
		b.Fatal(err)
	}
	for _, span := range []int{0, 256, 4096, 65536} {
		b.Run(fmt.Sprintf("span=%d", span), func(b *testing.B) {
			s := p.NewScanner(WithMaxMatchSpan(span))
			defer s.Close()
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				result, err := s.Scan(data)
				if err != nil || len(result.Matches["records"]["$line"]) != len("record complete") {
					b.Fatalf("unexpected result: %v, %v", result, err)
				}
			}
		})
	}
}

// Line breaks keep the individual attempts short. Scan also measures the
// cost of returning occurrences when the expression matches these records.
func BenchmarkRegexAtomlessRecords(b *testing.B) {
	for _, tc := range []struct {
		name, expression string
		matches          bool
	}{{"dot", ".*", true}, {"printable", "[ -~]{10,}", false}} {
		p, err := NewCompiler().CompileSource("rule records { strings: $line = /" + tc.expression + "/ condition: $line }")
		if err != nil {
			b.Fatal(err)
		}
		for _, size := range []int{64 << 10, 1 << 20} {
			data := bytes.Repeat([]byte("ok\n"), size/3+1)[:size]
			for _, method := range []string{"Matches", "Scan"} {
				b.Run(fmt.Sprintf("%s/%s/bytes=%d", tc.name, method, size), func(b *testing.B) {
					s := p.NewScanner()
					defer s.Close()
					scan := func() {
						var matched bool
						var scanErr error
						if method == "Matches" {
							matched, scanErr = s.Matches(data)
						} else {
							var result *ScanResult
							result, scanErr = s.Scan(data)
							matched = result != nil && len(result.MatchedRules) != 0
						}
						if scanErr != nil || matched != tc.matches {
							b.Fatalf("matched=%v err=%v", matched, scanErr)
						}
					}
					// A scanner acquires VM and rule-evaluation scratch on its first
					// use. Measure scanning with that same initialized scanner.
					scan()
					b.SetBytes(int64(len(data)))
					b.ReportAllocs()
					for b.Loop() {
						scan()
					}
				})
			}
		}
	}
}

// Repeated short fields exercise both early lazy acceptance and greedy runs
// stopped by the terminator. The output size is the same on each iteration.
func BenchmarkRegexCappedDenseTerminators(b *testing.B) {
	data := bytes.Repeat([]byte("a;"), 8192)
	for _, tc := range []struct {
		name, pattern string
		occurrences   int
	}{
		{"lazy", ".+?;", len(data) - 1},
		{"greedy", "a+;", len(data) / 2},
	} {
		b.Run(tc.name, func(b *testing.B) {
			p, err := NewCompiler().CompileSource("rule r {strings: $a=/" + tc.pattern + "/ condition: $a}")
			if err != nil {
				b.Fatal(err)
			}
			s := p.NewScanner(WithMaxMatchSpan(4096))
			defer s.Close()
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				res, err := s.Scan(data)
				if err != nil || len(res.Matches["r"]["$a"]) != tc.occurrences {
					b.Fatalf("wrong occurrence count or scan error: %v", err)
				}
			}
		})
	}
}

// Four sparse suffixes produce 3,063 distinct match starts in 4,800 bytes.
func BenchmarkCappedSparseSuffixResults(b *testing.B) {
	program, err := NewCompiler().CompileSource("rule r { strings: $s = /.+?XYZ/ condition: $s }")
	if err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("XYa"), 1600)
	for at := 0; at < len(data); at += 1200 {
		copy(data[at:], "XYZ")
	}
	scanner := program.NewScanner(WithMaxMatchSpan(1024))
	defer scanner.Close()
	b.ReportAllocs()
	for b.Loop() {
		result, err := scanner.Scan(data)
		if err != nil {
			b.Fatal(err)
		}
		if got := len(result.Matches["r"]["$s"]); got != 3063 {
			b.Fatalf("got %d matches, want 3063", got)
		}
	}
}
