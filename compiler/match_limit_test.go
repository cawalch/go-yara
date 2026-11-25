package compiler

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestPerRuleMatchLimit(t *testing.T) {
	const source = `rule words { strings: $a="aba" $b={62 61} condition: #a + #b == 3 }
rule regexes { strings: $r=/aba/ condition: #r == 3 and @r[3] == 4 }`
	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("abababababa")
	for _, method := range []string{"Scan", "ScanReader", "MatchingRules", "Matches", "BlockScanner", "MatchingRulesInBlock"} {
		t.Run(method, func(t *testing.T) {
			called := map[string]int{}
			options := []ScannerOption{WithReportedMatchesOnly(), WithStreamChunkSize(3), WithFastScan(), WithHooks(ScanHooks{MaxMatchesPerRule: 3, OnMaxMatchesExceeded: func(rule string, count int) {
				if count != 4 {
					t.Errorf("overflow count %d", count)
				}
				called[rule]++
			}})}
			s := p.NewScanner(options...)
			defer s.Close()
			for range 2 {
				clear(called)
				var rules []RuleMatch
				var scan *ScanResult
				var scanErr error
				switch method {
				case "Scan":
					scan, scanErr = s.Scan(data)
				case "ScanReader":
					scan, scanErr = s.ScanReader(bytes.NewReader(data))
				case "MatchingRules":
					rules, scanErr = s.MatchingRules(data)
				case "MatchingRulesInBlock":
					rules, scanErr = s.MatchingRulesInBlock(MemoryBlock{Data: data}, int64(len(data)))
				case "Matches":
					var matched bool
					matched, scanErr = s.Matches(data)
					if !matched {
						t.Fatal("expected a match")
					}
				case "BlockScanner":
					b := p.NewBlockScanner(options...)
					for _, block := range []MemoryBlock{{Data: data[:5]}, {Data: data[:5]}, {Base: 2, Data: data[2:]}} {
						if err := b.Scan(block.Base, block.Data); err != nil {
							t.Fatal(err)
						}
					}
					scan, scanErr = b.Finish()
					b.Close()
				}
				if scanErr != nil {
					t.Fatal(scanErr)
				}
				if scan != nil {
					rules = scan.MatchedRules
				}
				if method != "Matches" {
					if len(rules) != 2 {
						t.Fatalf("rules: %v", rules)
					}
					for _, rule := range rules {
						n := 0
						for _, ms := range rule.Matches {
							n += len(ms)
						}
						if n != 3 {
							t.Fatalf("%s retained %d: %v", rule.Rule, n, rule.Matches)
						}
					}
				}
				if called["words"] != 1 || called["regexes"] != 1 {
					t.Fatalf("callbacks: %v", called)
				}
			}
		})
	}
}

func TestMatchLimitAbortAndReset(t *testing.T) {
	p, err := NewCompiler().CompileSource(`rule test {strings:$a="aa" condition:#a>0}`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner(WithMaxMatches(2, nil))
	defer s.Close()
	data := []byte("aaaa")
	if _, err := s.Scan(data); !errors.Is(err, ErrMatchLimitExceeded) {
		t.Fatalf("Scan: %v", err)
	}
	if _, err := s.MatchingRules(data); !errors.Is(err, ErrMatchLimitExceeded) {
		t.Fatalf("MatchingRules: %v", err)
	}
	if _, err := s.ScanReader(bytes.NewReader(data)); !errors.Is(err, ErrMatchLimitExceeded) {
		t.Fatalf("ScanReader: %v", err)
	}
	if r, err := s.Scan(data[:3]); err != nil || len(r.Matches["test"]["$a"]) != 2 {
		t.Fatalf("reused scanner: %v, %v", r, err)
	}
	b := p.NewBlockScanner(WithMaxMatches(2, nil))
	defer b.Close()
	if err := b.Scan(0, data); !errors.Is(err, ErrMatchLimitExceeded) {
		t.Fatalf("block scan: %v", err)
	}
	if _, err := b.Finish(); !errors.Is(err, ErrMatchLimitExceeded) {
		t.Fatalf("block finish: %v", err)
	}
	b.Reset()
	if err := b.Scan(0, data[:3]); err != nil {
		t.Fatal(err)
	}
	if r, err := b.Finish(); err != nil || len(r.Matches["test"]["$a"]) != 2 {
		t.Fatalf("reset block scanner: %v, %v", r, err)
	}
	if r, err := p.Scan(data); err != nil || len(r.Matches["test"]["$a"]) != 3 {
		t.Fatalf("default: %v, %v", r, err)
	}
}

func BenchmarkDenseRuleMatchLimit(b *testing.B) {
	p, err := NewCompiler().CompileSource(`rule t {strings:$a="aaaa" condition:#a>0}`)
	if err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("a"), 64<<10)
	for _, tc := range []struct {
		name  string
		limit int
	}{{"unlimited", 0}, {"limit_10", 10}} {
		b.Run(tc.name, func(b *testing.B) {
			s := p.NewScanner(WithMaxMatches(tc.limit, func(string, int) {}))
			defer s.Close()
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := s.Scan(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestMatchLimitFastPresenceAndFixedOffsets(t *testing.T) {
	p, err := NewCompiler().CompileSource(`rule presence {strings:$a="aba" $b="xyz" condition:all of them}
rule fixed {strings:$x="aba" condition:$x at 4}`)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("abababaxyz")
	s := p.NewScanner(WithFastScan(), WithMaxMatches(2, nil), WithStreamChunkSize(3))
	defer s.Close()
	for _, reader := range []bool{false, true} {
		var r *ScanResult
		if reader {
			r, err = s.ScanReader(bytes.NewReader(data))
		} else {
			r, err = s.Scan(data)
		}
		if err != nil || len(r.MatchedRules) != 2 || len(r.Matches["presence"]["$a"]) != 1 || r.Matches["fixed"]["$x"][0].Offset != 4 {
			t.Fatalf("reader=%v: %v, %v", reader, r, err)
		}
	}
}

func TestReaderMatchLimitPreservesEncodingSelection(t *testing.T) {
	p, err := NewCompiler().CompileSource(`rule ex { strings: $a=/a?/ ascii wide condition: !a[1] == 2 }`)
	if err != nil {
		t.Fatal(err)
	}
	scan := func(limit int) *ScanResult {
		t.Helper()
		s := p.NewScanner(WithStreamChunkSize(1), WithStreamOverlapSize(1), WithMaxMatches(limit, nil))
		defer s.Close()
		r, err := s.ScanReader(bytes.NewReader([]byte{'a', 0}))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	want := scan(0)
	if !want.RuleResults["ex"] || want.Matches["ex"]["$a"][0].Length != 2 {
		t.Fatalf("expected the two-byte wide match: %+v", want)
	}
	if got := scan(2); !reflect.DeepEqual(got, want) {
		t.Fatalf("capped reader = %+v; want %+v", got, want)
	}
}

func TestBlockMatchLimitCancellation(t *testing.T) {
	p, err := NewCompiler().CompileSource(`rule ex { strings: $a="x" condition: #a > 0 }`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := p.NewBlockScanner(WithMaxMatches(1, func(string, int) { cancel() }))
	defer b.Close()

	alreadyCanceled, stop := context.WithCancel(context.Background())
	stop()
	if err := b.ScanWithContext(alreadyCanceled, 0, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled block: %v", err)
	}
	if err := b.Scan(2, []byte("other")); err != nil {
		t.Fatalf("pre-canceled scan should be retryable: %v", err)
	}
	if err := b.ScanWithContext(ctx, 0, []byte("xx")); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted block: %v", err)
	}
	if err := b.Scan(10, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("next block: %v", err)
	}
	if r, err := b.Finish(); r != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("partial result: %+v, %v", r, err)
	}
	b.Reset()
	if err := b.Scan(10, []byte("x")); err != nil {
		t.Fatal(err)
	}
	r, err := b.Finish()
	if err != nil || !r.RuleResults["ex"] || r.Matches["ex"]["$a"][0].Offset != 10 {
		t.Fatalf("reset result: %+v, %v", r, err)
	}
}
