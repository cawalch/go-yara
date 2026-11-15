package compiler

import (
	"bytes"
	"strings"
	"testing"
)

func TestChainedLazyDotVerificationBudget(t *testing.T) {
	t.Parallel()

	t.Run("matches beyond 4096 bytes for scan reader and roundtrip", func(t *testing.T) {
		t.Parallel()
		const source = `rule w {
			strings:
				$a = /:.{1,}?TARGET/
			condition:
				#a == 1 and @a[1] == 0
		}`
		prog, err := NewCompiler().CompileSourceWithContext(t.Context(), source)
		if err != nil {
			t.Fatalf("compile failed: %v", err)
		}
		encoded, err := prog.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		restored, err := UnmarshalCompiledProgram(encoded)
		if err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		for _, gap := range []int{4095, 4096, 5000, 12000} {
			data := []byte(":" + strings.Repeat("q", gap) + "TARGET")
			wantLen := 1 + gap + len("TARGET")
			for _, p := range []*CompiledProgram{prog, restored} {
				for _, stream := range []bool{false, true} {
					var metrics ScanTelemetry
					opts := []ScannerOption{WithTelemetry(&metrics)}
					if stream {
						opts = append(opts, WithStreamChunkSize(1024), WithMaxMatchSpan(wantLen))
					}
					s := p.NewScanner(opts...)
					var (
						res *ScanResult
						err error
					)
					if stream {
						res, err = s.ScanReader(bytes.NewReader(data))
					} else {
						res, err = s.Scan(data)
					}
					s.Close()
					if err != nil {
						t.Fatalf("gap=%d stream=%v scan err=%v", gap, stream, err)
					}
					if len(res.MatchedRules) != 1 || res.MatchedRules[0].Rule != "w" {
						t.Fatalf("gap=%d stream=%v got matched=%v, want rule w", gap, stream, res.MatchedRules)
					}
					matches := res.Matches["w"]["$a"]
					if len(matches) != 1 || matches[0].Offset != 0 || matches[0].Length != wantLen {
						t.Fatalf("gap=%d stream=%v got matches=%+v, want [0+%d]", gap, stream, matches, wantLen)
					}
					if metrics.VerificationBudgetRejects != 0 {
						t.Fatalf("gap=%d stream=%v unexpected VerificationBudgetRejects=%d", gap, stream, metrics.VerificationBudgetRejects)
					}
				}
			}
		}
	})

	t.Run("wide and nocase chained lazy dot beyond 4096 bytes", func(t *testing.T) {
		t.Parallel()
		const source = `rule w {
			strings:
				$a = /:.{1,}?TARGET/ wide nocase
			condition:
				#a == 1 and @a[1] == 0
		}`
		prog, err := NewCompiler().CompileSourceWithContext(t.Context(), source)
		if err != nil {
			t.Fatalf("compile failed: %v", err)
		}
		plain := ":" + strings.Repeat("q", 5000) + "target"
		data := make([]byte, len(plain)*2)
		for i := range len(plain) {
			data[2*i] = plain[i]
		}
		s := prog.NewScanner()
		defer s.Close()
		res, err := s.Scan(data)
		if err != nil {
			t.Fatalf("scan err=%v", err)
		}
		if len(res.MatchedRules) != 1 {
			t.Fatalf("expected match, got %+v", res.MatchedRules)
		}
		matches := res.Matches["w"]["$a"]
		if len(matches) != 1 || matches[0].Length != len(data) {
			t.Fatalf("got matches=%+v, want length=%d", matches, len(data))
		}
	})

	t.Run("multiple colons select expected non-greedy spans", func(t *testing.T) {
		t.Parallel()
		const source = `rule w {
			strings:
				$a = /:.{1,}?TARGET/
			condition:
				$a
		}`
		prog, err := NewCompiler().CompileSourceWithContext(t.Context(), source)
		if err != nil {
			t.Fatalf("compile failed: %v", err)
		}
		data := []byte(":aaaa:bbbTARGETcccTARGET")
		s := prog.NewScanner()
		defer s.Close()
		res, err := s.Scan(data)
		if err != nil {
			t.Fatalf("scan err=%v", err)
		}
		matches := res.Matches["w"]["$a"]
		if len(matches) != 2 || matches[0].Offset != 0 || matches[0].Length != 15 || matches[1].Offset != 5 || matches[1].Length != 10 {
			t.Fatalf("got matches=%+v, want [0+15, 5+10]", matches)
		}
	})

	t.Run("telemetry records verification budget rejects", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name   string
			source string
			data   []byte
		}{
			{
				name:   "backward-fullword-budget-reject",
				source: `rule p { strings: $a = /(ab|a)+xyz/ fullword condition: $a }`,
				data:   []byte(strings.Repeat("a", 5000) + "xyz"),
			},
			{
				name:   "forward-budget-reject",
				source: `rule p { strings: $a = /:.+?TARGET/ condition: $a }`,
				data:   []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				prog, err := NewCompiler().CompileSourceWithContext(t.Context(), tc.source)
				if err != nil {
					t.Fatalf("compile err=%v", err)
				}
				var metrics ScanTelemetry
				s := prog.NewScanner(WithTelemetry(&metrics))
				defer s.Close()
				res, err := s.Scan(tc.data)
				if err != nil {
					t.Fatalf("scan err=%v", err)
				}
				if len(res.MatchedRules) != 0 {
					t.Fatalf("expected no match, got %+v", res.MatchedRules)
				}
				if metrics.VerificationBudgetRejects == 0 {
					t.Fatalf("expected VerificationBudgetRejects > 0, got 0")
				}
			})
		}
	})
}
