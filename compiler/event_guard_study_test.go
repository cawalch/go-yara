//go:build perfstudy

package compiler

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func acStudyPatterns(portfolio string) [][]byte {
	var result [][]byte
	switch portfolio {
	case "credential":
		for _, s := range []string{"ghp_", "gho_", "github_pat_", "AKIA", "ASIA", "AIza", "npm_", "sk_live_", "rk_live_", "GOCSPX-", "xoxb-", "xoxp-", "aws_secret_access_key", "client_secret", "password", "Authorization: Bearer ", "BEGIN RSA PRIVATE KEY", "eyJhbGciOi", "ssh-rsa", "mongodb://", "postgresql://", "redis://", "jdbc:", "SNOWFLAKE"} {
			result = append(result, []byte(s))
		}
	case "broad":
		for i := range 72 {
			result = append(result, fmt.Appendf(nil, "%ctok_%d_%d_", 'a'+i%24, i/6, i%6))
		}
	case "shared":
		for i := range 1000 {
			result = append(result, fmt.Appendf(nil, "probe_marker_%04d", i))
		}
	case "random":
		r := rand.New(rand.NewSource(87))
		for range 128 {
			s := make([]byte, 12)
			for i := range s {
				s[i] = 'a' + byte(r.Intn(26))
			}
			result = append(result, s)
		}
	}
	return result
}
func acStudyAutomaton(t testing.TB, patterns [][]byte) *ACAutomaton {
	t.Helper()
	a := NewACAutomaton()
	for i, s := range patterns {
		if e := a.AddString(fmt.Sprint(i), s, false, false); e != nil {
			t.Fatal(e)
		}
	}
	if e := a.Compile(); e != nil {
		t.Fatal(e)
	}
	return a
}
func acStudyData(size int, traffic string, patterns [][]byte) []byte {
	base := `{"ts":"2026-09-19T12:00:00Z","level":"info","service":"checkout","msg":"request completed","status":200,"path":"/v1/orders","duration_ms":42} `
	d := []byte(strings.Repeat(base, size/len(base)+1))[:size]
	switch traffic {
	case "positive":
		copy(d[len(d)/2:], patterns[0])
	case "near":
		for start := 0; start < len(d); start += 32 {
			p := patterns[(start/32)%len(patterns)]
			copy(d[start:], p[:len(p)-1])
		}
	case "dense":
		for start := 0; start < len(d); {
			p := patterns[0]
			start += copy(d[start:], p)
		}
	}
	return d
}

var acOffsetSink bool

func BenchmarkACEventGuard(b *testing.B) {
	for _, portfolio := range []string{"credential", "broad", "shared"} {
		patterns := acStudyPatterns(portfolio)
		var source strings.Builder
		for i, p := range patterns {
			fmt.Fprintf(&source, "rule r%d { strings: $a = %q condition: $a }\n", i, p)
		}
		program, err := NewCompiler().CompileSource(source.String())
		if err != nil {
			b.Fatal(err)
		}
		for _, size := range []int{141, 4096} {
			for _, traffic := range []string{"clean", "near", "dense", "positive"} {
				data := acStudyData(size, traffic, patterns)
				b.Run(fmt.Sprintf("%s/%d/%s", portfolio, size, traffic), func(b *testing.B) {
					scanner := program.NewScanner(WithFastScan())
					defer scanner.Close()
					b.ReportAllocs()
					for b.Loop() {
						hit, err := scanner.Matches(data)
						if err != nil {
							b.Fatal(err)
						}
						acOffsetSink = hit
					}
				})
			}
		}
	}
}

func TestACEventGuardParity(t *testing.T) {
	for _, portfolio := range []string{"credential", "broad", "shared"} {
		patterns := acStudyPatterns(portfolio)
		var source strings.Builder
		for i, p := range patterns {
			fmt.Fprintf(&source, "rule r%d { strings: $a = %q condition: $a }\n", i, p)
		}
		program, err := NewCompiler().CompileSource(source.String())
		if err != nil {
			t.Fatal(err)
		}
		fast := program.NewScanner(WithFastScan())
		defer fast.Close()
		reference := program.NewScanner()
		reference.prefilterDisabled = true
		defer reference.Close()
		for _, size := range []int{141, 4096} {
			for _, traffic := range []string{"clean", "near", "dense", "positive"} {
				data := acStudyData(size, traffic, patterns)
				got, err := fast.Matches(data)
				if err != nil {
					t.Fatal(err)
				}
				want, err := reference.Scan(data)
				if err != nil {
					t.Fatal(err)
				}
				if got != (len(want.MatchedRules) > 0) {
					t.Fatalf("%s/%d/%s parity failed", portfolio, size, traffic)
				}
			}
		}
	}
}
