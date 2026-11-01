package integration

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraRegexVerificationDistance(t *testing.T) {
	for _, wide := range []bool{false, true} {
		step, modifier := 1, ""
		if wide {
			step, modifier = 2, "wide"
		}
		limit := 4096 / step
		for _, delta := range []int{-1, 0, 1} {
			n := limit + delta
			length := (n + 3) * step
			if delta > 0 {
				length = 0
			}
			checkVerificationDistance(t, fmt.Sprintf("suffix-%v-%d", wide, delta), `(ab|a)+xyz`, modifier+" fullword", strings.Repeat("a", n)+"xyz", wide, length)
			n = limit - 3 + delta
			length = (n + 3) * step
			if delta > 0 {
				length = 0
			}
			checkVerificationDistance(t, fmt.Sprintf("prefix-%v-%d", wide, delta), `xyz(a|ab)+`, modifier+" fullword", "xyz"+strings.Repeat("a", n), wide, length)
			n = limit + delta
			length = n * step
			if delta > 0 {
				length = 0
			}
			checkVerificationDistance(t, fmt.Sprintf("atomless-%v-%d", wide, delta), `^[a]+`, modifier+" fullword", strings.Repeat("a", n), wide, length)
		}
		for _, tc := range []struct {
			name, pattern, input string
			length               int
		}{
			{"combined-limit", `(a|ab)+`, strings.Repeat("a", 2*limit), 8192},
			{"combined-over", `(a|ab)+`, strings.Repeat("a", 2*limit+1), 0},
			{"lazy-limit", `(a|ab)+?`, strings.Repeat("a", limit+1), (limit + 1) * step},
			{"lazy-over", `(a|ab)+?`, strings.Repeat("a", limit+2), 0},
			{"middle-limit", `a+XYZb+`, strings.Repeat("a", limit) + "XYZ" + strings.Repeat("b", limit-3), 8192},
			{"middle-backward-over", `a+XYZb+`, strings.Repeat("a", limit+1) + "XYZ" + strings.Repeat("b", limit-3), 0},
			{"middle-forward-over", `a+XYZb+`, strings.Repeat("a", limit) + "XYZ" + strings.Repeat("b", limit-2), 0},
			{"finite-first-copy", fmt.Sprintf(`a{%d}`, limit+1), strings.Repeat("a", limit+1), 0},
			{"oversized-gap", `a.{5000}b`, "a" + strings.Repeat("x", 5000) + "b", 0},
			{"literal-exemption", strings.Repeat("a", limit+1), strings.Repeat("a", limit+1), (limit + 1) * step},
			{"physical-end", `^xyz.*$`, "xyz" + strings.Repeat("a", limit), 0},
			{"nocase-suffix", `(ab|a)+xyz`, strings.Repeat("A", limit) + "XYZ", (limit + 3) * step},
		} {
			checkVerificationDistance(t, fmt.Sprintf("%s-%v", tc.name, wide), tc.pattern, modifier+" nocase fullword", tc.input, wide, tc.length)
		}
		checkVerificationDistance(t, fmt.Sprintf("forward-truncation-%v", wide), `^xyz.*`, modifier, "xyz"+strings.Repeat("a", limit), wide, 4096)
	}
}

// Libyara's CLI caps displayed match data at 512 bytes. Use occurrence queries
// to verify the actual long spans, then check Go's public spans independently.
// The callback-based discovery oracle is deliberately not part of the repo.
//
//nolint:revive // table-driven oracle case arguments
func checkVerificationDistance(t *testing.T, name, pattern, modifiers, input string, wide bool, length int) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		condition := `#a==0`
		if length > 0 {
			condition = fmt.Sprintf(`#a==1 and $a at 0 and @a[1]==0 and !a[1]==%d`, length)
		}
		source := fmt.Sprintf(`rule p{strings:$a=/%s/ %s condition:%s}`, pattern, modifiers, condition)
		data := []byte(input)
		if wide {
			data = releaseWideBytes(data)
		}
		oracle, err := scanWithLibyara(t, libyaraOracle(t), source, data)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := oracle["p"]; !ok {
			t.Fatalf("libyara rejected expected occurrence queries: %s", condition)
		}
		program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := program.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := compiler.UnmarshalCompiledProgram(encoded)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []*compiler.CompiledProgram{program, restored} {
			for _, opts := range [][]compiler.ScannerOption{nil, {compiler.WithFastScan()}, {compiler.WithoutMatches(), compiler.WithoutRuleResults()}} {
				scanner := p.NewScanner(opts...)
				defer scanner.Close()
				for _, reader := range []bool{false, true} {
					var result *compiler.ScanResult
					if reader {
						result, err = scanner.ScanReader(bytes.NewReader(data))
					} else {
						result, err = scanner.Scan(data)
					}
					if err != nil {
						t.Fatal(err)
					}
					if len(result.MatchedRules) != 1 || result.MatchedRules[0].Rule != "p" {
						t.Fatalf("reader=%v result=%+v", reader, result)
					}
					if result.Matches != nil && length > 0 {
						matches := result.Matches["p"]["$a"]
						if len(matches) != 1 || matches[0].Offset != 0 || matches[0].Length != length {
							t.Fatalf("reader=%v spans=%+v", reader, matches)
						}
					}
				}
			}
		}
	})
}
