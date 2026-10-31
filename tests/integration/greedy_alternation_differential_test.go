package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraGreedyAlternation(t *testing.T) {
	bin := libyaraOracle(t)
	t.Run("fullword_priority", func(t *testing.T) {
		checkReleaseScanPaths(t, `rule probe { strings: $a = /(a|ab!)+b/ fullword condition: $a }`, []byte("ab!abx"))
	})
	for _, tc := range []struct {
		pattern, input string
		allModifiers   bool
	}{
		{"(a|ab)+b", "abab", true}, {"(ab|a)+b", "abab", true},
		{"((a|ab)|aba)+b", "abab", true}, {"(a|ab)+", "abab", true},
		{"(a|ab)*b", "abab", true}, {"(a|ab)+?b", "abab", true},
		{"(ab|a)+?b", "abab", true},
		// Original simple-alternation controls from #281, plus forward-priority controls.
		{"(ab|a)", "ab", false}, {"(a0|a)", "aa0", false},
		{"(abc|ab)", "abcd", false}, {".{2}(c+|..)", "0ca ._c0c.ac00ab.0c", false},
		{"(a|ab)*", "ababa", false}, {"(ab|a)*", "ababa", false},
		{"hello(a|ab)+b", "helloabab", true},
	} {
		modifiers := []string{"ascii"}
		if tc.allModifiers {
			modifiers = append(modifiers, "nocase", "wide", "wide nocase")
		}
		for _, modifier := range modifiers {
			t.Run(tc.pattern+"/"+modifier, func(t *testing.T) {
				data := []byte(tc.input)
				if modifier == "nocase" || modifier == "wide nocase" {
					data = bytes.ToUpper(data)
				}
				if modifier == "wide" || modifier == "wide nocase" {
					data = releaseWideBytes(data)
				}
				source := fmt.Sprintf(`rule probe { strings: $a = /%s/ %s condition: #a >= 1 and !a[1] > 0 }`, tc.pattern, modifier)
				if tc.pattern == "(a|ab)+b" {
					source += fmt.Sprintf(` rule length_probe { strings: $a = /%s/ %s condition: !a[1] == %d }`, tc.pattern, modifier, len(data))
				}
				want, err := scanWithLibyara(t, bin, source, data)
				if err != nil {
					t.Fatal(err)
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
				path := filepath.Join(t.TempDir(), "input.bin")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				for _, p := range []*compiler.CompiledProgram{program, restored} {
					for mode, opts := range map[string][]compiler.ScannerOption{
						"normal": nil, "fast": {compiler.WithFastScan()},
						"compact": {compiler.WithoutMatches(), compiler.WithoutRuleResults()},
					} {
						t.Run(mode, func(t *testing.T) {
							scanner := p.NewScanner(opts...)
							defer scanner.Close()
							expected := want
							if mode == "compact" {
								expected = make(map[string][]span, len(want))
								for name := range want {
									expected[name] = nil
								}
							}
							for _, scan := range []func() (*compiler.ScanResult, error){
								func() (*compiler.ScanResult, error) { return scanner.Scan(data) },
								func() (*compiler.ScanResult, error) { return scanner.ScanFile(path) },
								func() (*compiler.ScanResult, error) { return scanner.ScanReader(bytes.NewReader(data)) },
								func() (*compiler.ScanResult, error) { return scanner.Scan(data) },
							} {
								result, err := scan()
								if err != nil {
									t.Fatal(err)
								}
								assertReleaseScanResult(t, expected, result)
							}
							matched, err := scanner.MatchesReader(bytes.NewReader(data))
							if err != nil || matched != (len(want) > 0) {
								t.Fatalf("MatchesReader = %v, err = %v", matched, err)
							}
						})
					}
				}
			})
		}
	}
}
