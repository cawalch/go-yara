package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraRegexEncodingCollisions(t *testing.T) {
	bin := libyaraOracle(t)
	patterns := []string{
		`"a"`, `/a/`, `/a+/`, `/[ab]+/`, `/a.{0,4}/`, `/a.*?/`,
		`/a\x00+/`, `/[a]{1}/`, `/[a]/`, `/(a|b)+/`, `/(a|ab)+/`,
	}
	for _, tc := range []struct {
		modifier string
		patterns []string
	}{
		{"ascii wide", patterns}, {"wide ascii", patterns}, {"ascii wide nocase", patterns},
		{"ascii wide fullword", []string{`"a"`, `/a/`, `/a+/`, `/a.{0,4}/`, `/a.*?/`}},
	} {
		modifier := tc.modifier
		t.Run(modifier, func(t *testing.T) {
			var source strings.Builder
			for i, pattern := range tc.patterns {
				for j, condition := range []string{`#a >= 1 and !a[1] >= 0`, `!a[1] == 2`, `#a == 2`} {
					fmt.Fprintf(&source, "rule p%d_c%d { strings: $a = %s %s condition: %s }\n", i, j, pattern, modifier, condition)
				}
			}
			program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source.String())
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
			inputs := [][]byte{[]byte("a\x00"), []byte("a\x00a\x00"), []byte("a\x00bcd"),
				[]byte("aa\x00"), []byte("A\x00B\x00"), []byte("a\x00\x00\x00\x00!"), []byte("!"), nil, []byte("a\x00")}
			oracles := make([]map[string][]span, len(inputs))
			paths := make([]string, len(inputs))
			for i, input := range inputs {
				oracles[i], err = scanWithLibyara(t, bin, source.String(), input)
				if err != nil {
					t.Fatal(err)
				}
				paths[i] = filepath.Join(t.TempDir(), "input.bin")
				if err := os.WriteFile(paths[i], input, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for name, p := range map[string]*compiler.CompiledProgram{"compiled": program, "serialized": restored} {
				t.Run(name, func(t *testing.T) {
					for mode, opts := range map[string][]compiler.ScannerOption{
						"normal": nil, "fast": {compiler.WithFastScan()},
						"compact": {compiler.WithoutMatches(), compiler.WithoutRuleResults()},
					} {
						t.Run(mode, func(t *testing.T) {
							scanner := p.NewScanner(opts...)
							defer scanner.Close()
							for i, input := range inputs {
								t.Run(strconv.Itoa(i), func(t *testing.T) {
									want := oracles[i]
									if mode == "compact" {
										want = make(map[string][]span, len(oracles[i]))
										for name := range oracles[i] {
											want[name] = nil
										}
									}
									for pathName, scan := range map[string]func() (*compiler.ScanResult, error){
										"buffer": func() (*compiler.ScanResult, error) { return scanner.Scan(input) },
										"file":   func() (*compiler.ScanResult, error) { return scanner.ScanFile(paths[i]) },
										"reader": func() (*compiler.ScanResult, error) { return scanner.ScanReader(bytes.NewReader(input)) },
										"block": func() (*compiler.ScanResult, error) {
											blocks := p.NewBlockScanner(opts...)
											defer blocks.Close()
											if err := blocks.Scan(0, input); err != nil {
												return nil, err
											}
											return blocks.Finish()
										},
									} {
										t.Run(pathName, func(t *testing.T) {
											result, err := scan()
											if err != nil {
												t.Fatal(err)
											}
											assertReleaseScanResult(t, want, result)
										})
									}
								})
							}
						})
					}
				})
			}
		})
	}
}
