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

func TestLibyaraZeroLengthFullword(t *testing.T) {
	bin := libyaraOracle(t)
	patterns := []string{`/a*/`, `/a{0}/`, `/a{0,2}/`, `/^a*/`, `/^$/`, `/$/`, `/a?/`}
	for _, tc := range []struct {
		modifier string
		patterns []string
	}{
		{"", patterns}, {"fullword", patterns}, {"fullword nocase", patterns},
		{"wide", patterns}, {"wide fullword", patterns}, {"ascii wide fullword", patterns},
		{"wide ascii fullword nocase", patterns},
	} {
		modifier := tc.modifier
		t.Run(modifier, func(t *testing.T) {
			var source strings.Builder
			for i, pattern := range tc.patterns {
				for j, condition := range []string{`#a >= 1 and !a[1] >= 0`, `#a == 0`, `!a[1] == 0`, `#a == 2`} {
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
			inputs := [][]byte{nil}
			for _, input := range []string{"!", "!!", "_", "b", "!b", "b!", "a", "bb", "a!", "!a", "ab", "A!", "1!", "!1", "\x00", "a\x00!", "!\x00a"} {
				inputs = append(inputs, []byte(input), releaseWideBytes([]byte(input)))
			}
			inputs = append(inputs, nil, []byte("!"))
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
