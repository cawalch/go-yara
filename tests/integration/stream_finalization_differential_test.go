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

func TestLibyaraStreamFinalization(t *testing.T) {
	bin := libyaraOracle(t)
	patterns := []string{`/a.{0,3}b/`, `/a.{0,3}?b/`, `/a|ab/`, `/ab|a/`, `/ab$/`, `/^ab/`, `/^ab|cd/`, `/a{0}/`, `"ab"`, `{ 61 62 }`}

	for _, tc := range []struct {
		modifier string
		patterns []string
	}{
		{"", patterns}, {"fullword", patterns[:8]}, {"fullword nocase", patterns[:8]},
		{"wide", patterns[:8]}, {"ascii wide", patterns[:8]},
	} {
		modifier := tc.modifier
		t.Run(modifier, func(t *testing.T) {
			var source strings.Builder
			for i, pattern := range tc.patterns {
				for j, condition := range []string{`#a >= 1 and !a[1] >= 0`, `#a == 2 and !a[1] == 5`, `#a == 2 and !a[1] != 5`} {
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
			for _, input := range []string{"ab ab", "ab abx", "abab", "abx", "ab", "abxxxx", "AB AB", "!!ab ab!!", "a_b", "xxxxxxxxxxabcdxxx", "!"} {
				inputs = append(inputs, []byte(input), releaseWideBytes([]byte(input)))
			}
			inputs = append(inputs, nil, []byte("ab ab"))
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
							readers := make(map[int]*compiler.Scanner)
							for _, chunk := range []int{1, 2, 3, 7} {
								reader := p.NewScanner(append([]compiler.ScannerOption{compiler.WithStreamChunkSize(chunk), compiler.WithStreamEarlyTermination(false)}, opts...)...)
								defer reader.Close()
								readers[chunk] = reader
							}
							for i, input := range inputs {
								t.Run(strconv.Itoa(i), func(t *testing.T) {
									want := oracles[i]
									if mode == "compact" {
										want = make(map[string][]span, len(oracles[i]))
										for name := range oracles[i] {
											want[name] = nil
										}
									}
									scans := map[string]func() (*compiler.ScanResult, error){
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
									}
									for chunk, reader := range readers {
										scans[fmt.Sprintf("reader-%d", chunk)] = func() (*compiler.ScanResult, error) { return reader.ScanReader(bytes.NewReader(input)) }
									}
									for pathName, scan := range scans {
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

func TestLibyaraStreamDefaultBoundary(t *testing.T) {
	const source = `rule positive {strings:$a=/a.{0,3}b/ condition:#a==2 and !a[1]==5}
rule inverse {strings:$a=/a.{0,3}b/ condition:#a==2 and !a[1]!=5}
rule lazy {strings:$a=/a.{0,3}?b/ condition:#a==2 and !a[1]==2}`
	input := append(bytes.Repeat([]byte("!"), (1<<20)-2), []byte("ab ab")...)
	want, err := scanWithLibyara(t, libyaraOracle(t), source, input)
	if err != nil {
		t.Fatal(err)
	}
	p, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := compiler.UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range []*compiler.CompiledProgram{p, restored} {
		for _, opts := range [][]compiler.ScannerOption{nil, {compiler.WithFastScan()}} {
			scanner := program.NewScanner(opts...)
			result, err := scanner.ScanReader(bytes.NewReader(input))
			scanner.Close()
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseScanResult(t, want, result)
		}
	}
}
