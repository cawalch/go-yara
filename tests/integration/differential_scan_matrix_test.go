package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

type differentialScanCase struct {
	source       string
	inputs       [][]byte
	readerChunks []int
}

// checkLibyaraScanMatrix reuses each scanner across inputs, including repeated
// and empty inputs, to cover state reset as well as scan-result parity.
func checkLibyaraScanMatrix(t *testing.T, tc differentialScanCase) {
	t.Helper()
	bin := libyaraOracle(t)
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), tc.source)
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
	oracles := make([]map[string][]span, len(tc.inputs))
	paths := make([]string, len(tc.inputs))
	for i, input := range tc.inputs {
		oracles[i], err = scanWithLibyara(t, bin, tc.source, input)
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
					for _, chunk := range tc.readerChunks {
						reader := p.NewScanner(append([]compiler.ScannerOption{compiler.WithStreamChunkSize(chunk), compiler.WithStreamEarlyTermination(false)}, opts...)...)
						defer reader.Close()
						readers[chunk] = reader
					}
					for i, input := range tc.inputs {
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
}
