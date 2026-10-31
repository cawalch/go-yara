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

func TestLibyaraUndefinedIntegerReads(t *testing.T) {
	bin := libyaraOracle(t)
	var source strings.Builder
	source.WriteString("rule independent { condition: true }\n")
	index := 0
	for _, fn := range []string{"int8", "uint8", "int16", "uint16", "int32", "uint32", "int16be", "uint16be", "int32be", "uint32be"} {
		for _, offset := range []string{"-1", "0", "1", "4", "filesize", "0x7fffffffffffffff", "uint8(filesize)"} {
			read := fmt.Sprintf("%s(%s)", fn, offset)
			for _, condition := range []string{"defined " + read, "not defined " + read, read + " == 0", "not (" + read + " == 0)", read + " != 0", "(" + read + " == 0) or true"} {
				fmt.Fprintf(&source, "rule r%d { condition: %s }\n", index, condition)
				index++
			}
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
	for name, p := range map[string]*compiler.CompiledProgram{"compiled": program, "serialized": restored} {
		t.Run(name, func(t *testing.T) {
			for mode, opts := range map[string][]compiler.ScannerOption{"normal": nil, "fast": {compiler.WithFastScan()}, "compact": {compiler.WithoutMatches(), compiler.WithoutRuleResults()}} {
				t.Run(mode, func(t *testing.T) {
					scanner := p.NewScanner(opts...)
					defer scanner.Close()
					// Reuse the scanner through available -> partial -> empty -> available reads.
					for index, data := range [][]byte{{0, 0, 0, 0, 255, 255, 255, 255}, {255}, {0, 255, 0}, nil, {0, 0, 0, 0, 255, 255, 255, 255}} {
						t.Run(strconv.Itoa(index), func(t *testing.T) {
							want, err := scanWithLibyara(t, bin, source.String(), data)
							if err != nil {
								t.Fatal(err)
							}
							if _, ok := want["independent"]; !ok {
								t.Fatal("oracle lost independent rule")
							}
							path := filepath.Join(t.TempDir(), "input.bin")
							if err := os.WriteFile(path, data, 0600); err != nil {
								t.Fatal(err)
							}
							for pathName, scan := range map[string]func() (*compiler.ScanResult, error){
								"buffer": func() (*compiler.ScanResult, error) { return scanner.Scan(data) },
								"file":   func() (*compiler.ScanResult, error) { return scanner.ScanFile(path) },
								"reader": func() (*compiler.ScanResult, error) { return scanner.ScanReader(bytes.NewReader(data)) },
							} {
								t.Run(pathName, func(t *testing.T) {
									r, err := scan()
									if err != nil {
										t.Fatal(err)
									}
									assertReleaseScanResult(t, want, r)
								})
							}
						})
					}
				})
			}
		})
	}
}
