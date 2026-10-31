package integration

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraStreamHeaderRetention(t *testing.T) {
	bin := libyaraOracle(t)
	data := make([]byte, 65536)
	data[0] = 3
	var source strings.Builder
	source.WriteString("rule original { condition: uint8(3) == 98 }\n")
	for _, offset := range []int{3, 63, 4095, 65532} {
		copy(data[offset:], []byte{98, 0x12, 0x34, 0xfe})
		for name, condition := range map[string]string{
			"byte":    "uint8(%s) == 98",
			"word":    "uint16(%s) == 0x1262",
			"dword":   "uint32(%s) == 0xfe341262",
			"big":     "uint32be(%s) == 0x621234fe",
			"signed":  "int32(%s) < 0",
			"reject":  "uint32(%s) == 0",
			"defined": "defined uint32(%s)",
		} {
			for kind, expression := range map[string]string{
				"fixed":   strconv.Itoa(offset),
				"dynamic": "uint8(0) + " + strconv.Itoa(offset-3),
			} {
				fmt.Fprintf(&source, "rule %s_%s_%d { condition: %s }\n", name, kind, offset, fmt.Sprintf(condition, expression))
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
	// Reuse each scanner across full, partial, empty, and full headers.
	inputs := [][]byte{data, []byte("abab"), data[:65535], nil, data}
	oracles := make([]map[string][]span, len(inputs))
	for i, input := range inputs {
		oracles[i], err = scanWithLibyara(t, bin, source.String(), input)
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, p := range map[string]*compiler.CompiledProgram{"compiled": program, "serialized": restored} {
		t.Run(name, func(t *testing.T) {
			for mode, opts := range map[string][]compiler.ScannerOption{
				"normal":  nil,
				"fast":    {compiler.WithFastScan()},
				"compact": {compiler.WithoutMatches(), compiler.WithoutRuleResults()},
			} {
				t.Run(mode, func(t *testing.T) {
					for _, chunk := range []int{1, 3, 7, 64, 4096, 65536, 1024 * 1024} {
						t.Run(strconv.Itoa(chunk), func(t *testing.T) {
							options := append([]compiler.ScannerOption{compiler.WithStreamChunkSize(chunk), compiler.WithStreamOverlapSize(1)}, opts...)
							scanner := p.NewScanner(options...)
							defer scanner.Close()
							for i, input := range inputs {
								result, err := scanner.ScanReader(bytes.NewReader(input))
								if err != nil {
									t.Fatal(err)
								}
								assertReleaseScanResult(t, oracles[i], result)
								matched, err := scanner.MatchesReader(bytes.NewReader(input))
								if err != nil || matched != (len(oracles[i]) > 0) {
									t.Fatalf("input %d: matched = %v, err = %v; oracle = %v", i, matched, err, oracles[i])
								}
							}
							result, err := scanner.Scan(data)
							if err != nil {
								t.Fatal(err)
							}
							assertReleaseScanResult(t, oracles[0], result)
						})
					}
				})
			}
		})
	}
}
