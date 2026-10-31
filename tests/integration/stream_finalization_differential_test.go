package integration

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraStreamFinalization(t *testing.T) {
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
			inputs := [][]byte{nil}
			for _, input := range []string{"ab ab", "ab abx", "abab", "abx", "ab", "abxxxx", "AB AB", "!!ab ab!!", "a_b", "xxxxxxxxxxabcdxxx", "!"} {
				inputs = append(inputs, []byte(input), releaseWideBytes([]byte(input)))
			}
			inputs = append(inputs, nil, []byte("ab ab"))
			checkLibyaraScanMatrix(t, differentialScanCase{source: source.String(), inputs: inputs, readerChunks: []int{1, 2, 3, 7}})
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
