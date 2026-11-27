package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/compiler"
)

const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func TestLibyaraBase64ModifierCombinations(t *testing.T) {
	source := `
rule ascii_base64 { strings: $a = "\xfb\xef\xbeHello" ascii base64 condition: #a >= 1 }
rule wide_base64 { strings: $a = "\xfb\xef\xbeHello" wide base64 condition: #a >= 1 }
rule both_inputs { strings: $a = "\xfb\xef\xbeHello" ascii wide base64 condition: #a >= 1 }
rule wide_output { strings: $a = "\xfb\xef\xbeHello" ascii wide base64wide condition: #a >= 1 }
rule both_outputs { strings: $a = "\xfb\xef\xbeHello" base64wide base64 condition: #a >= 1 }
rule all_encodings { strings: $a = "\xfb\xef\xbeHello" ascii wide base64 base64wide condition: #a >= 1 }
rule explicit_standard { strings: $a = "\xfb\xef\xbeHello" base64("` + ast.DefaultBase64Alphabet + `") base64wide condition: #a >= 1 }
rule custom { strings: $a = "\xfb\xef\xbeHello" wide ascii base64wide("` + base64URLAlphabet + `") base64("` + base64URLAlphabet + `") condition: #a >= 1 }
`
	plain := []byte("\xfb\xef\xbeHello")
	inputs := [][]byte{plain, base64Wide(plain), []byte("reject")}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for _, raw := range [][]byte{plain, base64Wide(plain)} {
			for alignment := range 3 {
				payload := append(bytes.Repeat([]byte{'q'}, alignment), raw...)
				payload = append(payload, 'z', 'z')
				encoded := []byte(encoding.EncodeToString(payload))
				inputs = append(inputs, encoded, base64Wide(encoded))
			}
		}
	}
	checkLibyaraScanMatrix(t, differentialScanCase{source: source, inputs: inputs, readerChunks: []int{5}})
}

func TestLibyaraBase64ModifierOverlappingEncodings(t *testing.T) {
	checkLibyaraScanMatrix(t, differentialScanCase{
		source:       `rule overlaps { strings: $a = "a" ascii wide base64 base64wide condition: #a >= 1 }`,
		inputs:       [][]byte{[]byte("YQ|Y\x00Q\x00|Y|Y\x00|YQ==|YQA="), []byte("a\x00"), []byte("Y\x00"), nil},
		readerChunks: []int{3},
	})
}

func TestLibyaraBase64ModifierRejections(t *testing.T) {
	bin := libyaraOracle(t)
	for _, modifiers := range []string{
		`base64("` + base64URLAlphabet + `") base64wide`,
		`base64wide("` + base64URLAlphabet + `") base64`,
		`base64 base64wide fullword`, `base64 base64wide nocase`, `base64 base64wide xor`,
		`base64 base64`, `base64wide base64wide`,
	} {
		t.Run(modifiers, func(t *testing.T) {
			source := `rule reject { strings: $a = "marker" ` + modifiers + ` condition: $a }`
			if _, err := scanWithLibyara(t, bin, source, []byte("marker")); err == nil {
				t.Fatal("libyara accepted invalid modifiers")
			}
			if _, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source); err == nil {
				t.Fatal("go-yara accepted invalid modifiers")
			}
		})
	}
}

func base64Wide(data []byte) []byte {
	out := make([]byte, len(data)*2)
	for i, b := range data {
		out[2*i] = b
	}
	return out
}
