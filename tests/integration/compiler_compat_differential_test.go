package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/pefixture"
)

// TestLibyaraCompilerCompatibilityParity verifies runtime evaluation parity
// against libyara for lexer, parser, and meta compatibility constructs
// unlocked by the YARA Forge 20261108 audit.
func TestLibyaraCompilerCompatibilityParity(t *testing.T) {
	libyaraOracle(t)

	longHex := strings.Repeat("41 ", 200) + "50 72"
	source := `
import "pe"

rule compat_long_hex_lookback {
	strings:
		$pad = { ` + longHex + ` }
		$b = { 4D 5A }
	condition:
		$pad and $b
}

rule compat_meta_neg_and_dup {
	meta:
		score = -10
		hash = "first"
		hash = "second"
	condition:
		true
}

rule compat_range_arith_near {
	strings:
		$a = "HEAD"
		$b = "TAIL"
	condition:
		$b in (@a .. @a + 20)
}

rule compat_range_loop_indexed {
	strings:
		$a = "HEAD"
		$b = "TAIL"
	condition:
		for any i in (1..#a) : ($b in (@a[i] .. @a[i] + 10))
}

rule compat_keyword_and_numeric_string_ops {
	strings:
		$xor = "XX"
		$1 = "AA"
		$2 = "BB"
	condition:
		#xor == 2 and @1 [ 1 ] < @2 [ 1 ]
}

rule compat_dotdot_no_space_pe {
	strings:
		$pe = "NamedFunction"
	condition:
		pe.is_pe and for any s in pe.sections : ($pe in (s.raw_data_offset..s.raw_data_offset + s.raw_data_size))
}
`

	longPayload := append([]byte(strings.Repeat("A", 200)+"Pr"), []byte("MZ HEAD12345TAIL XXXX AABB")...)
	farPayload := []byte("HEAD" + strings.Repeat(".", 40) + "TAIL")
	pePayload := pefixture.Imports(false, 2)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "long_hex_and_near_ranges", data: longPayload},
		{name: "far_range_negative", data: farPayload},
		{name: "pe_dotdot_nospace", data: pePayload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkPEPaths(t, source, tc.data)
		})
	}

	t.Run("compiled_meta_values", func(t *testing.T) {
		prog, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source)
		if err != nil {
			t.Fatal(err)
		}
		matches, err := prog.MatchingRules([]byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, m := range matches {
			if m.Rule == "compat_meta_neg_and_dup" {
				found = true
				if got := m.Meta["score"]; got != int64(-10) {
					t.Fatalf("score meta = %v (%T), want int64(-10)", got, got)
				}
				if got := m.Meta["hash"]; got == "" || got == nil {
					t.Fatalf("expected non-empty duplicated meta hash, got %v", got)
				}
			}
		}
		if !found {
			t.Fatal("expected compat_meta_neg_and_dup to match")
		}
	})
}
