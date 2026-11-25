package integration

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraASCIIInsensitiveStringConditions(t *testing.T) {
	bin := libyaraOracle(t)
	input := []byte("input")
	for _, tc := range []struct {
		name, left, right string
	}{
		{"ascii_equal", "aBc", "AbC"},
		{"ascii_substring", "prefixAbCsuffix", "aBc"},
		{"ascii_prefix", "aBc-suffix", "AbC"},
		{"ascii_suffix", "prefix-aBc", "AbC"},
		{"invalid_utf8", "\xff", "\xfe"},
		{"binary_equal", "a\xffZ", "A\xffz"},
		{"non_ascii_case", "Ä", "ä"},
		{"kelvin", "K", "K"},
		{"dotted_i", "İ", "I"},
		{"dotless_i", "ı", "I"},
		{"embedded_nul_equal", "a\x00Z", "A\x00z"},
		{"embedded_nul_different", "a\x00Z", "A\x00y"},
		{"empty", "ABC", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var literals, externals strings.Builder
			left, right := yaraHexEscape([]byte(tc.left)), yaraHexEscape([]byte(tc.right))
			for _, op := range []string{"icontains", "istartswith", "iendswith", "iequals"} {
				fmt.Fprintf(&literals, "rule r_%s { condition: \"%s\" %s \"%s\" }\n", op, left, op, right)
				fmt.Fprintf(&externals, "rule r_%s { condition: left_value %s right_value }\n", op, op)
			}
			want, err := scanWithLibyara(t, bin, literals.String(), input)
			if err != nil {
				t.Fatal(err)
			}
			checkASCIIConditionRuleResults(t, literals.String(), input, want)

			// Use the native literal result when CLI transport cannot preserve the operands.
			if libyaraCanPassStringArgument(tc.left) && libyaraCanPassStringArgument(tc.right) {
				want, err = scanWithLibyara(t, bin, externals.String(), input, "-d", "left_value="+tc.left, "-d", "right_value="+tc.right)
				if err != nil {
					t.Fatal(err)
				}
			}
			source := "external left_value\nexternal right_value\n" + externals.String()
			checkASCIIConditionRuleResults(t, source, input, want, compiler.WithExternalVariables(map[string]any{
				"left_value": tc.left, "right_value": tc.right,
			}))
		})
	}
}

func libyaraCanPassStringArgument(s string) bool {
	return !strings.ContainsRune(s, 0) && (runtime.GOOS != "windows" || !strings.ContainsFunc(s, func(r rune) bool { return r > 127 }))
}

//nolint:revive // The source, input, and oracle results vary independently of scanner options.
func checkASCIIConditionRuleResults(t *testing.T, source string, input []byte, want map[string][]span, opts ...compiler.ScannerOption) {
	t.Helper()
	program, err := compiler.NewCompiler().CompileSourceWithContext(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(opts...)
	defer scanner.Close()
	result, err := scanner.Scan(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range program.Rules {
		_, matched := want[rule.Name]
		if got := result.RuleResults[rule.Name]; got != matched {
			t.Errorf("%s = %t, want libyara's %t", rule.Name, got, matched)
		}
	}
}
