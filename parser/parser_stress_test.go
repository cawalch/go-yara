package parser

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cawalch/go-yara/internal/lexer"
)

func TestParserScaleBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		wantRules   int
		wantStrings int
	}{
		{
			name:      "hundred nested parentheses",
			source:    `rule test { condition: ` + strings.Repeat("(", 100) + `true` + strings.Repeat(")", 100) + ` }`,
			wantRules: 1,
		},
		{
			name:      "ten nested for loops",
			source:    `rule test { condition: ` + strings.Repeat("for any i in (0..1) : (", 10) + "true" + strings.Repeat(")", 10) + ` }`,
			wantRules: 1,
		},
		{
			name:      "fifty rules",
			source:    generateStressRules(50),
			wantRules: 50,
		},
		{
			name:        "hundred strings",
			source:      generateStressRuleWithStrings(100),
			wantRules:   1,
			wantStrings: 100,
		},
		{
			name:        "thousand byte text string",
			source:      `rule test { strings: $a = "` + strings.Repeat("a", 1000) + `" condition: $a }`,
			wantRules:   1,
			wantStrings: 1,
		},
		{
			name:        "long mixed hex pattern",
			source:      `rule test { strings: $a = { ` + strings.Repeat("DE [2-3] (AD | BE) ?? FF ", 20) + `} condition: $a }`,
			wantRules:   1,
			wantStrings: 1,
		},
		{
			name:        "long grouped regex",
			source:      `rule test { strings: $a = /` + strings.Repeat("(abc)", 50) + `/ condition: $a }`,
			wantRules:   1,
			wantStrings: 1,
		},
		{
			name:      "long boolean expression",
			source:    `rule test { condition: ` + strings.Repeat("true and ", 49) + `true }`,
			wantRules: 1,
		},
		{
			name:      "long arithmetic expression",
			source:    `rule test { condition: ` + strings.Repeat("1 + ", 49) + `1 }`,
			wantRules: 1,
		},
		{
			name: "combined string expressions",
			source: `rule test {
				strings:
					$a = "test" private
					$a1 = "test1"
				condition:
					any of ($a*) and any of ($a, $a1) and
					#a > 0 and @a < 100 and !a == 4 and
					($a at 0 or $a in (0..100)) and $a matches /test/
			}`,
			wantRules:   1,
			wantStrings: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, err := New(lexer.New(test.source)).ParseRules()
			require.NoError(t, err)
			require.NotNil(t, program)
			require.Len(t, program.Rules, test.wantRules)
			if test.wantStrings > 0 {
				require.Len(t, program.Rules[0].Strings, test.wantStrings)
			}
		})
	}
}

func generateStressRules(count int) string {
	var rules strings.Builder
	for i := range count {
		rules.WriteString(`rule test_`)
		rules.WriteString(strconv.Itoa(i))
		rules.WriteString(` { condition: true } `)
	}
	return rules.String()
}

func generateStressRuleWithStrings(count int) string {
	var rule strings.Builder
	rule.WriteString(`rule test { strings: `)
	for i := range count {
		rule.WriteString(`$a`)
		rule.WriteString(strconv.Itoa(i))
		rule.WriteString(` = "test`)
		rule.WriteString(strconv.Itoa(i))
		rule.WriteString(`" `)
	}
	rule.WriteString(`condition: any of them }`)
	return rule.String()
}
