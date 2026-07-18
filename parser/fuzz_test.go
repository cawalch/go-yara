package parser

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
)

// FuzzYARAParser tests YARA rule parsing with malformed inputs
func FuzzYARAParser(f *testing.F) {
	// Seed corpus with valid and invalid YARA rules from existing tests
	f.Add([]byte("rule test { condition: true }"))
	f.Add([]byte("rule test { strings: $a = \"hello\" condition: $a }"))
	f.Add([]byte("rule test { strings: $a = { DE AD BE EF } condition: $a }"))
	f.Add([]byte("rule test { strings: $a = /pattern/ condition: $a }"))
	f.Add([]byte("rule test { meta: author = \"test\" condition: true }"))
	f.Add([]byte("import \"pe\" rule test { condition: pe.version_info }"))
	f.Add([]byte("rule test1 { condition: true } rule test2 { condition: false }"))
	f.Add([]byte("rule test { condition: 1 and 2 or 3 }"))
	f.Add([]byte("rule test { condition: (1 + 2) * 3 }"))
	f.Add([]byte("rule test { condition: \"hello\" == \"world\" }"))
	f.Add([]byte("rule test { condition: 0x1000 == 4096 }"))
	f.Add([]byte("rule test { condition: filesize > 1000 }"))
	f.Add([]byte("rule test { condition: entrypoint == 0x400000 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" $b = \"test2\" condition: all of them }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a at 0 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a in (0..100) }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a length > 5 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a offset == 10 }"))
	f.Add([]byte("rule test { condition: defined $a }"))
	f.Add([]byte("rule test { condition: not true }"))
	f.Add([]byte("rule test { condition: ~0xFF }"))
	f.Add([]byte("rule test { condition: 1 << 2 }"))
	f.Add([]byte("rule test { condition: 8 >> 2 }"))
	f.Add([]byte("rule test { condition: 1 & 2 }"))
	f.Add([]byte("rule test { condition: 1 | 2 }"))
	f.Add([]byte("rule test { condition: 1 ^ 2 }"))
	f.Add([]byte("rule test { condition: int8(0x1000) == 1 }"))
	f.Add([]byte("rule test { condition: uint16be(0x1000) == 1 }"))
	f.Add([]byte("rule incomplete { strings: $a = "))
	f.Add([]byte("rule { {"))
	f.Add([]byte("rule { condition:"))
	f.Add([]byte("rule test { strings: $a = \"unclosed"))
	f.Add([]byte("rule test { strings: $a = { unclosed"))
	f.Add([]byte("rule test { strings: $a = /unclosed"))
	f.Add([]byte("invalid syntax"))
	f.Add([]byte("rule { very nested ( ( ( ( ( ( condition }"))
	f.Add([]byte("rule test { condition: " + strings.Repeat("(", 1000) + "true" + strings.Repeat(")", 1000) + " }"))
	f.Add([]byte(strings.Repeat("rule test { condition: true } ", 100)))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("YARA parser panicked (fuzz input triggered crash): %v", r)
			}
		}()

		inputStr := string(input)

		// Test basic parsing
		l := lexer.New(inputStr)
		p := New(l)
		program, err := p.ParseRules()

		// Whether parse succeeds or fails, we shouldn't panic
		if err == nil && program != nil {
			_ = program.Rules

			// Test that we can access the rules without panicking
			for _, rule := range program.Rules {
				_ = rule.Name
				_ = rule.Strings
				_ = rule.Meta
				_ = rule.Condition
			}
		}

		// Test with recovery mode enabled
		l2 := lexer.New(inputStr)
		l2.SetRecoveryMode(lexer.RecoverySection)
		p2 := New(l2)
		program2, err2 := p2.ParseRules()
		_ = program2
		_ = err2

		// Test parsing individual sections by truncating input
		inputLines := strings.Split(inputStr, "\n")
		for i := 1; i <= len(inputLines) && i <= 10; i++ {
			partialInput := strings.Join(inputLines[:i], "\n")
			l3 := lexer.New(partialInput)
			p3 := New(l3)
			_, err3 := p3.ParseRules()
			_ = err3
		}

		// Test with very long single lines
		longLines := strings.SplitSeq(inputStr, "\n")
		for line := range longLines {
			if len(line) > 1000 {
				// Test with truncated versions of very long lines
				for truncateLen := 100; truncateLen < len(line) && truncateLen < 2000; truncateLen += 100 {
					truncatedLine := line[:truncateLen]
					l4 := lexer.New(truncatedLine)
					p4 := New(l4)
					_, err4 := p4.ParseRules()
					_ = err4
				}
			}
		}
	})
}

// FuzzExpressionParser tests expression parsing with various malformed expressions
func FuzzExpressionParser(f *testing.F) {
	// Seed corpus with expressions
	f.Add([]byte("true"))
	f.Add([]byte("false"))
	f.Add([]byte("1 and 2"))
	f.Add([]byte("1 or 2"))
	f.Add([]byte("not true"))
	f.Add([]byte("1 + 2"))
	f.Add([]byte("1 - 2"))
	f.Add([]byte("1 * 2"))
	f.Add([]byte("1 / 2"))
	f.Add([]byte("1 % 2"))
	f.Add([]byte("1 == 2"))
	f.Add([]byte("1 != 2"))
	f.Add([]byte("1 < 2"))
	f.Add([]byte("1 <= 2"))
	f.Add([]byte("1 > 2"))
	f.Add([]byte("1 >= 2"))
	f.Add([]byte("1 & 2"))
	f.Add([]byte("1 | 2"))
	f.Add([]byte("1 ^ 2"))
	f.Add([]byte("~1"))
	f.Add([]byte("1 << 2"))
	f.Add([]byte("1 >> 2"))
	f.Add([]byte("\"hello\" == \"world\""))
	f.Add([]byte("0x1000"))
	f.Add([]byte("filesize"))
	f.Add([]byte("entrypoint"))
	f.Add([]byte("$a"))
	f.Add([]byte("($a)"))
	f.Add([]byte("(1 + 2) * 3"))
	f.Add([]byte("1 + 2 * 3"))
	f.Add([]byte("and or"))
	f.Add([]byte("1 ++ 2"))
	f.Add([]byte("1 &&& 2"))
	f.Add([]byte("(unmatched"))
	f.Add([]byte("unmatched)"))
	f.Add([]byte("1 +"))
	f.Add([]byte("+ 1"))
	f.Add([]byte(strings.Repeat("(", 100) + "1" + strings.Repeat(")", 100)))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Expression parser panicked (fuzz input triggered crash): %v", r)
			}
		}()

		inputStr := string(input)

		// Test expression parsing by wrapping it in a rule
		ruleInput := "rule test { condition: " + inputStr + " }"

		l := lexer.New(ruleInput)
		p := New(l)
		program, err := p.ParseRules()

		// Whether parse succeeds or fails, we shouldn't panic
		if err == nil && program != nil {
			_ = program.Rules
		}

		// Test with different wrapping contexts
		contexts := []string{
			"rule test { condition: %s }",
			"rule test { condition: (%s) }",
			"rule test { condition: not (%s) }",
			"rule test { condition: (%s) and true }",
			"rule test { condition: true and (%s) }",
		}

		for _, context := range contexts {
			ruleInput := fmt.Sprintf(context, inputStr)
			l2 := lexer.New(ruleInput)
			p2 := New(l2)
			_, err2 := p2.ParseRules()
			_ = err2
		}
	})
}
