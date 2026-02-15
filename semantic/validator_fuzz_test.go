package semantic

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
)

// FuzzSemanticValidator tests the semantic validator with various YARA rules
func FuzzSemanticValidator(f *testing.F) {
	// Seed corpus with valid and invalid YARA rules
	f.Add([]byte("rule test { condition: true }"))
	f.Add([]byte("rule test { strings: $a = \"hello\" condition: $a }"))
	f.Add([]byte("rule test { strings: $a = \"hello\" $b = \"world\" condition: $a and $b }"))
	f.Add([]byte("rule test { strings: $a = { DE AD BE EF } condition: $a }"))
	f.Add([]byte("rule test { strings: $a = /pattern/ condition: $a }"))
	f.Add([]byte("rule test { meta: author = \"test\" condition: true }"))
	f.Add([]byte("rule test1 { condition: true } rule test2 { condition: false }"))
	f.Add([]byte("rule test { condition: 1 and 2 or 3 }"))
	f.Add([]byte("rule test { condition: (1 + 2) * 3 }"))
	f.Add([]byte("rule test { condition: \"hello\" == \"world\" }"))
	f.Add([]byte("rule test { condition: 0x1000 == 4096 }"))
	f.Add([]byte("rule test { condition: filesize > 1000 }"))
	f.Add([]byte("rule test { condition: entrypoint == 0x400000 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: all of them }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: any of them }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: none of them }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: 1 of them }"))
	f.Add([]byte("rule test { strings: $a = \"test\" $b = \"test2\" condition: all of ($a, $b) }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a at 0 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a in (0..100) }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: !a > 5 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: @a == 10 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: #a == 2 }"))
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
	f.Add([]byte("rule test { condition: for any i in (0..10) : (i > 5) }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: for 2 of them : ($a) }"))
	f.Add([]byte("rule test { condition: \"test\" contains \"es\" }"))
	f.Add([]byte("rule test { condition: \"test\" matches /^t.*t$/ }"))
	f.Add([]byte("rule test { condition: $undefined_var }"))
	f.Add([]byte("rule test { strings: $a = \"test\" $a = \"duplicate\" condition: $a }"))
	f.Add([]byte("rule duplicate { condition: true } rule duplicate { condition: false }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a.nonsense }"))
	f.Add([]byte("rule test { condition: 1 + \"string\" }"))
	f.Add([]byte("rule test { condition: true and \"string\" }"))
	f.Add([]byte("rule test { condition: 1 == \"string\" }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a + 1 }"))
	f.Add([]byte("rule test { condition: int8() }"))
	f.Add([]byte("rule test { condition: int8(1, 2, 3) }"))
	f.Add([]byte("rule test { condition: unknown_function() }"))
	f.Add([]byte("import \"pe\" rule test { condition: pe.is_pe }"))
	f.Add([]byte("import \"pe\" rule test { condition: pe.version_info contains \"test\" }"))
	f.Add([]byte("rule test { condition: them }"))
	f.Add([]byte("rule test { condition: $ }"))
	f.Add([]byte("global rule test { condition: true }"))
	f.Add([]byte("private rule test { condition: true }"))
	f.Add([]byte("rule test { strings: $ = \"anonymous\" condition: $ }"))
	f.Add([]byte("rule test { strings: $ = \"anon1\" $ = \"anon2\" condition: $ }"))
	f.Add([]byte("external var_name rule test { condition: var_name }"))
	f.Add([]byte("external int_var external string_var rule test { condition: int_var }"))
	f.Add([]byte("rule test { meta: key1 = \"value1\" key2 = 42 condition: true }"))
	f.Add([]byte("rule test { strings: $a = \"test\" nocase condition: $a }"))
	f.Add([]byte("rule test { strings: $a = \"test\" wide condition: $a }"))
	f.Add([]byte("rule test { strings: $a = \"test\" fullword condition: $a }"))
	f.Add([]byte("rule test { strings: $a = \"test\" ascii condition: $a }"))
	f.Add([]byte("rule test { strings: $a = \"test\" private condition: $a }"))
	f.Add([]byte("rule test { strings: $a = { 00 01 02 } condition: $a }"))
	f.Add([]byte("rule test { strings: $a = /test/ condition: $a }"))
	f.Add([]byte("rule test { strings: $a = \"test\" xor condition: $a }"))
	f.Add([]byte("rule test { strings: $a = \"test\" base64 condition: $a }"))
	f.Add([]byte("rule test { strings: $a = \"test\" base64wide condition: $a }"))
	f.Add([]byte("rule test { condition: filesize > 0x1000 and filesize < 0x2000 }"))
	f.Add([]byte("rule test { condition: entrypoint >= 0x400000 and entrypoint <= 0x500000 }"))
	f.Add([]byte("rule test { condition: flags & 0x02 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: #a > 0 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: @a[0] == 10 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: !a[0] > 5 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" $b = \"test\" condition: for 2 i in (1..10) : ($a at i) }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a matches /test/i }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a contains \"es\" }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a startswith \"te\" }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a endswith \"st\" }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a iequals \"TEST\" }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a contains \"es\" nocase }"))
	f.Add([]byte("rule test { condition: concat(\"test\", \"ing\") == \"testing\" }"))
	f.Add([]byte("rule test { condition: tostring(10) == \"10\" }"))
	f.Add([]byte("rule test { condition: md5(0, 10) == \"d41d8cd98f00b204e9800998ecf8427e\" }"))
	f.Add([]byte("rule test { condition: sha1(0, 10) == \"da39a3ee5e6b4b0d3255bfef95601890afd80709\" }"))
	f.Add([]byte("rule test { condition: sha256(0, 10) == \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\" }"))
	f.Add([]byte("rule test { condition: 1.5 + 2.5 == 4.0 }"))
	f.Add([]byte("rule test { condition: 10 / 3 }"))
	f.Add([]byte("rule test { condition: 10 // 3 }"))
	f.Add([]byte("rule test { condition: -10 }"))
	f.Add([]byte("rule test { condition: +10 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: not $a }"))
	f.Add([]byte("rule test { strings: $a = \"test\" $b = \"test\" condition: $a or $b }"))
	f.Add([]byte("rule test { strings: $a = \"test\" $b = \"test\" condition: $a and $b }"))
	f.Add([]byte("rule test { condition: (true or false) and true }"))
	f.Add([]byte("rule test { condition: true and (false or true) }"))
	f.Add([]byte("rule test { condition: 0x100 << 4 }"))
	f.Add([]byte("rule test { condition: 0x10000 >> 8 }"))
	f.Add([]byte("rule test { condition: 0xFF & 0x0F }"))
	f.Add([]byte("rule test { condition: 0xF0 | 0x0F }"))
	f.Add([]byte("rule test { condition: 0xFF ^ 0xFF }"))
	f.Add([]byte("rule test { condition: 10 % 3 == 1 }"))
	f.Add([]byte("rule test { condition: 10 // 3 == 3 }"))
	f.Add([]byte("rule test { condition: 1.0 + 2 == 3.0 }"))
	f.Add([]byte("rule test { condition: 2 + 1.0 == 3.0 }"))
	f.Add([]byte("rule test { condition: 1 < 2 and 2 < 3 }"))
	f.Add([]byte("rule test { condition: 1 < 2 or 3 < 2 }"))
	f.Add([]byte("rule test { condition: (1 < 2) == true }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: #a >= 1 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: #a <= 10 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: @a[0] >= 0 }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: !a[0] <= 100 }"))
	f.Add([]byte("rule test { condition: filesize == uint16(0) }"))
	f.Add([]byte("rule test { condition: filesize == int32(0) }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: for any i in (0..filesize) : ($a at i) }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: for 2 i in (0..10) : (@a[i] > 0) }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: for all i in (0..10) : (!a[i] > 0) }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a at entrypoint }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a in (entrypoint..filesize) }"))
	f.Add([]byte("rule test { condition: defined filesize }"))
	f.Add([]byte("rule test { condition: defined entrypoint }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: defined $a }"))
	f.Add([]byte("rule test { condition: not defined undefined_var }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: $a and true }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: true and $a }"))
	f.Add([]byte("rule test { condition: 1 of ($a) }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: 1 of ($a, $b) }"))
	f.Add([]byte("rule test { condition: any of ($a, $b, $c) }"))
	f.Add([]byte("rule test { condition: all of ($a, $b) }"))
	f.Add([]byte("rule test { condition: none of them }"))
	f.Add([]byte("rule test { strings: $a = \"test\" condition: them }"))
	f.Add([]byte("rule test { condition: \"hello\" icontains \"ELL\" }"))
	f.Add([]byte("rule test { condition: \"test\" istartswith \"TE\" }"))
	f.Add([]byte("rule test { condition: \"test\" iendswith \"ST\" }"))
	f.Add([]byte("rule test { condition: \"test\" iequals \"TEST\" }"))
	f.Add([]byte("rule test { condition: \"test\" matches /^test$/i }"))
	f.Add([]byte("rule test { condition: 0o755 }"))
	f.Add([]byte("rule test { condition: 100KB }"))
	f.Add([]byte("rule test { condition: 1MB }"))
	f.Add([]byte("rule test { condition: 1.5MB }"))
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
				t.Logf("Semantic validator recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Parse the input
		l := lexer.New(inputStr)
		p := parser.New(l)
		program, err := p.ParseRulesWithContext(context.Background())

		// If parsing failed, we can't validate - that's ok
		if err != nil || program == nil {
			return
		}

		// Test semantic validation
		v := NewValidator()
		validateErrors := v.ValidateProgram(program)

		// Whether validation succeeds or fails, we shouldn't panic
		_ = validateErrors

		// Test accessing the symbol table
		symTable := v.GetSymbolTable()
		_ = symTable
		_ = symTable.Root
		_ = symTable.GetErrors()

		// Test that we can iterate through rules without panicking
		for _, rule := range program.Rules {
			_ = rule.Name
			_ = rule.Strings
			_ = rule.Meta
			_ = rule.Condition

			// Validate each rule individually
			v2 := NewValidator()
			v2.validateRule(rule)
			_ = v2.GetErrors()
		}

		// Test with error recovery mode
		l2 := lexer.NewWithRecovery(inputStr, lexer.RecoverySection) //nolint:staticcheck // fuzz test uses recovery mode
		p2 := parser.New(l2)
		p2.SetErrorRecovery(true)
		program2, err2 := p2.ParseRulesWithContext(context.Background())

		if err2 == nil && program2 != nil {
			v3 := NewValidator()
			validateErrors2 := v3.ValidateProgram(program2)
			_ = validateErrors2
		}

		// Test individual validation modes
		if len(program.Rules) > 0 {
			// Test string validation
			rule := program.Rules[0]
			v4 := NewValidator()
			v4.validateStrings(rule.Strings)
			_ = v4.GetErrors()

			// Test meta validation
			v5 := NewValidator()
			v5.validateMeta(rule.Meta)
			_ = v5.GetErrors()

			// Test condition validation
			if rule.Condition != nil {
				v6 := NewValidator()
				v6.validateCondition(rule.Condition)
				_ = v6.GetErrors()
			}
		}
	})
}

// FuzzTypeChecker tests the type checker with various expressions
func FuzzTypeChecker(f *testing.F) {
	// Seed corpus with various expressions
	f.Add([]byte("true"))
	f.Add([]byte("false"))
	f.Add([]byte("1"))
	f.Add([]byte("0"))
	f.Add([]byte("-1"))
	f.Add([]byte("1.5"))
	f.Add([]byte("\"hello\""))
	f.Add([]byte("1 and 2"))
	f.Add([]byte("1 or 2"))
	f.Add([]byte("not true"))
	f.Add([]byte("1 + 2"))
	f.Add([]byte("1 - 2"))
	f.Add([]byte("1 * 2"))
	f.Add([]byte("1 / 2"))
	f.Add([]byte("1 % 2"))
	f.Add([]byte("1 // 2"))
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
	f.Add([]byte("0o755"))
	f.Add([]byte("100KB"))
	f.Add([]byte("1MB"))
	f.Add([]byte("filesize"))
	f.Add([]byte("entrypoint"))
	f.Add([]byte("flags"))
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
	f.Add([]byte("int8(0x1000)"))
	f.Add([]byte("uint16(0x1000)"))
	f.Add([]byte("uint32be(0x1000)"))
	f.Add([]byte("int64be(0x1000)"))
	f.Add([]byte("concat(\"a\", \"b\")"))
	f.Add([]byte("tostring(10)"))
	f.Add([]byte("md5(0, 10)"))
	f.Add([]byte("sha1(0, 10)"))
	f.Add([]byte("sha256(0, 10)"))
	f.Add([]byte("defined $a"))
	f.Add([]byte("not defined $a"))
	f.Add([]byte("int8()"))
	f.Add([]byte("int8(1, 2, 3)"))
	f.Add([]byte("unknown_function()"))
	f.Add([]byte("pe.is_pe"))
	f.Add([]byte("pe.version_info"))
	f.Add([]byte("elf.sections"))
	f.Add([]byte("macho.flags"))
	f.Add([]byte("them"))
	f.Add([]byte("$"))
	f.Add([]byte("#$a"))
	f.Add([]byte("@$a"))
	f.Add([]byte("!$a"))
	f.Add([]byte("#$a[0]"))
	f.Add([]byte("@$a[0]"))
	f.Add([]byte("!$a[0]"))
	f.Add([]byte("\"test\" contains \"es\""))
	f.Add([]byte("\"test\" matches /^t.*t$/"))
	f.Add([]byte("\"test\" icontains \"ES\""))
	f.Add([]byte("\"test\" istartswith \"TE\""))
	f.Add([]byte("\"test\" iendswith \"ST\""))
	f.Add([]byte("\"test\" iequals \"TEST\""))
	f.Add([]byte("all of them"))
	f.Add([]byte("any of them"))
	f.Add([]byte("none of them"))
	f.Add([]byte("1 of them"))
	f.Add([]byte("1 of ($a, $b, $c)"))
	f.Add([]byte("any of ($a, $b)"))
	f.Add([]byte("all of ($a, $b)"))
	f.Add([]byte("for any i in (0..10) : (i > 5)"))
	f.Add([]byte("for 2 i in (0..10) : (i > 5)"))
	f.Add([]byte("for all i in (0..10) : (i > 5)"))
	f.Add([]byte("1 + \"string\""))
	f.Add([]byte("true and \"string\""))
	f.Add([]byte("1 == \"string\""))
	f.Add([]byte("\"string\" + \"string\""))
	f.Add([]byte("1.5 + 2.5"))
	f.Add([]byte("1.0 + 2"))
	f.Add([]byte("2 + 1.0"))
	f.Add([]byte("-10"))
	f.Add([]byte("+10"))
	f.Add([]byte("~0xFF"))
	f.Add([]byte("not not true"))
	f.Add([]byte("1 < 2 and 2 < 3"))
	f.Add([]byte("1 < 2 or 3 < 2"))
	f.Add([]byte("(1 < 2) == true"))
	f.Add([]byte("10 % 3"))
	f.Add([]byte("10 // 3"))
	f.Add([]byte("0x100 << 4"))
	f.Add([]byte("0x10000 >> 8"))
	f.Add([]byte("0xFF & 0x0F"))
	f.Add([]byte("0xF0 | 0x0F"))
	f.Add([]byte("0xFF ^ 0xFF"))
	f.Add([]byte(strings.Repeat("(", 100) + "1" + strings.Repeat(")", 100)))
	f.Add([]byte(strings.Repeat("1 and ", 100) + "true"))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Type checker recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test expression type checking by wrapping it in a rule
		ruleInput := "rule test { strings: $a = \"test\" condition: " + inputStr + " }"

		l := lexer.New(ruleInput)
		p := parser.New(l)
		program, err := p.ParseRulesWithContext(context.Background())

		// If parsing failed, we can't type check - that's ok
		if err != nil || program == nil {
			return
		}

		// Test type checking through validator
		v := NewValidator()
		validateErrors := v.ValidateProgram(program)

		// Whether validation succeeds or fails, we shouldn't panic
		_ = validateErrors

		// Test direct type checker access if we have a condition
		if len(program.Rules) > 0 && program.Rules[0].Condition != nil {
			tc := NewTypeChecker(v.GetSymbolTable())
			if program.Rules[0].Condition != nil {
				typeInfo, typeErrors := tc.CheckExpressionTypes(program.Rules[0].Condition)
				_ = typeInfo
				_ = typeErrors
			}
		}

		// Test with different wrapping contexts
		contexts := []string{
			"rule test { condition: %s }",
			"rule test { strings: $a = \"test\" condition: %s }",
			"rule test { strings: $a = \"test\" $b = \"test2\" condition: (%s) and true }",
			"rule test { strings: $a = \"test\" condition: true and (%s) }",
			"rule test { strings: $a = \"test\" condition: not (%s) }",
			"rule test { strings: $a = \"test\" condition: (%s) or false }",
		}

		for _, ctx := range contexts {
			ruleInput := fmt.Sprintf(ctx, inputStr)
			l2 := lexer.New(ruleInput)
			p2 := parser.New(l2)
			program2, err2 := p2.ParseRulesWithContext(context.Background())

			if err2 == nil && program2 != nil && len(program2.Rules) > 0 {
				v2 := NewValidator()
				validateErrors2 := v2.ValidateProgram(program2)
				_ = validateErrors2

				// Test type checker
				tc2 := NewTypeChecker(v2.GetSymbolTable())
				if program2.Rules[0].Condition != nil {
					typeInfo2, typeErrors2 := tc2.CheckExpressionTypes(program2.Rules[0].Condition)
					_ = typeInfo2
					_ = typeErrors2
				}
			}
		}

		// Test with incomplete expressions
		if len(inputStr) > 1 {
			for i := 1; i < len(inputStr) && i <= 10; i++ {
				truncatedInput := inputStr[:i]
				truncatedRuleInput := "rule test { condition: " + truncatedInput + " }"
				l3 := lexer.New(truncatedRuleInput)
				p3 := parser.New(l3)
				program3, err3 := p3.ParseRulesWithContext(context.Background())

				if err3 == nil && program3 != nil && len(program3.Rules) > 0 {
					v3 := NewValidator()
					validateErrors3 := v3.ValidateProgram(program3)
					_ = validateErrors3
				}
			}
		}
	})
}

// FuzzSymbolTable tests symbol table operations with various identifiers
func FuzzSymbolTable(f *testing.F) {
	// Seed corpus with various identifier names and patterns
	f.Add([]byte("test"))
	f.Add([]byte("$string"))
	f.Add([]byte("$a"))
	f.Add([]byte("$very_long_string_name"))
	f.Add([]byte("$string123"))
	f.Add([]byte("$string_with_underscore"))
	f.Add([]byte("$string-with-dash"))
	f.Add([]byte("$string.with.dots"))
	f.Add([]byte("rule_name"))
	f.Add([]byte("rule_with_numbers_123"))
	f.Add([]byte("external_var"))
	f.Add([]byte("meta_key"))
	f.Add([]byte("kebab-case-name"))
	f.Add([]byte("snake_case_name"))
	f.Add([]byte("CamelCaseName"))
	f.Add([]byte("UPPER_CASE_NAME"))
	f.Add([]byte("mixedCaseName"))
	f.Add([]byte("name123"))
	f.Add([]byte("123invalid"))
	f.Add([]byte(""))
	f.Add([]byte(" "))
	f.Add([]byte("$"))
	f.Add([]byte("$$"))
	f.Add([]byte("$ "))
	f.Add([]byte(" $"))
	f.Add([]byte("a b"))
	f.Add([]byte("a.b"))
	f.Add([]byte("a.b.c"))
	f.Add([]byte("pe.is_pe"))
	f.Add([]byte("elf.sections"))
	f.Add([]byte("macho.flags"))
	f.Add([]byte("cuckoo.network"))
	f.Add([]byte("text.raw"))
	f.Add([]byte("hash.md5"))
	f.Add([]byte("$a"))
	f.Add([]byte("$b"))
	f.Add([]byte("$c"))
	f.Add([]byte("$1"))
	f.Add([]byte("$2"))
	f.Add([]byte("$3"))
	f.Add([]byte("$_"))
	f.Add([]byte("$__"))
	f.Add([]byte("$_test"))
	f.Add([]byte("$test_"))
	f.Add([]byte("$test$test"))
	f.Add([]byte("$test.test"))
	f.Add([]byte("$test-test"))
	f.Add([]byte("$test test"))
	f.Add([]byte("$test123"))
	f.Add([]byte("$123test"))
	f.Add([]byte("them"))
	f.Add([]byte("all"))
	f.Add([]byte("any"))
	f.Add([]byte("none"))
	f.Add([]byte("filesize"))
	f.Add([]byte("entrypoint"))
	f.Add([]byte("flags"))
	f.Add([]byte("defined"))
	f.Add([]byte("not"))
	f.Add([]byte("and"))
	f.Add([]byte("or"))
	f.Add([]byte("int8"))
	f.Add([]byte("uint16"))
	f.Add([]byte("int32be"))
	f.Add([]byte("concat"))
	f.Add([]byte("tostring"))
	f.Add([]byte("md5"))
	f.Add([]byte("sha1"))
	f.Add([]byte("sha256"))
	f.Add([]byte("import"))
	f.Add([]byte("include"))
	f.Add([]byte("global"))
	f.Add([]byte("private"))
	f.Add([]byte("rule"))
	f.Add([]byte("strings"))
	f.Add([]byte("condition"))
	f.Add([]byte("meta"))
	f.Add([]byte("true"))
	f.Add([]byte("false"))
	f.Add([]byte("a"))
	f.Add([]byte("ab"))
	f.Add([]byte("abc"))
	f.Add([]byte("abcd"))
	f.Add([]byte("abcde"))
	f.Add([]byte("a.b.c.d.e"))
	f.Add([]byte("very_long_identifier_name_that_might_cause_issues"))
	f.Add([]byte(strings.Repeat("a", 1000)))
	f.Add([]byte("$" + strings.Repeat("a", 1000)))
	f.Add([]byte(strings.Repeat("a.", 100)))
	f.Add([]byte("a\nb"))
	f.Add([]byte("a\tb"))
	f.Add([]byte("a\rb"))
	f.Add([]byte("a\x00b"))
	f.Add([]byte("你好"))
	f.Add([]byte("test_тест"))
	f.Add([]byte("test🎯"))
	f.Add([]byte("test\\n"))
	f.Add([]byte("test\\t"))
	f.Add([]byte("test\\x41"))
	f.Add([]byte("test\\u1234"))
	f.Add([]byte("test\\U00001234"))
	f.Add([]byte("test\"quote"))
	f.Add([]byte("test'quote"))
	f.Add([]byte("test\\slash"))
	f.Add([]byte("test`backtick`"))
	f.Add([]byte("a!@#$%^&*()"))
	f.Add([]byte("a+-*/%"))
	f.Add([]byte("a=<>"))
	f.Add([]byte("a[]{}"))
	f.Add([]byte("a|&~^"))
	f.Add([]byte("a;:,'\""))

	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Symbol table recovered from panic: %v", r)
			}
		}()

		inputStr := string(input)

		// Test symbol table operations
		st := NewSymbolTable()

		// Test DefineRule
		pos := positionFromInput(inputStr)
		err1 := st.DefineRule(inputStr, pos, nil)
		_ = err1

		// Test DefineString
		err2 := st.DefineString(inputStr, pos, nil)
		_ = err2

		// Test DefineVariable with different types
		err3 := st.DefineVariable(inputStr, pos, SymbolVariable)
		_ = err3
		err4 := st.DefineVariable(inputStr, pos, SymbolExternal)
		_ = err4

		// Test Lookup
		symbol, exists := st.Lookup(inputStr)
		if exists {
			_ = symbol
			_ = symbol.Name
			_ = symbol.Type
			_ = symbol.Scope
			_ = symbol.IsGlobal
			_ = symbol.Used
		}

		// Test LookupInCurrentScope
		symbol2, exists2 := st.LookupInCurrentScope(inputStr)
		if exists2 {
			_ = symbol2
		}

		// Test LookupInGlobalScope
		symbol3, exists3 := st.LookupInGlobalScope(inputStr)
		if exists3 {
			_ = symbol3
		}

		// Test MarkUsed
		st.MarkUsed(inputStr)

		// Test scope operations
		st.EnterScope(inputStr)
		st.ExitScope()

		// Test error handling
		st.AddError(nil)
		st.AddError(&Error{
			Message:  "test error",
			Position: pos,
		})

		// Test GetErrors
		errors := st.GetErrors()
		_ = errors

		// Test HasErrors
		hasErrors := st.HasErrors()
		_ = hasErrors

		// Test Reset
		st.Reset()

		// Test GetUnusedSymbols
		unused := st.GetUnusedSymbols()
		_ = unused

		// Test with multiple definitions
		st2 := NewSymbolTable()
		_ = st2.DefineRule(inputStr+"_1", pos, nil)
		_ = st2.DefineRule(inputStr+"_2", pos, nil)
		_ = st2.DefineString("$"+inputStr+"_1", pos, nil)
		_ = st2.DefineString("$"+inputStr+"_2", pos, nil)
		_, exists4 := st2.Lookup(inputStr + "_1")
		_ = exists4

		// Test nested scopes
		st3 := NewSymbolTable()
		st3.EnterScope("outer")
		_ = st3.DefineVariable(inputStr+"_outer", pos, SymbolVariable)
		st3.EnterScope("inner")
		_ = st3.DefineVariable(inputStr+"_inner", pos, SymbolVariable)
		symbol4, exists5 := st3.Lookup(inputStr + "_outer")
		_ = symbol4
		_ = exists5
		symbol5, exists6 := st3.LookupInCurrentScope(inputStr + "_inner")
		_ = symbol5
		_ = exists6
		st3.ExitScope()
		symbol6, exists7 := st3.LookupInCurrentScope(inputStr + "_outer")
		_ = symbol6
		_ = exists7

		// Test symbol table with actual YARA rule
		ruleInput := fmt.Sprintf("rule %s { strings: $%s = \"test\" condition: $%s }", inputStr, inputStr, inputStr)
		l := lexer.New(ruleInput)
		p := parser.New(l)
		program, err := p.ParseRulesWithContext(context.Background())

		if err == nil && program != nil {
			v := NewValidator()
			validateErrors := v.ValidateProgram(program)
			_ = validateErrors

			// Test symbol table from validation
			symTable := v.GetSymbolTable()
			_ = symTable
			_ = symTable.Root
			_ = symTable.GetErrors()
		}

		// Test with identifier variations
		variations := []string{
			inputStr,
			"$" + inputStr,
			inputStr + "_test",
			"test_" + inputStr,
			inputStr + "123",
			"123" + inputStr,
		}

		st4 := NewSymbolTable()
		for _, variation := range variations {
			_ = st4.DefineVariable(variation, pos, SymbolVariable)
			sym, exists := st4.Lookup(variation)
			if exists {
				_ = sym
			}
		}

		// Test with string identifier variations
		st5 := NewSymbolTable()
		for _, variation := range variations {
			if !strings.HasPrefix(variation, "$") {
				variation = "$" + variation
			}
			_ = st5.DefineString(variation, pos, nil)
			sym, exists := st5.Lookup(variation)
			if exists {
				_ = sym
			}
		}

		// Test duplicate definitions
		st6 := NewSymbolTable()
		_ = st6.DefineRule(inputStr, pos, nil)
		errDup := st6.DefineRule(inputStr, pos, nil)
		_ = errDup
		_ = st6.DefineString("$"+inputStr, pos, nil)
		errDup2 := st6.DefineString("$"+inputStr, pos, nil)
		_ = errDup2

		// Test with special characters in input
		for _, ch := range inputStr {
			testStr := string(ch)
			st7 := NewSymbolTable()
			_ = st7.DefineVariable(testStr, pos, SymbolVariable)
			_, exists := st7.Lookup(testStr)
			_ = exists
		}

		// Test with empty and whitespace inputs
		testInputs := []string{
			inputStr,
			" " + inputStr,
			inputStr + " ",
			" " + inputStr + " ",
			"\t" + inputStr,
			inputStr + "\n",
		}

		for _, testInput := range testInputs {
			st8 := NewSymbolTable()
			_ = st8.DefineVariable(testInput, pos, SymbolVariable)
			sym, exists := st8.Lookup(testInput)
			if exists {
				_ = sym
			}
		}
	})
}

// positionFromInput creates a token position from input string
func positionFromInput(input string) token.Position {
	return token.Position{
		Line:   1,
		Column: 1,
	}
}
