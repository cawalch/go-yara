package compiler

import "testing"

func TestFullwordTextModifier(t *testing.T) {
	source := `
rule FullwordText {
	strings:
		$a = "test" fullword
	condition:
		$a
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "exact", data: []byte("test"), want: true},
		{name: "suffix", data: []byte("testing"), want: false},
		{name: "bounded", data: []byte("a test!"), want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := evaluateRule(program.Rules[0], program, tc.data)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("matched=%v, want %v", ok, tc.want)
			}
		})
	}
}

func TestFullwordWideModifier(t *testing.T) {
	source := `
rule FullwordWide {
	strings:
		$a = "test" wide fullword
	condition:
		$a
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	match := []byte{0x00, 0x00, 't', 0x00, 'e', 0x00, 's', 0x00, 't', 0x00, 0x00, 0x00}
	noMatch := []byte{'A', 0x00, 't', 0x00, 'e', 0x00, 's', 0x00, 't', 0x00}

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "wide_match", data: match, want: true},
		{name: "wide_no_match", data: noMatch, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := evaluateRule(program.Rules[0], program, tc.data)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("matched=%v, want %v", ok, tc.want)
			}
		})
	}
}

func TestXorRangeModifier(t *testing.T) {
	source := `
rule XorRange {
	strings:
		$a = "hi" xor(1-2)
	condition:
		$a
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	data := []byte{('h' ^ 0x02), ('i' ^ 0x02)}
	ok, err := evaluateRule(program.Rules[0], program, data)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !ok {
		t.Fatalf("expected rule to match")
	}
}

func TestBase64Modifiers(t *testing.T) {
	source := `
rule Base64Mods {
	strings:
		$a = "Hi" base64
		$b = "Hi" base64wide
	condition:
		$a and $b
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	sc := NewStringCompiler(nil)
	baseVariants, err := sc.base64AlignedPatterns([]byte("Hi"), "", false)
	if err != nil || len(baseVariants) == 0 {
		t.Fatalf("base64 variants: %v", err)
	}
	wideVariants, err := sc.base64AlignedPatterns([]byte("Hi"), "", true)
	if err != nil || len(wideVariants) == 0 {
		t.Fatalf("base64wide variants: %v", err)
	}

	data := append(append([]byte{}, baseVariants[0]...), ' ')
	data = append(data, wideVariants[0]...)
	ok, err := evaluateRule(program.Rules[0], program, data)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !ok {
		t.Fatalf("expected rule to match")
	}
}

func TestHexXorModifier(t *testing.T) {
	source := `
rule HexXor {
	strings:
		$h = { 41 42 } xor(0x01)
	condition:
		$h
}`

	compiler := NewCompiler()
	program, err := compiler.CompileSource(source)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	data := []byte{0x40, 0x43}
	ok, err := evaluateRule(program.Rules[0], program, data)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !ok {
		t.Fatalf("expected rule to match")
	}
}
