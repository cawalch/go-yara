package regex

import "testing"

func TestVM_WIDE_Literal_Anchored(t *testing.T) {
	code := mustCompile(t, "ab")

	// Anchored by default: exact match at start in WIDE (ASCII UTF-16LE pairs)
	if !Exec(code, []byte{'a', 0, 'b', 0}, FlagsWide) {
		t.Fatalf("expect WIDE anchored match for 'ab' in a\\x00b\\x00")
	}

	// Anchored mode should not scan in WIDE without FlagsScan
	if Exec(code, []byte{'x', 0, 'a', 0, 'b', 0}, FlagsWide) {
		t.Fatalf("anchored should not scan in WIDE")
	}
}

func TestVM_WIDE_Scan(t *testing.T) {
	code := mustCompile(t, "ab")
	data := []byte{'z', 0, 'a', 0, 'b', 0}

	if !Exec(code, data, FlagsWide|FlagsScan) {
		t.Fatalf("expect scan match in WIDE")
	}
}

func TestVM_WIDE_WordBoundaries(t *testing.T) {
	code := mustCompile(t, "\\bab\\b")

	// " a b " in WIDE (ASCII UTF-16LE) to ensure word boundaries around "ab"
	data := []byte{' ', 0, 'a', 0, 'b', 0, ' ', 0}
	if !Exec(code, data, FlagsWide|FlagsScan) {
		t.Fatalf("expect word boundary match in WIDE")
	}

	// "a b c" continuous word context should not match \bab\b
	data2 := []byte{'a', 0, 'b', 0, 'c', 0}
	if Exec(code, data2, FlagsWide|FlagsScan) {
		t.Fatalf("should not match inside word in WIDE")
	}
}

func TestVM_WIDE_DotAndDotAll(t *testing.T) {
	code := mustCompile(t, "a.b")

	// "a \\n b" in WIDE
	data := []byte{'a', 0, '\n', 0, 'b', 0}

	// Without DOT_ALL, dot should not match newline (even in WIDE)
	if Exec(code, data, FlagsWide) {
		t.Fatalf("dot should not match newline pair without DOT_ALL in WIDE")
	}

	// With DOT_ALL, dot should match newline pair in WIDE
	if !Exec(code, data, FlagsWide|FlagsDotAll) {
		t.Fatalf("dot should match newline pair with DOT_ALL in WIDE")
	}
}

// Additional WIDE-mode class and flag tests

func TestVM_WIDE_Classes_Word_Space_Digit(t *testing.T) {
	// \w+ should match letters, digits, underscore in WIDE
	codeWord := mustCompile(t, "\\w+")
	dataWord := []byte{'a', 0, '_', 0, '1', 0}
	if !Exec(codeWord, dataWord, FlagsWide) {
		t.Fatalf("\\w+ should match 'a_1' in WIDE anchored")
	}

	// \W should match non-word characters (e.g., space) in WIDE with scan
	codeNonWord := mustCompile(t, "\\W")
	dataNonWord := []byte{'a', 0, ' ', 0}
	if !Exec(codeNonWord, dataNonWord, FlagsWide|FlagsScan) {
		t.Fatalf("\\W should find space in WIDE with scan")
	}
	if Exec(codeNonWord, []byte{'a', 0}, FlagsWide) {
		t.Fatalf("\\W should not match word char in anchored WIDE")
	}

	// \s+ should match whitespace (space and newline) in WIDE
	codeSpace := mustCompile(t, "\\s+")
	dataSpace := []byte{' ', 0, '\n', 0}
	if !Exec(codeSpace, dataSpace, FlagsWide) {
		t.Fatalf("\\s+ should match space+newline in WIDE")
	}

	// \S+ should match non-whitespace in WIDE
	codeNonSpace := mustCompile(t, "\\S+")
	dataNonSpace := []byte{'a', 0, 'B', 0, '1', 0}
	if !Exec(codeNonSpace, dataNonSpace, FlagsWide) {
		t.Fatalf("\\S+ should match 'aB1' in WIDE")
	}

	// \d{2,} should match consecutive digits in WIDE
	codeDigit := mustCompile(t, "\\d{2,}")
	dataDigit := []byte{'1', 0, '2', 0, 'x', 0}
	if !Exec(codeDigit, dataDigit, FlagsWide) {
		t.Fatalf("\\d{2,} should match '12' prefix in WIDE")
	}

	// \D should match a non-digit in WIDE
	codeNonDigit := mustCompile(t, "\\D")
	if !Exec(codeNonDigit, []byte{'x', 0}, FlagsWide) {
		t.Fatalf("\\D should match non-digit 'x' in WIDE")
	}
	if Exec(codeNonDigit, []byte{'5', 0}, FlagsWide) {
		t.Fatalf("\\D should not match digit in WIDE")
	}
}

func TestVM_WIDE_Class_NoCase(t *testing.T) {
	// Class with NO_CASE in WIDE: [a] should match 'A' under NO_CASE
	code := mustCompile(t, "[a]")

	// Without NO_CASE should not match
	if Exec(code, []byte{'A', 0}, FlagsWide) {
		t.Fatalf("[a] should not match 'A' in WIDE without NO_CASE")
	}

	// With NO_CASE should match
	if !Exec(code, []byte{'A', 0}, FlagsWide|FlagsNoCase) {
		t.Fatalf("[a] should match 'A' in WIDE with NO_CASE")
	}
}

// WIDE audit: character classes inside explicit [...] with WIDE and NO_CASE folding
func TestVM_WIDE_Class_Range_NoCase(t *testing.T) {
	// [a-z] should match 'A' only with NO_CASE in WIDE
	code := mustCompile(t, "[a-z]")
	if Exec(code, []byte{'A', 0}, FlagsWide) {
		t.Fatalf("[a-z] should not match 'A' in WIDE without NO_CASE")
	}
	if !Exec(code, []byte{'A', 0}, FlagsWide|FlagsNoCase) {
		t.Fatalf("[a-z] should match 'A' in WIDE with NO_CASE")
	}
	// Symmetry: [A-Z] should match 'z' with NO_CASE
	code2 := mustCompile(t, "[A-Z]")
	if !Exec(code2, []byte{'z', 0}, FlagsWide|FlagsNoCase) {
		t.Fatalf("[A-Z] should match 'z' in WIDE with NO_CASE")
	}
}

func TestVM_WIDE_Class_Negated(t *testing.T) {
	code := mustCompile(t, "[^a]")
	if !Exec(code, []byte{'b', 0}, FlagsWide) {
		t.Fatalf("[^a] should match 'b' in WIDE")
	}
	if Exec(code, []byte{'a', 0}, FlagsWide) {
		t.Fatalf("[^a] should not match 'a' in WIDE")
	}
}

func TestVM_WIDE_ExplicitClass_DotLiteral(t *testing.T) {
	code := mustCompile(t, "[.]")
	if !Exec(code, []byte{'.', 0}, FlagsWide) {
		t.Fatalf("[.] should match '.' literally in WIDE")
	}
}