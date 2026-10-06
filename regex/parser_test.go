package regex

import (
	"strings"
	"testing"
)

func TestParseLiteralsAndDot(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("a.c")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if ast.Root.Kind != NodeConcat || len(ast.Root.Children) != 3 {
		t.Fatalf("want concat of 3, got %v/%d", ast.Root.Kind, len(ast.Root.Children))
	}
	if ast.Root.Children[0].Kind != NodeLiteral || ast.Root.Children[1].Kind != NodeAny || ast.Root.Children[2].Kind != NodeLiteral {
		t.Fatalf("unexpected node kinds")
	}
}

func TestParseGroupingAndAlt(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("(ab|cd)e")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if ast.Root.Kind != NodeConcat || len(ast.Root.Children) != 2 {
		t.Fatalf("want concat of 2, got %d", len(ast.Root.Children))
	}
	alt := ast.Root.Children[0]
	if alt.Kind != NodeGroup || alt.Group != 1 || len(alt.Children) != 1 {
		t.Fatalf("want numbered group, got kind=%v group=%d", alt.Kind, alt.Group)
	}
	alt = alt.Children[0]
	if alt.Kind != NodeAlt || len(alt.Children) != 2 {
		t.Fatalf("want alt with 2 branches")
	}
	if alt.Children[0].Kind != NodeConcat || alt.Children[1].Kind != NodeConcat {
		t.Fatalf("alt branches should be concats")
	}
}

func TestParseAnchors(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("^abc$")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if ast.Root.Kind != NodeConcat || len(ast.Root.Children) < 3 {
		t.Fatalf("want concat with anchors and body")
	}
	last := len(ast.Root.Children) - 1
	if ast.Root.Children[0].Kind != NodeAnchorStart || ast.Root.Children[last].Kind != NodeAnchorEnd {
		t.Fatalf("missing anchors at ends")
	}
}

func bitSet(b [32]byte, ch byte) bool {
	idx := ch / 8
	bit := ch % 8
	return (b[idx] & (1 << bit)) != 0
}

func TestParseClassSimple(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("[a-c]")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodeClass || n.Class == nil || n.Class.Negated {
		t.Fatalf("expected non-negated class")
	}
	for _, ch := range []byte{'a', 'b', 'c'} {
		if !bitSet(n.Class.Bitmap, ch) {
			t.Fatalf("missing %q in class", ch)
		}
	}
}

func TestParseClassNegatedDigits(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("[^0-9]")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodeClass || n.Class == nil || !n.Class.Negated {
		t.Fatalf("expected negated class")
	}
	for _, ch := range []byte{'0', '5', '9'} {
		if !bitSet(n.Class.Bitmap, ch) {
			t.Fatalf("missing %q in class bits", ch)
		}
	}
}

func TestParseQuantifiersBasic(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("a*")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodeStar || len(n.Children) != 1 || n.Children[0].Kind != NodeLiteral || n.Children[0].Value != 'a' {
		t.Fatalf("expected NodeStar over 'a'")
	}
}

func TestParseQuantifiersUngreedyPlus(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("b+?")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodePlus || n.Greedy {
		t.Fatalf("expected ungreedy plus")
	}
}

func TestParseQuantifiersRange(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("c{2,4}")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodeRange || n.Start != 2 || n.End != 4 {
		t.Fatalf("expected {2,4}")
	}
}

func TestParseQuantifiersExactAndUnbounded(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("d{3}")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if ast.Root.Kind != NodeRange || ast.Root.Start != 3 || ast.Root.End != 3 {
		t.Fatalf("expected {3}")
	}
	ast, err = p.Parse("e{2,}?")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if ast.Root.Kind != NodeRange || ast.Root.Start != 2 || ast.Root.End != 65535 || ast.Root.Greedy {
		t.Fatalf("expected {2,}? ungreedy with max=65535")
	}
}

func TestParseOptionalUngreedy(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("f??")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodeRange || n.Start != 0 || n.End != 1 || n.Greedy {
		t.Fatalf("expected optional ungreedy")
	}
}

func TestParsePredefinedClasses(t *testing.T) {
	p := NewParser(0)
	cases := []struct {
		pat  string
		kind NodeKind
	}{
		{"\\w", NodeWordChar},
		{"\\W", NodeNonWordChar},
		{"\\s", NodeSpace},
		{"\\S", NodeNonSpace},
		{"\\d", NodeDigit},
		{"\\D", NodeNonDigit},
	}
	for _, c := range cases {
		ast, err := p.Parse(c.pat)
		if err != nil {
			t.Fatalf("parse %q: %v", c.pat, err)
		}
		if ast.Root.Kind != c.kind {
			t.Fatalf("%q kind=%v want=%v", c.pat, ast.Root.Kind, c.kind)
		}
	}
}

func TestParseWordBoundaries(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("\\b\\B")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodeConcat || len(n.Children) != 2 {
		t.Fatalf("expected concat of 2")
	}
	if n.Children[0].Kind != NodeWordBoundary || n.Children[1].Kind != NodeNonWordBoundary {
		t.Fatalf("expected \\b then \\B")
	}
}

func TestParseHexEscapes(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("\\x41\\x42")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodeConcat || len(n.Children) != 2 {
		t.Fatalf("expected concat of 2")
	}
	if n.Children[0].Value != 0x41 || n.Children[1].Value != 0x42 {
		t.Fatalf("expected 0x41 and 0x42, got %x %x", n.Children[0].Value, n.Children[1].Value)
	}
}

func TestParseStrictEscapeSequences(t *testing.T) {
	p := NewParser(ParserFlagEnableStrictEscapeSequences)

	validPatterns := []string{
		`https?:\/\/[a-zA-Z0-9\.]+\/`,
		`\n\t\x41\w\.`,
	}
	for _, pattern := range validPatterns {
		if _, err := p.Parse(pattern); err != nil {
			t.Fatalf("Parse(%q) unexpected error: %v", pattern, err)
		}
	}

	invalidPatterns := []string{
		`test\p`,
		`test\x4`,
		`test\x4g`,
		`test\`,
	}
	for _, pattern := range invalidPatterns {
		if _, err := p.Parse(pattern); err == nil {
			t.Fatalf("Parse(%q) expected strict escape error", pattern)
		}
	}
}

func TestParseUnknownEscapeNonStrict(t *testing.T) {
	p := NewParser(0)
	if _, err := p.Parse(`test\p`); err != nil {
		t.Fatalf("Parse() in non-strict mode error = %v, want nil", err)
	}
}

func TestParseShorthandInClass(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("[\\w\\s]")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodeClass {
		t.Fatalf("expected NodeClass")
	}
	// just check a few expected chars
	if !bitSet(n.Class.Bitmap, 'a') || !bitSet(n.Class.Bitmap, ' ') {
		t.Fatalf("missing expected chars in shorthand class")
	}
}

func TestParsePOSIXClass(t *testing.T) {
	p := NewParser(0)
	ast, err := p.Parse("[[:alnum:]]")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodeClass {
		t.Fatalf("expected NodeClass")
	}
	if !bitSet(n.Class.Bitmap, 'A') || !bitSet(n.Class.Bitmap, '9') || bitSet(n.Class.Bitmap, ' ') {
		t.Fatalf("incorrect bits set for [:alnum:]")
	}
}

func TestParseReversedRangeRejected(t *testing.T) {
	p := NewParser(0)
	cases := []string{
		"[z-a]",
		"[9-0]",
		`[\xff-\x00]`,
		"[^z-a]",
		"[a-d9-0]",
	}
	for _, pattern := range cases {
		_, err := p.Parse(pattern)
		if err == nil {
			t.Fatalf("Parse(%q) expected error, got nil", pattern)
		}
		if !strings.Contains(err.Error(), "bad character range") {
			t.Fatalf("Parse(%q) error = %v, want 'bad character range'", pattern, err)
		}
	}
}

func TestParseInvertedBoundsRejected(t *testing.T) {
	p := NewParser(0)
	cases := []string{
		"a{3,2}",
		"a{10,2}",
		"a{1,0}",
	}
	for _, pattern := range cases {
		_, err := p.Parse(pattern)
		if err == nil {
			t.Fatalf("Parse(%q) expected error, got nil", pattern)
		}
		if !strings.Contains(err.Error(), "bad repeat interval") {
			t.Fatalf("Parse(%q) error = %v, want 'bad repeat interval'", pattern, err)
		}
	}
}

func TestParseStackedQuantifiersRejected(t *testing.T) {
	p := NewParser(0)
	cases := []string{
		"x**",
		"x*+",
		"x+*",
		"x++",
		"x???",
		"x?*",
		"x?+",
		"x{2}*",
		"x*{2}",
		"x{2}{3}",
		"x{2}?{3}",
		"x*?*",
		"(x**)",
		"[a-z]**",
		".**",
	}
	for _, pattern := range cases {
		_, err := p.Parse(pattern)
		if err == nil {
			t.Fatalf("Parse(%q) expected error, got nil", pattern)
		}
		if !strings.Contains(err.Error(), "syntax error") {
			t.Fatalf("Parse(%q) error = %v, want 'syntax error'", pattern, err)
		}
	}
}

func TestParseValidQuantifiersAccepted(t *testing.T) {
	p := NewParser(0)
	valid := []string{
		"x*",
		"x+",
		"x?",
		"x*?",
		"x+?",
		"x??",
		"x{2,3}?",
		"x{3}",
		"x{3,}",
		"(x*)*",
		"(x+)+",
		"x*y",
		"x?y",
		"x??y",
		"[a-z]*",
		"[a-z]+?",
		"[a-a]",
	}
	for _, pattern := range valid {
		if _, err := p.Parse(pattern); err != nil {
			t.Fatalf("Parse(%q) unexpected error: %v", pattern, err)
		}
	}
}

func TestParseOmittedLowerBound(t *testing.T) {
	p := NewParser(0)

	// {,3} should parse as NodeRange with Start=0, End=3
	ast, err := p.Parse("a{,3}")
	if err != nil {
		t.Fatalf("Parse(\"a{,3}\") unexpected error: %v", err)
	}
	n := ast.Root
	if n.Kind != NodeRange || n.Start != 0 || n.End != 3 || !n.Greedy {
		t.Fatalf("Parse(\"a{,3}\") = {Kind: %v, Start: %d, End: %d, Greedy: %v}, want {NodeRange, 0, 3, true}",
			n.Kind, n.Start, n.End, n.Greedy)
	}

	// a{,3}? ungreedy
	ast, err = p.Parse("a{,3}?")
	if err != nil {
		t.Fatalf("Parse(\"a{,3}?\") unexpected error: %v", err)
	}
	n = ast.Root
	if n.Kind != NodeRange || n.Start != 0 || n.End != 3 || n.Greedy {
		t.Fatalf("Parse(\"a{,3}?\") want ungreedy range {0, 3, false}")
	}

	// a{,0} should parse as NodeRange with Start=0, End=0
	ast, err = p.Parse("a{,0}")
	if err != nil {
		t.Fatalf("Parse(\"a{,0}\") unexpected error: %v", err)
	}
	n = ast.Root
	if n.Kind != NodeRange || n.Start != 0 || n.End != 0 {
		t.Fatalf("Parse(\"a{,0}\") want range {0, 0}")
	}

	// a{,} should parse as NodeRange with Start=0, End=65535 (unbounded)
	ast, err = p.Parse("a{,}")
	if err != nil {
		t.Fatalf("Parse(\"a{,}\") unexpected error: %v", err)
	}
	n = ast.Root
	if n.Kind != NodeRange || n.Start != 0 || n.End != 65535 {
		t.Fatalf("Parse(\"a{,}\") want range {0, 65535}")
	}

	// Empty braces a{} should be rejected
	if _, err := p.Parse("a{}"); err == nil {
		t.Fatalf("Parse(\"a{}\") expected error, got nil")
	}
}

func TestParseBoundWithWhitespace(t *testing.T) {
	p := NewParser(0)
	tests := []struct {
		pattern  string
		wantMin  uint16
		wantMax  uint16
		ungreedy bool
	}{
		{"a{ 3, 8 }", 3, 8, false},
		{"a{3, 8}", 3, 8, false},
		{"a{3 ,8}", 3, 8, false},
		{"a{3 , 8}", 3, 8, false},
		{"a{ , 5 }", 0, 5, false},
		{"a{, 5}", 0, 5, false},
		{"a{7, }", 7, 65535, false},
		{"a{ 7 , }", 7, 65535, false},
		{"a{ , }", 0, 65535, false},
		{"a{ 5 }", 5, 5, false},
		{"a{ 3, 8 }?", 3, 8, true},
		{"a{ , 3 }?", 0, 3, true},
	}

	for _, tt := range tests {
		ast, err := p.Parse(tt.pattern)
		if err != nil {
			t.Fatalf("Parse(%q) unexpected error: %v", tt.pattern, err)
		}
		n := ast.Root
		if n.Kind != NodeRange || n.Start != tt.wantMin || n.End != tt.wantMax || n.Greedy != !tt.ungreedy {
			t.Fatalf("Parse(%q) = {Start: %d, End: %d, Greedy: %v}, want {Start: %d, End: %d, Greedy: %v}",
				tt.pattern, n.Start, n.End, n.Greedy, tt.wantMin, tt.wantMax, !tt.ungreedy)
		}
	}
}
