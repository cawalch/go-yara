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

	// In YARA, a{} parses as literal characters rather than being rejected
	if _, err := p.Parse("a{}"); err != nil {
		t.Fatalf("Parse(\"a{}\") unexpected error: %v", err)
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

// TestParseMalformedInputsRejected pins the end-of-input guards across the
// group-modifier, bound, class, POSIX-class and escape parsers. Every input
// must return an error rather than reading past the pattern buffer.
func TestParseMalformedInputsRejected(t *testing.T) {
	p := NewParser(ParserFlagEnableStrictEscapeSequences)
	patterns := []string{
		"(?",       // group modifier lookahead at end of input
		"[a\\",     // trailing backslash inside a class
		"[[",       // '[' at end (POSIX lookahead)
		"[[:alpha", // unterminated POSIX class (no ':]')
		"[[:",      // '[:' at end (negation lookahead)
		"[[:]",     // unterminated POSIX class
		"[a-",      // '-' at end (range lookahead)
		`[\x4`,     // truncated hex escape in a class
		"[a",       // unterminated class
		"[]",       // unterminated class
		`\x4`,      // incomplete top-level hex escape
		`\`,        // trailing backslash
		"(",        // missing ')'
		"(?:",      // missing ')'
		"(a",       // missing ')'
	}
	for _, pattern := range patterns {
		if _, err := p.Parse(pattern); err == nil {
			t.Fatalf("Parse(%q) error = nil, want error", pattern)
		}
	}
}

// TestParseUnclosedBoundsFallBackToLiterals pins the bound parser's
// end-of-input handling: an unclosed or invalid bound is treated as literal
// characters (YARA-compatible), not rejected, and must not read past the
// pattern.
func TestParseUnclosedBoundsFallBackToLiterals(t *testing.T) {
	p := NewParser(0)
	for _, pattern := range []string{"a{", "a{1", "a{1,", "a{9"} {
		if _, err := p.Parse(pattern); err != nil {
			t.Fatalf("Parse(%q) error = %v, want literal fallback", pattern, err)
		}
	}
}

// TestParseBoundDigitBoundaries pins the '0'/'9' digit comparisons and the
// inclusive clamp, so exact-digit bounds still form a NodeRange.
func TestParseBoundDigitBoundaries(t *testing.T) {
	p := NewParser(0)
	tests := []struct {
		pattern string
		min     uint16
		max     uint16
	}{
		{pattern: "a{0}", min: 0, max: 0},
		{pattern: "a{9}", min: 9, max: 9},
		{pattern: "a{99}", min: 99, max: 99},
		{pattern: "a{65535}", min: 65535, max: 65535},
		{pattern: "a{99999}", min: 65535, max: 65535},
		{pattern: "a{0,9}", min: 0, max: 9},
		{pattern: "a{9,9}", min: 9, max: 9},
	}
	for _, tt := range tests {
		ast, err := p.Parse(tt.pattern)
		if err != nil {
			t.Fatalf("Parse(%q) unexpected error: %v", tt.pattern, err)
		}
		n := ast.Root
		if n.Kind != NodeRange || n.Start != tt.min || n.End != tt.max {
			t.Fatalf("Parse(%q) = {Kind: %v, Start: %d, End: %d}, want {NodeRange, %d, %d}",
				tt.pattern, n.Kind, n.Start, n.End, tt.min, tt.max)
		}
	}
}

// TestParseClassLiteralEdges pins the leading ']'/'-' literal handling in a
// character class.
func TestParseClassLiteralEdges(t *testing.T) {
	p := NewParser(0)
	tests := []struct {
		pattern string
		present string
		absent  string
	}{
		{pattern: "[]]", present: "]", absent: "["},
		{pattern: "[-a]", present: "-a", absent: "b"},
		{pattern: "[a-]", present: "a-", absent: "b"},
		{pattern: `[a\-]`, present: "a-", absent: "b"},
	}
	for _, tt := range tests {
		ast, err := p.Parse(tt.pattern)
		if err != nil {
			t.Fatalf("Parse(%q) unexpected error: %v", tt.pattern, err)
		}
		n := ast.Root
		if n.Kind != NodeClass {
			t.Fatalf("Parse(%q) kind = %v, want NodeClass", tt.pattern, n.Kind)
		}
		for i := range len(tt.present) {
			if !bitSet(n.Class.Bitmap, tt.present[i]) {
				t.Fatalf("Parse(%q) missing %q", tt.pattern, tt.present[i])
			}
		}
		for i := range len(tt.absent) {
			if bitSet(n.Class.Bitmap, tt.absent[i]) {
				t.Fatalf("Parse(%q) unexpectedly contains %q", tt.pattern, tt.absent[i])
			}
		}
	}
}

// TestParsePOSIXClassVariants pins the POSIX class negation and terminator
// scan.
func TestParsePOSIXClassVariants(t *testing.T) {
	p := NewParser(0)

	negated, err := p.Parse("[[:^digit:]]")
	if err != nil {
		t.Fatalf("negated POSIX parse error: %v", err)
	}
	if !bitSet(negated.Root.Class.Bitmap, 'a') || bitSet(negated.Root.Class.Bitmap, '5') {
		t.Fatal("[[:^digit:]] must contain 'a' and exclude '5'")
	}

	combined, err := p.Parse("[[:alpha:][:digit:]]")
	if err != nil {
		t.Fatalf("combined POSIX parse error: %v", err)
	}
	if !bitSet(combined.Root.Class.Bitmap, 'A') || !bitSet(combined.Root.Class.Bitmap, '5') {
		t.Fatal("[[:alpha:][:digit:]] must contain 'A' and '5'")
	}

	space, err := p.Parse("[[:space:]]")
	if err != nil {
		t.Fatalf("space POSIX parse error: %v", err)
	}
	if !bitSet(space.Root.Class.Bitmap, ' ') || bitSet(space.Root.Class.Bitmap, 'a') {
		t.Fatal("[[:space:]] must contain ' ' and exclude 'a'")
	}
}

// TestParseHexEscapeErrorMessages pins the operand indices in the invalid-hex
// error strings so the reported characters stay aligned with the pattern.
func TestParseHexEscapeErrorMessages(t *testing.T) {
	p := NewParser(ParserFlagEnableStrictEscapeSequences)
	tests := []struct {
		pattern string
		want    string
	}{
		{pattern: `\xZ1`, want: `invalid hex escape \xZ1`},
		{pattern: `\x1Z`, want: `invalid hex escape \x1Z`},
	}
	for _, tt := range tests {
		_, err := p.Parse(tt.pattern)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("Parse(%q) error = %v, want containing %q", tt.pattern, err, tt.want)
		}
	}
}

// TestIsPrimaryStart pins the token set that continues a concatenation,
// including the tComma/tRBracket literal tokens.
func TestIsPrimaryStart(t *testing.T) {
	tests := []struct {
		kind tokenKind
		want bool
	}{
		{kind: tChar, want: true},
		{kind: tLParen, want: true},
		{kind: tLBracket, want: true},
		{kind: tComma, want: true},
		{kind: tRBracket, want: true},
		{kind: tLBrace, want: true},
		{kind: tRBrace, want: true},
		{kind: tDot, want: true},
		{kind: tCaret, want: true},
		{kind: tDollar, want: true},
		{kind: tWord, want: true},
		{kind: tNonWord, want: true},
		{kind: tSpace, want: true},
		{kind: tNonSpace, want: true},
		{kind: tDigit, want: true},
		{kind: tNonDigit, want: true},
		{kind: tWordBoundary, want: true},
		{kind: tNonWordBoundary, want: true},
		{kind: tEOF, want: false},
		{kind: tBar, want: false},
		{kind: tStar, want: false},
		{kind: tPlus, want: false},
		{kind: tQMark, want: false},
		{kind: tRParen, want: false},
	}
	for _, tt := range tests {
		if got := isPrimaryStart(tt.kind); got != tt.want {
			t.Fatalf("isPrimaryStart(%v) = %v, want %v", tt.kind, got, tt.want)
		}
	}
}

// TestParseMalformedInputsRejectedNonStrict reaches the lexer/class-level
// end-of-input guards that strict pre-validation would otherwise catch first.
func TestParseMalformedInputsRejectedNonStrict(t *testing.T) {
	p := NewParser(0)
	for _, pattern := range []string{"[a\\", "[\\", "[[:alpha:"} {
		if _, err := p.Parse(pattern); err == nil {
			t.Fatalf("Parse(%q) error = nil, want error", pattern)
		}
	}
}

// TestParseAllPOSIXClasses drives every applyPOSIXClass match function and
// checks representative members and boundary endpoints.
func TestParseAllPOSIXClasses(t *testing.T) {
	p := NewParser(0)
	tests := []struct {
		class string
		has   []byte
		not   []byte
	}{
		{class: "alnum", has: []byte{'a', 'Z', '0', '9'}, not: []byte{' ', '_', '!'}},
		{class: "alpha", has: []byte{'a', 'z', 'A', 'Z'}, not: []byte{'0', '5', ' '}},
		{class: "ascii", has: []byte{0x00, 0x7F, 'a'}, not: []byte{0x80, 0xFF}},
		{class: "blank", has: []byte{' ', '\t'}, not: []byte{'a', '\n'}},
		{class: "cntrl", has: []byte{0x00, 0x1F, 0x7F}, not: []byte{' ', 'a'}},
		{class: "digit", has: []byte{'0', '9'}, not: []byte{'a', '/'}},
		{class: "graph", has: []byte{0x21, 0x7E, 'a'}, not: []byte{' ', 0x7F}},
		{class: "lower", has: []byte{'a', 'z'}, not: []byte{'A', '0'}},
		{class: "print", has: []byte{0x20, 0x7E, 'a'}, not: []byte{0x1F, 0x7F}},
		{class: "punct", has: []byte{0x21, 0x2F, 0x3A, 0x40, 0x5B, 0x60, 0x7B, 0x7E}, not: []byte{'a', '0', ' '}},
		{class: "space", has: []byte{' ', '\t', '\n'}, not: []byte{'a'}},
		{class: "upper", has: []byte{'A', 'Z'}, not: []byte{'a', '0'}},
		{class: "word", has: []byte{'a', 'Z', '0', '_'}, not: []byte{' ', '!'}},
		{class: "xdigit", has: []byte{'0', '9', 'a', 'f', 'A', 'F'}, not: []byte{'g', 'G', 'z'}},
	}
	for _, tt := range tests {
		t.Run(tt.class, func(t *testing.T) {
			ast, err := p.Parse("[[:" + tt.class + ":]]")
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.class, err)
			}
			if ast.Root.Kind != NodeClass {
				t.Fatalf("Parse(%q) kind = %v, want NodeClass", tt.class, ast.Root.Kind)
			}
			for _, ch := range tt.has {
				if !bitSet(ast.Root.Class.Bitmap, ch) {
					t.Fatalf("[[:%s:]] missing %#x", tt.class, ch)
				}
			}
			for _, ch := range tt.not {
				if bitSet(ast.Root.Class.Bitmap, ch) {
					t.Fatalf("[[:%s:]] unexpectedly contains %#x", tt.class, ch)
				}
			}
		})
	}
}

// Mutation-test classification for regex/parser.go (gremlins v0.6.0,
// --workers 1):
//   - isPrimaryStart 208:21 and 242:16 (int(kind) < len(tokenToSimpleNode)):
//     equivalent-mode. tokenToSimpleNode has len(tNonWordBoundary+1) entries and
//     no tokenKind reaches that length, so the guard bound is unreachable.
//   - clampToUint16 338:9 and 340:16: equivalent-mode. readBoundNumber already
//     clamps to [0,65535] before calling clampToUint16, so both branches assign
//     the value they already hold.
//   - readEscaped 592:9 (l.i >= l.len): equivalent-mode. Both call sites
//     (parseClassContent, parseRange) guarantee l.i < l.len, so the guard is
//     unreachable defense-in-depth.
//   - readEscapeSequence 614:20/614:23: equivalent-mode. validateHexEscapes runs
//     first and rejects every incomplete \x, so the l.i+1 < l.len boundary is
//     never the deciding term.
//   - validateStrictEscapes 698:8/698:11: equivalent-mode (dead). validateHexEscapes
//     always runs first and already rejects incomplete \x escapes, so this hex
//     branch is unreachable.
//   - parseAlternative 73:17, parseRange 585:39, readEscapeSequence 612:5,
//     validateHexEscapes 667:4 and validateStrictEscapes 692:4: non-terminating
//     mutants (gremlins TIMED OUT) from inverting a loop counter.
