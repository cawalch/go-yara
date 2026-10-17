package regex

import "testing"

// TestParseHexDigit pins every branch of the hex-digit decoder. The lowercase
// and uppercase arms have distinct arithmetic, so a table with lowercase 'a'/'f'
// is required to reach them.
func TestParseHexDigit(t *testing.T) {
	tests := []struct {
		c    byte
		want byte
		ok   bool
	}{
		{c: '0', want: 0, ok: true},
		{c: '9', want: 9, ok: true},
		{c: 'a', want: 10, ok: true},
		{c: 'f', want: 15, ok: true},
		{c: 'A', want: 10, ok: true},
		{c: 'F', want: 15, ok: true},
		{c: 'g', ok: false},
		{c: 'G', ok: false},
		{c: ':', ok: false},
		{c: '/', ok: false},
	}

	for _, tt := range tests {
		got, ok := parseHexDigit(tt.c)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Fatalf("parseHexDigit(%q) = (%d, %v), want (%d, %v)", tt.c, got, ok, tt.want, tt.ok)
		}
	}
}

// TestLexerEscapeBoundaries exercises the end-of-input guards in
// handleEscapeSequence: a trailing backslash, a complete \xNN escape, and a
// truncated \xN that must fall back to a literal 'x' without reading past the
// end of the pattern.
func TestLexerEscapeBoundaries(t *testing.T) {
	t.Run("trailing backslash", func(t *testing.T) {
		l := newLexer(`\`)
		tok := l.next()
		if tok.kind != tChar || tok.ch != '\\' {
			t.Fatalf("lexer(%q) = %+v, want tChar '\\\\'", `\`, tok)
		}
		if next := l.next(); next.kind != tEOF {
			t.Fatalf("lexer(%q) second token = %+v, want EOF", `\`, next)
		}
	})

	t.Run("complete hex escape", func(t *testing.T) {
		l := newLexer(`\x41`)
		tok := l.next()
		if tok.kind != tChar || tok.ch != 0x41 {
			t.Fatalf("lexer(%q) = %+v, want tChar 0x41", `\x41`, tok)
		}
	})

	t.Run("truncated hex escape", func(t *testing.T) {
		l := newLexer(`\x4`)
		tok := l.next()
		if tok.kind != tChar || tok.ch != 'x' {
			t.Fatalf("lexer(%q) = %+v, want tChar 'x'", `\x4`, tok)
		}
		if next := l.next(); next.kind != tChar || next.ch != '4' {
			t.Fatalf("lexer(%q) second token = %+v, want tChar '4'", `\x4`, next)
		}
	})
}

// Mutation-test classification for regex/lexer.go (gremlins v0.6.0,
// --workers 1):
//   - handleEscapeSequence 113:5 (l.i++ -> l.i--) is a non-terminating mutant
//     (gremlins TIMED OUT): the input index runs backwards forever. Not a test
//     gap and not a production defect.
//   - parseHexDigit 139:9/139:21, 141:9/141:21 and 143:9/143:21 are reported
//     NOT COVERED because Go coverage emits no block for switch case-condition
//     expressions, so gremlins never mutates them even though every branch is
//     exercised by TestParseHexDigit. Only the case bodies (142/144) have
//     coverage blocks.
