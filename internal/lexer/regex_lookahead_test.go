package lexer

import (
	"strings"
	"testing"

	"github.com/cawalch/go-yara/token"
)

func TestEmptyRegexLookaheadRestoresReader(t *testing.T) {
	for _, prefix := range []string{"", "first\r\nsecond\n  ", strings.Repeat("padding\n", 1024)} {
		for _, tc := range []struct {
			input string
			want  bool
		}{
			{"//", true}, {"//is)", true}, {"//is \t nocase\nnext", true},
			{"// \r\nnext", true}, {"// comment\nnext", false},
			{"//is \t unknown", false}, {"// \t )", false},
			{"/x/", false}, {"x", false},
		} {
			l, control := New(prefix+tc.input), New(prefix+tc.input)
			for range len(prefix) {
				l.reader.ReadChar()
				control.reader.ReadChar()
			}
			before := *l.reader
			for range 3 {
				if got := l.isEmptyRegex(); got != tc.want {
					t.Fatalf("prefix=%d input=%q: got %v, want %v", len(prefix), tc.input, got, tc.want)
				}
				if *l.reader != before {
					t.Fatalf("prefix=%d input=%q: lookahead changed reader state", len(prefix), tc.input)
				}
			}
			for {
				got, want := l.NextToken(), control.NextToken()
				if got != want {
					t.Fatalf("input=%q: token after lookahead = %+v, want %+v", tc.input, got, want)
				}
				if got.Type == token.EOF {
					break
				}
			}
		}
	}
}
