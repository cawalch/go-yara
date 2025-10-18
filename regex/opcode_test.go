package regex

import "testing"

func TestOpcodeValues(t *testing.T) {
	// Spot-check a subset to guard against accidental edits.
	cases := []struct{ name string; got, want int }{
		{"OpAny", int(OpAny), 0xA0},
		{"OpLiteral", int(OpLiteral), 0xA2},
		{"OpClass", int(OpClass), 0xA5},
		{"OpMatch", int(OpMatch), 0xAD},
		{"OpSplitA", int(OpSplitA), 0xC0},
		{"OpRepeatEndUngreedy", int(OpRepeatEndUngreedy), 0xC6},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = 0x%x, want 0x%x", c.name, c.got, c.want)
		}
	}
}

