package regex

import "testing"

func TestFlagsValues(t *testing.T) {
	if FlagsFastRegexp != 0x02 || FlagsBackwards != 0x04 || FlagsExhaustive != 0x08 {
		t.Fatalf("flag low nibble mismatch: fast=0x%x back=0x%x ex=0x%x", FlagsFastRegexp, FlagsBackwards, FlagsExhaustive)
	}
	if FlagsWide != 0x10 || FlagsNoCase != 0x20 || FlagsScan != 0x40 || FlagsDotAll != 0x80 {
		t.Fatalf("flag high nibble mismatch: wide=0x%x nocase=0x%x scan=0x%x dotall=0x%x", FlagsWide, FlagsNoCase, FlagsScan, FlagsDotAll)
	}
	if FlagsGreedy != 0x400 || FlagsUngreedy != 0x800 {
		t.Fatalf("greedy flags mismatch: greedy=0x%x ungreedy=0x%x", FlagsGreedy, FlagsUngreedy)
	}
}

func TestParserStrictFlag(t *testing.T) {
	p := NewParser(ParserFlagEnableStrictEscapeSequences)
	if !p.strictEscape {
		t.Fatal("expected strictEscape to be true with flag set")
	}
	p2 := NewParser(0)
	if p2.strictEscape {
		t.Fatal("expected strictEscape to be false with flag unset")
	}
}
