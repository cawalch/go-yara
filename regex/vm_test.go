package regex

import "testing"

func mustCompile(t *testing.T, pat string) []byte {
	t.Helper()
	p := NewParser(0)
	ast, err := p.Parse(pat)
	if err != nil {
		t.Fatalf("parse %q: %v", pat, err)
	}
	code, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile %q: %v", pat, err)
	}
	return code
}

func TestVM_LiteralAndAny(t *testing.T) {
	code := mustCompile(t, "a.")
	if !Exec(code, []byte("zaX"), FlagsScan) {
		t.Fatalf("expected match in 'zaX'")
	}
	if Exec(code, []byte("za\n"), FlagsScan) {
		t.Fatalf("dot should not match newline by default")
	}
}

func TestVM_AltAndConcat(t *testing.T) {
	code := mustCompile(t, "(ab|cd)e")
	if !Exec(code, []byte("xxcdeyy"), FlagsScan) {
		t.Fatalf("expect match for cde")
	}
	if !Exec(code, []byte("abe"), FlagsScan) {
		t.Fatalf("expect match for abe")
	}
	if Exec(code, []byte("abx"), FlagsScan) {
		t.Fatalf("unexpected match")
	}
}

func TestVM_Quantifiers(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"ab*c", "ac", true},
		{"ab*c", "abc", true},
		{"ab*c", "abbbc", true},
		{"ab+c", "ac", false},
		{"ab{2,3}c", "abbc", true},
		{"ab{2,3}c", "abbbc", true},
		{"ab{2,3}c", "abbbbc", false},
		{"ab{2,}c", "abbbbbc", true},
	}
	for _, c := range cases {
		code := mustCompile(t, c.pat)
		got := Exec(code, []byte(c.s), 0)
		if got != c.want {
			t.Fatalf("%q on %q: got %v want %v", c.pat, c.s, got, c.want)
		}
	}
}

func TestExecMatchBatchRepeatedStartsMatchesFreshState(t *testing.T) {
	code := mustCompile(t, "[a-z]{1,2}aba")
	data := []byte("zaba zzaba")
	batch, release := NewVMBatch(len(code))
	defer release()

	for start := 0; start <= len(data); start++ {
		gotMatch, gotStart, gotEnd := ExecMatchBatch(batch, code, data, 0, start)
		fresh, freshRelease := NewVMBatch(len(code))
		wantMatch, wantStart, wantEnd := ExecMatchBatch(fresh, code, data, 0, start)
		freshRelease()
		if gotMatch != wantMatch || gotStart != wantStart || gotEnd != wantEnd {
			t.Fatalf(
				"start %d: repeated batch = (%v,%d,%d), fresh state = (%v,%d,%d)",
				start,
				gotMatch,
				gotStart,
				gotEnd,
				wantMatch,
				wantStart,
				wantEnd,
			)
		}
	}
}

func TestVM_AnchorsAndClass(t *testing.T) {
	code := mustCompile(t, "^[a-c]$")
	if !Exec(code, []byte("b"), 0) {
		t.Fatalf("expect match for 'b'")
	}
	if Exec(code, []byte("ab"), 0) {
		t.Fatalf("should not match multi-char when anchored")
	}
	if Exec(code, []byte("db"), 0) {
		t.Fatalf("should not match when start anchor fails")
	}
}

func TestVM_WordBoundaries(t *testing.T) {
	code := mustCompile(t, "\\bcat\\b")
	if !Exec(code, []byte("a cat!"), FlagsScan) {
		t.Fatalf("expect match at word boundaries")
	}
	if Exec(code, []byte("concatenate"), FlagsScan) {
		t.Fatalf("should not match inside word")
	}
}

func TestVM_AnchoredVsScan(t *testing.T) {
	code := mustCompile(t, "abc")
	if Exec(code, []byte("zabc"), 0) {
		t.Fatalf("anchored mode should not scan")
	}
	if !Exec(code, []byte("zabc"), FlagsScan) {
		t.Fatalf("scan mode should find match")
	}
}

func TestVM_ExecMatch_Positions(t *testing.T) {
	code := mustCompile(t, "a+")
	ok, start, end := ExecMatch(code, []byte("zaaaX"), FlagsScan)
	if !ok || start != 1 || end != 4 {
		t.Fatalf("want match at [1,4), got ok=%v start=%d end=%d", ok, start, end)
	}
}

func TestVM_EmptyMatch_Anchored(t *testing.T) {
	code := mustCompile(t, "a*")
	if !Exec(code, []byte(""), 0) {
		t.Fatalf("expect empty to match a* in anchored mode")
	}
	ok, start, end := ExecMatch(code, []byte(""), 0)
	if !ok || start != 0 || end != 0 {
		t.Fatalf("want empty match at [0,0), got ok=%v start=%d end=%d", ok, start, end)
	}
}

func TestVM_LeftmostLongest_Alternation(t *testing.T) {
	cases := []struct {
		pat        string
		s          string
		start, end int
	}{
		{"a|ab", "ab", 0, 2},
		{"ab|a", "ab", 0, 2},
		{"aa|a", "aab", 0, 2},  // prefer longer 'AA' at same start
		{"a|aa", "zaab", 1, 3}, // leftmost start 1, longest end 3
	}
	for _, c := range cases {
		code := mustCompile(t, c.pat)
		ok, start, end := ExecMatch(code, []byte(c.s), FlagsScan)
		if !ok || start != c.start || end != c.end {
			t.Fatalf("%q on %q: want [%d,%d), got ok=%v [%d,%d)", c.pat, c.s, c.start, c.end, ok, start, end)
		}
	}
}

func TestVM_NestedRepeats_LeftmostLongest(t *testing.T) {
	code := mustCompile(t, "(ab*)*")
	s := []byte("abbbab")
	if !Exec(code, s, 0) {
		t.Fatalf("expect match for nested repeats")
	}
	ok, start, end := ExecMatch(code, s, 0)
	if !ok || start != 0 || end != len(s) {
		t.Fatalf("want longest prefix match [0,%d), got ok=%v [%d,%d)", len(s), ok, start, end)
	}
}

// Edge cases: empty matches under scan mode
func TestVM_EmptyMatch_Scan(t *testing.T) {
	code := mustCompile(t, "a*")
	// In scan mode, empty should match at start position 0
	if !Exec(code, []byte("x"), FlagsScan) {
		t.Fatalf("expect scan to report a match for a* on any input")
	}
	ok, start, end := ExecMatch(code, []byte("x"), FlagsScan)
	if !ok || start != 0 || end != 0 {
		t.Fatalf("want empty match at [0,0) under scan, got ok=%v [%d,%d)", ok, start, end)
	}
}

// Nested repeats with alternation: ensure leftmost-longest across repeating groups
func TestVM_NestedRepeats_WithAlternation_Scan(t *testing.T) {
	cases := []struct {
		pat        string
		s          string
		start, end int
	}{
		{"(a|ab)*", "ababa", 0, 5}, // consume 'ab' 'ab' 'a' => longest at start 0 is entire string
		{"(ab|a)*", "ababa", 0, 5}, // equivalent ordering should yield same longest match
		{"(a|ab)*b", "aab", 0, 3},  // ensure trailing literal enforces full consumption
	}
	for _, c := range cases {
		code := mustCompile(t, c.pat)
		ok, start, end := ExecMatch(code, []byte(c.s), FlagsScan)
		if !ok || start != c.start || end != c.end {
			t.Fatalf("%q on %q: want [%d,%d), got ok=%v [%d,%d)", c.pat, c.s, c.start, c.end, ok, start, end)
		}
	}
}

// Leftmost-longest interactions across grouped alternations
func TestVM_LeftmostLongest_GroupsAlternation(t *testing.T) {
	code := mustCompile(t, "(ab|a)b")
	ok, start, end := ExecMatch(code, []byte("zab"), FlagsScan)
	if !ok || start != 1 || end != 3 {
		t.Fatalf("want match at [1,3), got ok=%v [%d,%d)", ok, start, end)
	}
}
