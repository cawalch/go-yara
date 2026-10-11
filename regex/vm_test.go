package regex

import "testing"

func mustCompile(t testing.TB, pat string) []byte {
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

func TestVM_FastForwardGreedyTerminalLoop(t *testing.T) {
	execMatchAtWithFlags := func(code, input []byte, start int, flags Flags) (bool, int, int) {
		bs, release := NewVMBatch(len(code))
		defer release()
		matched, sOff, eOff := ExecMatchBatch(bs, code, input, flags, start)
		return matched, start + sOff, start + eOff
	}
	execMatchAt := func(code, input []byte, start int) (bool, int, int) {
		return execMatchAtWithFlags(code, input, start, 0)
	}

	t.Run("ClassesAndNegatedClasses", func(t *testing.T) {
		tests := []struct {
			pattern string
			input   string
			wantEnd int
		}{
			{`[^\s]+`, "hello_world_12345 6789", 17},
			{`[^\s]+`, "https://example.com/test\nnext", 24},
			{`[a-z]+`, "abcdefghijklmnopqrstuvwxyz123", 26},
			{`[^0-9]+`, "abcdef-xyz#$!12345", 13},
			{`[0-9]+`, "1234567890abc", 10},
		}
		for _, tc := range tests {
			code := mustCompile(t, tc.pattern)
			ok, start, end := execMatchAt(code, []byte(tc.input), 0)
			if !ok || start != 0 || end != tc.wantEnd {
				t.Errorf("%q on %q: want [0,%d), got ok=%v [%d,%d)", tc.pattern, tc.input, tc.wantEnd, ok, start, end)
			}
		}
	})

	t.Run("CaseInsensitiveClasses", func(t *testing.T) {
		code := mustCompile(t, `[a-z]+`)
		input := "AbCdEfGhIjKlMnOpQrStUvWxYz123"
		ok, start, end := execMatchAtWithFlags(code, []byte(input), 0, FlagsNoCase)
		if !ok || start != 0 || end != 26 {
			t.Fatalf("want [0,26), got ok=%v [%d,%d)", ok, start, end)
		}
	})

	t.Run("OpAnyAndDotAll", func(t *testing.T) {
		code := mustCompile(t, `.+`)
		input := "line1\nline2"
		ok, start, end := execMatchAt(code, []byte(input), 0)
		if !ok || start != 0 || end != 5 {
			t.Fatalf("want [0,5) without dotAll, got ok=%v [%d,%d)", ok, start, end)
		}

		ok, start, end = execMatchAtWithFlags(code, []byte(input), 0, FlagsDotAll)
		if !ok || start != 0 || end != len(input) {
			t.Fatalf("want [0,%d) with dotAll, got ok=%v [%d,%d)", len(input), ok, start, end)
		}
	})

	t.Run("OpNotLiteralAndLiteral", func(t *testing.T) {
		codeNotLit := mustCompile(t, `[^x]+`)
		input := "abcde_12345xfoo"
		ok, start, end := execMatchAt(codeNotLit, []byte(input), 0)
		if !ok || start != 0 || end != 11 {
			t.Fatalf("want [0,11), got ok=%v [%d,%d)", ok, start, end)
		}

		codeLit := mustCompile(t, `a+`)
		inputA := "aaaaaaaabb"
		ok, start, end = execMatchAt(codeLit, []byte(inputA), 0)
		if !ok || start != 0 || end != 8 {
			t.Fatalf("want [0,8), got ok=%v [%d,%d)", ok, start, end)
		}
	})

	t.Run("CharacterClassShortcuts", func(t *testing.T) {
		tests := []struct {
			pattern string
			input   string
			wantEnd int
		}{
			{`\S+`, "non_space_chars remaining", 15},
			{`\s+`, "   \t\t\nnext", 6},
			{`\d+`, "9876543210abc", 10},
			{`\D+`, "abcdef_not_digit123", 16},
			{`\w+`, "word_123!@#", 8},
			{`\W+`, "!@#$%^&abc", 7},
		}
		for _, tc := range tests {
			code := mustCompile(t, tc.pattern)
			ok, start, end := execMatchAt(code, []byte(tc.input), 0)
			if !ok || start != 0 || end != tc.wantEnd {
				t.Errorf("%q on %q: want [0,%d), got ok=%v [%d,%d)", tc.pattern, tc.input, tc.wantEnd, ok, start, end)
			}
		}
	})

	t.Run("NonMatchingFirstByte", func(t *testing.T) {
		tests := []struct {
			pattern string
			input   string
		}{
			{`.+`, "\n"},
			{`.+`, ""},
			{`[^x]+`, "x"},
			{`[^x]+`, ""},
			{`a+`, "b"},
			{`a+`, ""},
			{`[0-9]+`, "abc"},
			{`\s+`, "abc"},
		}
		for _, tc := range tests {
			code := mustCompile(t, tc.pattern)
			ok, _, _ := execMatchAt(code, []byte(tc.input), 0)
			if ok {
				t.Errorf("%q on %q: expected no match, got match", tc.pattern, tc.input)
			}
		}
	})

	t.Run("LargeBufferFastForward", func(t *testing.T) {
		data := make([]byte, 200_000)
		for i := range data {
			data[i] = 'a'
		}
		data[150_000] = ' '
		code := mustCompile(t, `[^\s]+`)
		ok, start, end := execMatchAt(code, data, 0)
		if !ok || start != 0 || end != 150_000 {
			t.Fatalf("want [0,150000), got ok=%v [%d,%d)", ok, start, end)
		}
	})

	t.Run("NonTerminalLoopsDoNotOverrun", func(t *testing.T) {
		code := mustCompile(t, `[^\s]+end`)
		input := "prefix_end extra"
		ok, start, end := execMatchAt(code, []byte(input), 0)
		if !ok || start != 0 || end != 10 {
			t.Fatalf("want [0,10), got ok=%v [%d,%d)", ok, start, end)
		}
	})

	t.Run("CancellationStopsFastForward", func(t *testing.T) {
		data := make([]byte, 100_000)
		for i := range data {
			data[i] = 'a'
		}
		code := mustCompile(t, `[^\s]+`)
		done := make(chan struct{})
		close(done)
		bs, release := NewVMBatch(len(code))
		defer release()
		matched, _, _, _ := ExecMatchBatchWithCancel(bs, code, data, 0, 0, done)
		if matched {
			t.Fatal("expected match to stop due to cancellation")
		}
	})
}
