package compiler

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"slices"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestIssue688ACMixedNocaseFailureLinks(t *testing.T) {
	t.Run("rule_repro_xb_nocase_and_B", func(t *testing.T) {
		sources := []string{
			`
rule R1 { strings: $a = "xb" nocase condition: $a }
rule R2 { strings: $b = "B" condition: $b }
`,
			`
rule R2 { strings: $b = "B" condition: $b }
rule R1 { strings: $a = "xb" nocase condition: $a }
`,
		}
		for idx, source := range sources {
			prog, err := NewCompiler().CompileSource(source)
			if err != nil {
				t.Fatalf("source[%d] compile: %v", idx, err)
			}
			res, err := prog.Scan([]byte("xB"))
			if err != nil {
				t.Fatalf("source[%d] scan: %v", idx, err)
			}
			if !res.RuleResults["R1"] || !res.RuleResults["R2"] {
				t.Fatalf("source[%d] on %q: got %v, want R1=true and R2=true", idx, "xB", res.RuleResults)
			}

			resLower, err := prog.Scan([]byte("xb"))
			if err != nil {
				t.Fatalf("source[%d] scan lower: %v", idx, err)
			}
			if !resLower.RuleResults["R1"] || resLower.RuleResults["R2"] {
				t.Fatalf("source[%d] on %q: got %v, want R1=true and R2=false", idx, "xb", resLower.RuleResults)
			}
		}
	})

	t.Run("multilevel_split_and_reconvergence", func(t *testing.T) {
		source := `
rule NocaseLong { strings: $a = "xbcdef" nocase condition: $a }
rule CasePrefix { strings: $b = "Bc" condition: $b }
rule DeepCS { strings: $c = "XB" condition: $c }
rule NocaseWrap { strings: $d = "axcdef" nocase condition: $d }
`
		prog, err := NewCompiler().CompileSource(source)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		for _, tc := range []struct {
			input string
			want  map[string]bool
		}{
			{"xBcdef", map[string]bool{"NocaseLong": true, "CasePrefix": true, "DeepCS": false, "NocaseWrap": false}},
			{"xBCdef", map[string]bool{"NocaseLong": true, "CasePrefix": false, "DeepCS": false, "NocaseWrap": false}},
			{"AXCDEF", map[string]bool{"NocaseLong": false, "CasePrefix": false, "DeepCS": false, "NocaseWrap": true}},
			{"aXCdef", map[string]bool{"NocaseLong": false, "CasePrefix": false, "DeepCS": false, "NocaseWrap": true}},
			{"aXCdeZ", map[string]bool{"NocaseLong": false, "CasePrefix": false, "DeepCS": false, "NocaseWrap": false}},
			{"aXB", map[string]bool{"NocaseLong": false, "CasePrefix": false, "DeepCS": true, "NocaseWrap": false}},
		} {
			res, err := prog.Scan([]byte(tc.input))
			if err != nil {
				t.Fatalf("scan(%q): %v", tc.input, err)
			}
			for rule, want := range tc.want {
				if res.RuleResults[rule] != want {
					t.Fatalf("input %q rule %s = %v, want %v", tc.input, rule, res.RuleResults[rule], want)
				}
			}
			// Round-trip via MarshalBinary + streaming ScanReader.
			blob, err := prog.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			rt, err := UnmarshalCompiledProgram(blob)
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			scanner := NewScanner(rt, WithStreamChunkSize(3))
			streamRes, err := scanner.ScanReaderWithContext(context.Background(), bytes.NewReader([]byte(tc.input)))
			scanner.Close()
			if err != nil {
				t.Fatalf("stream scan(%q): %v", tc.input, err)
			}
			for rule, want := range tc.want {
				if streamRes.RuleResults[rule] != want {
					t.Fatalf("stream input %q rule %s = %v, want %v", tc.input, rule, streamRes.RuleResults[rule], want)
				}
			}
		}
	})

	t.Run("all_ac_table_builders", func(t *testing.T) {
		addMixed := func(t *testing.T, ac *acAutomaton, padStates int) {
			t.Helper()
			if padStates > 0 {
				pad := bytes.Repeat([]byte{0x01}, padStates)
				if err := ac.AddString("$pad", pad, false, false); err != nil {
					t.Fatal(err)
				}
			}
			if err := ac.AddStringWithFlags("$nc", []byte("xbc"), false, false, regex.FlagsNoCase); err != nil {
				t.Fatal(err)
			}
			if err := ac.AddStringWithFlags("$cs", []byte("Bc"), false, false, 0); err != nil {
				t.Fatal(err)
			}
		}
		assertMatches := func(t *testing.T, ac *acAutomaton) {
			t.Helper()
			for _, tc := range []struct {
				input string
				want  []string
			}{
				{"xBc", []string{"$nc", "$cs"}},
				{"xBC", []string{"$nc"}},
				{"xbc", []string{"$nc"}},
			} {
				var got []string
				for m := range ac.SearchIter([]byte(tc.input)) {
					got = append(got, m.StringID)
				}
				slices.Sort(got)
				slices.Sort(tc.want)
				if !slices.Equal(got, tc.want) {
					t.Fatalf("input %q: got %v, want %v", tc.input, got, tc.want)
				}
			}
		}

		// 1. Sparse flat 16-bit table.
		flat16 := newacAutomaton()
		addMixed(t, flat16, 0)
		if err := flat16.Compile(); err != nil {
			t.Fatal(err)
		}
		if len(flat16.transitions16) == 0 {
			t.Fatal("expected transitions16")
		}
		assertMatches(t, flat16)

		// 2. Sparse class 16-bit table (> 16384 states, <= 128 byte classes).
		class16 := newacAutomaton()
		addMixed(t, class16, 17000)
		if err := class16.Compile(); err != nil {
			t.Fatal(err)
		}
		if len(class16.flatClass16) == 0 {
			t.Fatal("expected flatClass16")
		}
		assertMatches(t, class16)

		// 3. Sparse class 32-bit table (> 65536 states, <= 128 byte classes), plus 16->32 overflow via cloning.
		class32 := newacAutomaton()
		addMixed(t, class32, 65530)
		if len(class32.trieStates) > 65536 {
			t.Fatalf("expected pre-compile states <= 65536 to exercise overflow, got %d", len(class32.trieStates))
		}
		if err := class32.Compile(); err != nil {
			t.Fatal(err)
		}
		if len(class32.flatClass32) == 0 || len(class32.flatClass16) != 0 {
			t.Fatalf("expected flatClass32 upgrade on clone overflow (flatClass32=%d flatClass16=%d)", len(class32.flatClass32), len(class32.flatClass16))
		}
		if class32.GetStateCount() <= 65536 {
			t.Fatalf("expected GetStateCount > 65536 after cloning, got %d", class32.GetStateCount())
		}
		assertMatches(t, class32)

		// 4. Sparse flat 32-bit table (16->32 overflow when > 128 classes).
		flat32 := newacAutomaton()
		// Add 130 distinct byte classes so numClasses > 128 forces flat table.
		var classData [130]byte
		for i := range classData {
			classData[i] = byte(120 + i)
		}
		if err := flat32.AddString("$classes", classData[:], false, false); err != nil {
			t.Fatal(err)
		}
		addMixed(t, flat32, 65400)
		if len(flat32.trieStates) > 65536 {
			t.Fatalf("expected pre-compile states <= 65536 to exercise flat overflow, got %d", len(flat32.trieStates))
		}
		if err := flat32.Compile(); err != nil {
			t.Fatal(err)
		}
		if len(flat32.transitions32) == 0 || len(flat32.transitions16) != 0 {
			t.Fatalf("expected transitions32 upgrade on clone overflow (t32=%d t16=%d)", len(flat32.transitions32), len(flat32.transitions16))
		}
		assertMatches(t, flat32)

		// 5. Dense construction path (insertPatternEdgesDenseFrom + buildFailureLinks).
		dense := &acAutomaton{
			states: []acState{{failure: -1}},
		}
		for i := range dense.states[0].transitions {
			dense.states[0].transitions[i] = -1
		}
		addMixed(t, dense, 0)
		if err := dense.Compile(); err != nil {
			t.Fatal(err)
		}
		assertMatches(t, dense)
	})
}

func TestIssue688XorNocaseNoPostXorFolding(t *testing.T) {
	xorBytes := func(in []byte, key byte) []byte {
		out := make([]byte, len(in))
		for i, b := range in {
			out[i] = b ^ key
		}
		return out
	}

	t.Run("letters_xored_out_of_ascii_alpha_range", func(t *testing.T) {
		prog, err := NewCompiler().CompileSource(`
rule R {
	strings:
		$a = "abc" xor(1) nocase
	condition:
		$a
}`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		for _, tc := range []struct {
			name string
			data []byte
			want bool
		}{
			{"lower", xorBytes([]byte("abc"), 1), true},
			{"upper", xorBytes([]byte("ABC"), 1), true},
			{"mixed", xorBytes([]byte("AbC"), 1), true},
			{"plaintext", []byte("abc"), false},
			{"wrong_char", xorBytes([]byte("abd"), 1), false},
		} {
			res, err := prog.Scan(tc.data)
			if err != nil {
				t.Fatalf("%s scan: %v", tc.name, err)
			}
			if res.RuleResults["R"] != tc.want {
				t.Fatalf("%s: got %v, want %v (data=%x)", tc.name, res.RuleResults["R"], tc.want, tc.data)
			}
		}
	})

	t.Run("non_letters_xored_into_ascii_alpha_range", func(t *testing.T) {
		prog, err := NewCompiler().CompileSource(`
rule R {
	strings:
		$a = "@@@" xor(1) nocase
	condition:
		$a
}`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		// "@" (0x40) ^ 1 = "A" (0x41); "`" (0x60) ^ 1 = "a" (0x61) must NOT match.
		for _, tc := range []struct {
			name string
			data []byte
			want bool
		}{
			{"exact_xored", xorBytes([]byte("@@@"), 1), true},
			{"false_folded_backticks", xorBytes([]byte("```"), 1), false},
		} {
			res, err := prog.Scan(tc.data)
			if err != nil {
				t.Fatalf("%s scan: %v", tc.name, err)
			}
			if res.RuleResults["R"] != tc.want {
				t.Fatalf("%s: got %v, want %v", tc.name, res.RuleResults["R"], tc.want)
			}
		}
	})

	t.Run("wide_xor_nocase", func(t *testing.T) {
		prog, err := NewCompiler().CompileSource(`
rule R {
	strings:
		$a = "abc" xor(0-2) nocase wide
	condition:
		$a
}`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		wideAbcUpper := []byte{'A', 0, 'B', 0, 'C', 0}
		res, err := prog.Scan(xorBytes(wideAbcUpper, 2))
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !res.RuleResults["R"] {
			t.Fatal("expected wide xor(2) nocase to match wide ABC^2")
		}
		resMiss, err := prog.Scan(xorBytes([]byte{'@', 0, '@', 0, '@', 0}, 2))
		if err != nil {
			t.Fatalf("scan miss: %v", err)
		}
		if resMiss.RuleResults["R"] {
			t.Fatal("unexpected match on non-letter bytes")
		}
	})

	t.Run("excessive_expansion_rejected_cleanly", func(t *testing.T) {
		_, err := NewCompiler().CompileSource(`
rule R {
	strings:
		$a = "abcdefghijklmnopqrst" xor nocase
	condition:
		$a
}`)
		if err == nil {
			t.Fatal("expected error for excessive xor+nocase expansion, got nil")
		}
	})
}

func TestIssue688CustomBase64AlphabetNewlinesAndRawBytes(t *testing.T) {
	t.Run("newline_and_cr_in_alphabet_no_panic", func(t *testing.T) {
		alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567\n\r+/"
		if len(alphabet) != 64 {
			t.Fatalf("alphabet len = %d", len(alphabet))
		}
		src := `
rule B64 {
	strings:
		$a = "\xf0\x0f\x3d" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567\n\r+/")
		$w = "\xf0\x0f\x3d" base64wide("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567\n\r+/")
	condition:
		$a and $w
}`
		prog, err := NewCompiler().CompileSource(src)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		sc := newStringCompiler()
		variants, err := sc.base64AlignedPatterns([]byte{0xf0, 0x0f, 0x3d}, alphabet, false)
		if err != nil || len(variants) != 3 {
			t.Fatalf("base64AlignedPatterns = (%d, %v), want 3", len(variants), err)
		}
		wideVariants, err := sc.base64AlignedPatterns([]byte{0xf0, 0x0f, 0x3d}, alphabet, true)
		if err != nil || len(wideVariants) != 3 {
			t.Fatalf("base64AlignedPatterns wide = (%d, %v), want 3", len(wideVariants), err)
		}
		if !bytes.Contains(variants[0], []byte("\n")) || !bytes.Contains(variants[0], []byte("\r")) {
			t.Fatalf("expected newline/CR characters in encoded variant[0]: %q", variants[0])
		}
		for i := range 3 {
			data := append(slices.Clone(variants[i]), byte(' '))
			data = append(data, wideVariants[i]...)
			res, err := prog.Scan(data)
			if err != nil {
				t.Fatalf("offset %d scan: %v", i, err)
			}
			if !res.RuleResults["B64"] {
				t.Fatalf("offset %d did not match (ascii=%x wide=%x)", i, variants[i], wideVariants[i])
			}
		}
	})

	t.Run("parity_with_stdlib_base64", func(t *testing.T) {
		alphabet := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"
		enc := base64.NewEncoding(alphabet)
		sc := newStringCompiler()
		for length := 0; length <= 10; length++ {
			input := make([]byte, length)
			for i := range input {
				input[i] = byte(i*37 + 11)
			}
			got, err := encodeBase64Raw(alphabet, input)
			if err != nil {
				t.Fatalf("len=%d err=%v", length, err)
			}
			want := enc.EncodeToString(input)
			if string(got) != want {
				t.Fatalf("len=%d: got %q, want %q", length, got, want)
			}
			variants, err := sc.base64AlignedPatterns(input, alphabet, false)
			if err != nil {
				t.Fatalf("base64AlignedPatterns(len=%d): %v", length, err)
			}
			for _, v := range variants {
				if len(v) == 0 && length > 0 {
					t.Fatalf("len=%d produced empty aligned variant", length)
				}
			}
		}
	})
}

func TestIssue688ScanHexAnchorKeyDedupe(t *testing.T) {
	sc := newStringCompiler()
	t.Run("large_overlapping_jump_no_duplicates", func(t *testing.T) {
		pat, err := sc.parseHexPattern(`{ [0-500] AA }`)
		if err != nil {
			t.Fatal(err)
		}
		data := bytes.Repeat([]byte{0xAA}, 600)
		matches := FindHexMatches(pat, data)
		type span struct {
			off int64
			len int
		}
		seen := make(map[span]int, len(matches))
		for _, m := range matches {
			s := span{m.Offset, m.Length}
			seen[s]++
			if seen[s] > 1 {
				t.Fatalf("duplicate match emitted at %+v", s)
			}
		}
		// Each start 0..599 matches once for each end in [start..min(599, start+500)].
		wantCount := 0
		for start := range data {
			maxEnd := min(len(data)-1, start+500)
			wantCount += maxEnd - start + 1
		}
		if len(matches) != wantCount {
			t.Fatalf("got %d matches, want %d", len(matches), wantCount)
		}
	})

	t.Run("offset_anchor_at_zero_does_not_skip", func(t *testing.T) {
		pat, err := sc.parseHexPattern(`{ [1-3] AA BB }`)
		if err != nil {
			t.Fatal(err)
		}
		// AA at index 0 cannot satisfy [1-3] (needs at least 1 prefix byte),
		// while AA at index 2 must still match starting at offset 0 and 1.
		data := []byte{0xAA, 0x00, 0xAA, 0xBB, 0xAA, 0xBB}
		matches := FindHexMatches(pat, data)
		if len(matches) == 0 {
			t.Fatal("expected matches, got 0")
		}
		var starts []int64
		for _, m := range matches {
			starts = append(starts, m.Offset)
		}
		if !slices.Contains(starts, 0) || !slices.Contains(starts, 1) {
			t.Fatalf("missing expected start offsets in %+v", matches)
		}
	})
}

func TestIssue688TrailingHexJumpEOFClamp(t *testing.T) {
	sc := newStringCompiler()

	for _, tc := range []struct {
		name    string
		pattern string
		data    []byte
		want    []Match
	}{
		{
			name:    "single_jump_min_exceeds_eof",
			pattern: `{ AA [2-5] }`,
			data:    []byte{0x00, 0xAA, 0xBB},
			want:    nil,
		},
		{
			name:    "single_jump_clamped_to_eof",
			pattern: `{ AA [1-5] }`,
			data:    []byte{0x00, 0xAA, 0xBB},
			want:    []Match{{Offset: 1, Length: 2}},
		},
		{
			name:    "single_jump_zero_at_eof",
			pattern: `{ AA [0-5] }`,
			data:    []byte{0xAA},
			want:    []Match{{Offset: 0, Length: 1}},
		},
		{
			name:    "non_single_jump_alt_min_exceeds_eof",
			pattern: `{ AA ( BB | CC ) [2-5] }`,
			data:    []byte{0xAA, 0xBB, 0x00},
			want:    nil,
		},
		{
			name:    "non_single_jump_alt_clamped_to_eof",
			pattern: `{ AA ( BB | CC ) [1-5] }`,
			data:    []byte{0xAA, 0xBB, 0x00},
			want:    []Match{{Offset: 0, Length: 3}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pat, err := sc.parseHexPattern(tc.pattern)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := FindHexMatches(pat, tc.data)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("FindHexMatches = %+v, want %+v", got, tc.want)
			}
			for _, m := range got {
				if int(m.Offset)+m.Length > len(tc.data) {
					t.Fatalf("match %+v exceeds len(data)=%d", m, len(tc.data))
				}
			}
		})
	}

	t.Run("rule_match_end_within_filesize", func(t *testing.T) {
		prog, err := NewCompiler().CompileSource(`
rule TrailingJump {
	strings:
		$a = { AA [1-5] }
	condition:
		#a == 1 and !a[1] == 2 and (@a[1] + !a[1]) <= filesize
}`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		res, err := prog.Scan([]byte{0x00, 0xAA, 0xBB})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !res.RuleResults["TrailingJump"] {
			t.Fatal("expected rule to match with clamped length")
		}
	})
}

func TestIssue688WideRawByteInterleaving(t *testing.T) {
	prog, err := NewCompiler().CompileSource(`
rule WideRaw {
	strings:
		$raw = "\xff\x80" wide
		$utf8 = "\xc3\xa9" wide
		$b64w = "\xfb\xef\xbe" base64wide("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\xff\x80")
	condition:
		$raw and $utf8 and $b64w
}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	good := []byte{
		0xFF, 0x00, 0x80, 0x00,
		0xC3, 0x00, 0xA9, 0x00,
		0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
	}
	res, err := prog.Scan(good)
	if err != nil {
		t.Fatalf("scan good: %v", err)
	}
	if !res.RuleResults["WideRaw"] {
		t.Fatal("expected raw byte wide interleaving to match")
	}

	// Ensure UTF-8 / U+FFFD decoding does NOT match.
	bad := []byte{
		0xFD, 0xFF, 0xFD, 0xFF,
		0xE9, 0x00,
		0xFD, 0xFF, 0xFD, 0xFF, 0xFD, 0xFF, 0xFD, 0xFF,
	}
	resBad, err := prog.Scan(bad)
	if err != nil {
		t.Fatalf("scan bad: %v", err)
	}
	if resBad.RuleResults["WideRaw"] {
		t.Fatal("unexpected match for UTF-8 decoded wide bytes")
	}
}

type testCancelTeddyPrefilter struct{}

func (testCancelTeddyPrefilter) findCandidate(data []byte, from int) int {
	if rel := bytes.Index(data[from:], []byte("alpha_pat")); rel >= 0 {
		return from + rel
	}
	return -1
}

func (testCancelTeddyPrefilter) findCandidateWithCancel(data []byte, from int, done <-chan struct{}) int {
	if scanCanceled(done) {
		return -1
	}
	if rel := bytes.Index(data[from:], []byte("alpha_pat")); rel >= 0 {
		return from + rel
	}
	return -1
}

func (testCancelTeddyPrefilter) tailBytes() int { return 31 }

func TestIssue688TeddyTailNotScannedAfterCancellation(t *testing.T) {
	buildTeddyAC := func(t *testing.T, padStates int) *acAutomaton {
		t.Helper()
		ac := newacAutomaton()
		if padStates > 0 {
			if err := ac.AddString("$pad", bytes.Repeat([]byte{0x01}, padStates), false, false); err != nil {
				t.Fatal(err)
			}
		}
		for id, pat := range map[string]string{
			"$first": "alpha_pat",
			"$tail":  "bravo_pat",
		} {
			if err := ac.AddString(id, []byte(pat), false, false); err != nil {
				t.Fatal(err)
			}
		}
		if err := ac.Compile(); err != nil {
			t.Fatal(err)
		}
		if ac.teddy == nil {
			ac.teddy = testCancelTeddyPrefilter{}
		}
		return ac
	}

	for _, tc := range []struct {
		name      string
		padStates int
		wantClass bool
	}{
		{"flat_table", 0, false},
		{"class_table", 17000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ac := buildTeddyAC(t, tc.padStates)
			if tc.wantClass && len(ac.flatClass16) == 0 {
				t.Fatal("expected class table")
			}
			data := bytes.Repeat([]byte("z"), 1024)
			// Match at offset 70 (>= 64 so linearUntil remains 0) triggers yield at i=78
			// (not a cancellation checkpoint) where cancel() fires; tail match sits in
			// the final tailBytes window.
			copy(data[70:], "alpha_pat")
			tailOffset := len(data) - len("bravo_pat") - 1
			copy(data[tailOffset:], "bravo_pat")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var got []string
			ac.SearchWithCancel(data, ctx.Done(), func(m acMatch) bool {
				got = append(got, m.StringID)
				cancel()
				return true
			})
			if slices.Contains(got, "$tail") {
				t.Fatalf("yielded tail match %v after cancellation", got)
			}
			if !slices.Equal(got, []string{"$first"}) {
				t.Fatalf("got %v, want only [$first]", got)
			}
		})
	}
}
