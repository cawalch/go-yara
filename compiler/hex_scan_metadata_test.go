package compiler

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/cawalch/go-yara/ast"
)

func TestPreparedHexScanParity(t *testing.T) {
	for _, source := range []string{
		`{ 41 42 43 }`, `{ ?? ?1 ~42 }`, `{ 41 [0-3] 42 }`,
		`{ 41 [0-64] ?? [0-64] 42 }`, `{ (41 | 41 42) (43 | 44) 45 }`,
		`{ 41 [-] 42 }`, `{ 41 42 43 } xor(0-3)`,
	} {
		t.Run(source, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(`rule h { strings: $h = ` + source + ` condition: $h }`)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := program.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := UnmarshalCompiledProgram(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range []*CompiledProgram{program, loaded, NewCompiledProgram(program.Rules)} {
				pattern := p.Rules[0].HexPatterns["$h"]
				if pattern.scanMetadata == nil {
					t.Fatal("program missing prepared metadata")
				}
				for _, data := range [][]byte{nil, []byte("A"), []byte("ABCDEABDE"), bytes.Repeat([]byte{0x41, 0x42, 0x43, 0, 0x40, 0x43, 0x42}, 12)} {
					want := FindHexMatches(pattern, data)
					matched, err := p.Matches(data)
					if err != nil || matched != (len(want) > 0) {
						t.Fatalf("program scan data=%x: matched=%v err=%v, standalone=%v", data, matched, err, want)
					}
					for _, stop := range []bool{false, true} {
						var got []Match
						var scratch hexMatchScratch
						findPreparedHexMatchesEach(pattern, data, nil, &scratch, func(m Match) bool { got = append(got, m); return !stop })
						expected := want
						if stop && len(expected) > 0 {
							expected = expected[:1]
						}
						if !reflect.DeepEqual(got, expected) {
							t.Fatalf("stop=%v data=%x: got %v, want %v", stop, data, got, expected)
						}
					}
				}
				done := make(chan struct{})
				close(done)
				findPreparedHexMatchesEach(pattern, []byte("ABCDE"), done, nil, func(Match) bool { t.Fatal("callback after cancellation"); return false })
			}
		})
	}
}

func TestStandaloneHexIgnoresPreparedMetadata(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule h { strings: $h = { 41 (42 | 43) } condition: $h }`)
	if err != nil {
		t.Fatal(err)
	}
	pattern := program.Rules[0].HexPatterns["$h"]
	// Standalone matching still observes nested edits even when the pattern
	// originated in a prepared program. The program itself is no longer scanned.
	pattern.Tokens[1].Alternatives[0][0].Value = 0x44
	if got := FindHexMatches(pattern, []byte("AD")); len(got) != 1 {
		t.Fatalf("nested edit: %v", got)
	}
	pattern.Tokens = []HexPatternToken{{Kind: HexTokenByte, Value: 0x41}, {Kind: HexTokenByte, Value: 0x42}}
	pattern.XorRange = []ast.XorRange{{Min: 1, Max: 1}}
	if got := FindHexMatches(pattern, []byte("@C")); len(got) != 1 {
		t.Fatalf("range edit: %v", got)
	}
	pattern.XorKeys = []byte{2}
	if got := FindHexMatches(pattern, []byte("C@")); len(got) != 1 {
		t.Fatalf("explicit key precedence: %v", got)
	}
	clone := pattern.Clone()
	clone.XorKeys[0] = 3
	if got := FindHexMatches(clone, []byte("BA")); len(got) != 1 {
		t.Fatalf("clone edit: %v", got)
	}
	// Re-preparing caller-provided rules must refresh metadata, not borrow the
	// stale cache from the source pattern.
	fresh := NewCompiledProgram(program.Rules)
	var count int
	findPreparedHexMatchesEach(fresh.Rules[0].HexPatterns["$h"], []byte("C@"), nil, nil, func(Match) bool { count++; return true })
	if count != 1 {
		t.Fatalf("reprepared pattern: got %d matches", count)
	}
}

func BenchmarkHexPreparedScan(b *testing.B) {
	for _, tc := range []struct{ name, pattern string }{
		{"literal", `{ 41 42 43 44 }`},
		{"jump", `{ 41 [1-3] 42 }`},
		{"alternatives", `{ 41 (42 | 43 44) 45 }`},
		{"xor", `{ 41 42 43 44 } xor(0-255)`},
	} {
		b.Run(tc.name, func(b *testing.B) {
			program, err := NewCompiler().CompileSource(`rule h { strings: $h = ` + tc.pattern + ` condition: $h }`)
			if err != nil {
				b.Fatal(err)
			}
			pattern := program.Rules[0].HexPatterns["$h"]
			data := bytes.Repeat([]byte("ABCDEXY"), 8)
			var scratch hexMatchScratch
			onMatch := func(Match) bool { return true }
			findPreparedHexMatchesEach(pattern, data, nil, &scratch, onMatch)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				findPreparedHexMatchesEach(pattern, data, nil, &scratch, onMatch)
			}
		})
	}
}

func TestPreparedHexRangeAndMinimum(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule h { strings: $h = { 41 42 } condition: $h at 0 }`)
	if err != nil {
		t.Fatal(err)
	}
	pattern := program.Rules[0].HexPatterns["$h"]
	pattern.XorRange = []ast.XorRange{{Min: 1, Max: 2}, {Min: 2, Max: 1}}
	prepared := NewCompiledProgram(program.Rules)
	pattern = prepared.Rules[0].HexPatterns["$h"]
	for _, data := range [][]byte{[]byte("@C"), []byte("C@"), []byte("@"), []byte("AB")} {
		want := FindHexMatches(pattern, data)
		var got []Match
		findPreparedHexMatchesEach(pattern, data, nil, nil, func(m Match) bool { got = append(got, m); return true })
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("data=%x: got %v want %v", data, got, want)
		}
		if matched := compiledPatternMatchesAtWithCancel(prepared.Rules[0], "$h", data, 0, nil); matched != (len(want) > 0) {
			t.Fatalf("fixed-offset check data=%x: matched=%v want=%v", data, matched, want)
		}
	}
}

func TestPreparedHexXorAllocationBound(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule h { strings: $h = { 41 42 43 44 } xor condition: $h }`)
	if err != nil {
		t.Fatal(err)
	}
	pattern := program.Rules[0].HexPatterns["$h"]
	data := []byte("ABCDABCD")
	var scratch hexMatchScratch
	onMatch := func(Match) bool { return true }
	findPreparedHexMatchesEach(pattern, data, nil, &scratch, onMatch)
	if allocs := testing.AllocsPerRun(100, func() { findPreparedHexMatchesEach(pattern, data, nil, &scratch, onMatch) }); allocs != 0 {
		t.Fatalf("prepared XOR scan allocated %.1f times after warmup", allocs)
	}
}
