package compiler

import (
	"bytes"
	"slices"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestFixedOffsetCandidateFiltering(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		atom    []byte
		offset  int
		wide    bool
		nocase  bool
		filters bool
		want    []int
	}{
		{"overlap", []byte("aaaa"), []byte("aa"), 0, false, false, false, []int{0, 1, 2}},
		{"negative start", []byte("abxab"), []byte("ab"), 1, false, false, false, []int{2}},
		{"wide odd start", []byte{'x', 'q', 0, 'a', 0, 'b', 0}, []byte{'a', 0, 'b', 0}, 1, true, false, false, []int{1}},
		{"nocase", []byte("xAByxaby"), []byte("ab"), 1, false, true, false, []int{0, 4}},
		{"filters", []byte("zabyxabyzabyxaby"), []byte("ab"), 1, false, false, true, []int{4, 12}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pattern := RegexPattern{atomMinOffset: tc.offset, atomMaxOffset: tc.offset, atomASCIINoCase: tc.nocase}
			if tc.filters {
				pattern.hasFirstByteSet = true
				pattern.firstByteSet = regex.NewByteSet([]byte{'x'})
				pattern.hasPrecedingByteSet = true
				pattern.precedingByteSet = regex.NewByteSet([]byte{'x'})
				pattern.exactPrefixSuffix = []byte{'x'}
			}
			got, ok := regexAtomCandidateStarts(tc.data, tc.atom, pattern, 0, tc.wide, nil)
			if !ok || !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, %v; want %v, true", got, ok, tc.want)
			}
		})
	}
	pattern := RegexPattern{}
	data := bytes.Repeat([]byte("ab"), 1025)
	if _, ok := regexAtomCandidateStarts(data, []byte("ab"), pattern, 0, false, nil); ok {
		t.Fatal("exceeding the hit limit must request fallback")
	}
	done := make(chan struct{})
	close(done)
	if got, ok := regexAtomCandidateStarts(data, []byte("ab"), pattern, 0, false, done); !ok || len(got) != 0 {
		t.Fatalf("canceled collection returned %v, %v", got, ok)
	}
}

func FuzzFixedOffsetCandidateParity(f *testing.F) {
	f.Add([]byte("xabyxaby"), []byte("ab"), uint8(1), uint8(0))
	f.Add([]byte("aaaa"), []byte("aa"), uint8(0), uint8(2))
	f.Add([]byte{'x', 'q', 0, 'a', 0, 'b', 0}, []byte{'a', 0, 'b', 0}, uint8(1), uint8(1))
	f.Fuzz(func(t *testing.T, data, atom []byte, offset, mode uint8) {
		if len(data) > 4096 || len(atom) == 0 || len(atom) > 4 {
			return
		}
		pattern := RegexPattern{atomMinOffset: int(offset), atomMaxOffset: int(offset), atomASCIINoCase: mode&2 != 0}
		if mode&4 != 0 {
			pattern.hasFirstByteSet = true
			pattern.firstByteSet = regex.NewByteSet([]byte{'x', 'a', 0})
		}
		if mode&8 != 0 {
			pattern.hasPrecedingByteSet = true
			pattern.precedingByteSet = regex.NewByteSet([]byte{'x', 'a', 0})
		}
		wide := mode&1 != 0
		got, ok := regexAtomCandidateStarts(data, atom, pattern, 0, wide, nil)
		// An empty repeat class with min=max=0 leaves validation and offsets
		// unchanged, but selects the original expanding/sorting path.
		pattern.hasPrefixRepeat = true
		want, wantOK := regexAtomCandidateStarts(data, atom, pattern, 0, wide, nil)
		if ok != wantOK || !slices.Equal(got, want) {
			t.Fatalf("got %v, %v; generic path returned %v, %v", got, ok, want, wantOK)
		}
	})
}

func FuzzVariableOffsetCandidateParity(f *testing.F) {
	f.Add([]byte("xaaaxaaaxaaa"), []byte("aa"), uint8(0), uint8(3), uint8(0))
	f.Add(bytes.Repeat([]byte("ab"), 1025), []byte("ab"), uint8(0), uint8(2), uint8(0))
	f.Fuzz(func(t *testing.T, data, atom []byte, offset, width, mode uint8) {
		if len(data) > 8192 || len(atom) == 0 || len(atom) > 4 {
			return
		}
		p := RegexPattern{atomMinOffset: int(offset), atomMaxOffset: int(offset) + int(width), atomASCIINoCase: mode&2 != 0}
		if mode&4 != 0 {
			p.hasFirstByteSet = true
			p.firstByteSet = regex.NewByteSet([]byte{'x', 'a', 0})
		}
		if mode&8 != 0 {
			p.hasPrecedingByteSet = true
			p.precedingByteSet = regex.NewByteSet([]byte{'x', 'a', 0})
		}
		if mode&16 != 0 {
			p.hasPrefixRepeat = true
			p.prefixRepeatMax = int(width)
			p.prefixRepeatClass = regex.NewByteSet([]byte{'a', 'x', 0})
		}
		want, wantOK := referenceRegexAtomCandidateStarts(data, atom, p, 0, mode&1 != 0, nil)
		got, ok := regexAtomCandidateStartsInto(&MatchContext{regexCandidates: make([]int, 0, 32)}, data, atom, p, 0, mode&1 != 0, nil)
		if ok != wantOK || !slices.Equal(got, want) {
			t.Fatalf("got %v,%v want %v,%v", got, ok, want, wantOK)
		}
	})
}

func TestRegexCandidateScratchReuse(t *testing.T) {
	data := bytes.Repeat([]byte("xxxxab"), 64)
	pattern := RegexPattern{atomMinOffset: 1, atomMaxOffset: 4}
	ctx := &MatchContext{}
	collect := func() {
		starts, ok := regexAtomCandidateStartsInto(ctx, data, []byte("ab"), pattern, 0, false, nil)
		if !ok || len(starts) != 256 {
			t.Fatalf("got %d starts, handled=%v", len(starts), ok)
		}
		ctx.retainRegexCandidates(starts)
	}
	collect()
	if allocs := testing.AllocsPerRun(100, collect); allocs != 0 {
		t.Fatalf("warmed collection allocated %.1f times", allocs)
	}
	ctx.retainRegexCandidates(make([]int, 0, 4097))
	if ctx.regexCandidates != nil {
		t.Fatal("oversized candidate storage retained")
	}
	collect()
	ctx.Reset(nil)
	collect()
}

func TestRegexCandidateScratchAlternatingPaths(t *testing.T) {
	ctx := &MatchContext{}
	for range 3 {
		for _, tc := range []struct {
			data     []byte
			min, max int
		}{
			{bytes.Repeat([]byte("xab"), 64), 1, 4},
			{bytes.Repeat([]byte("xab"), 64), 1, 1},
			{bytes.Repeat([]byte("ab"), 1025), 0, 0},
			{[]byte("no hits"), 0, 4},
			{[]byte("xxxabxxxab"), 1, 4},
		} {
			p := RegexPattern{atomMinOffset: tc.min, atomMaxOffset: tc.max}
			want, wantOK := referenceRegexAtomCandidateStarts(tc.data, []byte("ab"), p, 0, false, nil)
			got, ok := regexAtomCandidateStartsInto(ctx, tc.data, []byte("ab"), p, 0, false, nil)
			ctx.retainRegexCandidates(got)
			if ok != wantOK || !slices.Equal(got, want) {
				t.Fatalf("got %v,%v want %v,%v", got, ok, want, wantOK)
			}
		}
	}
}

func BenchmarkRegexCandidateReuseScan(b *testing.B) {
	ruleSource := `
rule reverse_pruning {
    strings:
        $re = /[0-9]{2,10}_target_atom\b/
    condition:
        $re
}`
	program, err := NewCompiler().CompileSource(ruleSource)
	if err != nil {
		b.Fatal(err)
	}
	body := bytes.Repeat([]byte("xx_target_atom benignFillerCode123 "), 128)
	copy(body[1000:], []byte("12345_target_atom "))

	scanner := NewScanner(program)
	defer scanner.Close()

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, scanErr := scanner.Scan(body); scanErr != nil {
			b.Fatal(scanErr)
		}
	}
}
