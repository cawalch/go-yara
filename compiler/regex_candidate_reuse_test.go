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
