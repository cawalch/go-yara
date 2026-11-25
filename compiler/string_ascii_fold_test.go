package compiler

import (
	"strings"
	"testing"
)

func TestASCIIContainsFoldAllocations(t *testing.T) {
	for _, tc := range []struct{ input, needle string }{
		{"AZ\x00\xffTOKEN", "Token"},
		{strings.Repeat("A", asciiFoldWindowSize-2) + "\x00\xffTOKEN", "\x00\xfftoken"},
		{"AZ\x00\xff" + strings.Repeat("TOGGLE", 64) + "!", strings.Repeat("tOgGlE", 64) + "!"},
	} {
		var matched bool
		allocs := testing.AllocsPerRun(100, func() {
			matched = asciiContainsFold(tc.input, tc.needle)
		})
		if !matched || allocs != 0 {
			t.Fatalf("contains with %d-byte needle = %t, %.0f allocations", len(tc.needle), matched, allocs)
		}
	}
}

func FuzzASCIIContainsFold(f *testing.F) {
	f.Add("A\x00\xffB", "\x00\xffb")
	f.Add("A\x00\xffB", "\x00\xfeb")
	f.Add("short", "")
	f.Add(strings.Repeat("a", 200), strings.Repeat("A", 100)+"b")
	f.Add(strings.Repeat("aA", 100)+"B", strings.Repeat("Aa", 50)+"b")
	f.Add("ba"+strings.Repeat("AB", 33)+"ba", strings.Repeat("ab", 18))
	f.Add(strings.Repeat("zAB\x00\xff", 100), strings.Repeat("aB\x00\xffz", 20))
	f.Add(strings.Repeat("A", asciiFoldWindowSize-2)+"\x00\xffTOKEN", "\x00\xfftoken")
	refFold := func(s string) string {
		folded := []byte(s)
		for i, b := range folded {
			if b >= 'A' && b <= 'Z' {
				folded[i] = b + ('a' - 'A')
			}
		}
		return string(folded)
	}
	f.Fuzz(func(t *testing.T, input, needle string) {
		want := strings.Contains(refFold(input), refFold(needle))
		if got := asciiContainsFold(input, needle); got != want {
			t.Fatalf("asciiContainsFold(%q, %q) = %t, want %t", input, needle, got, want)
		}
	})
}

func BenchmarkASCIIContainsFold(b *testing.B) {
	oldContains := func(s, needle string) bool { return strings.Contains(strings.ToLower(s), strings.ToLower(needle)) }
	for _, tc := range []struct {
		name, input, needle string
		want                bool
	}{
		{"short", "example/Path/File.EXE", "fILE", true},
		{"long_short_needle", strings.Repeat("PREFIX_", 4096) + "TOKEN", "token", true},
		{"long_single_byte_miss", strings.Repeat("a", 65536), "B", false},
		{"small_near_miss", strings.Repeat("a", 64), strings.Repeat("a", 14) + "ba", false},
		{"medium_near_miss", strings.Repeat("a", 256), strings.Repeat("a", 14) + "ba", false},
		{"long_prefix", strings.Repeat("a", 4100), strings.Repeat("a", 4096), true},
		{"long_short_near_miss", strings.Repeat("a", 65536), strings.Repeat("a", 14) + "ba", false},
		{"mixed_short_near_miss", strings.Repeat("aA", 32768), strings.Repeat("aA", 7) + "Ba", false},
		{"mixed_long_near_miss", strings.Repeat("aA", 32768), strings.Repeat("Aa", 2048) + "Ba", false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			for _, impl := range []struct {
				name string
				fn   func(string, string) bool
			}{{"previous", oldContains}, {"ascii", asciiContainsFold}} {
				b.Run(impl.name, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(tc.input)))
					for b.Loop() {
						if got := impl.fn(tc.input, tc.needle); got != tc.want {
							b.Fatalf("contains = %t, want %t", got, tc.want)
						}
					}
				})
			}
		})
	}
}
