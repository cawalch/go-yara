package compiler

import (
	"testing"
)

func TestMatchContextBinarySearch(t *testing.T) {
	offsets := []int64{10, 50, 100, 200, 500, 1000}

	mcCompact := &MatchContext{compact: true, spans: make(map[string][]matchSpan)}
	for _, o := range offsets {
		mcCompact.spans["$a"] = append(mcCompact.spans["$a"], matchSpan{Offset: o, Length: 4})
	}

	mcNonCompact := &MatchContext{compact: false, Matches: make(map[string][]Match)}
	for _, o := range offsets {
		mcNonCompact.Matches["$a"] = append(mcNonCompact.Matches["$a"], Match{Offset: o, Length: 4})
	}

	contexts := []struct {
		name string
		mc   *MatchContext
	}{
		{"compact", mcCompact},
		{"non-compact", mcNonCompact},
	}

	for _, tc := range contexts {
		t.Run(tc.name+"_hasMatchAt", func(t *testing.T) {
			// Exact matches
			for _, o := range offsets {
				if !tc.mc.hasMatchAt("$a", o) {
					t.Errorf("expected hasMatchAt($a, %d) = true", o)
				}
			}
			// Misses
			misses := []int64{0, 9, 11, 49, 150, 999, 1001, 2000, -1}
			for _, o := range misses {
				if tc.mc.hasMatchAt("$a", o) {
					t.Errorf("expected hasMatchAt($a, %d) = false", o)
				}
			}
			// Missing pattern
			if tc.mc.hasMatchAt("$nonexistent", 100) {
				t.Errorf("expected hasMatchAt($nonexistent, 100) = false")
			}
		})

		t.Run(tc.name+"_hasMatchInRange", func(t *testing.T) {
			rangeTests := []struct {
				min, max int64
				want     bool
			}{
				{10, 10, true},      // Exact match at lower boundary
				{1000, 1000, true},  // Exact match at upper boundary
				{60, 150, true},     // Contains 100
				{10, 1000, true},    // Full range
				{0, 5, false},       // Completely before first match
				{1001, 2000, false}, // Completely after last match
				{11, 49, false},     // In gap (between 10 and 50)
				{101, 199, false},   // In gap (between 100 and 200)
				{100, 50, false},    // Inverted range (min > max)
				{-10, -5, false},    // Negative range
			}

			for _, rt := range rangeTests {
				got := tc.mc.hasMatchInRange("$a", rt.min, rt.max)
				if got != rt.want {
					t.Errorf("hasMatchInRange($a, %d, %d) = %v, want %v", rt.min, rt.max, got, rt.want)
				}
			}

			// Missing pattern
			if tc.mc.hasMatchInRange("$nonexistent", 10, 500) {
				t.Errorf("expected hasMatchInRange($nonexistent) = false")
			}
		})
	}
}

func BenchmarkMatchOffsetSearch(b *testing.B) {
	// 5,000 matches distributed across 1 MB
	const numMatches = 5000
	mc := &MatchContext{compact: true, spans: make(map[string][]matchSpan)}
	for i := 0; i < numMatches; i++ {
		mc.spans["$a"] = append(mc.spans["$a"], matchSpan{Offset: int64(i * 200), Length: 5})
	}

	b.Run("hasMatchAt_Hit", func(b *testing.B) {
		target := int64(2500 * 200)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !mc.hasMatchAt("$a", target) {
				b.Fatalf("expected match")
			}
		}
	})

	b.Run("hasMatchAt_Miss", func(b *testing.B) {
		target := int64(2500*200 + 1)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if mc.hasMatchAt("$a", target) {
				b.Fatalf("unexpected match")
			}
		}
	})

	b.Run("hasMatchInRange_Hit", func(b *testing.B) {
		minO := int64(2500*200 - 50)
		maxO := int64(2500*200 + 50)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !mc.hasMatchInRange("$a", minO, maxO) {
				b.Fatalf("expected match")
			}
		}
	})

	b.Run("hasMatchInRange_GapMiss", func(b *testing.B) {
		minO := int64(2500*200 + 10)
		maxO := int64(2500*200 + 50)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if mc.hasMatchInRange("$a", minO, maxO) {
				b.Fatalf("unexpected match")
			}
		}
	})
}
