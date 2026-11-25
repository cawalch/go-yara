package compiler

import (
	"fmt"
	"math"
	"testing"
)

func TestSizeLiteralSyntaxAndRange(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int64
	}{
		{"0KB", 0}, {"0009KB", 9 << 10}, {"0xAbMB", 0xab << 20}, {"0X10KB", 0x10 << 10},
		{"2GB", 2 << 30}, {"3TB", 3 << 40}, {"\u2003\t10KB\r\n", 10 << 10},
	} {
		got, err := parseSizeLiteral(tc.input)
		if got != tc.want || err != nil {
			t.Errorf("%q: got %d, %v; want %d", tc.input, got, err, tc.want)
		}
	}
	for _, input := range []string{
		"", "KB", "1B", "1kb", "1Kb", "1kB", "1PB", "1 KB", "1\nKB",
		"+1KB", "-1KB", "1.5KB", "1e3KB", "1_000KB", "0xKB", "0b10KB", "0o10KB", "0x_1KB", "0x1_0KB", "0xgKB", "١KB", "１KB", "1KB\x00",
	} {
		want := "invalid size literal format: " + input
		if _, err := parseSizeLiteral(input); err == nil || err.Error() != want {
			t.Errorf("%q: got %v, want %q", input, err, want)
		}
	}
	for _, number := range []string{"9223372036854775808", "0x8000000000000000"} {
		want := "invalid number in size literal: " + number
		if _, err := parseSizeLiteral(number + "KB"); err == nil || err.Error() != want {
			t.Errorf("%q: got %v, want %q", number, err, want)
		}
	}
	for i, unit := range []string{"KB", "MB", "GB", "TB"} {
		multiplier := int64(1) << (10 * (i + 1))
		limit := math.MaxInt64 / multiplier
		for _, format := range []string{"%d%s", "0x%x%s"} {
			input := fmt.Sprintf(format, limit, unit)
			if got, err := parseSizeLiteral(input); err != nil || got != limit*multiplier {
				t.Errorf("%q: got %d, %v", input, got, err)
			}
			input = fmt.Sprintf(format, limit+1, unit)
			want := "size literal exceeds int64 range: " + input
			if _, err := parseSizeLiteral(input); err == nil || err.Error() != want {
				t.Errorf("%q: got %v, want %q", input, err, want)
			}
		}
	}
}

func TestSizeLiteralZeroAllocations(t *testing.T) {
	for _, input := range []string{"10KB", "0009MB", "0xAbGB", "\u20031TB\t"} {
		if allocs := testing.AllocsPerRun(100, func() {
			if _, err := parseSizeLiteral(input); err != nil {
				t.Fatal(err)
			}
		}); allocs != 0 {
			t.Errorf("%q: %g allocations, want zero", input, allocs)
		}
	}
}
