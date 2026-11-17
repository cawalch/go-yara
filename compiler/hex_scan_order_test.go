package compiler

import (
	"slices"
	"testing"
)

func TestHexScanEncodingOrder(t *testing.T) {
	for _, tc := range []struct {
		name, pattern string
		data          []byte
		keys          []byte
		want          []int64
	}{
		{"plain anchored", `{ 41 }`, []byte("@A"), nil, []int64{1}},
		{"zero key anchored", `{ 41 }`, []byte("@A"), []byte{0}, []int64{1}},
		{"anchored key order", `{ 41 }`, []byte("@A"), []byte{0, 1}, []int64{1, 0}},
		{"anchored reverse keys", `{ 41 }`, []byte("@A"), []byte{1, 0}, []int64{0, 1}},
		{"anchored duplicate keys", `{ 41 }`, []byte("@A"), []byte{0, 0}, []int64{1, 1}},
		{"plain brute force", `{ ?1 }`, []byte{0x40, 0x41, 0x50, 0x51}, nil, []int64{1, 3}},
		{"brute force position order", `{ ?1 }`, []byte{0x40, 0x41, 0x50, 0x51}, []byte{0, 1}, []int64{0, 1, 2, 3}},
		{"brute force duplicate keys", `{ ?1 }`, []byte{0x40, 0x41, 0x50, 0x51}, []byte{0, 0}, []int64{1, 1, 3, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pattern, err := newStringCompiler().parseHexPattern(tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			pattern.XorKeys = tc.keys
			for _, stop := range []bool{false, true} {
				var offsets []int64
				findHexMatchesEach(pattern, tc.data, nil, nil, func(m Match) bool { offsets = append(offsets, m.Offset); return !stop })
				want := tc.want
				if stop {
					want = want[:1]
				}
				if !slices.Equal(offsets, want) {
					t.Fatalf("stop=%v: got %v, want %v", stop, offsets, want)
				}
			}
			done := make(chan struct{})
			close(done)
			findHexMatchesEach(pattern, tc.data, done, nil, func(Match) bool { t.Fatal("callback after cancellation"); return false })
		})
	}
}
