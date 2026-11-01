package compiler

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func BenchmarkBoundedClassCounter(b *testing.B) {
	class := newBoundedClassSet(regex.NewByteSet([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")))
	for _, size := range []int{16, 32, 64, 256, 1024} {
		data := bytes.Repeat([]byte{'a'}, size)
		for _, tc := range []struct {
			name  string
			count func([]byte, *boundedClassSet) int
		}{{"scalar", countBoundedClassScalar}, {"dispatch", countBoundedClass}} {
			b.Run(strconv.Itoa(size)+"/"+tc.name, func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if tc.count(data, &class) != size {
						b.Fatal("wrong count")
					}
				}
			})
		}
	}
}
