//go:build hyperscan

package hyperscan_cgo

import (
	"fmt"
	"strings"
	"testing"
)

var matchSink bool

func TestCorpusParity(t *testing.T) {
	engine, err := newEngine(10_000)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.close()
	for index, event := range events(256, 1_024) {
		matched, matchErr := engine.matches(event)
		if matchErr != nil {
			t.Fatal(matchErr)
		}
		if want := index%100 == 0; matched != want {
			t.Fatalf("event %d: matched=%v, want %v", index, matched, want)
		}
	}
}

func BenchmarkCGOBlockScan10KRegex(b *testing.B) {
	engine, err := newEngine(10_000)
	if err != nil {
		b.Fatal(err)
	}
	defer engine.close()
	events := events(256, 1_024)
	b.ReportAllocs()
	b.SetBytes(256)
	index := 0
	b.ResetTimer()
	for b.Loop() {
		matched, matchErr := engine.matches(events[index&1_023])
		if matchErr != nil {
			b.Fatal(matchErr)
		}
		matchSink = matched
		index++
	}
}

func events(size, count int) [][]byte {
	result := make([][]byte, count)
	for index := range count {
		payload := ""
		if index%100 == 0 {
			payload = " sig_00000=deny_00000 sig_00001=AB123456"
		}
		prefix := fmt.Sprintf(
			`{"timestamp":%d,"tenant":"tenant-%02d","src_ip":"10.20.%d.%d","path":"/api/v1/events","message":"`,
			1_800_000_000+index,
			index%32,
			index%256,
			(index*17)%256,
		)
		suffix := `"}`
		filler := size - len(prefix) - len(payload) - len(suffix)
		if filler < 0 {
			panic("event size is too small")
		}
		event := make([]byte, 0, size)
		event = append(event, prefix...)
		event = append(event, strings.Repeat("x", filler)...)
		event = append(event, payload...)
		event = append(event, suffix...)
		result[index] = event
	}
	return result
}
