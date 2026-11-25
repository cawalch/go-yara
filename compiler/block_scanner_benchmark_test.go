package compiler

import (
	"bytes"
	"fmt"
	"testing"
)

func BenchmarkBlockScannerFinishEvidence(b *testing.B) {
	const blockSize = 4096
	program := mustCompileStreamingProgram(b, `rule events {
    strings:
        $item = /event=([0-9]{4})/ capture(id = 1)
    condition:
        $item
}`)
	data := make([]byte, blockSize)
	copy(data, bytes.Repeat([]byte("event=1234 "), 10))

	for _, blockCount := range []int{1, 100, 10000} {
		for _, mode := range []struct {
			name string
			opts []ScannerOption
		}{
			{name: "plain"},
			{name: "match_data", opts: []ScannerOption{WithMatchData(64), WithMatchContext(16, 16)}},
			{name: "evidence", opts: []ScannerOption{WithEvidence(64)}},
		} {
			b.Run(fmt.Sprintf("blocks=%d/%s", blockCount, mode.name), func(b *testing.B) {
				scanner := program.NewBlockScanner(mode.opts...)
				defer scanner.Close()
				b.ReportAllocs()
				b.SetBytes(int64(blockCount * blockSize))
				for b.Loop() {
					scanner.Reset()
					for i := range blockCount {
						if err := scanner.Scan(int64(i*blockSize), data); err != nil {
							b.Fatal(err)
						}
					}
					result, err := scanner.Finish()
					if err != nil {
						b.Fatal(err)
					}
					if got := len(result.Matches["events"]["$item"]); got != blockCount*10 {
						b.Fatalf("match count = %d, want %d", got, blockCount*10)
					}
				}
			})
		}
	}
}

func BenchmarkBlockScannerBorrowedInput(b *testing.B) {
	program := mustCompileStreamingProgram(b, `rule header { condition: uint8(0) == 42 }`)
	data := make([]byte, 16*1024*1024)
	data[0] = 42

	for _, borrowed := range []bool{false, true} {
		b.Run(fmt.Sprintf("borrowed=%t", borrowed), func(b *testing.B) {
			scanner := program.NewBlockScanner()
			defer scanner.Close()
			scan := scanner.Scan
			if borrowed {
				scan = scanner.ScanBorrowed
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				scanner.Reset()
				if err := scan(0, data); err != nil {
					b.Fatal(err)
				}
				result, err := scanner.Finish()
				if err != nil || !result.RuleResults["header"] {
					b.Fatalf("Finish() = %+v, %v, want header match", result, err)
				}
			}
		})
	}
}
