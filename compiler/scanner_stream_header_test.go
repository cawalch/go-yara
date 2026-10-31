package compiler

import (
	"bytes"
	"strconv"
	"testing"
)

func TestStreamHeaderPrefixAndCapacity(t *testing.T) {
	data := make([]byte, 70000)
	for i := range data {
		data[i] = byte(i % 251)
	}
	var acc streamAccumulator
	chunks := []int{1, 3, 7, 4093, 65, 16381}
	for primary, step := 0, 0; primary < len(data); step++ {
		next := min(primary+chunks[step%len(chunks)], len(data))
		end := min(next+streamingLookaheadContext, len(data))
		start := max(0, primary-1)
		acc.retainHeader(data[start:end], int64(start))
		if !bytes.Equal(acc.headerBlock, data[:min(end, streamingHeaderSize)]) {
			t.Fatalf("window [%d:%d] did not retain the exact prefix", start, end)
		}
		if cap(acc.headerBlock) > streamingHeaderSize {
			t.Fatalf("header capacity %d exceeds limit", cap(acc.headerBlock))
		}
		primary = next
	}
}

func TestScanReaderHeaderRetention(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule probe { condition: uint8(3) == 98 }`)
	for _, chunk := range []int{1, 2, 3, 7, 64} {
		t.Run(strconv.Itoa(chunk), func(t *testing.T) {
			scanner := program.NewScanner(WithStreamChunkSize(chunk), WithStreamOverlapSize(1))
			defer scanner.Close()
			for _, data := range [][]byte{[]byte("abab"), nil, []byte("aba"), []byte("abba"), []byte("abab")} {
				result, err := scanner.ScanReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				want := bytes.Equal(data, []byte("abab"))
				if got := len(result.MatchedRules) > 0; got != want {
					t.Fatalf("data %q: matched = %v, want %v", data, got, want)
				}
			}
		})
	}
}

func TestScanReaderGrowingHeaderEarlyTermination(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule probe {
		strings: $a = "a"
		condition: $a and uint16(100) == 0x6263
	}`)
	if len(program.sharedAssertions) == 0 || !program.Rules[0].ConditionMonotonic {
		t.Fatal("test requires a cached assertion and an early-termination eligible rule")
	}
	scanner := program.NewScanner(WithStreamChunkSize(1), WithStreamOverlapSize(1))
	defer scanner.Close()
	for _, match := range []bool{true, false, true} {
		data := make([]byte, 128*1024)
		data[0] = 'a'
		if match {
			data[100], data[101] = 'c', 'b'
		}
		reader := &countingReader{r: bytes.NewReader(data)}
		got, err := scanner.MatchesReader(reader)
		if err != nil || got != match {
			t.Fatalf("matched = %v, err = %v, want %v", got, err, match)
		}
		if match && reader.bytesRead >= int64(len(data)) {
			t.Fatal("matching header did not allow early termination")
		}
	}
}

func TestScanReaderHeaderLimit(t *testing.T) {
	program := mustCompileStreamingProgram(t, `rule probe { condition:
		uint32(65532) == 0x64636261 and
		not defined uint32(65533) and not defined uint8(65536)
	}`)
	data := make([]byte, 65540)
	copy(data[65532:], "abcdefgh")
	for _, chunk := range []int{7, 4096, 65536, 1024 * 1024} {
		t.Run(strconv.Itoa(chunk), func(t *testing.T) {
			scanner := program.NewScanner(WithStreamChunkSize(chunk))
			defer scanner.Close()
			result, err := scanner.ScanReader(bytes.NewReader(data))
			if err != nil || len(result.MatchedRules) != 1 {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
		})
	}
}
