package compiler

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"
)

func TestByteSearchScanOccurrences(t *testing.T) {
	for _, sample := range []struct {
		pattern, text string
		offsets       []int
	}{
		{`"aba" nocase`, "AbABa", []int{95, 97}},
		{`/[Q-Z]{3}/`, "QRS.QRS", []int{95, 99}},
	} {
		source := fmt.Sprintf(`rule r {
			strings: $a = %s
			condition: #a == 2 and @a[1] == %d and @a[2] == %d and !a[1] == 3
		}`, sample.pattern, sample.offsets[0], sample.offsets[1])
		program, err := NewCompiler().CompileSource(source)
		if err != nil {
			t.Fatal(err)
		}
		data := bytes.Repeat([]byte("."), 1024)
		copy(data[95:], sample.text)
		for _, options := range [][]ScannerOption{nil, {WithFastScan()}} {
			scanner := NewScanner(program, options...)
			result, scanErr := scanner.Scan(data)
			scanner.Close()
			if scanErr != nil {
				t.Fatal(scanErr)
			}
			if !result.RuleResults["r"] || len(result.Matches["r"]["$a"]) != 2 {
				t.Fatalf("pattern %s: occurrence-sensitive scan = %+v", sample.pattern, result)
			}
		}
	}
}

func TestByteSearchBoundaries(t *testing.T) {
	// Exercise every byte value, alignment, vector boundary, scalar prefix and
	// tail. The inserted byte's position is the expected first match.
	for want := range 256 {
		for _, size := range []int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 79, 80, 127, 128, 129, 257} {
			for alignment := range 8 {
				storage := bytes.Repeat([]byte{byte(want) ^ 0x80}, size+alignment)
				data := storage[alignment:]
				for position := -1; position < size; position++ {
					if position >= 0 {
						data[position] = byte(want)
					}
					got := indexASCIIFoldByte(data, byte(want))
					if got != position {
						t.Fatalf("fold byte=%d size=%d alignment=%d position=%d: got %d", want, size, alignment, position, got)
					}
					got = indexByteRange(data, byte(want), byte(want))
					if got != position {
						t.Fatalf("range byte=%d size=%d alignment=%d position=%d: got %d", want, size, alignment, position, got)
					}
					if position >= 0 {
						data[position] = byte(want) ^ 0x80
					}
				}
			}
		}
	}
}

func TestByteSearchDifferential(t *testing.T) {
	random := rand.New(rand.NewPCG(27, 1))
	for sample := range 20000 {
		data := make([]byte, random.IntN(1025))
		for i := range data {
			data[i] = byte(random.Uint32())
		}
		lower := byte(random.Uint32())
		upper := byte(int(lower) + random.IntN(256-int(lower)))
		wantRange, wantFold := -1, -1
		for i, value := range data {
			if wantRange < 0 && value >= lower && value <= upper {
				wantRange = i
			}
			foldedValue, foldedWant := value, lower
			if foldedValue >= 'A' && foldedValue <= 'Z' {
				foldedValue += 'a' - 'A'
			}
			if foldedWant >= 'A' && foldedWant <= 'Z' {
				foldedWant += 'a' - 'A'
			}
			if wantFold < 0 && foldedValue == foldedWant {
				wantFold = i
			}
		}
		if got := indexByteRange(data, lower, upper); got != wantRange {
			t.Fatalf("sample %d range [%d,%d]: got %d want %d", sample, lower, upper, got, wantRange)
		}
		if got := indexASCIIFoldByte(data, lower); got != wantFold {
			t.Fatalf("sample %d fold %d: got %d want %d", sample, lower, got, wantFold)
		}
	}
}
