package compiler

import (
	"bytes"
	"fmt"
	"testing"
)

// Complete Scan calls, with compilation and scanner construction outside the
// timer. Keep identical input/rules when comparing normal and SIMD builds.
func BenchmarkSIMDScan(b *testing.B) {
	for _, pattern := range []struct {
		name, source, match string
	}{
		{"nocase", `"qZ_token" nocase`, "Qz_TOKEN"},
		{"range", `/[Q-Z]{3}[0-9]{4}/`, "QRS1234"},
		{"literal_control", `"qZ_token"`, "qZ_token"},
	} {
		program, err := NewCompiler().CompileSource("rule probe { strings: $a = " + pattern.source + " condition: $a }")
		if err != nil {
			b.Fatal(err)
		}
		for _, size := range []int{64, 1024, 16384} {
			for _, density := range []string{"absent", "tail", "dense"} {
				b.Run(fmt.Sprintf("%s/%d/%s", pattern.name, size, density), func(b *testing.B) {
					data := bytes.Repeat([]byte("."), size)
					switch density {
					case "tail":
						copy(data[len(data)-len(pattern.match):], pattern.match)
					case "dense":
						for offset := 0; offset+len(pattern.match) <= len(data); offset += 16 {
							copy(data[offset:], pattern.match)
						}
					}
					scanner := NewScanner(program)
					defer scanner.Close()
					result, scanErr := scanner.Scan(data)
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					if result.RuleResults["probe"] != (density != "absent") {
						b.Fatal("incorrect scan result")
					}
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						if _, scanErr := scanner.Scan(data); scanErr != nil {
							b.Fatal(scanErr)
						}
					}
				})
			}
		}
	}
}

func BenchmarkSIMDRootScan(b *testing.B) {
	for _, rootCount := range []int{2, 4} {
		source := "rule probe { strings: "
		for index, lead := range "qvyz"[:rootCount] {
			source += fmt.Sprintf("$s%d = \"%c_marker\" ", index, lead)
		}
		program, err := NewCompiler().CompileSource(source + " condition: any of them }")
		if err != nil {
			b.Fatal(err)
		}
		for _, density := range []string{"absent", "tail", "dense_candidates"} {
			b.Run(fmt.Sprintf("roots=%d/%s", rootCount, density), func(b *testing.B) {
				data := bytes.Repeat([]byte("."), 16384)
				switch density {
				case "tail":
					copy(data[len(data)-8:], "q_marker")
				case "dense_candidates":
					data = bytes.Repeat([]byte("q---v---y---z---"), 1024)
				}
				scanner := NewScanner(program)
				defer scanner.Close()
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					result, scanErr := scanner.Scan(data)
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					if result.RuleResults["probe"] != (density == "tail") {
						b.Fatal("incorrect scan result")
					}
				}
			})
		}
	}
}
