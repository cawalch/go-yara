//go:build perfstudy

package compiler

import (
	"fmt"
	"testing"
)

func BenchmarkTwoStageSmallStudy(b *testing.B) {
	for _, count := range []int{2, 4, 8} {
		source, markers := twoStageStudySource("conjunction", count)
		program, err := NewCompiler().CompileSource(source)
		if err != nil {
			b.Fatal(err)
		}
		for _, traffic := range []string{"clean", "partial_near", "dense", "anchor_only", "no_markers"} {
			events := twoStageStudyCorpus("conjunction", markers, traffic)
			b.Run(fmt.Sprintf("conjunction/rules_%d/bytes_256/%s", count, traffic), func(b *testing.B) {
				scanner := program.NewScanner(WithFastScan())
				defer scanner.Close()
				for _, event := range events {
					if got, err := scanner.Matches(event); err != nil || got != (traffic == "dense") {
						b.Fatalf("fixture match=%v error=%v", got, err)
					}
				}
				b.ReportAllocs()
				b.SetBytes(256)
				index := 0
				for b.Loop() {
					got, err := scanner.Matches(events[index%len(events)])
					if err != nil {
						b.Fatal(err)
					}
					highEPSBoolSink = got
					index++
				}
			})
		}
	}
}
