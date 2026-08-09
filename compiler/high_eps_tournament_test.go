package compiler

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

var (
	highEPSBoolSink        bool
	highEPSResultSink      *ScanResult
	highEPSRuleMatchesSink []RuleMatch
	highEPSWorkerSink      atomic.Uint64
)

func BenchmarkHighEPSEventScan(b *testing.B) {
	portfolios := []string{"literal", "regex", "mixed"}
	ruleCounts := []int{100, 1_000, 10_000}
	eventSizes := []int{256, 1_024, 4_096}

	for _, portfolio := range portfolios {
		for _, ruleCount := range ruleCounts {
			name := fmt.Sprintf("%s/rules_%d", portfolio, ruleCount)
			b.Run(name, func(b *testing.B) {
				program, err := NewCompiler().CompileSource(highEPSRuleSource(portfolio, ruleCount))
				if err != nil {
					b.Fatalf("compile %s: %v", name, err)
				}

				for _, eventSize := range eventSizes {
					events := highEPSEvents(eventSize, 1_024)
					b.Run(fmt.Sprintf("bytes_%d", eventSize), func(b *testing.B) {
						b.Run("matches", func(b *testing.B) {
							scanner := NewScanner(program, WithFastScan())
							defer scanner.Close()
							b.ReportAllocs()
							b.SetBytes(int64(eventSize))
							index := 0
							b.ResetTimer()
							for b.Loop() {
								matched, err := scanner.Matches(events[index&1_023])
								if err != nil {
									b.Fatal(err)
								}
								highEPSBoolSink = matched
								index++
							}
						})

						b.Run("matching_rules", func(b *testing.B) {
							scanner := NewScanner(program, WithFastScan())
							defer scanner.Close()
							b.ReportAllocs()
							b.SetBytes(int64(eventSize))
							index := 0
							b.ResetTimer()
							for b.Loop() {
								matches, err := scanner.MatchingRules(events[index&1_023])
								if err != nil {
									b.Fatal(err)
								}
								highEPSRuleMatchesSink = matches
								index++
							}
						})

						b.Run("reported_scan", func(b *testing.B) {
							scanner := NewScanner(program, WithFastScan(), WithReportedMatchesOnly())
							defer scanner.Close()
							b.ReportAllocs()
							b.SetBytes(int64(eventSize))
							index := 0
							b.ResetTimer()
							for b.Loop() {
								result, err := scanner.Scan(events[index&1_023])
								if err != nil {
									b.Fatal(err)
								}
								highEPSResultSink = result
								index++
							}
						})
					})
				}
			})
		}
	}
}

func BenchmarkHighEPSEventParallel(b *testing.B) {
	const ruleCount = 1_000
	program, err := NewCompiler().CompileSource(highEPSRuleSource("mixed", ruleCount))
	if err != nil {
		b.Fatal(err)
	}

	for _, eventSize := range []int{256, 1_024, 4_096} {
		events := highEPSEvents(eventSize, 1_024)
		b.Run(fmt.Sprintf("bytes_%d", eventSize), func(b *testing.B) {
			var next atomic.Uint64
			b.ReportAllocs()
			b.SetBytes(int64(eventSize))
			b.RunParallel(func(pb *testing.PB) {
				scanner := NewScanner(program, WithFastScan())
				defer scanner.Close()
				matchedSink := false
				for pb.Next() {
					index := next.Add(1) - 1
					matched, err := scanner.Matches(events[index&1_023])
					if err != nil {
						b.Error(err)
						return
					}
					matchedSink = matched
				}
				if matchedSink {
					highEPSWorkerSink.Add(1)
				}
			})
		})
	}
}

func BenchmarkHighEPSSelectivity(b *testing.B) {
	const ruleCount = 10_000
	for _, portfolio := range []string{"literal", "regex", "mixed"} {
		program, err := NewCompiler().CompileSource(highEPSRuleSource(portfolio, ruleCount))
		if err != nil {
			b.Fatalf("compile %s: %v", portfolio, err)
		}
		for _, traffic := range []string{"clean", "sparse", "dense", "common_miss", "near_miss"} {
			events := highEPSPortfolioEvents(portfolio, ruleCount, 256, 1_024, traffic)
			b.Run(portfolio+"/"+traffic, func(b *testing.B) {
				scanner := NewScanner(program, WithFastScan())
				defer scanner.Close()
				b.ReportAllocs()
				b.SetBytes(256)
				index := 0
				b.ResetTimer()
				for b.Loop() {
					matched, scanErr := scanner.Matches(events[index&1_023])
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					highEPSBoolSink = matched
					index++
				}
			})
		}
	}
}

func BenchmarkHighEPSMatchingRulesSelectivity(b *testing.B) {
	const ruleCount = 10_000
	for _, portfolio := range []string{"literal", "regex", "mixed"} {
		program, err := NewCompiler().CompileSource(highEPSRuleSource(portfolio, ruleCount))
		if err != nil {
			b.Fatalf("compile %s: %v", portfolio, err)
		}
		for _, traffic := range []string{"sparse", "dense"} {
			events := highEPSPortfolioEvents(portfolio, ruleCount, 256, 1_024, traffic)
			b.Run(portfolio+"/"+traffic, func(b *testing.B) {
				scanner := NewScanner(program, WithFastScan())
				defer scanner.Close()
				b.ReportAllocs()
				b.SetBytes(256)
				index := 0
				b.ResetTimer()
				for b.Loop() {
					matches, scanErr := scanner.MatchingRules(events[index&1_023])
					if scanErr != nil {
						b.Fatal(scanErr)
					}
					highEPSRuleMatchesSink = matches
					index++
				}
			})
		}
	}
}

func BenchmarkHighEPSParallel10K(b *testing.B) {
	const ruleCount = 10_000
	for _, portfolio := range []string{"regex", "mixed"} {
		program, err := NewCompiler().CompileSource(highEPSRuleSource(portfolio, ruleCount))
		if err != nil {
			b.Fatalf("compile %s: %v", portfolio, err)
		}
		for _, traffic := range []string{"sparse", "dense"} {
			events := highEPSPortfolioEvents(portfolio, ruleCount, 256, 1_024, traffic)
			b.Run(portfolio+"/"+traffic, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(256)
				b.RunParallel(func(pb *testing.PB) {
					scanner := NewScanner(program, WithFastScan())
					defer scanner.Close()
					index := 0
					matchedSink := false
					for pb.Next() {
						matched, scanErr := scanner.Matches(events[index&1_023])
						if scanErr != nil {
							b.Error(scanErr)
							return
						}
						matchedSink = matched
						index++
					}
					if matchedSink {
						highEPSWorkerSink.Add(1)
					}
				})
			})
		}
	}
}

func BenchmarkHighEPSGateThenScan(b *testing.B) {
	const ruleCount = 10_000
	for _, portfolio := range []string{"literal", "regex", "mixed"} {
		program, err := NewCompiler().CompileSource(highEPSRuleSource(portfolio, ruleCount))
		if err != nil {
			b.Fatalf("compile %s: %v", portfolio, err)
		}
		for _, traffic := range []string{"sparse", "dense"} {
			events := highEPSPortfolioEvents(portfolio, ruleCount, 256, 1_024, traffic)
			b.Run(portfolio+"/"+traffic, func(b *testing.B) {
				scanner := NewScanner(program, WithFastScan(), WithReportedMatchesOnly())
				defer scanner.Close()
				b.ReportAllocs()
				b.SetBytes(256)
				index := 0
				b.ResetTimer()
				for b.Loop() {
					event := events[index&1_023]
					matched, matchErr := scanner.Matches(event)
					if matchErr != nil {
						b.Fatal(matchErr)
					}
					if matched {
						result, scanErr := scanner.Scan(event)
						if scanErr != nil {
							b.Fatal(scanErr)
						}
						highEPSResultSink = result
					}
					highEPSBoolSink = matched
					index++
				}
			})
		}
	}
}

func TestHighEPSEventCorpusParity(t *testing.T) {
	for _, portfolio := range []string{"literal", "regex", "mixed"} {
		t.Run(portfolio, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(highEPSRuleSource(portfolio, 100))
			if err != nil {
				t.Fatal(err)
			}
			scanner := NewScanner(program, WithFastScan(), WithReportedMatchesOnly())
			defer scanner.Close()
			events := highEPSEvents(256, 200)
			for index, event := range events {
				if index%100 == 0 && !bytes.Contains(event, []byte("sig_00000=deny_00000")) {
					t.Fatalf("positive fixture omitted literal marker: %q", event)
				}
				result, err := scanner.Scan(event)
				if err != nil {
					t.Fatalf("Scan event %d: %v", index, err)
				}
				matched, err := scanner.Matches(event)
				if err != nil {
					t.Fatalf("Matches event %d: %v", index, err)
				}
				want := index%100 == 0
				if matched != want || (len(result.MatchedRules) != 0) != want {
					t.Fatalf(
						"event %d: Matches=%v MatchedRules=%v, want match=%v",
						index,
						matched,
						result.MatchedRules,
						want,
					)
				}
			}
		})
	}
}

func highEPSRuleSource(portfolio string, ruleCount int) string {
	var source strings.Builder
	source.Grow(ruleCount * 128)
	for index := range ruleCount {
		switch portfolio {
		case "literal":
			fmt.Fprintf(&source, `rule literal_%05d {
  strings:
    $a = "sig_%05d=deny_%05d"
  condition:
    $a
}
`, index, index, index)
		case "regex":
			fmt.Fprintf(&source, `rule regex_%05d {
  strings:
    $a = /sig_%05d=[A-Z]{2}[0-9]{6}/
  condition:
    $a
}
`, index, index)
		case "mixed":
			switch index % 4 {
			case 0:
				fmt.Fprintf(&source, `rule mixed_literal_%05d {
  strings:
    $a = "sig_%05d=deny_%05d"
  condition:
    $a
}
`, index, index, index)
			case 1:
				fmt.Fprintf(&source, `rule mixed_regex_%05d {
  strings:
    $a = /sig_%05d=[A-Z]{2}[0-9]{6}/
  condition:
    $a
}
`, index, index)
			case 2:
				fmt.Fprintf(&source, `rule mixed_hex_%05d {
  strings:
    $a = { 53 49 47 %02X %02X [0-3] 44 45 4E 59 }
  condition:
    $a
}
`, index, byte(index>>8), byte(index))
			case 3:
				fmt.Fprintf(&source, `rule mixed_count_%05d {
  strings:
    $a = "count_%05d"
  condition:
    #a >= 2
}
`, index, index)
			}
		default:
			panic("unknown high-EPS portfolio: " + portfolio)
		}
	}
	return source.String()
}

func highEPSEvents(size, count int) [][]byte {
	events := make([][]byte, count)
	for index := range count {
		payload := ""
		if index%100 == 0 {
			payload = " sig_00000=deny_00000 sig_00001=AB123456 count_00003 count_00003"
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
			panic("high-EPS event size is too small")
		}
		event := make([]byte, 0, size)
		event = append(event, prefix...)
		event = append(event, strings.Repeat("x", filler)...)
		event = append(event, payload...)
		event = append(event, suffix...)
		events[index] = event
	}
	return events
}

//nolint:revive // benchmark fixture dimensions remain explicit at call sites
func highEPSPortfolioEvents(portfolio string, ruleCount, size, count int, traffic string) [][]byte {
	events := make([][]byte, count)
	for index := range events {
		positive := traffic == "dense" || traffic == "sparse" && index%100 == 0
		payload := ""
		if positive {
			ruleIndex := index % ruleCount
			switch portfolio {
			case "literal":
				payload = fmt.Sprintf(" sig_%05d=deny_%05d", ruleIndex, ruleIndex)
			case "regex":
				payload = fmt.Sprintf(" sig_%05d=AB123456", ruleIndex)
			case "mixed":
				ruleIndex = (ruleIndex/4)*4 + 1
				if ruleIndex >= ruleCount {
					ruleIndex = 1
				}
				payload = fmt.Sprintf(" sig_%05d=AB123456", ruleIndex)
			}
		} else {
			switch traffic {
			case "clean", "sparse", "dense":
			case "common_miss":
				payload = " sig_99999=AB123456"
			case "near_miss":
				payload = " sig_00000=ab12345x sig_00001=A1234567"
			default:
				panic("unknown high-EPS traffic: " + traffic)
			}
		}
		if payload == "" {
			events[index] = highEPSJSONEvent(size, index, "")
		} else {
			events[index] = highEPSJSONEvent(size, index, payload)
		}
	}
	return events
}

func highEPSJSONEvent(size, index int, payload string) []byte {
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
		panic("high-EPS event size is too small")
	}
	event := make([]byte, 0, size)
	event = append(event, prefix...)
	event = append(event, strings.Repeat("x", filler)...)
	event = append(event, payload...)
	event = append(event, suffix...)
	return event
}
