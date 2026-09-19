//go:build perfstudy

package compiler

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func twoStageStudySource(kind string, count int) (string, []string) {
	var source strings.Builder
	markers := make([]string, count)
	for n := range count {
		stem := fmt.Sprintf("%s%04x", eventStudyPrefixes[n%len(eventStudyPrefixes)], n*37+11)
		digest := sha256.Sum256([]byte(stem))
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		token := make([]byte, 16)
		for i := range token {
			token[i] = alphabet[int(digest[i])%len(alphabet)]
		}
		markers[n] = stem + string(token)
		role := 0
		if kind == "mixed" {
			role = n % 4
		}
		switch role {
		case 0:
			fmt.Fprintf(&source, "rule event_%d {strings:$common=\"status=200\" $specific=%q condition:$common and $specific}\n", n, markers[n])
		case 1:
			fmt.Fprintf(&source, "rule event_%d {strings:$value=%q condition:$value}\n", n, markers[n])
		case 2:
			fmt.Fprintf(&source, "rule event_%d {strings:$value=/%s[A-Za-z0-9]{16}/ condition:$value}\n", n, strings.ReplaceAll(stem, ".", `\.`))
		case 3:
			fmt.Fprintf(&source, "rule event_%d {strings:$value=%q condition:#value>=2}\n", n, markers[n])
		}
	}
	return source.String(), markers
}

func twoStageStudyCorpus(kind string, markers []string, traffic string) [][]byte {
	messages := []string{
		"request completed after retry; upstream=checkout; cache=hit",
		"session refreshed; user=service-account; mfa=verified",
		"queue item processed; transaction committed; worker=jobs",
		"health check accepted; memory=normal; cpu=normal",
		"backup verified; object upload completed; storage=archive",
		"client disconnected normally; rate_limit=available",
	}
	events := make([][]byte, 100)
	for n := range events {
		index := (n*41 + 7) % len(markers)
		if traffic == "late_positive" {
			index = len(markers) - 1
		}
		status := "status=200"
		if traffic == "anchor_only" || traffic == "no_markers" {
			status = "status=201"
		}
		payload := ""
		switch traffic {
		case "partial_near":
			payload = markers[index][:len(markers[index])-1] + "!"
		case "sparse":
			if n == 99 {
				payload = markers[index]
			}
		case "dense", "late_positive", "anchor_only":
			payload = markers[index]
		}
		if payload != "" && kind == "mixed" && index%4 == 3 {
			payload += " " + payload
		}
		prefix := fmt.Sprintf(`{"seq":%d,"host":"node-%d","msg":"%s; %s `, n, n%11, messages[n%len(messages)], status)
		padding := 256 - len(prefix) - len(payload) - 2
		if padding < 0 {
			panic("two-stage fixture exceeds256bytes")
		}
		if traffic == "late_positive" {
			events[n] = []byte(prefix + strings.Repeat(" ", padding) + payload + `"}`)
		} else {
			events[n] = []byte(prefix + payload + strings.Repeat(" ", padding) + `"}`)
		}
	}
	return events
}

func BenchmarkTwoStageStudy(b *testing.B) {
	for _, kind := range []string{"conjunction", "mixed"} {
		for _, count := range []int{24, 256, 2048} {
			source, markers := twoStageStudySource(kind, count)
			program, err := NewCompiler().CompileSource(source)
			if err != nil {
				b.Fatal(err)
			}
			for _, traffic := range []string{"clean", "partial_near", "sparse", "dense", "anchor_only", "late_positive", "no_markers"} {
				events := twoStageStudyCorpus(kind, markers, traffic)
				b.Run(fmt.Sprintf("%s/rules_%d/bytes_256/%s", kind, count, traffic), func(b *testing.B) {
					scanner := program.NewScanner(WithFastScan())
					defer scanner.Close()
					for _, event := range events {
						if _, err := scanner.Matches(event); err != nil {
							b.Fatal(err)
						}
					}
					b.ReportAllocs()
					b.SetBytes(256)
					index := 0
					for b.Loop() {
						hit, err := scanner.Matches(events[index%len(events)])
						if err != nil {
							b.Fatal(err)
						}
						highEPSBoolSink = hit
						index++
					}
				})
			}
		}
	}
}

func BenchmarkTwoStageCompile(b *testing.B) {
	for _, kind := range []string{"conjunction", "mixed"} {
		for _, count := range []int{24, 256, 2048} {
			source, _ := twoStageStudySource(kind, count)
			b.Run(fmt.Sprintf("%s/rules_%d", kind, count), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					program, err := NewCompiler().CompileSource(source)
					if err != nil {
						b.Fatal(err)
					}
					runtime.KeepAlive(program)
				}
			})
		}
	}
}

func TestTwoStageStudyParity(t *testing.T) {
	for _, kind := range []string{"conjunction", "mixed"} {
		source, markers := twoStageStudySource(kind, 24)
		program, err := NewCompiler().CompileSource(source)
		if err != nil {
			t.Fatal(err)
		}
		fast := program.NewScanner(WithFastScan())
		defer fast.Close()
		reference := program.NewScanner()
		defer reference.Close()
		reference.prefilterDisabled = true
		for _, traffic := range []string{"clean", "partial_near", "sparse", "dense", "anchor_only", "late_positive", "no_markers"} {
			positives := 0
			for index, event := range twoStageStudyCorpus(kind, markers, traffic) {
				if len(event) != 256 {
					t.Fatalf("event length%d", len(event))
				}
				got, err := fast.Matches(event)
				if err != nil {
					t.Fatal(err)
				}
				report, err := reference.Scan(event)
				if err != nil {
					t.Fatal(err)
				}
				want := traffic == "dense" || traffic == "late_positive" || traffic == "sparse" && index == 99 || traffic == "anchor_only" && kind == "mixed" && ((index*41+7)%len(markers))%4 != 0
				if got != want || (len(report.MatchedRules) > 0) != want {
					t.Fatalf("%s/%s/%d: got%v rules%v want%v", kind, traffic, index, got, report.MatchedRules, want)
				}
				if got {
					positives++
				}
			}
			if traffic == "sparse" && positives != 1 {
				t.Fatal("sparse fixture must have exactly1%matches")
			}
		}
	}
}

func TestTwoStageStudyReuse(t *testing.T) {
	source, markers := twoStageStudySource("conjunction", 24)
	source += `rule metadata {strings:$source="status=200" $count="counted" condition:$source and #count>=2}
rule modifiers {strings:$common="status=200" $specific="admin_token" fullword nocase condition:all of them}
rule encodings {strings:$common="status=200" $specific="wide_token" ascii wide condition:all of them}`
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	reference := program.NewScanner()
	defer reference.Close()
	reference.prefilterDisabled = true
	events := [][]byte{
		[]byte("status=200"), []byte(markers[23]), []byte("status=200 " + markers[23]),
		[]byte("status=200 counted counted"), []byte("status=200 counted"),
		[]byte("status=200 " + markers[0]), []byte("status=200"), nil,
		[]byte("status=200 xADMIN_TOKENx"), []byte("status=200 ADMIN_TOKEN"),
		[]byte("status=200 wide_token"), []byte("status=200 w\x00i\x00d\x00e\x00_\x00t\x00o\x00k\x00e\x00n\x00"),
	}
	for round := 0; round < 3; round++ {
		for _, event := range events {
			expected, err := reference.Scan(event)
			if err != nil {
				t.Fatal(err)
			}
			got, err := scanner.Matches(event)
			if err != nil || got != (len(expected.MatchedRules) > 0) {
				t.Fatalf("Matches(%q)=%v,%v", event, got, err)
			}
			full, err := scanner.Scan(event)
			if err != nil || !reflect.DeepEqual(full, expected) {
				t.Fatalf("Scan after compact(%q) differs:%v", event, err)
			}
			rules, err := scanner.MatchingRules(event)
			if err != nil {
				t.Fatal(err)
			}
			wantRules, err := reference.MatchingRules(event)
			if err != nil || !reflect.DeepEqual(rules, wantRules) {
				t.Fatalf("MatchingRules(%q) differs:%v", event, err)
			}
			scanner.reportedMatchesOnly = true
			compact, err := scanner.Scan(event)
			scanner.reportedMatchesOnly = false
			if err != nil || !reflect.DeepEqual(compact.MatchedRules, expected.MatchedRules) {
				t.Fatalf("reported Scan(%q) differs:%v", event, err)
			}
		}
	}
}

func TestTwoStageStudyMemory(t *testing.T) {
	for _, kind := range []string{"conjunction", "mixed"} {
		for _, count := range []int{24, 256, 2048} {
			t.Run(fmt.Sprintf("%s/rules_%d", kind, count), func(t *testing.T) {
				source, markers := twoStageStudySource(kind, count)
				runtime.GC()
				var before, compiled, warmed runtime.MemStats
				runtime.ReadMemStats(&before)
				program, err := NewCompiler().CompileSource(source)
				if err != nil {
					t.Fatal(err)
				}
				runtime.GC()
				runtime.ReadMemStats(&compiled)
				scanner := program.NewScanner(WithFastScan())
				defer scanner.Close()
				event := twoStageStudyCorpus(kind, markers, "clean")[0]
				if _, err := scanner.Matches(event); err != nil {
					t.Fatal(err)
				}
				runtime.GC()
				runtime.ReadMemStats(&warmed)
				t.Logf("program_heap_B=%d warmed_scanner_heap_B=%d compile_alloc_B=%d compile_allocs=%d", int64(compiled.HeapAlloc)-int64(before.HeapAlloc), int64(warmed.HeapAlloc)-int64(compiled.HeapAlloc), compiled.TotalAlloc-before.TotalAlloc, compiled.Mallocs-before.Mallocs)
				runtime.KeepAlive(program)
				runtime.KeepAlive(scanner)
			})
		}
	}
}

func twoStageStudyLateRecord(markers []string, size int) []byte {
	prefix := `{"service":"checkout","msg":"status=200 `
	marker := markers[len(markers)-1]
	width := size - len(prefix) - len(marker) - 2
	filler := "routine event detail; request completed; "
	padding := strings.Repeat(filler, 1+width/len(filler))[:width]
	return []byte(prefix + padding + marker + `"}`)
}

func BenchmarkTwoStageLatePositive(b *testing.B) {
	for _, count := range []int{24, 256, 2048} {
		source, markers := twoStageStudySource("conjunction", count)
		program, err := NewCompiler().CompileSource(source)
		if err != nil {
			b.Fatal(err)
		}
		for _, size := range []int{4096, 65536} {
			data := twoStageStudyLateRecord(markers, size)
			b.Run(fmt.Sprintf("conjunction/rules_%d/bytes_%d", count, size), func(b *testing.B) {
				scanner := program.NewScanner(WithFastScan())
				defer scanner.Close()
				if got, err := scanner.Matches(data); err != nil || !got {
					b.Fatalf("late positive=%v,%v", got, err)
				}
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					hit, err := scanner.Matches(data)
					if err != nil {
						b.Fatal(err)
					}
					highEPSBoolSink = hit
				}
			})
		}
	}
}

func TestTwoStageStudyLateParity(t *testing.T) {
	source, markers := twoStageStudySource("conjunction", 24)
	program, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner(WithFastScan())
	defer scanner.Close()
	reference := program.NewScanner()
	defer reference.Close()
	reference.prefilterDisabled = true
	for _, size := range []int{4096, 65536} {
		data := twoStageStudyLateRecord(markers, size)
		text := string(data)
		if len(data) != size || strings.Count(text, "status=200") != 1 || strings.Count(text, markers[len(markers)-1]) != 1 || !strings.HasSuffix(text, markers[len(markers)-1]+`"}`) {
			t.Fatal("late-positive fixture changed")
		}
		got, err := scanner.Matches(data)
		if err != nil || !got {
			t.Fatalf("late positive=%v,%v", got, err)
		}
		report, err := reference.Scan(data)
		if err != nil || len(report.MatchedRules) != 1 || report.MatchedRules[0].Rule != "event_23" {
			t.Fatalf("late reference=%+v,%v", report, err)
		}
	}
}
