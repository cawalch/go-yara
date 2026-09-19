//go:build perfstudy

package compiler

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

var eventStudyPrefixes = []string{
	"AKIA", "ghp_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "sk_live_", "rk_live_",
	"AIza", "ya29.", "SG.", "sq0atp-", "shpat_", "hf_", "npm_", "pypi-",
	"dop_v1_", "DO00", "lin_api_", "tr_live_", "secret_key=", "authorization: Bearer ", "password=", "PRIVATE_KEY=",
}

func eventStudyProgram(tb testing.TB, kind string, count int) (*CompiledProgram, []string) {
	tb.Helper()
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
		pattern := fmt.Sprintf("%q", markers[n])
		if kind == "regex" {
			pattern = "/" + strings.ReplaceAll(stem, ".", `\.`) + "[A-Za-z0-9]{16}/"
		}
		if kind == "conjunction" {
			fmt.Fprintf(&source, "rule event_%d { strings: $common = \"status=200\" $specific = %s condition: $common and $specific }\n", n, pattern)
		} else {
			fmt.Fprintf(&source, "rule event_%d { strings: $value = %s condition: $value }\n", n, pattern)
		}
	}
	p, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		tb.Fatal(err)
	}
	return p, markers
}

func eventStudyCorpus(markers []string, size int, traffic string) [][]byte {
	messages := []string{
		"request completed successfully after retry; cache hit; upstream healthy; status=200",
		"user session refreshed; authorization: none; password=redacted; connection reused; status=200",
		"worker processed pending queue items; database transaction committed; status=200",
		"health check accepted from load balancer; memory and CPU below limits; status=200",
		"scheduled backup verified; object upload completed; response content-type application/json; status=200",
		"client disconnected normally; rate limit remaining; service configuration unchanged; status=200",
	}
	events := make([][]byte, 256)
	for n := range events {
		message := messages[n%len(messages)]
		marker := markers[(n*41)%len(markers)]
		switch traffic {
		case "sparse":
			if n%100 == 0 {
				message += " " + marker
			}
		case "dense":
			message += " " + marker
		case "near":
			message += " " + marker[:len(marker)-8] + "!!!!!!!!"
		}
		prefix := fmt.Sprintf(`{"ts":%d,"tenant":"team-%d","route":"/api/v2/items/%d","msg":"%s`, 1800000000+n, n%19, n*7, message)
		var out strings.Builder
		out.WriteString(prefix)
		for out.Len()+len(`"}`) < size {
			out.WriteByte(' ')
			if out.Len()+len(message)+2 < size {
				out.WriteString(message)
			}
		}
		out.WriteString(`"}`)
		events[n] = []byte(out.String())
	}
	return events
}

func BenchmarkEventStudy(b *testing.B) {
	for _, kind := range []string{"literal", "regex", "conjunction"} {
		for _, count := range []int{24, 256, 2048} {
			p, markers := eventStudyProgram(b, kind, count)
			for _, size := range []int{256, 1024} {
				for _, traffic := range []string{"clean", "near", "sparse", "dense"} {
					events := eventStudyCorpus(markers, size, traffic)
					b.Run(fmt.Sprintf("%s/rules_%d/bytes_%d/%s", kind, count, size, traffic), func(b *testing.B) {
						s := p.NewScanner(WithFastScan())
						defer s.Close()
						for _, event := range events {
							if _, err := s.Matches(event); err != nil {
								b.Fatal(err)
							}
						}
						b.ReportAllocs()
						b.SetBytes(int64(len(events[0])))
						n := 0
						for b.Loop() {
							matched, err := s.Matches(events[n&255])
							if err != nil {
								b.Fatal(err)
							}
							highEPSBoolSink = matched
							n++
						}
					})
				}
			}
		}
	}
}

func TestEventStudyParity(t *testing.T) {
	for _, kind := range []string{"literal", "regex", "conjunction"} {
		p, markers := eventStudyProgram(t, kind, 24)
		s := p.NewScanner(WithFastScan())
		defer s.Close()
		reference := p.NewScanner()
		defer reference.Close()
		reference.prefilterDisabled = true
		for _, traffic := range []string{"clean", "near", "sparse", "dense"} {
			for index, event := range eventStudyCorpus(markers, 256, traffic) {
				got, err := s.Matches(event)
				if err != nil {
					t.Fatal(err)
				}
				result, err := reference.Scan(event)
				if err != nil {
					t.Fatal(err)
				}
				want := traffic == "dense" || traffic == "sparse" && index%100 == 0
				if got != want || (len(result.MatchedRules) > 0) != want {
					t.Fatalf("%s/%s/%d got=%v rules=%v want=%v", kind, traffic, index, got, result.MatchedRules, want)
				}
			}
		}
	}
}

func BenchmarkRootThreshold(b *testing.B) {
	for _, roots := range []int{1, 2, 4} {
		var source strings.Builder
		source.WriteString("rule r { strings:")
		for i, pattern := range []string{"card_number", "mobile_phone", "password_value", "social_security"}[:roots] {
			fmt.Fprintf(&source, " $s%d=%q", i, pattern)
		}
		source.WriteString(" condition: any of them }")
		p, err := NewCompiler().CompileSource(source.String())
		if err != nil {
			b.Fatal(err)
		}
		for _, size := range []int{64, 128, 192, 256, 1024} {
			for _, traffic := range []string{"absent", "json", "dense"} {
				seed := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
				if traffic == "json" {
					seed = `{"level":"info","service":"payments","status":200,"message":"request completed"}`
				}
				if traffic == "dense" {
					seed = "cmpscmpscmpscmps"
				}
				data := []byte(strings.Repeat(seed, 1+size/len(seed))[:size])
				b.Run(fmt.Sprintf("roots_%d/bytes_%d/%s", roots, size, traffic), func(b *testing.B) { benchmarkScannerMatches(b, p, data) })
			}
		}
	}
}
