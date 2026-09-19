//go:build witnessstudy

package witness_test

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/experiments/witness"
)

// Supplemental coverage; these cases do not replace the original frozen gate.
type stressCase struct {
	family   string
	size     int
	positive bool
}

func (c stressCase) name() string {
	return fmt.Sprintf("%s/bytes_%d/positive_%v", c.family, c.size, c.positive)
}

func stressCases() []stressCase {
	var cases []stressCase
	for _, family := range []string{"short1", "short2", "mixed", "repeated"} {
		size := 256
		if family == "repeated" {
			size = 4096
		}
		for _, positive := range []bool{false, true} {
			cases = append(cases, stressCase{family, size, positive})
		}
	}
	for _, size := range []int{4096, 65536} {
		for _, positive := range []bool{false, true} {
			cases = append(cases, stressCase{"large_end", size, positive})
		}
	}
	return cases
}

func stressFixture(c stressCase) ([]witness.Rule, [][]byte) {
	var rules []witness.Rule
	var payloads []string
	anchor := "ANCHOR_REPEATED_0123456789AB"
	switch c.family {
	case "short1", "short2":
		for i := 0; i < 24; i++ {
			literal := string(rune('A' + i))
			if c.family == "short2" {
				literal = "A" + literal
			}
			rules = append(rules, witness.Rule{All: []witness.Pattern{witness.Text(literal)}})
			payloads = append(payloads, literal)
		}
	case "mixed":
		for _, pair := range [][2]string{{"!", "?"}, {"ABC", "DEF"}, {"LONGKEY", "NEXTKEY"}, {"LITERAL01234567", "ALTERNATE123456"}} {
			pattern := witness.Pattern{}
			for _, literal := range pair {
				pattern.Any = append(pattern.Any, witness.Sequence{witness.Literal(literal), witness.Bytes(2, 2, witness.ByteRange('0', '9')), witness.Literal("|")})
				payloads = append(payloads, literal+"12|")
			}
			rules = append(rules, witness.Rule{All: []witness.Pattern{pattern}})
		}
	case "repeated":
		for i := 0; i < 24; i++ {
			sequence := witness.Sequence{witness.Literal(anchor), witness.Bytes(4, 4, witness.ByteRange('0', '9')), witness.Bytes(2, 2, witness.ByteRange('A', 'Z')), witness.Literal(string(rune('A' + i)))}
			rules = append(rules, witness.Rule{All: []witness.Pattern{{Any: []witness.Sequence{sequence}}}})
		}
	case "large_end":
		for i := 0; i < 24; i++ {
			literal := "guard_" + marker("stress-v1", i)
			sequence := witness.Sequence{witness.Literal(literal), witness.Bytes(1, 8, witness.ByteRange('0', '9')), witness.Literal("!")}
			rules = append(rules, witness.Rule{All: []witness.Pattern{{Any: []witness.Sequence{sequence}}}})
			payloads = append(payloads, literal+strings.Repeat("7", 1+i%8)+"!")
		}
	}
	var events [][]byte
	for i := 0; i < 16; i++ {
		line := fmt.Sprintf("host=edge%02d;level=info;route=/v1/check;status=200;elapsed=42;result=ok;tick=!;\n", i)
		data := bytes.Repeat([]byte(line), (c.size+len(line)-1)/len(line))[:c.size]
		if c.family == "repeated" {
			payload := anchor + "1234zz#"
			if c.positive {
				payload = anchor + "1234ZZX"
			}
			repeated := bytes.Repeat([]byte(payload), (c.size+len(payload)-1)/len(payload))
			copy(data[i%8:], repeated)
		} else if c.positive {
			payload := payloads[i%len(payloads)]
			copy(data[len(data)-len(payload):], payload)
		}
		events = append(events, data)
	}
	return rules, events
}

func checkStressDecision(t testing.TB, name string, decision witness.Decision, positive bool) {
	t.Helper()
	if decision > witness.Unknown || decision == witness.Match && !positive || decision == witness.NoMatch && positive {
		t.Fatalf("%s: decision %v, expected match %v", name, decision, positive)
	}
}

func TestWitnessStressParity(t *testing.T) {
	for _, c := range stressCases() {
		t.Run(c.name(), func(t *testing.T) {
			rules, events := stressFixture(c)
			baseline, err := compiler.NewCompiler().CompileSource(yaraSource(rules))
			if err != nil {
				t.Fatal(err)
			}
			program, err := witness.Compile(rules)
			if err != nil {
				t.Fatal(err)
			}
			scanner := baseline.NewScanner(compiler.WithFastScan())
			defer scanner.Close()
			candidate := program.NewScanner()
			counts := [3]int{}
			for repeat := 0; repeat < 2; repeat++ {
				for _, event := range events {
					got, err := scanner.Matches(event)
					if err != nil || got != c.positive {
						t.Fatalf("baseline %v,%v; expected %v", got, err, c.positive)
					}
					decision := candidate.Match(event)
					checkStressDecision(t, c.name(), decision, c.positive)
					counts[decision]++
				}
			}
			t.Logf("stats=%+v no_match=%d match=%d unknown=%d", program.Stats(), counts[0], counts[1], counts[2])
		})
	}
}

func BenchmarkWitnessStress(b *testing.B) {
	for _, c := range stressCases() {
		rules, events := stressFixture(c)
		baseline, err := compiler.NewCompiler().CompileSource(yaraSource(rules))
		if err != nil {
			b.Fatal(err)
		}
		program, err := witness.Compile(rules)
		if err != nil {
			b.Fatal(err)
		}
		variants := []string{"baseline", "candidate", "hybrid"}
		if os.Getenv("WITNESS_REVERSE") == "1" {
			slices.Reverse(variants)
		}
		for _, variant := range variants {
			b.Run(c.name()+"/"+variant, func(b *testing.B) {
				scanner := baseline.NewScanner(compiler.WithFastScan())
				defer scanner.Close()
				candidate := program.NewScanner()
				match := candidate.Match
				unknown := 0
				for _, event := range events {
					decision := match(event)
					checkStressDecision(b, c.name(), decision, c.positive)
					if decision == witness.Unknown {
						unknown++
					}
					got, err := scanner.Matches(event)
					if err != nil || got != c.positive {
						b.Fatalf("baseline %v,%v; expected %v", got, err, c.positive)
					}
				}
				b.ReportAllocs()
				b.SetBytes(int64(c.size))
				i := 0
				for b.Loop() {
					data := events[i%len(events)]
					switch variant {
					case "candidate":
						decisionSink = match(data)
					case "hybrid":
						decision := match(data)
						if decision != witness.Unknown {
							boolSink = decision == witness.Match
							break
						}
						fallthrough
					default:
						got, err := scanner.Matches(data)
						if err != nil {
							b.Fatal(err)
						}
						boolSink = got
					}
					i++
				}
				if variant != "baseline" {
					b.ReportMetric(float64(unknown)/float64(len(events)), "unknown/op")
				}
			})
		}
	}
}
