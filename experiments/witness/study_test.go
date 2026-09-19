//go:build witnessstudy

package witness_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/experiments/witness"
)

type studyCase struct {
	split, family, traffic string
	count, size            int
}

func (c studyCase) name() string {
	return fmt.Sprintf("%s/%s/rules_%d/bytes_%d/%s", c.split, c.family, c.count, c.size, c.traffic)
}

func studyCases() []studyCase {
	var cases []studyCase
	for _, split := range []string{"training", "heldout"} {
		for _, count := range []int{24, 256, 2048} {
			for _, family := range []string{"literal", "conjunction", "complex"} {
				for _, traffic := range []string{"clean", "sparse", "dense"} {
					cases = append(cases, studyCase{split, family, traffic, count, 256})
				}
			}
			cases = append(cases, studyCase{split, "complex", "near", count, 256})
		}
		for _, count := range []int{24, 256} {
			for _, traffic := range []string{"sparse", "near"} {
				cases = append(cases, studyCase{split, "short", traffic, count, 256})
			}
		}
	}
	for _, traffic := range []string{"low_entropy", "common_suffix", "binary", "shuffled"} {
		cases = append(cases, studyCase{"heldout", "complex", traffic, 256, 256})
	}
	for _, size := range []int{4096, 65536} {
		for _, traffic := range []string{"sparse", "dense"} {
			cases = append(cases, studyCase{"heldout", "complex", traffic, 24, size})
		}
	}
	return cases
}

type studyFixture struct {
	rules    []witness.Rule
	source   string
	events   [][]byte
	positive []bool
	literals [][]byte
}

func marker(split string, n int) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("word-witness-v1/%s/%d", split, n)))
	return fmt.Sprintf("%x", digest[:10])
}

func studyFixtureFor(c studyCase) studyFixture {
	f := studyFixture{rules: make([]witness.Rule, c.count)}
	prefixes, suffixes := make([]string, c.count), make([]string, c.count)
	for n := range c.count {
		prefix, suffix := "token_"+marker(c.split, n), "_end_"+marker(c.split+"/suffix", n)[:12]
		if c.family == "short" {
			prefix, suffix = fmt.Sprintf("%02x", n%256), fmt.Sprintf("Z%03x", n)
		}
		if c.traffic == "low_entropy" || c.traffic == "common_suffix" {
			prefix = "AAAAAAAAAAAA" + fmt.Sprintf("%06x", n)
			suffix = "ZZZZZZZZZZZZ"
		}
		prefixes[n], suffixes[n] = prefix, suffix
		switch c.family {
		case "literal":
			f.rules[n].All = []witness.Pattern{witness.Text(prefix)}
			f.literals = append(f.literals, []byte(prefix))
		case "conjunction":
			f.rules[n].All = []witness.Pattern{witness.Text("status=200"), witness.Text(prefix)}
		default:
			sequence := witness.Sequence{witness.Literal(prefix), witness.Bytes(3, 5, witness.ByteRange('0', '9')), witness.Bytes(1, 3, witness.ByteRange('A', 'Z')), witness.Bytes(0, 3, witness.AllBytes()), witness.Literal(suffix)}
			alternative := append(witness.Sequence(nil), sequence...)
			alternative[0] = witness.Literal("alt_" + marker(c.split+"/alternative", n))
			f.rules[n].All = []witness.Pattern{{Any: []witness.Sequence{sequence, alternative}}}
		}
	}
	f.source = yaraSource(f.rules)
	seed := int64(27011)
	if c.split == "heldout" {
		seed = 918773
	}
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // frozen deterministic fixture
	for i := range 100 {
		n := (i*41 + 7) % c.count
		prefix, suffix := prefixes[n], suffixes[n]
		payload := ""
		positive := c.traffic == "dense" || c.traffic == "sparse" && i == 99
		if positive {
			payload = prefix
			if c.family != "literal" && c.family != "conjunction" {
				if i%2 == 1 {
					payload = "alt_" + marker(c.split+"/alternative", n)
				}
				payload += "1234AB_" + suffix
			}
		}
		switch c.traffic {
		case "near":
			payload = prefix + "1234AB_" + suffix[:len(suffix)-1] + "!"
		case "low_entropy":
			payload = strings.Repeat("A", 96) + "1234AB_ZZZZZZZZZZZ!"
		case "common_suffix":
			payload = "missing_prefix1234AB_" + suffix
		case "shuffled":
			payload = suffix + "1234AB_" + prefix
		}
		data := bytes.Repeat([]byte{' '}, c.size)
		if c.traffic == "binary" {
			_, _ = rng.Read(data)
		} else {
			copy(data, fmt.Sprintf("{\"node\":%d,\"message\":\"request complete status=200; cache=hit; ", i%11))
			offset := 80 + i%8
			if i%9 == 8 {
				offset = len(data) - len(payload)
			}
			copy(data[offset:], payload)
		}
		f.events = append(f.events, data)
		f.positive = append(f.positive, positive)
	}
	return f
}

func yaraSource(rules []witness.Rule) string {
	var source strings.Builder
	for i, rule := range rules {
		fmt.Fprintf(&source, "rule w%d { strings:\n", i)
		for j, pattern := range rule.All {
			if len(pattern.Any) == 1 && len(pattern.Any[0]) == 1 && len(pattern.Any[0][0].Literal) > 0 && !pattern.Any[0][0].NoCase {
				fmt.Fprintf(&source, "$s%d=%q\n", j, string(pattern.Any[0][0].Literal))
				continue
			}
			var alternatives []string
			for _, sequence := range pattern.Any {
				var expression strings.Builder
				for _, term := range sequence {
					if len(term.Literal) > 0 {
						for _, b := range term.Literal {
							if term.NoCase && (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z') {
								fmt.Fprintf(&expression, "[%c%c]", b|32, b&^32)
							} else {
								expression.WriteString(strings.ReplaceAll(regexp.QuoteMeta(string([]byte{b})), "/", `\/`))
							}
						}
					} else {
						expression.WriteByte('[')
						for b := 0; b < 256; b++ {
							if term.Set[b/64]&(uint64(1)<<uint(b%64)) == 0 {
								continue
							}
							first := b
							for b < 255 && term.Set[(b+1)/64]&(uint64(1)<<uint((b+1)%64)) != 0 {
								b++
							}
							fmt.Fprintf(&expression, `\x%02x`, first)
							if b > first {
								fmt.Fprintf(&expression, `-\x%02x`, b)
							}
						}
						fmt.Fprintf(&expression, "]{%d,%d}", term.Min, term.Max)
					}
				}
				alternatives = append(alternatives, expression.String())
			}
			fmt.Fprintf(&source, "$s%d=/(%s)/\n", j, strings.Join(alternatives, "|"))
		}
		source.WriteString("condition: all of them }\n")
	}
	return source.String()
}

var decisionSink witness.Decision
var boolSink bool

func BenchmarkWitnessStudy(b *testing.B) {
	for _, c := range studyCases() {
		f := studyFixtureFor(c)
		baseline, err := compiler.NewCompiler().CompileSource(f.source)
		if err != nil {
			b.Fatal(c.name(), err)
		}
		candidate, candidateErr := witness.Compile(f.rules)
		if candidateErr != nil {
			b.Logf("%s unsupported: %v", c.name(), candidateErr)
		}
		variants := []string{"baseline"}
		if candidateErr == nil {
			variants = append(variants, "candidate", "hybrid")
		}
		if c.family == "literal" {
			variants = append(variants, "naive")
		}
		if os.Getenv("WITNESS_REVERSE") == "1" {
			slices.Reverse(variants)
		}
		for _, variant := range variants {
			b.Run(c.name()+"/"+variant, func(b *testing.B) {
				scanner := baseline.NewScanner(compiler.WithFastScan())
				defer scanner.Close()
				var match func([]byte) witness.Decision
				unknown := 0
				if candidateErr == nil {
					candidateScanner := candidate.NewScanner()
					match = candidateScanner.Match
					for _, event := range f.events {
						if match(event) == witness.Unknown {
							unknown++
						}
					}
				}
				for i, event := range f.events {
					got, err := scanner.Matches(event)
					if err != nil || got != f.positive[i] {
						b.Fatalf("baseline fixture %d: %v,%v want %v", i, got, err, f.positive[i])
					}
				}
				b.ReportAllocs()
				b.SetBytes(int64(c.size))
				i := 0
				for b.Loop() {
					data := f.events[i%len(f.events)]
					switch variant {
					case "candidate":
						decisionSink = match(data)
					case "hybrid":
						decision := match(data)
						if decision == witness.Unknown {
							got, err := scanner.Matches(data)
							if err != nil {
								b.Fatal(err)
							}
							boolSink = got
						} else {
							boolSink = decision == witness.Match
						}
					case "naive":
						got := false
						for _, literal := range f.literals {
							if bytes.Contains(data, literal) {
								got = true
								break
							}
						}
						boolSink = got
					default:
						got, err := scanner.Matches(data)
						if err != nil {
							b.Fatal(err)
						}
						boolSink = got
					}
					i++
				}
				if variant == "candidate" || variant == "hybrid" {
					b.ReportMetric(float64(unknown)/float64(len(f.events)), "unknown/op")
				}
			})
		}
	}
}

func TestWitnessStudyParity(t *testing.T) {
	for _, c := range studyCases() {
		t.Run(c.name(), func(t *testing.T) {
			f := studyFixtureFor(c)
			baseline, err := compiler.NewCompiler().CompileSource(f.source)
			if err != nil {
				t.Fatal(err)
			}
			program, candidateErr := witness.Compile(f.rules)
			match := func([]byte) witness.Decision { return witness.Unknown }
			if candidateErr != nil {
				t.Logf("unsupported: %v", candidateErr)
			} else {
				match = program.NewScanner().Match
				t.Logf("stats=%+v", program.Stats())
			}
			scanner := baseline.NewScanner(compiler.WithFastScan())
			defer scanner.Close()
			counts := [3]int{}
			for i, event := range f.events {
				want, err := scanner.Matches(event)
				if err != nil || want != f.positive[i] {
					t.Fatalf("baseline fixture %d: %v,%v want %v", i, want, err, f.positive[i])
				}
				got := match(event)
				if got > witness.Unknown || got == witness.Match && !want || got == witness.NoMatch && want {
					t.Fatalf("event %d: decision %v, baseline %v", i, got, want)
				}
				counts[got]++
			}
			t.Logf("coverage no_match=%d match=%d unknown=%d", counts[0], counts[1], counts[2])
		})
	}
}

func TestWitnessStudyCoverage(t *testing.T) {
	for name, sequence := range map[string]witness.Sequence{
		"no_anchor":    {witness.Bytes(3, 6, witness.ByteRange('0', '9'))},
		"short_anchor": {witness.Literal("A"), witness.Bytes(0, 3, witness.AllBytes()), witness.Literal("Z")},
		"nocase":       {{Literal: []byte("LongCaseFoldAnchor"), NoCase: true}, witness.Bytes(1, 4, witness.ByteRange('0', '9'))},
	} {
		t.Run(name, func(t *testing.T) {
			rules := []witness.Rule{{All: []witness.Pattern{{Any: []witness.Sequence{sequence}}}}}
			program, err := witness.Compile(rules)
			if err != nil {
				t.Logf("unsupported: %v", err)
				return
			}
			baseline, err := compiler.NewCompiler().CompileSource(yaraSource(rules))
			if err != nil {
				t.Fatal(err)
			}
			scanner := program.NewScanner()
			for _, input := range []string{"", "1234", "A12Z", "LONGCASEFOLDANCHOR12", "longcasefoldanchor9", "LongCaseFoldAnchor!", "A1234Z"} {
				got := scanner.Match([]byte(input))
				want, err := baseline.Matches([]byte(input))
				if err != nil || got > witness.Unknown || got == witness.Match && !want || got == witness.NoMatch && want {
					t.Fatalf("%q: decision %v, baseline %v,%v", input, got, want, err)
				}
				t.Logf("%q: %v", input, got)
			}
		})
	}
}

func BenchmarkWitnessCompile(b *testing.B) {
	for _, family := range []string{"literal", "conjunction", "complex"} {
		for _, count := range []int{24, 256, 2048} {
			f := studyFixtureFor(studyCase{"heldout", family, "clean", count, 256})
			for _, variant := range []string{"baseline", "candidate"} {
				b.Run(fmt.Sprintf("%s/rules_%d/%s", family, count, variant), func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if variant == "baseline" {
							program, err := compiler.NewCompiler().CompileSource(f.source)
							if err != nil {
								b.Fatal(err)
							}
							runtime.KeepAlive(program)
						} else {
							program, err := witness.Compile(f.rules)
							if err != nil {
								b.Skipf("unsupported: %v", err)
							}
							runtime.KeepAlive(program)
						}
					}
				})
			}
		}
	}
}

func TestWitnessStudyMemory(t *testing.T) {
	for _, family := range []string{"literal", "conjunction", "complex"} {
		for _, count := range []int{24, 256, 2048} {
			f := studyFixtureFor(studyCase{"heldout", family, "clean", count, 256})
			for _, variant := range []string{"baseline", "candidate"} {
				t.Run(fmt.Sprintf("%s/rules_%d/%s", family, count, variant), func(t *testing.T) {
					runtime.GC()
					var before, after runtime.MemStats
					runtime.ReadMemStats(&before)
					var retained any
					if variant == "baseline" {
						program, err := compiler.NewCompiler().CompileSource(f.source)
						if err != nil {
							t.Fatal(err)
						}
						retained = program
					} else {
						program, err := witness.Compile(f.rules)
						if err != nil {
							t.Skipf("unsupported: %v", err)
						}
						retained = program
					}
					runtime.GC()
					runtime.ReadMemStats(&after)
					t.Logf("program_heap_B=%d compile_alloc_B=%d compile_allocs=%d", int64(after.HeapAlloc)-int64(before.HeapAlloc), after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs)
					if program, ok := retained.(*witness.Program); ok {
						t.Logf("stats=%+v", program.Stats())
					}
					runtime.KeepAlive(retained)
					runtime.KeepAlive(f)
				})
			}
		}
	}
}
