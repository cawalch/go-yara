//go:build witnessstudy

package witness_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/experiments/witness"
)

type routingCase struct {
	family, traffic string
	count, size     int
}

func (c routingCase) name() string {
	return fmt.Sprintf("%s/rules_%d/bytes_%d/%s", c.family, c.count, c.size, c.traffic)
}

func routingCases() []routingCase {
	var cases []routingCase
	for _, count := range []int{24, 256, 2048} {
		for _, family := range []string{"literal", "conjunction", "complex"} {
			cases = append(cases, routingCase{family, "sparse", count, 256})
		}
		for _, family := range []string{"shared_tail", "shared_context"} {
			cases = append(cases, routingCase{family, "near", count, 256})
		}
	}
	cases = append(cases, routingCase{"shared_prefix", "near", 256, 256})
	for _, traffic := range []string{"near", "positive"} {
		cases = append(cases, routingCase{"repeated", traffic, 256, 4096})
	}
	for _, family := range []string{"short1", "short2", "mixed_short"} {
		for _, traffic := range []string{"clean", "positive"} {
			cases = append(cases, routingCase{family, traffic, 24, 256})
		}
	}
	for _, size := range []int{4096, 65536} {
		for _, traffic := range []string{"clean", "late"} {
			cases = append(cases, routingCase{"complex", traffic, 24, size})
		}
	}
	return append(cases, routingCase{"complex", "binary", 256, 256}, routingCase{"nocase", "sparse", 256, 256},
		routingCase{"irreducible", "near", 256, 256}, routingCase{"conjunction", "shuffled", 256, 256})
}

type routingFixture struct {
	rules    []witness.Rule
	events   [][]byte
	positive []bool
}

const routingShared = "universalSessionContextAnchor"
const routingTail = "synchronizationCheckpointSharedTail"

func routingMarker(label string, n int) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("routing-new-corpus-v1/%s/%d", label, n)))
	const alphabet = "ghjkmnpqrstuvwxyzGHJKMNPQRSTUVWXYZ"
	word := make([]byte, 24)
	for i := range word {
		word[i] = alphabet[int(digest[i])%len(alphabet)]
	}
	return string(word)
}

func routingContext(n int) string {
	a, b, c := n%26, n/26%26, n/(26*26)
	return string([]byte{byte('A' + a), byte('A' + (a*7+b)%26), byte('A' + (a*11+c)%26)})
}

func routingFixtureFor(c routingCase) routingFixture {
	f := routingFixture{rules: make([]witness.Rule, c.count)}
	payloads := make([]string, c.count)
	for n := range c.count {
		word, tail := routingMarker("anchor", n), routingMarker("suffix", n)
		var patterns []witness.Pattern
		switch c.family {
		case "literal":
			patterns, payloads[n] = []witness.Pattern{witness.Text(word)}, word
		case "nocase":
			patterns = []witness.Pattern{{Any: []witness.Sequence{{{Literal: []byte(word), NoCase: true}}}}}
			payloads[n] = strings.ToUpper(word)
		case "conjunction":
			patterns, payloads[n] = []witness.Pattern{witness.Text("accepted"), witness.Text(word)}, word
		case "shared_tail":
			patterns, payloads[n] = []witness.Pattern{witness.Text(word + routingTail)}, word+routingTail
		case "shared_prefix":
			patterns, payloads[n] = []witness.Pattern{witness.Text(routingTail + word)}, routingTail+word
		case "shared_context", "repeated", "irreducible":
			sequence := witness.Sequence{witness.Literal(routingShared)}
			if c.family == "irreducible" {
				sequence = append(sequence, witness.Bytes(0, 5, witness.AllBytes()))
			}
			for _, b := range []byte(routingContext(n)) {
				sequence = append(sequence, witness.Bytes(1, 1, witness.ByteRange(b, b)))
			}
			patterns, payloads[n] = []witness.Pattern{{Any: []witness.Sequence{sequence}}}, routingShared+routingContext(n)
		case "short1", "short2", "mixed_short":
			literal := string(rune('A' + n))
			if c.family == "short2" {
				literal = "Q" + literal
			}
			if c.family == "mixed_short" && n > 0 {
				literal = word
			}
			patterns, payloads[n] = []witness.Pattern{witness.Text(literal)}, literal
		default:
			sequence := witness.Sequence{witness.Literal(word), witness.Bytes(2, 6, witness.ByteRange('0', '9')),
				witness.Bytes(1, 2, witness.ByteRange('a', 'z')), witness.Bytes(0, 4, witness.AllBytes()), witness.Literal(tail)}
			alternative := append(witness.Sequence(nil), sequence...)
			alternative[0] = witness.Literal(routingMarker("alternative", n))
			patterns = []witness.Pattern{{Any: []witness.Sequence{sequence, alternative}}}
			if n%2 == 1 {
				word = string(alternative[0].Literal)
			}
			payloads[n] = word + "725xy:_" + tail
		}
		f.rules[n].All = patterns
	}
	rng := rand.New(rand.NewSource(63489117)) //nolint:gosec // deterministic frozen data
	for i := range 100 {
		n := (i*67 + 19) % c.count
		positive := c.traffic == "positive" || c.traffic == "late" || c.traffic == "sparse" && i == 99
		payload := "routine"
		if positive {
			payload = payloads[n]
		}
		if c.traffic == "near" {
			switch c.family {
			case "shared_tail":
				payload = "wrongPrefix" + routingTail
			case "shared_prefix":
				payload = routingTail + "wrongSuffix"
			default:
				context := []byte(routingContext(n))
				context[2] = 'A' + (context[2]-'A'+13)%26
				payload = routingShared + string(context)
			}
		}
		if c.traffic == "shuffled" {
			// AND permits reordering; this is intentionally a positive control.
			payload, positive = payloads[n]+" accepted", true
		}
		prefix, suffix := routingLog(i)
		if c.traffic == "shuffled" {
			prefix = strings.ReplaceAll(prefix, "accepted", "pending")
		}
		data := bytes.Repeat([]byte{' '}, c.size)
		copy(data, prefix)
		offset := len(prefix) + i%8
		if c.traffic == "late" || i%9 == 8 {
			offset = len(data) - len(payload) - len(suffix)
		}
		copy(data[offset:], payload)
		copy(data[offset+len(payload):], suffix)
		if c.family == "repeated" {
			copy(data[len(prefix):], bytes.Repeat([]byte(payload+";"), c.size/(len(payload)+1)+1))
		}
		if c.traffic == "binary" {
			_, _ = rng.Read(data)
		}
		f.events, f.positive = append(f.events, data), append(f.positive, positive)
	}
	return f
}

func routingLog(i int) (string, string) {
	switch i % 8 {
	case 0:
		return fmt.Sprintf(`{"host":"edge%d","message":"accepted `, i%13), `"}`
	case 1:
		return "<30>sep 20 03:11:07 worker svc: accepted ", "\n"
	case 2:
		return fmt.Sprintf("ts=1900 level=info accepted seq=%d msg=", i), "\n"
	case 3:
		return "2026-09-20,checkout,accepted,\"", "\"\n"
	case 4:
		return "request\taccepted\tcache-hit\t", "\n"
	case 5:
		return "10.2.3.4 - svc [20/sep/2026] accepted \"", "\" 200\n"
	case 6:
		return fmt.Sprintf(`{"seq":%d,"accepted":true,"detail":"`, i), `"}`
	default:
		return "health-check accepted detail=", ""
	}
}

func TestWitnessRoutingParity(t *testing.T) {
	if len(routingCases()) != 32 {
		t.Fatal("frozen matrix must contain 32 cases")
	}
	for _, c := range routingCases() {
		t.Run(c.name(), func(t *testing.T) { checkRoutingFixture(t, routingFixtureFor(c)) })
	}
}

func checkRoutingFixture(t *testing.T, f routingFixture) {
	t.Helper()
	baseline, err := compiler.NewCompiler().CompileSource(yaraSource(f.rules))
	if err != nil {
		t.Fatal(err)
	}
	v1, err := witness.Compile(f.rules)
	if err != nil {
		t.Fatal(err)
	}
	routed, err := witness.CompileRouted(f.rules)
	if err != nil && !errors.Is(err, witness.ErrIneligible) {
		t.Fatal(err)
	}
	eligible := err == nil
	scanner := baseline.NewScanner(compiler.WithFastScan())
	defer scanner.Close()
	legacy := v1.NewScanner()
	var route func([]byte) witness.Decision
	if eligible {
		route = routed.NewScanner().Match
	}
	unknown := [2]int{}
	for repeat := range 2 {
		for i, event := range f.events {
			want, err := scanner.Matches(event)
			if err != nil || want != f.positive[i] {
				t.Fatalf("baseline repeat=%d event=%d: %v,%v want %v", repeat, i, want, err, f.positive[i])
			}
			decision := legacy.Match(event)
			checkStressDecision(t, "v1", decision, want)
			if decision == witness.Unknown {
				unknown[0]++
			}
			if eligible {
				decision = route(event)
				checkStressDecision(t, "routed", decision, want)
				if decision == witness.Unknown {
					unknown[1]++
				}
			}
		}
	}
	stats := witness.RoutingStats{}
	if eligible {
		stats = routed.Stats()
	}
	t.Logf("eligible=%v v1_unknown=%d routed_unknown=%d events=%d stats=%+v", eligible, unknown[0], unknown[1], 2*len(f.events), stats)
}

func BenchmarkWitnessRouting(b *testing.B) {
	for _, c := range routingCases() {
		benchmarkRoutingFixture(b, c.name(), c.size, routingFixtureFor(c))
	}
}

//nolint:revive // frozen benchmark dimensions and fixture are independent
func benchmarkRoutingFixture(b *testing.B, name string, size int, f routingFixture) {
	baseline, err := compiler.NewCompiler().CompileSource(yaraSource(f.rules))
	if err != nil {
		b.Fatal(err)
	}
	v1, err := witness.Compile(f.rules)
	if err != nil {
		b.Fatal(err)
	}
	routed, err := witness.CompileRouted(f.rules)
	if err != nil && !errors.Is(err, witness.ErrIneligible) {
		b.Fatal(err)
	}
	eligible := err == nil
	variants := []string{"baseline", "v1", "routed"}
	if os.Getenv("WITNESS_REVERSE") == "1" {
		slices.Reverse(variants)
	}
	for _, variant := range variants {
		b.Run(name+"/"+variant, func(b *testing.B) {
			scanner := baseline.NewScanner(compiler.WithFastScan())
			defer scanner.Close()
			match := v1.NewScanner().Match
			execution := variant
			if variant == "routed" {
				if eligible {
					match = routed.NewScanner().Match
				} else {
					execution = "baseline"
				}
			}
			unknown := 0
			for i, event := range f.events {
				got, err := scanner.Matches(event)
				if err != nil || got != f.positive[i] {
					b.Fatalf("fixture %d: %v,%v want %v", i, got, err, f.positive[i])
				}
				if execution != "baseline" {
					decision := match(event)
					checkStressDecision(b, variant, decision, got)
					if decision == witness.Unknown {
						unknown++
					}
				}
			}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			i := 0
			for b.Loop() {
				data := f.events[i%len(f.events)]
				if execution == "baseline" {
					got, err := scanner.Matches(data)
					if err != nil {
						b.Fatal(err)
					}
					boolSink = got
				} else {
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
				}
				i++
			}
			if variant != "baseline" {
				b.ReportMetric(float64(unknown)/float64(len(f.events)), "unknown/op")
			}
			if variant == "routed" {
				coverage := 0.0
				if eligible {
					coverage = 1
				}
				b.ReportMetric(coverage, "eligible/op")
				nodes := 0
				if eligible {
					nodes = routed.Stats().Nodes
				}
				b.ReportMetric(float64(nodes), "nodes/op")
			}
		})
	}
}

func routingResourceCases() []routingCase {
	var cases []routingCase
	for _, family := range []string{"complex", "shared_tail", "shared_context"} {
		for _, count := range []int{24, 256, 2048} {
			cases = append(cases, routingCase{family, "near", count, 256})
		}
	}
	return cases
}

func compileRoutingResource(variant string, rules []witness.Rule, source string) (any, error) {
	switch variant {
	case "baseline":
		return compiler.NewCompiler().CompileSource(source)
	case "v1":
		return witness.Compile(rules)
	default:
		return witness.CompileRouted(rules)
	}
}

func BenchmarkWitnessRoutingCompile(b *testing.B) {
	for _, c := range routingResourceCases() {
		f := routingFixtureFor(c)
		source := yaraSource(f.rules)
		for _, variant := range []string{"baseline", "v1", "routed"} {
			b.Run(fmt.Sprintf("%s/rules_%d/%s", c.family, c.count, variant), func(b *testing.B) {
				b.ReportAllocs()
				eligible, nodes := 1.0, 0
				for b.Loop() {
					program, err := compileRoutingResource(variant, f.rules, source)
					if err != nil {
						if !errors.Is(err, witness.ErrIneligible) {
							b.Fatal(err)
						}
						eligible = 0
					} else if plan, ok := program.(*witness.RoutedProgram); ok {
						nodes = plan.Stats().Nodes
					}
					runtime.KeepAlive(program)
				}
				b.ReportMetric(eligible, "eligible/op")
				b.ReportMetric(float64(nodes), "nodes/op")
			})
		}
	}
}

func historicalRoutingFixture(f studyFixture) routingFixture {
	return routingFixture{rules: f.rules, events: f.events, positive: f.positive}
}

func stressRoutingFixture(c stressCase) routingFixture {
	rules, events := stressFixture(c)
	positive := make([]bool, len(events))
	for i := range positive {
		positive[i] = c.positive
	}
	return routingFixture{rules: rules, events: events, positive: positive}
}

func TestWitnessRoutingHistoricalParity(t *testing.T) {
	for _, c := range studyCases() {
		t.Run(c.name(), func(t *testing.T) { checkRoutingFixture(t, historicalRoutingFixture(studyFixtureFor(c))) })
	}
	for _, c := range stressCases() {
		t.Run(c.name(), func(t *testing.T) { checkRoutingFixture(t, stressRoutingFixture(c)) })
	}
}

func BenchmarkWitnessRoutingHistorical(b *testing.B) {
	for _, c := range studyCases() {
		if c.split == "heldout" && (c.family == "short" || c.traffic == "low_entropy") {
			benchmarkRoutingFixture(b, c.name(), c.size, historicalRoutingFixture(studyFixtureFor(c)))
		}
	}
	for _, c := range stressCases() {
		benchmarkRoutingFixture(b, c.name(), c.size, stressRoutingFixture(c))
	}
}

func TestWitnessRoutingMemory(t *testing.T) {
	for _, c := range routingResourceCases() {
		f := routingFixtureFor(c)
		source := yaraSource(f.rules)
		for _, variant := range []string{"baseline", "v1", "routed"} {
			t.Run(fmt.Sprintf("%s/rules_%d/%s", c.family, c.count, variant), func(t *testing.T) {
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				program, err := compileRoutingResource(variant, f.rules, source)
				eligible, nodes := err == nil, 0
				if err != nil && !errors.Is(err, witness.ErrIneligible) {
					t.Fatal(err)
				}
				if eligible {
					if plan, ok := program.(*witness.RoutedProgram); ok {
						nodes = plan.Stats().Nodes
					}
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				heap := int64(after.HeapAlloc) - int64(before.HeapAlloc)
				if !eligible {
					heap = 0
				}
				t.Logf("eligible=%v nodes=%d program_heap_B=%d compile_alloc_B=%d compile_allocs=%d", eligible, nodes, heap, after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs)
				runtime.KeepAlive(program)
				runtime.KeepAlive(f)
				runtime.KeepAlive(source)
			})
		}
	}
}
