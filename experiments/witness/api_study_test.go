//go:build witnessstudy

package witness_test

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func apiPositiveCases() []routingCase {
	var cases []routingCase
	for _, count := range []int{24, 256, 2048} {
		for _, family := range []string{"literal", "complex", "shared_tail", "shared_context"} {
			cases = append(cases, routingCase{family, "positive", count, 256})
		}
	}
	return cases
}

func apiVariants() []string {
	variants := []string{"baseline", "routed"}
	if os.Getenv("BOOLEAN_API_REVERSE") == "1" {
		slices.Reverse(variants)
	}
	return variants
}

func apiOptions(variant string) []compiler.ScannerOption {
	options := []compiler.ScannerOption{compiler.WithFastScan()}
	if variant == "routed" {
		options = append(options, compiler.WithBooleanRouting())
	}
	return options
}

func apiPlanActive(scanner *compiler.Scanner) bool {
	// Study-only coverage inspection; no reflection in measured scanner calls.
	return !reflect.ValueOf(scanner).Elem().FieldByName("booleanRouting").IsNil()
}

func apiCompile(t testing.TB, f routingFixture) *compiler.CompiledProgram {
	t.Helper()
	p, err := compiler.NewCompiler().CompileSource(yaraSource(f.rules))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func apiWarm(t testing.TB, scanner *compiler.Scanner, f routingFixture) {
	t.Helper()
	for i, event := range f.events {
		got, err := scanner.Matches(event)
		if err != nil || got != f.positive[i] {
			t.Fatalf("event %d: %v,%v want %v", i, got, err, f.positive[i])
		}
	}
}

func TestBooleanRoutingAPIParity(t *testing.T) {
	if len(routingCases()) != 32 || len(apiPositiveCases()) != 12 {
		t.Fatal("frozen matrix changed")
	}
	for _, group := range []struct {
		name  string
		cases []routingCase
	}{{"frozen", routingCases()}, {"positive", apiPositiveCases()}} {
		for _, c := range group.cases {
			t.Run(group.name+"/"+c.name(), func(t *testing.T) {
				f := routingFixtureFor(c)
				p := apiCompile(t, f)
				for _, variant := range apiVariants() {
					scanner := p.NewScanner(apiOptions(variant)...)
					for range 2 {
						apiWarm(t, scanner, f)
					}
					t.Logf("variant=%s plan_active=%v size_bypass=%v events=%d", variant, apiPlanActive(scanner), c.size > 1024, len(f.events))
					scanner.Close()
				}
			})
		}
	}
}

func BenchmarkBooleanRoutingAPI(b *testing.B) {
	for _, c := range routingCases() {
		benchmarkAPICase(b, c)
	}
}
func BenchmarkBooleanRoutingAPIPositive(b *testing.B) {
	for _, c := range apiPositiveCases() {
		benchmarkAPICase(b, c)
	}
}
func benchmarkAPICase(b *testing.B, c routingCase) {
	f := routingFixtureFor(c)
	p := apiCompile(b, f)
	for _, variant := range apiVariants() {
		b.Run(c.name()+"/"+variant, func(b *testing.B) {
			scanner := p.NewScanner(apiOptions(variant)...)
			defer scanner.Close()
			apiWarm(b, scanner, f)
			active := 0.0
			if apiPlanActive(scanner) {
				active = 1
			}
			b.ReportAllocs()
			b.SetBytes(int64(c.size))
			i := 0
			for b.Loop() {
				got, err := scanner.Matches(f.events[i])
				if err != nil || got != f.positive[i] {
					b.Fatalf("event %d: %v,%v want %v", i, got, err, f.positive[i])
				}
				i++
				if i == len(f.events) {
					i = 0
				}
			}
			b.ReportMetric(active, "plan_active/op")
			bypass := 0.0
			if c.size > 1024 {
				bypass = 1
			}
			b.ReportMetric(bypass, "size_bypass/op")
		})
	}
}

func BenchmarkBooleanRoutingAPIFirstScanner(b *testing.B) {
	for _, c := range routingResourceCases() {
		f := routingFixtureFor(c)
		for _, variant := range apiVariants() {
			b.Run(fmt.Sprintf("%s/rules_%d/%s", c.family, c.count, variant), func(b *testing.B) {
				b.StopTimer()
				b.ReportAllocs()
				for range b.N {
					p := apiCompile(b, f)
					options := apiOptions(variant)
					b.StartTimer()
					scanner := p.NewScanner(options...)
					b.StopTimer()
					active := 0.0
					if apiPlanActive(scanner) {
						active = 1
					}
					b.ReportMetric(active, "plan_active/op")
					scanner.Close()
				}
			})
		}
	}
}

func BenchmarkBooleanRoutingAPIReusedScanner(b *testing.B) {
	for _, c := range routingResourceCases() {
		f := routingFixtureFor(c)
		p := apiCompile(b, f)
		for _, variant := range apiVariants() {
			b.Run(fmt.Sprintf("%s/rules_%d/%s", c.family, c.count, variant), func(b *testing.B) {
				options := apiOptions(variant)
				first := p.NewScanner(options...)
				active := 0.0
				if apiPlanActive(first) {
					active = 1
				}
				first.Close()
				scanners := make([]*compiler.Scanner, b.N)
				b.ReportAllocs()
				b.ResetTimer()
				for i := range scanners {
					scanners[i] = p.NewScanner(options...)
				}
				b.StopTimer()
				for _, scanner := range scanners {
					scanner.Close()
				}
				b.ReportMetric(active, "plan_active/op")
			})
		}
	}
}
