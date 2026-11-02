package compiler

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkCompileIdentifierSuggestions(b *testing.B) {
	for _, count := range []int{64, 1024} {
		var source strings.Builder
		for i := range count {
			fmt.Fprintf(&source, "rule Threat_Family_Detection_Signature_%04d {condition:true}\n", i)
		}
		valid := source.String()
		invalid := valid + `rule unknown_external {condition:filename == "sample"}`
		for _, mode := range []string{"valid", "strict", "ignore"} {
			b.Run(fmt.Sprintf("rules=%d/%s", count, mode), func(b *testing.B) {
				input := invalid
				if mode == "valid" {
					input = valid
				}
				b.ReportAllocs()
				for b.Loop() {
					c := NewCompiler(WithIgnoreInvalidRules(mode == "ignore"))
					p, err := c.CompileSource(input)
					if mode == "strict" {
						if err == nil {
							b.Fatal("expected undefined identifier")
						}
					} else if err != nil || p.GetRuleCount() != count {
						b.Fatalf("compile: %v", err)
					}
				}
			})
		}
	}
}
