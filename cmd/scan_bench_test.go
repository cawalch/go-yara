package main

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func BenchmarkCLIScanUnusedText(b *testing.B) {
	data := bytes.Repeat([]byte("unrelated content\x00"), 1<<17)
	for _, tc := range []struct {
		name      string
		patterns  string
		condition string
	}{
		{"referenced", `$a = "TOKEN_{{id}}_0000" $b = "BEACON_{{id}}/api/v1/x"`, "#a > 1 and $b"},
		{"unused", `$a = "TOKEN_{{id}}_0000" $b = "BEACON_{{id}}/api/v1/x"`, "#a > 1"},
		{"regex_range", `$c = /cmd_run_[0-9a-f]{8}/`, "#c in (1..5)"},
		{"regex_range_with_unused", `$c = /cmd_run_[0-9a-f]{8}/ $b = "BEACON_{{id}}/api/v1/x"`, "#c in (1..5)"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var source strings.Builder
			for i := range 512 {
				patterns := strings.ReplaceAll(tc.patterns, "{{id}}", strconv.Itoa(i))
				fmt.Fprintf(&source, "rule r%d { strings: %s condition: %s }\n", i, patterns, tc.condition)
			}
			program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source.String())
			if err != nil {
				b.Fatal(err)
			}
			scanner := program.NewScanner(buildScannerOptions(&commandArgs{})...)
			defer scanner.Close()
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				result, err := scanner.Scan(data)
				if err != nil || len(result.MatchedRules) != 0 {
					b.Fatalf("expected a clean reject, got %v (%v)", result, err)
				}
			}
		})
	}
}
