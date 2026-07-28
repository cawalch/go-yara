package compiler

import (
	"fmt"
	"strings"
	"testing"
)

func buildCommonRootRegexProgram(tb testing.TB, entries int) *CompiledProgram {
	tb.Helper()

	var source strings.Builder
	source.WriteString("rule common_root_regexes {\n\tstrings:\n")
	for index := range entries {
		first := 'a' + byte(index/26)
		second := 'a' + byte(index%26)
		fmt.Fprintf(
			&source,
			"\t\t$token_%d = /\\bg%c%c_[A-Za-z0-9]{36}/\n",
			index,
			first,
			second,
		)
	}
	source.WriteString("\tcondition:\n\t\tany of them\n}\n")

	program, err := NewCompiler().CompileSource(source.String())
	if err != nil {
		tb.Fatalf("CompileSource() error = %v", err)
	}
	if len(program.SharedLookup) != entries {
		tb.Fatalf("shared lookup entries = %d, want %d", len(program.SharedLookup), entries)
	}
	return program
}

func forceSharedPatternStrategy(program *CompiledProgram, shared bool) *CompiledProgram {
	clone := *program
	if !shared {
		clone.SharedAutomaton = nil
		return &clone
	}

	clone.SharedLookup = append([]SharedAutomatonEntry(nil), program.SharedLookup...)
	clone.SharedLookup[0].forceShared = true
	return &clone
}

// BenchmarkSharedPatternDensityStrategies compares the count-sensitive gate
// with both underlying strategies. The common-root corpus mirrors credential
// token patterns whose atom root occurs regularly in otherwise clean input.
func BenchmarkSharedPatternDensityStrategies(b *testing.B) {
	const size = 16 << 10
	data := []byte(strings.Repeat("abcdefghij0123456789 msg=payload ", size/32+1)[:size])

	for _, entries := range []int{2, 4, 8, 12, 20, 31} {
		program := buildCommonRootRegexProgram(b, entries)
		for _, strategy := range []struct {
			name    string
			program *CompiledProgram
		}{
			{name: "selected", program: program},
			{name: "local", program: forceSharedPatternStrategy(program, false)},
			{name: "shared", program: forceSharedPatternStrategy(program, true)},
		} {
			b.Run(fmt.Sprintf("entries=%d/%s", entries, strategy.name), func(b *testing.B) {
				benchmarkScannerMatches(b, strategy.program, data)
			})
		}
	}
}
