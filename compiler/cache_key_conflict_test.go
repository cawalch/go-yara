package compiler

import (
	"strings"
	"testing"
)

func TestConflictingSerializedCacheKeysRejected(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule first { strings: $a = /ab/ condition: $a }
rule second { strings: $a = /cd/ condition: $a }
`)
	if err != nil {
		t.Fatal(err)
	}
	firstKey := program.Rules[0].RegexPatterns["$a"].cacheKey
	second := program.Rules[1].RegexPatterns["$a"]
	second.cacheKey = firstKey
	program.Rules[1].RegexPatterns["$a"] = second

	rebuilt := NewCompiledProgram(program.Rules)
	if err := rebuilt.Validate(); err == nil || !strings.Contains(err.Error(), "conflicting regex cache key") {
		t.Fatalf("Validate() error = %v, want conflicting cache key", err)
	}
}
