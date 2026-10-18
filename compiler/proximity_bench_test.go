package compiler

import (
	"bytes"
	"testing"
)

func BenchmarkProximityPathologicalJSLoader(b *testing.B) {
	ruleSrc := `
rule JS_Loader_TokenToEval {
	strings:
		$f1 = ".token"
		$e1 = "eval("
	condition:
		for any i in (1..#f1) : ( for any j in (1..#e1) : ( @e1[j] > @f1[i] and @e1[j] - @f1[i] < 200 ) )
}`
	compiler := NewCompiler()
	program, err := compiler.CompileSource(ruleSrc)
	if err != nil {
		b.Fatalf("compile error: %v", err)
	}

	// Create synthetic ~500 KB bundle with 1,000 occurrences of .token and eval(
	// Separated by 250 bytes so proximity (<200) is never satisfied (worst-case full negative search!)
	var buf bytes.Buffer
	for i := 0; i < 1000; i++ {
		buf.WriteString(".token")
		buf.Write(bytes.Repeat([]byte("x"), 250))
		buf.WriteString("eval(")
		buf.Write(bytes.Repeat([]byte("y"), 250))
	}
	data := buf.Bytes()

	scanner := NewScanner(program)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		res, err := scanner.Scan(data)
		if err != nil {
			b.Fatalf("scan error: %v", err)
		}
		if len(res.MatchedRules) != 0 {
			b.Fatalf("expected no match")
		}
	}
}
