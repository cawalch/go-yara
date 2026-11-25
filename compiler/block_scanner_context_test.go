package compiler

import "testing"

func TestBlockScannerNilContext(t *testing.T) {
	program, err := NewCompiler().CompileSource(`rule r { strings: $a = "needle" condition: $a }`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewBlockScanner()
	defer scanner.Close()
	if err := scanner.ScanWithContext(nil, 0, []byte("needle")); err != nil { //nolint:staticcheck // verify supported nil context
		t.Fatalf("ScanWithContext(nil) error = %v", err)
	}
	result, err := scanner.FinishWithContext(nil) //nolint:staticcheck // verify supported nil context
	if err != nil {
		t.Fatalf("FinishWithContext(nil) error = %v", err)
	}
	if len(result.MatchedRules) != 1 || result.MatchedRules[0].Rule != "r" {
		t.Fatalf("MatchedRules = %+v, want rule r", result.MatchedRules)
	}
}
