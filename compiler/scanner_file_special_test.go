package compiler

import (
	"runtime"
	"testing"
)

func TestScanFileStreamsNonRegularFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/dev/null is not available on Windows")
	}
	program, err := NewCompiler().CompileSource(`rule r { condition: filesize == 0 }`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := program.ScanFile("/dev/null")
	if err != nil {
		t.Fatalf("ScanFile(/dev/null) error = %v", err)
	}
	if !result.RuleResults["r"] {
		t.Fatalf("RuleResults = %v, want r true", result.RuleResults)
	}
}
