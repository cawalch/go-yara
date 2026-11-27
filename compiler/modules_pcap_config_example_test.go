package compiler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPCAPConfigResponseExample(t *testing.T) {
	const fixtureDir = "../examples/pcap/config-response"
	rule, err := os.ReadFile(filepath.Join(fixtureDir, "config.yar"))
	if err != nil {
		t.Fatal(err)
	}
	program, err := NewCompiler().CompileSourceWithContext(t.Context(), string(rule))
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		capture string
		match   bool
	}{
		{"tampered.pcap", true},
		{"unrelated.pcap", false},
	} {
		t.Run(tt.capture, func(t *testing.T) {
			capture, err := os.ReadFile(filepath.Join(fixtureDir, tt.capture))
			if err != nil {
				t.Fatal(err)
			}
			result, err := program.Scan(capture)
			if err != nil {
				t.Fatal(err)
			}
			if got := result.RuleResults["tampered_config_response"]; got != tt.match {
				t.Fatalf("match = %t, want %t", got, tt.match)
			}
		})
	}
}
