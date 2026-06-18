package compiler

import (
	"strings"
	"testing"
)

func TestCompileUnsupportedModules(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		wantError string
	}{
		{
			name: "import_pe",
			source: `import "pe"

rule test {
	condition:
		true
}`,
			wantError: "unsupported module: pe",
		},
		{
			name: "pe_member_access",
			source: `rule test {
	condition:
		pe.is_pe
}`,
			wantError: "unsupported module: pe",
		},
		{
			name: "pe_function_call",
			source: `rule test {
	condition:
		pe.imphash() == ""
}`,
			wantError: "unsupported module: pe",
		},
		{
			name: "hash_function_call",
			source: `rule test {
	condition:
		hash.md5(0, 4) == ""
}`,
			wantError: "unsupported module: hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCompiler().CompileSource(tt.source)
			if err == nil {
				t.Fatal("CompileSource() expected unsupported module error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("CompileSource() error = %v, want containing %q", err, tt.wantError)
			}
		})
	}
}
