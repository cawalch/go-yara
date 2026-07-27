package compiler

import (
	"strings"
	"testing"
)

func TestEmptyLineCommentsCompileInEveryRuleSection(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{
			name:   "file header",
			source: "//\nrule r { strings: $a = \"tok\" condition: $a }\n",
		},
		{
			name: "between non-empty comments",
			source: `
// Accepted formats:
//
//   E.164
rule r { strings: $a = "tok" condition: $a }
`,
		},
		{
			name: "inside meta",
			source: `
rule r {
    meta:
        author = "example"
        //
        enabled = true
    strings:
        $a = "tok"
    condition:
        $a
}
`,
		},
		{
			name: "inside strings",
			source: `
rule r {
    strings:
        //
        $a = "tok"
    condition:
        $a
}
`,
		},
		{
			name: "inside condition",
			source: `
rule r {
    strings:
        $a = "tok"
    condition:
        //
        $a
}
`,
		},
		{
			name:   "trailing whitespace",
			source: "// \t  \nrule r { strings: $a = \"tok\" condition: $a }\n",
		},
		{
			name:   "consecutive",
			source: "//\n//\nrule r { strings: $a = \"tok\" condition: $a }\n",
		},
		{
			name:   "CRLF",
			source: "//\r\nrule r { strings: $a = \"tok\" condition: $a }\r\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, err := NewCompiler().CompileSource(test.source)
			if err != nil {
				t.Fatalf("CompileSource() error = %v", err)
			}
			if got := program.GetRuleCount(); got != 1 {
				t.Fatalf("rule count = %d, want 1", got)
			}
		})
	}
}

func TestEmptyLineCommentDoesNotSwallowFollowingRules(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule first {
    strings:
        $a = "first"
    condition:
        $a
}

//

rule second {
    strings:
        $b = "second"
    condition:
        $b
}
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}
	if got := program.GetRuleCount(); got != 2 {
		t.Fatalf("rule count = %d, want 2", got)
	}
}

func TestEmptyRegexPatternRemainsRejected(t *testing.T) {
	_, err := NewCompiler().CompileSource(`
rule empty_regex {
    strings:
        $a = //
    condition:
        $a
}
`)
	if err == nil {
		t.Fatal("CompileSource() accepted an empty regex")
	}
}

func TestCompilerReportsLexerErrorPosition(t *testing.T) {
	compiler := NewCompiler()
	_, err := compiler.CompileSource(`
rule invalid {
    strings:
        $a = "unterminated
    condition:
        $a
}
`)
	if err == nil {
		t.Fatal("CompileSource() accepted an unterminated string")
	}
	for _, compilationErr := range compiler.GetErrors() {
		if compilationErr.Phase == "parsing" &&
			compilationErr.Line == 4 &&
			strings.Contains(compilationErr.Message, "unterminated string literal") {
			return
		}
	}
	t.Fatalf("compiler errors = %+v, want unterminated string at line 4", compiler.GetErrors())
}
