package compiler

import (
	"testing"
)

// TestTextStringSetIteration tests "for any s in (\"text1\", \"text2\") : ($a matches s)"
func TestTextStringSetIteration(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		data     string
		expected bool
	}{
		{
			name: "simple_text_string_set_match",
			source: `
				rule test {
					strings:
						$a = "hello"
					condition:
						for any s in ("hello", "world") : ($a matches s)
				}
			`,
			data:     "hello world",
			expected: true,
		},
		{
			name: "text_string_set_no_match",
			source: `
				rule test {
					strings:
						$a = "hello"
					condition:
						for any s in ("foo", "bar") : ($a matches s)
				}
			`,
			data:     "hello world",
			expected: false,
		},
		{
			name: "text_string_set_all_match",
			source: `
				rule test {
					strings:
						$a = "hello"
						$b = "world"
					condition:
						for all s in ("hello", "world") : (
							$a matches s or $b matches s
						)
				}
			`,
			data:     "hello world",
			expected: true,
		},
		{
			name: "text_string_set_single_element",
			source: `
				rule test {
					strings:
						$a = "test"
					condition:
						for any s in ("test") : ($a matches s)
				}
			`,
			data:     "this is a test",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := NewCompiler()
			program, err := compiler.CompileSource(tt.source)
			if err != nil {
				t.Fatalf("CompileSource failed: %v", err)
			}

			scanner := NewScanner(program)
			defer scanner.Close()
			data := []byte(tt.data)
			result, err := scanner.Scan(data)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			var matched bool
			for _, ruleMatch := range result.MatchedRules {
				if ruleMatch.Rule == "test" {
					matched = len(ruleMatch.Matches) > 0
					break
				}
			}

			if matched != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, matched)
			}
		})
	}
}
