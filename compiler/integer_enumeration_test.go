package compiler

import (
	"context"
	"strings"
	"testing"
)

func TestIntegerEnumerationIteration(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		data     string
		expected bool
	}{
		{
			name: "any_match",
			source: `
				rule test {
					strings:
						$a = "hello"
					condition:
						for any i in (1, 2, 3) : ( i == 2 ) and $a
				}
			`,
			data:     "hello world",
			expected: true,
		},
		{
			name: "any_no_match",
			source: `
				rule test {
					strings:
						$a = "hello"
					condition:
						for any i in (1, 2, 3) : ( i == 5 ) and $a
				}
			`,
			data:     "hello world",
			expected: false,
		},
		{
			name: "all_match",
			source: `
				rule test {
					strings:
						$a = "hello"
					condition:
						for all i in (10, 20, 30) : ( i >= 10 ) and $a
				}
			`,
			data:     "hello world",
			expected: true,
		},
		{
			name: "all_no_match",
			source: `
				rule test {
					strings:
						$a = "hello"
					condition:
						for all i in (10, 20, 30) : ( i > 15 ) and $a
				}
			`,
			data:     "hello world",
			expected: false,
		},
		{
			name: "none_match",
			source: `
				rule test {
					strings:
						$a = "hello"
					condition:
						for none i in (1, 2, 3) : ( i == 99 ) and $a
				}
			`,
			data:     "hello world",
			expected: true,
		},
		{
			name: "none_fails_when_found",
			source: `
				rule test {
					strings:
						$a = "hello"
					condition:
						for none i in (1, 2, 3) : ( i == 2 ) and $a
				}
			`,
			data:     "hello world",
			expected: false,
		},
		{
			name: "numeric_quantifier",
			source: `
				rule test {
					strings:
						$a = "hello"
					condition:
						for 2 i in (1, 2, 3, 4) : ( i % 2 == 0 ) and $a
				}
			`,
			data:     "hello world",
			expected: true,
		},
		{
			name: "string_offset_at_index",
			source: `
				rule test {
					strings:
						$a = "world"
					condition:
						for any offset in (0, 6, 12) : ( $a at offset )
				}
			`,
			data:     "hello world!",
			expected: true,
		},
		{
			name: "string_offset_at_index_mismatch",
			source: `
				rule test {
					strings:
						$a = "world"
					condition:
						for any offset in (0, 2, 4) : ( $a at offset )
				}
			`,
			data:     "hello world!",
			expected: false,
		},
		{
			name: "with_arithmetic_elements",
			source: `
				rule test {
					strings:
						$a = "hello"
					condition:
						for any i in (1 + 1, 2 * 3, 10 - 2) : ( i == 6 ) and $a
				}
			`,
			data:     "hello",
			expected: true,
		},
		{
			name: "with_filesize",
			source: `
				rule test {
					condition:
						for any i in (filesize, 100) : ( i == 5 )
				}
			`,
			data:     "12345",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSourceWithContext(context.Background(), tt.source)
			if err != nil {
				t.Fatalf("failed to compile: %v", err)
			}

			result, err := program.Scan([]byte(tt.data))
			if err != nil {
				t.Fatalf("failed to scan: %v", err)
			}

			matched := len(result.MatchedRules) > 0
			if matched != tt.expected {
				t.Errorf("expected match=%v, got match=%v", tt.expected, matched)
			}
		})
	}
}

func TestIntegerEnumerationTypeValidation(t *testing.T) {
	c := NewCompiler()
	invalidSource := `
		rule test {
			condition:
				for any i in (1, "not_an_int") : ( i == 1 )
		}
	`
	_, err := c.CompileSourceWithContext(context.Background(), invalidSource)
	if err == nil {
		t.Fatal("expected compilation error for mixed integer/string tuple, got nil")
	}
	if !strings.Contains(err.Error(), "must be integer") {
		t.Fatalf("expected error mentioning 'must be integer', got: %v", err)
	}
}
