package compiler

import (
	"testing"
)

// TestStreamingWithLargeData documents compiler behavior with large data patterns
// DO NOT modify code to make tests pass - document current behavior only
func TestStreamingWithLargeData(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "simple-pattern-for-large-data",
			rule:        `rule test { strings: $a = "test" condition: $a }`,
			expectError: false,
			description: "Documents compilation for large data scanning",
		},
		{
			name:        "hex-pattern-for-large-data",
			rule:        `rule test { strings: $a = { DE AD BE EF } condition: $a }`,
			expectError: false,
			description: "Documents hex pattern compilation for large data",
		},
		{
			name:        "regex-for-large-data",
			rule:        `rule test { strings: $a = /test.*end/ condition: $a }`,
			expectError: false,
			description: "Documents regex compilation for large data",
		},
		{
			name:        "count-based-condition",
			rule:        `rule test { strings: $a = "ab" condition: #a > 10 }`,
			expectError: false,
			description: "Documents match count condition for large data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestStreamingWithMultipleMatches documents compiler behavior for multiple matches
// DO NOT modify code to make tests pass - document current behavior only
func TestStreamingWithMultipleMatches(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "many-overlapping-matches",
			rule:        `rule test { strings: $a = "aa" condition: #a > 50 }`,
			expectError: false,
			description: "Documents compilation for many overlapping matches",
		},
		{
			name:        "multiple-strings-count",
			rule:        `rule test { strings: $a = "aa" $b = "bb" condition: #a > 5 and #b > 5 }`,
			expectError: false,
			description: "Documents compilation for multiple string counts",
		},
		{
			name:        "wide-strings",
			rule:        `rule test { strings: $a = "AB" wide condition: #a > 0 }`,
			expectError: false,
			description: "Documents wide string compilation",
		},
		{
			name:        "nocase-matches",
			rule:        `rule test { strings: $a = "test" nocase condition: #a > 3 }`,
			expectError: false,
			description: "Documents nocase string compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestStreamingWithNoMatches documents compiler behavior when no matches occur
// DO NOT modify code to make tests pass - document current behavior only
func TestStreamingWithNoMatches(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "simple-no-match",
			rule:        `rule test { strings: $a = "notfound" condition: $a }`,
			expectError: false,
			description: "Documents simple no-match compilation",
		},
		{
			name:        "hex-no-match",
			rule:        `rule test { strings: $a = { DE AD BE EF } condition: $a }`,
			expectError: false,
			description: "Documents hex pattern compilation",
		},
		{
			name:        "regex-no-match",
			rule:        `rule test { strings: $a = /test.*end/ condition: $a }`,
			expectError: false,
			description: "Documents regex compilation",
		},
		{
			name:        "wide-no-match",
			rule:        `rule test { strings: $a = "AB" wide condition: $a }`,
			expectError: false,
			description: "Documents wide string compilation",
		},
		{
			name:        "fullword-no-match",
			rule:        `rule test { strings: $a = "test" fullword condition: $a }`,
			expectError: false,
			description: "Documents fullword compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}

// TestStreamingStateManagement documents compiler state management for multiple rules
// DO NOT modify code to make tests pass - document current behavior only
func TestStreamingStateManagement(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		expectError bool
		description string
	}{
		{
			name:        "sequential-rules",
			rule:        `rule test1 { strings: $a = "a" condition: $a } rule test2 { strings: $b = "b" condition: $b }`,
			expectError: false,
			description: "Documents multiple sequential rules compilation",
		},
		{
			name:        "interdependent-rules",
			rule:        `rule test1 { strings: $a = "a" condition: $a } rule test2 { strings: $b = "b" condition: test1 and $b }`,
			expectError: false,
			description: "Documents rule dependency compilation",
		},
		{
			name:        "global-rule",
			rule:        `global rule test { strings: $a = "a" condition: $a } rule other { condition: test }`,
			expectError: false,
			description: "Documents global rule compilation",
		},
		{
			name:        "private-rule",
			rule:        `private rule test { strings: $a = "a" condition: $a } rule other { condition: true }`,
			expectError: false,
			description: "Documents private rule compilation",
		},
		{
			name:        "tags-usage",
			rule:        `rule test1 tag : tag1 { strings: $a = "a" condition: $a } rule test2 tag : tag2 { strings: $b = "b" condition: $b }`,
			expectError: false,
			description: "Documents tag filtering compilation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			program, err := c.CompileSource(tt.rule)

			assertAnonymousStringResult(t, program, err, tt.expectError, tt.description)
		})
	}
}
