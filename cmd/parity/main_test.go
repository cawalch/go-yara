package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b, c", []string{"a", "b", "c"}},
		{"a,,b", []string{"a", "b"}},
		{"", []string{}},
		{"a", []string{"a"}},
		{" a , b ", []string{"a", "b"}},
	}

	for _, tt := range tests {
		result := splitCSV(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("splitCSV(%q) length = %d, want %d", tt.input, len(result), len(tt.expected))
			continue
		}
		for i, v := range result {
			if v != tt.expected[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
			}
		}
	}
}

func TestEqStringSets(t *testing.T) {
	tests := []struct {
		a, b     []string
		expected bool
	}{
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"b", "a"}, true},
		{[]string{"a", "b"}, []string{"a", "c"}, false},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{}, []string{}, true},
		{[]string{"a", "b", "c"}, []string{"c", "b", "a"}, true},
	}

	for _, tt := range tests {
		result := eqStringSets(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("eqStringSets(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		off, gores RunResult
		expected   string
	}{
		{
			off:      RunResult{Ok: true, MatchedRules: []string{"rule1"}},
			gores:    RunResult{Ok: true, MatchedRules: []string{"rule1"}},
			expected: "parity_ok",
		},
		{
			off:      RunResult{Ok: true, MatchedRules: []string{"rule1"}},
			gores:    RunResult{Ok: true, MatchedRules: []string{"rule2"}},
			expected: "mismatch",
		},
		{
			off:      RunResult{Ok: false, Err: nil},
			gores:    RunResult{Ok: true},
			expected: "error: official failed",
		},
		{
			off:      RunResult{Ok: true},
			gores:    RunResult{Ok: false, Err: nil},
			expected: "error: go-yara failed",
		},
		{
			off:      RunResult{Ok: false, Err: nil},
			gores:    RunResult{Ok: false, Err: nil},
			expected: "error: both failed",
		},
	}

	for _, tt := range tests {
		result := classify(tt.off, tt.gores)
		if result != tt.expected {
			t.Errorf("classify(%+v, %+v) = %q, want %q", tt.off, tt.gores, result, tt.expected)
		}
	}
}

func TestParseYaraOutput(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "rule1 file1\nrule2 file2\n",
			expected: []string{"rule1", "rule2"},
		},
		{
			input:    "rule1 file1\n\nrule2 file2\n",
			expected: []string{"rule1", "rule2"},
		},
		{
			input:    "invalid line\nrule1 file1\n",
			expected: []string{"invalid", "rule1"},
		},
		{
			input:    "",
			expected: []string{},
		},
		{
			input:    "rule1 file1\nrule1 file2\n",
			expected: []string{"rule1"},
		},
	}

	for _, tt := range tests {
		result := parseYaraOutput(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("parseYaraOutput(%q) length = %d, want %d", tt.input, len(result), len(tt.expected))
			continue
		}
		for i, v := range result {
			if v != tt.expected[i] {
				t.Errorf("parseYaraOutput(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
			}
		}
	}
}

func TestParseGoYaraMatches(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "Executing rule: rule1\nResult: MATCH\nExecuting rule: rule2\nResult: MATCH\n",
			expected: []string{"rule1", "rule2"},
		},
		{
			input:    "Executing rule: rule1\nResult: NO MATCH\n",
			expected: []string{},
		},
		{
			input:    "Executing rule: rule1\nResult: MATCH\nExecuting rule: rule1\nResult: MATCH\n",
			expected: []string{"rule1"},
		},
		{
			input:    "",
			expected: []string{},
		},
		{
			input:    "Executing rule: rule1\nResult: MATCH\nInvalid line\n",
			expected: []string{"rule1"},
		},
	}

	for _, tt := range tests {
		result := parseGoYaraMatches(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("parseGoYaraMatches(%q) length = %d, want %d", tt.input, len(result), len(tt.expected))
			continue
		}
		for i, v := range result {
			if v != tt.expected[i] {
				t.Errorf("parseGoYaraMatches(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
			}
		}
	}
}

func TestDefaultRules(t *testing.T) {
	rules := defaultRules()
	if len(rules) == 0 {
		t.Error("defaultRules() should return non-empty list")
	}
	// Check if they are strings
	for _, r := range rules {
		if r == "" {
			t.Error("defaultRules() should not contain empty strings")
		}
	}
}

func TestDefaultData(t *testing.T) {
	data := defaultData()
	if data == "" {
		t.Error("defaultData() should return non-empty string")
	}
}

func TestBuildRegexSuiteCases(t *testing.T) {
	cases := buildRegexSuiteCases()
	if len(cases) == 0 {
		t.Error("buildRegexSuiteCases() should return non-empty list")
	}
	for _, c := range cases {
		if c.RulePath == "" || c.DataPath == "" {
			t.Error("buildRegexSuiteCases() should have non-empty paths")
		}
	}
}

func TestFileHasRegex(t *testing.T) {
	tmpDir := t.TempDir()

	// Test file without regex
	noRegexFile := filepath.Join(tmpDir, "no_regex.yar")
	err := os.WriteFile(noRegexFile, []byte("rule test { condition: true }"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tmpDir)
	has, err := fileHasRegex("no_regex.yar")
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Error("fileHasRegex should return false for file without regex")
	}

	// Test file with regex
	withRegexFile := filepath.Join(tmpDir, "with_regex.yar")
	err = os.WriteFile(withRegexFile, []byte("rule test { strings: $a = /abc/ condition: $a }"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	has, err = fileHasRegex("with_regex.yar")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Error("fileHasRegex should return true for file with regex")
	}
}

func TestFileHasInclude(t *testing.T) {
	tmpDir := t.TempDir()

	// Test file without include
	noIncludeFile := filepath.Join(tmpDir, "no_include.yar")
	err := os.WriteFile(noIncludeFile, []byte("rule test { condition: true }"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tmpDir)
	has, err := fileHasInclude("no_include.yar")
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Error("fileHasInclude should return false for file without include")
	}

	// Test file with include
	withIncludeFile := filepath.Join(tmpDir, "with_include.yar")
	err = os.WriteFile(withIncludeFile, []byte("include \"other.yar\"\nrule test { condition: true }"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	has, err = fileHasInclude("with_include.yar")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Error("fileHasInclude should return true for file with include")
	}
}

func TestFileHasImport(t *testing.T) {
	tmpDir := t.TempDir()

	// Test file without import
	noImportFile := filepath.Join(tmpDir, "no_import.yar")
	err := os.WriteFile(noImportFile, []byte("rule test { condition: true }"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	// Change to temp dir to use relative paths
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tmpDir)
	has, err := fileHasImport("no_import.yar")
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Error("fileHasImport should return false for file without import")
	}

	// Test file with import
	withImportFile := filepath.Join(tmpDir, "with_import.yar")
	err = os.WriteFile(withImportFile, []byte("import \"pe\"\nrule test { condition: true }"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	has, err = fileHasImport("with_import.yar")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Error("fileHasImport should return true for file with import")
	}
}
