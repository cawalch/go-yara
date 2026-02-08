package compiler

import (
	"os"
	"path/filepath"
	"testing"
)

func compileRuleFile(t *testing.T, path string) *CompiledProgram {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rule file %s: %v", path, err)
	}

	compiler := NewCompiler()
	program, err := compiler.CompileSource(string(source))
	if err != nil {
		t.Fatalf("compile rule file %s: %v", path, err)
	}
	if len(program.Rules) == 0 {
		t.Fatalf("no compiled rules for %s", path)
	}

	return program
}

func readPerformanceFile(t *testing.T, filename string) []byte {
	t.Helper()
	path := filepath.Join("..", "testdata", "performance", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read data file %s: %v", path, err)
	}
	return data
}

func evaluateProgramRules(t *testing.T, program *CompiledProgram, data []byte) map[string]bool {
	t.Helper()
	results := make(map[string]bool, len(program.Rules))
	for _, rule := range program.Rules {
		ok, err := evaluateRule(rule, program, data)
		if err != nil {
			t.Fatalf("evaluate %s: %v", rule.Name, err)
		}
		results[rule.Name] = ok
	}
	return results
}

func assertExpectedMatches(t *testing.T, results map[string]bool, expected map[string]bool, dataFile string) {
	t.Helper()
	for ruleName, want := range expected {
		got, ok := results[ruleName]
		if !ok {
			t.Fatalf("rule %s not found in compiled program", ruleName)
		}
		if got != want {
			t.Errorf("%s: rule %s matched=%v, want %v", dataFile, ruleName, got, want)
		}
	}
}

func TestPerformanceSimpleRules(t *testing.T) {
	rulePath := filepath.Join("..", "testdata", "performance", "simple_rules.yar")
	program := compileRuleFile(t, rulePath)

	files := []string{
		"pe_malware_sample.bin",
		"elf_backdoor_sample.bin",
		"webshell_sample.php",
		"ransomware_sample.exe",
		"banker_sample.dll",
		"ddos_bot_sample.exe",
		"miner_sample.exe",
		"apt_surveillance_sample.exe",
		"clean_program.exe",
		"clean_document.pdf",
		"clean_script.js",
	}

	positives := map[string]map[string]bool{
		"pe_detection": {
			"pe_malware_sample.bin":       true,
			"ransomware_sample.exe":       true,
			"banker_sample.dll":           true,
			"ddos_bot_sample.exe":         true,
			"miner_sample.exe":            true,
			"apt_surveillance_sample.exe": true,
			"clean_program.exe":           true,
		},
		"elf_detection": {
			"elf_backdoor_sample.bin": true,
		},
		"malware_strings": {
			"pe_malware_sample.bin": true,
		},
		"web_detection": {
			"webshell_sample.php": true,
			"ddos_bot_sample.exe": true,
		},
	}

	for _, file := range files {
		data := readPerformanceFile(t, file)
		results := evaluateProgramRules(t, program, data)

		expected := map[string]bool{
			"pe_detection":    positives["pe_detection"][file],
			"elf_detection":   positives["elf_detection"][file],
			"malware_strings": positives["malware_strings"][file],
			"web_detection":   positives["web_detection"][file],
		}

		assertExpectedMatches(t, results, expected, file)
	}
}

func TestPerformanceRealWorldRules(t *testing.T) {
	rulePath := filepath.Join("..", "testdata", "performance", "real_world_rules.yar")
	program := compileRuleFile(t, rulePath)

	files := []string{
		"pe_malware_sample.bin",
		"elf_backdoor_sample.bin",
		"webshell_sample.php",
		"ransomware_sample.exe",
		"banker_sample.dll",
		"ddos_bot_sample.exe",
		"miner_sample.exe",
		"apt_surveillance_sample.exe",
		"clean_program.exe",
		"clean_document.pdf",
		"clean_script.js",
	}

	positives := map[string]map[string]bool{
		"pe_malware_detection": {
			"pe_malware_sample.bin": true,
		},
		"elf_backdoor": {
			"elf_backdoor_sample.bin": true,
		},
		"webshell_detection": {
			"webshell_sample.php": true,
		},
		"ransomware_indicators": {
			"ransomware_sample.exe": true,
		},
		"banker_trojan": {
			"banker_sample.dll": true,
		},
		"ddos_bot": {
			"ddos_bot_sample.exe":         true,
			"apt_surveillance_sample.exe": true,
			"elf_backdoor_sample.bin":     true,
		},
		"miner_malware": {
			"miner_sample.exe": true,
		},
		"apt_surveillance": {
			"apt_surveillance_sample.exe": true,
		},
	}

	for _, file := range files {
		data := readPerformanceFile(t, file)
		results := evaluateProgramRules(t, program, data)

		expected := map[string]bool{
			"pe_malware_detection":  positives["pe_malware_detection"][file],
			"elf_backdoor":          positives["elf_backdoor"][file],
			"webshell_detection":    positives["webshell_detection"][file],
			"ransomware_indicators": positives["ransomware_indicators"][file],
			"banker_trojan":         positives["banker_trojan"][file],
			"ddos_bot":              positives["ddos_bot"][file],
			"miner_malware":         positives["miner_malware"][file],
			"apt_surveillance":      positives["apt_surveillance"][file],
		}

		assertExpectedMatches(t, results, expected, file)
	}
}

func TestPerformanceComparisonRules(t *testing.T) {
	rulePath := filepath.Join("..", "testdata", "performance", "comparison_rules.yar")
	program := compileRuleFile(t, rulePath)

	cases := []struct {
		file     string
		expected bool
	}{
		{file: "pe_malware_sample.bin", expected: true},
		{file: "clean_program.exe", expected: false},
		{file: "clean_document.pdf", expected: true},
		{file: "clean_script.js", expected: true},
	}

	for _, tc := range cases {
		data := readPerformanceFile(t, tc.file)
		results := evaluateProgramRules(t, program, data)
		assertExpectedMatches(t, results, map[string]bool{"simple_string": tc.expected}, tc.file)
	}
}
