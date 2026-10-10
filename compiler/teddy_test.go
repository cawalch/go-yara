package compiler

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestTeddyMultiPatternCorrectness(t *testing.T) {
	for _, tc := range []struct {
		name     string
		patterns []string
		noCase   bool
	}{
		{
			name: "8_distinct_patterns",
			patterns: []string{
				"alpha_test", "bravo_test", "charlie_test", "delta_test",
				"echo_test", "foxtrot_test", "golf_test", "hotel_test",
			},
		},
		{
			name: "16_distinct_patterns",
			patterns: []string{
				"alpha_test", "bravo_test", "charlie_test", "delta_test",
				"echo_test", "foxtrot_test", "golf_test", "hotel_test",
				"india_test", "juliet_test", "kilo_test", "lima_test",
				"mike_test", "november_test", "oscar_test", "papa_test",
			},
		},
		{
			name: "16_nocase_patterns",
			patterns: []string{
				"powershell", "cmd.exe", "wscript", "cscript",
				"rundll32", "regsvr32", "mshta.exe", "certutil",
				"vssadmin", "wbadmin", "bcdedit", "netsh.exe",
				"schtasks", "taskkill", "whoami.exe", "nltest.exe",
			},
			noCase: true,
		},
		{
			name: "overlapping_prefixes",
			patterns: []string{
				"token_abc", "token_abd", "token_xyz", "tok_123",
				"other_abc", "other_abd", "oth_999", "sample_pattern",
			},
		},
		{
			name: "short_and_long_patterns",
			patterns: []string{
				"ab", "abc", "abcd", "xyz", "wxyz", "longer_pattern_here",
				"another_one", "middle_len",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ac := newacAutomaton()
			for i, pat := range tc.patterns {
				flags := regex.Flags(0)
				if tc.noCase {
					flags |= regex.FlagsNoCase
				}
				if err := ac.AddStringWithFlags(fmt.Sprintf("$s%d", i), []byte(pat), false, false, flags); err != nil {
					t.Fatalf("AddStringWithFlags error = %v", err)
				}
			}
			if err := ac.Compile(); err != nil {
				t.Fatalf("Compile error = %v", err)
			}

			filler := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. 0123456789 "), 50)
			for pIdx, pat := range tc.patterns {
				for _, offset := range []int{0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 256, 512, 1024} {
					data := slices.Clone(filler)
					if offset+len(pat) > len(data) {
						continue
					}
					copy(data[offset:], pat)

					var matches []acMatch
					for m := range ac.SearchIter(data) {
						matches = append(matches, m)
					}

					found := false
					for _, m := range matches {
						if m.StringIndex == pIdx && m.Backtrack == offset {
							found = true
							break
						}
					}
					if !found {
						t.Fatalf("pattern %q at offset %d not found in matches: %+v", pat, offset, matches)
					}
				}
			}
		})
	}
}

func TestTeddyCancellation(t *testing.T) {
	ac := newacAutomaton()
	for i, pat := range []string{
		"alpha_token", "bravo_token", "charlie_token", "delta_token",
		"echo_token", "foxtrot_token", "golf_token", "hotel_token",
	} {
		if err := ac.AddString(fmt.Sprintf("$s%d", i), []byte(pat), false, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}

	data := bytes.Repeat([]byte("clean filler content here 12345 "), 100_000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Pre-canceled

	for m := range ac.searchIterWithCancel(data, ctx.Done()) {
		t.Fatalf("unexpected match from canceled context: %+v", m)
	}
}

func TestTeddyMultiPatternRuleIntegration(t *testing.T) {
	ruleSource := `rule multi_detect {
		strings:
			$s1 = "powershell.exe" nocase
			$s2 = "cmd.exe /c" nocase
			$s3 = "vssadmin delete" nocase
			$s4 = "wbadmin delete" nocase
			$s5 = "certutil -urlcache" nocase
			$s6 = "rundll32.exe" nocase
			$s7 = "regsvr32.exe /s" nocase
			$s8 = "bitsadmin /transfer" nocase
			$s9 = "mimikatz" nocase
			$s10 = "sekurlsa::logonpasswords" nocase
		condition:
			any of them
	}`

	program, err := NewCompiler().CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource error: %v", err)
	}

	scanner := NewScanner(program)
	defer scanner.Close()

	clean := bytes.Repeat([]byte("standard benign system logs 12345 "), 2000)
	res, err := scanner.Scan(clean)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.MatchedRules) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(res.MatchedRules))
	}

	hitData := slices.Clone(clean)
	copy(hitData[4000:], "POWERSHELL.EXE")
	res, err = scanner.Scan(hitData)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.MatchedRules) != 1 || res.MatchedRules[0].Rule != "multi_detect" {
		t.Fatalf("expected multi_detect match, got %+v", res.MatchedRules)
	}

	matches := res.Matches["multi_detect"]["$s1"]
	if len(matches) != 1 || matches[0].Offset != 4000 {
		t.Fatalf("unexpected match detail: %+v", matches)
	}
}
