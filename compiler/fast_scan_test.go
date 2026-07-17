package compiler

import (
	"context"
	"testing"
)

func TestFastScanRetainsFirstOccurrenceForPresenceOnlyRules(t *testing.T) {
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), `
rule presence_only {
    strings:
        $text = "abc"
        $regex = /ab./
        $hex = { 61 62 63 }
    condition:
        all of them
}
`)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}
	rule, ok := program.GetRuleByName("presence_only")
	if !ok {
		t.Fatal("compiled program does not contain presence_only")
	}
	if !rule.FastScanSafe {
		t.Fatal("presence-only rule is not marked FastScanSafe")
	}

	data := []byte("abcabcabc")
	regular := program.NewScanner()
	defer regular.Close()
	regularResult, err := regular.Scan(data)
	if err != nil {
		t.Fatalf("regular Scan() error = %v", err)
	}
	for _, id := range []string{"$text", "$regex", "$hex"} {
		if got := len(regularResult.Matches["presence_only"][id]); got != 3 {
			t.Fatalf("regular %s match count = %d, want 3", id, got)
		}
	}

	fast := program.NewScanner(WithFastScan())
	defer fast.Close()
	fastResult, err := fast.Scan(data)
	if err != nil {
		t.Fatalf("fast Scan() error = %v", err)
	}
	if !fastResult.RuleResults["presence_only"] {
		t.Fatal("fast scan changed presence_only rule result")
	}
	for _, id := range []string{"$text", "$regex", "$hex"} {
		if got := len(fastResult.Matches["presence_only"][id]); got != 1 {
			t.Fatalf("fast %s match count = %d, want 1", id, got)
		}
	}
}

func TestFastScanPreservesOccurrenceSensitiveRules(t *testing.T) {
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), `
rule occurrence_sensitive {
    strings:
        $a = "abc"
    condition:
        #a == 3 and @a[2] == 3
}
`)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}
	rule, ok := program.GetRuleByName("occurrence_sensitive")
	if !ok {
		t.Fatal("compiled program does not contain occurrence_sensitive")
	}
	if rule.FastScanSafe {
		t.Fatal("occurrence-sensitive rule is marked FastScanSafe")
	}

	fast := program.NewScanner(WithFastScan())
	defer fast.Close()
	result, err := fast.Scan([]byte("abcabcabc"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !result.RuleResults["occurrence_sensitive"] {
		t.Fatal("fast scan changed occurrence-sensitive rule result")
	}
	if got := len(result.Matches["occurrence_sensitive"]["$a"]); got != 3 {
		t.Fatalf("occurrence-sensitive match count = %d, want 3", got)
	}
}

func TestFastScanDoesNotTruncateSharedCacheForSensitiveRule(t *testing.T) {
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), `
rule safe {
    strings:
        $a = /ab./
    condition:
        $a
}

rule sensitive {
    strings:
        $a = /ab./
    condition:
        #a == 3
}
`)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}

	fast := program.NewScanner(WithFastScan())
	defer fast.Close()
	result, err := fast.Scan([]byte("abcabdabe"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got := len(result.Matches["safe"]["$a"]); got != 1 {
		t.Fatalf("safe match count = %d, want 1", got)
	}
	if !result.RuleResults["sensitive"] {
		t.Fatal("sensitive rule did not match")
	}
	if got := len(result.Matches["sensitive"]["$a"]); got != 3 {
		t.Fatalf("sensitive match count = %d, want 3", got)
	}
}

func TestFastScanPreservesOffsetConstrainedRules(t *testing.T) {
	program, err := NewCompiler().CompileSourceWithContext(context.Background(), `
rule at_offset {
    strings:
        $a = "abc"
    condition:
        $a at 3
}
rule in_range {
    strings:
        $a = "abc"
    condition:
        $a in (3..5)
}
`)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}
	for _, name := range []string{"at_offset", "in_range"} {
		rule, _ := program.GetRuleByName(name)
		if rule.FastScanSafe {
			t.Fatalf("offset-constrained rule %s is marked FastScanSafe", name)
		}
	}

	fast := program.NewScanner(WithFastScan())
	defer fast.Close()
	result, err := fast.Scan([]byte("abcabc"))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, name := range []string{"at_offset", "in_range"} {
		if !result.RuleResults[name] {
			t.Errorf("fast scan changed %s rule result", name)
		}
		if got := len(result.Matches[name]["$a"]); got != 2 {
			t.Errorf("%s match count = %d, want 2", name, got)
		}
	}
}
