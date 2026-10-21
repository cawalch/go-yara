package compiler

import (
	"strings"
	"testing"
)

func TestDeadStringEliminationBasic(t *testing.T) {
	c := NewCompiler()
	prog, err := c.CompileSource(`
		rule test_basic {
			strings:
				$used = "alive"
				$unused = "dead_pattern"
			condition:
				$used
		}
	`)
	if err != nil {
		t.Fatalf("CompileSource error: %v", err)
	}

	rule := prog.Rules[0]
	if rule.IsStringDead("$used") {
		t.Errorf("expected $used to be alive")
	}
	if !rule.IsStringDead("$unused") {
		t.Errorf("expected $unused to be dead")
	}

	// Verify metadata consistency for external queries
	allStrings := rule.GetStrings()
	if len(allStrings) != 2 {
		t.Fatalf("expected 2 strings in metadata, got %d", len(allStrings))
	}
	if rule.GetStringCount() != 2 {
		t.Fatalf("expected GetStringCount() == 2, got %d", rule.GetStringCount())
	}
	if _, ok := allStrings["$used"]; !ok {
		t.Errorf("expected $used in GetStrings()")
	}
	if _, ok := allStrings["$unused"]; !ok {
		t.Errorf("expected $unused in GetStrings()")
	}

	// Verify shared automaton contains only $used
	for _, entry := range prog.sharedLookup {
		if entry.RuleIndex == rule.Index {
			strID := rule.IndexToStringID[entry.StringIdx]
			if strID == "$unused" {
				t.Fatalf("dead string $unused found in shared automaton lookup")
			}
		}
	}
	for _, info := range prog.sharedAutomaton.strings {
		if strings.Contains(info.Identifier, "$unused") {
			t.Fatalf("dead string $unused found in shared automaton strings: %s", info.Identifier)
		}
	}

	// Scanning data containing only the dead pattern should not match
	scanner := prog.NewScanner()
	defer scanner.Close()

	res, err := scanner.Scan([]byte("dead_pattern only"))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(res.MatchedRules) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(res.MatchedRules))
	}

	// Scanning data containing the live pattern should match
	res, err = scanner.Scan([]byte("alive and well"))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(res.MatchedRules) != 1 || res.MatchedRules[0].Rule != "test_basic" {
		t.Fatalf("expected test_basic to match, got %v", res.MatchedRules)
	}
}

func TestDeadStringEliminationInDeadBranch(t *testing.T) {
	c := NewCompiler()
	prog, err := c.CompileSource(`
		rule test_dead_branch {
			strings:
				$a = "live_data"
				$b = "unreachable_data"
			condition:
				$a or (1 == 2 and $b)
		}
	`)
	if err != nil {
		t.Fatalf("CompileSource error: %v", err)
	}

	rule := prog.Rules[0]
	if rule.IsStringDead("$a") {
		t.Errorf("expected $a to be alive")
	}
	if !rule.IsStringDead("$b") {
		t.Errorf("expected $b to be dead")
	}

	for _, info := range prog.sharedAutomaton.strings {
		if strings.Contains(info.Identifier, "$b") {
			t.Fatalf("dead string $b in dead branch found in shared automaton: %s", info.Identifier)
		}
	}
}

func TestDeadStringEliminationRuleStaticallyFalse(t *testing.T) {
	c := NewCompiler()
	prog, err := c.CompileSource(`
		rule test_statically_false {
			strings:
				$a = "never_compile_a"
				$b = "never_compile_b"
			condition:
				1 == 2
		}
	`)
	if err != nil {
		t.Fatalf("CompileSource error: %v", err)
	}

	rule := prog.Rules[0]
	if !rule.IsDead {
		t.Fatalf("expected rule to be dead")
	}
	if !rule.IsStringDead("$a") || !rule.IsStringDead("$b") {
		t.Fatalf("expected all strings in dead rule to be dead")
	}

	for _, entry := range prog.sharedLookup {
		if entry.RuleIndex == rule.Index {
			t.Fatalf("dead rule strings found in shared automaton lookup")
		}
	}

	scanner := prog.NewScanner()
	defer scanner.Close()
	res, err := scanner.Scan([]byte("never_compile_a never_compile_b"))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(res.MatchedRules) != 0 {
		t.Fatalf("expected 0 matches for dead rule, got %d", len(res.MatchedRules))
	}
}

func TestDeadStringEliminationAnonymous(t *testing.T) {
	t.Run("anonymous used via them", func(t *testing.T) {
		c := NewCompiler()
		prog, err := c.CompileSource(`
			rule test_anon_used {
				strings:
					$ = "anon_one"
					$ = "anon_two"
				condition:
					any of them
			}
		`)
		if err != nil {
			t.Fatalf("CompileSource error: %v", err)
		}
		rule := prog.Rules[0]
		for _, anonID := range rule.AnonymousStrings {
			if rule.IsStringDead(anonID) {
				t.Errorf("expected anonymous string %s to be alive", anonID)
			}
		}
	})

	t.Run("anonymous unused when named string used", func(t *testing.T) {
		c := NewCompiler()
		prog, err := c.CompileSource(`
			rule test_anon_unused {
				strings:
					$ = "anon_unused"
					$used = "alive_named"
				condition:
					$used
			}
		`)
		if err != nil {
			t.Fatalf("CompileSource error: %v", err)
		}
		rule := prog.Rules[0]
		if rule.IsStringDead("$used") {
			t.Errorf("expected $used to be alive")
		}
		for _, anonID := range rule.AnonymousStrings {
			if !rule.IsStringDead(anonID) {
				t.Errorf("expected anonymous string %s to be dead", anonID)
			}
		}
	})
}

func TestDeadStringEliminationPrefixWildcard(t *testing.T) {
	c := NewCompiler()
	prog, err := c.CompileSource(`
		rule test_prefix {
			strings:
				$foo_1 = "foo1"
				$foo_2 = "foo2"
				$bar = "bar_dead"
			condition:
				1 of ($foo_*)
		}
	`)
	if err != nil {
		t.Fatalf("CompileSource error: %v", err)
	}

	rule := prog.Rules[0]
	if rule.IsStringDead("$foo_1") {
		t.Errorf("expected $foo_1 to be alive")
	}
	if rule.IsStringDead("$foo_2") {
		t.Errorf("expected $foo_2 to be alive")
	}
	if !rule.IsStringDead("$bar") {
		t.Errorf("expected $bar to be dead")
	}

	for _, info := range prog.sharedAutomaton.strings {
		if strings.Contains(info.Identifier, "$bar") {
			t.Fatalf("dead string $bar found in shared automaton: %s", info.Identifier)
		}
	}
}

func TestDeadStringEliminationSpecialOperators(t *testing.T) {
	t.Run("count operator #foo", func(t *testing.T) {
		c := NewCompiler()
		prog, err := c.CompileSource(`
			rule test_count {
				strings:
					$a = "alive_count"
					$b = "dead_count"
				condition:
					#a > 0
			}
		`)
		if err != nil {
			t.Fatalf("CompileSource error: %v", err)
		}
		rule := prog.Rules[0]
		if rule.IsStringDead("$a") {
			t.Errorf("expected $a to be alive")
		}
		if !rule.IsStringDead("$b") {
			t.Errorf("expected $b to be dead")
		}
	})

	t.Run("offset operator @foo", func(t *testing.T) {
		c := NewCompiler()
		prog, err := c.CompileSource(`
			rule test_offset {
				strings:
					$a = "alive_offset"
					$b = "dead_offset"
				condition:
					@a > 0
			}
		`)
		if err != nil {
			t.Fatalf("CompileSource error: %v", err)
		}
		rule := prog.Rules[0]
		if rule.IsStringDead("$a") {
			t.Errorf("expected $a to be alive")
		}
		if !rule.IsStringDead("$b") {
			t.Errorf("expected $b to be dead")
		}
	})

	t.Run("length operator !foo", func(t *testing.T) {
		c := NewCompiler()
		prog, err := c.CompileSource(`
			rule test_length {
				strings:
					$a = "alive_len"
					$b = "dead_len"
				condition:
					!a == 9
			}
		`)
		if err != nil {
			t.Fatalf("CompileSource error: %v", err)
		}
		rule := prog.Rules[0]
		if rule.IsStringDead("$a") {
			t.Errorf("expected $a to be alive")
		}
		if !rule.IsStringDead("$b") {
			t.Errorf("expected $b to be dead")
		}
	})
}

func TestDeadStringEliminationThem(t *testing.T) {
	t.Run("1 of them keeps all alive", func(t *testing.T) {
		c := NewCompiler()
		prog, err := c.CompileSource(`
			rule test_them {
				strings:
					$a = "alpha"
					$b = "beta"
					$c = "gamma"
				condition:
					1 of them
			}
		`)
		if err != nil {
			t.Fatalf("CompileSource error: %v", err)
		}
		rule := prog.Rules[0]
		if rule.IsStringDead("$a") || rule.IsStringDead("$b") || rule.IsStringDead("$c") {
			t.Errorf("expected all strings to be alive with 'them'")
		}
	})

	t.Run("for any of them keeps all alive", func(t *testing.T) {
		c := NewCompiler()
		prog, err := c.CompileSource(`
			rule test_for_them {
				strings:
					$a = "alpha"
					$b = "beta"
				condition:
					for any of them : ( $ )
			}
		`)
		if err != nil {
			t.Fatalf("CompileSource error: %v", err)
		}
		rule := prog.Rules[0]
		if rule.IsStringDead("$a") || rule.IsStringDead("$b") {
			t.Errorf("expected all strings to be alive with for loop over them")
		}
	})
}

func TestDeadStringEliminationRegexAndHex(t *testing.T) {
	c := NewCompiler()
	prog, err := c.CompileSource(`
		rule test_regex_hex_dead {
			strings:
				$t = "alive_text"
				$r = /dead_regex_[0-9]+/
				$h = { 01 02 03 04 05 }
			condition:
				$t
		}
	`)
	if err != nil {
		t.Fatalf("CompileSource error: %v", err)
	}

	rule := prog.Rules[0]
	if rule.IsStringDead("$t") {
		t.Errorf("expected $t to be alive")
	}
	if !rule.IsStringDead("$r") {
		t.Errorf("expected $r to be dead")
	}
	if !rule.IsStringDead("$h") {
		t.Errorf("expected $h to be dead")
	}

	// Verify no prefilter entries were emitted for dead regex or hex in sharedLookup
	for _, entry := range prog.sharedLookup {
		if entry.RuleIndex == rule.Index {
			strID := rule.IndexToStringID[entry.StringIdx]
			if strID == "$r" || strID == "$h" {
				t.Fatalf("dead string %s emitted to sharedLookup", strID)
			}
		}
	}
}

func TestDeadStringEliminationMultipleRules(t *testing.T) {
	c := NewCompiler()
	prog, err := c.CompileSource(`
		rule r1 {
			strings:
				$live1 = "apple"
				$dead1 = "banana"
			condition:
				$live1
		}
		rule r2 {
			strings:
				$live2 = "cherry"
				$dead2 = "date"
			condition:
				$live2
		}
	`)
	if err != nil {
		t.Fatalf("CompileSource error: %v", err)
	}

	r1 := prog.Rules[0]
	r2 := prog.Rules[1]

	if r1.IsStringDead("$live1") || !r1.IsStringDead("$dead1") {
		t.Errorf("r1 string status mismatch")
	}
	if r2.IsStringDead("$live2") || !r2.IsStringDead("$dead2") {
		t.Errorf("r2 string status mismatch")
	}

	// Ensure only live strings are in shared automaton
	for _, info := range prog.sharedAutomaton.strings {
		if strings.Contains(info.Identifier, "$dead1") || strings.Contains(info.Identifier, "$dead2") {
			t.Fatalf("dead string found in shared automaton: %s", info.Identifier)
		}
	}
}
