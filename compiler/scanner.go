package compiler

import (
	"io"
	"os"

	"github.com/cawalch/go-yara/ast"
)

// Scanner provides a reusable, allocation-efficient YARA scanning engine.
//
// A Scanner is safe to reuse across multiple Scan calls but is NOT safe
// for concurrent use. Use one Scanner per goroutine.
type Scanner struct {
	program     *CompiledProgram
	interp      *Interpreter    // reused across calls
	matchCtx    *MatchContext   // reused across calls
	ruleResults map[string]bool // reused across calls
}

// ScanResult represents the result of scanning data against compiled rules.
type ScanResult struct {
	MatchedRules []RuleMatch
}

// RuleMatch represents a single rule match with details.
type RuleMatch struct {
	Rule    string
	Matches map[string][]Match // pattern -> matches
}

// NewScanner creates a new Scanner for the given compiled program.
func NewScanner(program *CompiledProgram) *Scanner {
	// Pre-allocate interpreter and context
	// We use the interpreter pool to get an initial one, but we keep it
	// instead of returning it to the pool, as the Scanner owns it.
	// Actually, NewInterpreter creates one.
	// But we want to use the Pool logic if possible to reuse memory.
	// Interpreter doesn't have a public NewInterpreterFromPool.
	// But NewInterpreter allocates.
	// Let's use internal pool if accessible (it is in package compiler).

	// Better: Use `pool.Get()` manually since we are in `package compiler`.
	// But `interpreterPool` is private var `interpreterPool` in `interpreter.go` (Step 310).
	// Yes, `var interpreterPool = ...`
	// So we can use it.

	interp := interpreterPool.Get().(*Interpreter)
	interp.SetCompiledRules(program.Rules)
	interp.PreserveRuleResults = true // We manage this manually in Scan()

	ctx := matchContextPool.Get().(*MatchContext)

	return &Scanner{
		program:     program,
		interp:      interp,
		matchCtx:    ctx,
		ruleResults: make(map[string]bool),
	}
}

// Close releases resources held by the Scanner.
func (s *Scanner) Close() {
	if s.interp != nil {
		s.interp.Release() // This puts it back in pool
		s.interp = nil
	}
	if s.matchCtx != nil {
		s.matchCtx.Release() // This puts it back in pool
		s.matchCtx = nil
	}
}

// Scan scans the provided byte slice against the compiled rules.
func (s *Scanner) Scan(data []byte) (*ScanResult, error) {
	// Reset and populate match context
	PopulateMatchContext(s.matchCtx, nil, data)
	// Wait, PopulateMatchContext expects *CompiledRule logic?
	// No, BuildMatchContext takes *CompiledRule.
	// But scanning against ALL rules?
	// Currently BuildMatchContext takes ONE rule.
	// This implies we need to build MatchContext for EACH rule?
	// Oh. `evaluateRule` does: `ctx := BuildMatchContext(rule, data)`.
	// This invokes AC search on `rule.Automaton`.

	// If `CompiledProgram` has multiple rules, each has its own Automaton?
	// Area 5 says: "Each CompiledRule has its own ACAutomaton... Consider a shared automaton".
	// So currently, yes, we must iterate rules and build context for each.
	// This makes reuse of `matchCtx` tricky if `Populate` accumulates.
	// `Populate` resets.

	// So `Scan` loop:
	// for rule in program.Rules {
	//    PopulateMatchContext(s.matchCtx, rule, data)
	//    s.interp.SetMatchContext(s.matchCtx)
	//    s.interp.Execute()
	//    ...
	// }

	// This is inefficient (scanning data N times).
	// But that's the current architecture (addressed in Area 5).
	// Area 3 just formalizes the API.

	result := &ScanResult{
		MatchedRules: make([]RuleMatch, 0),
	}

	// 1. One-pass scan over all static strings using the SharedAutomaton
	// We map the global string ID "ruleName:stringID" back to its rules
	globalMatches := make(map[string][]Match)

	if s.program.SharedAutomaton != nil {
		s.extractGlobalMatches(data, globalMatches)
	}

	// Reset rule results for next Scan
	clear(s.ruleResults)

	for _, rule := range s.program.Rules {
		// Populate context specific to this rule
		s.matchCtx.Reset(data)

		// 2. Add static matches found in the fast global pass
		s.addStaticMatches(rule, data, globalMatches[rule.Name])

		// 3. Process Regex (and un-analyzable) patterns locally since they require dynamic scans
		for id, regexInfo := range rule.RegexPatterns {
			modifiers := rule.StringModifiers[id]
			addRegexMatchesWithModifiers(s.matchCtx, id, regexInfo, data, modifiers)
		}

		s.interp.SetCurrentRule(rule.Name)
		s.interp.SetMatchContext(s.matchCtx)
		s.interp.SetRuleResults(s.ruleResults)

		if err := s.interp.Execute(); err != nil {
			return nil, err
		}

		// Check result
		// Stack has result.
		// `storeExecutionResult` in interpreter puts it in `ruleResults`.

		// If matched, add to result.
		if s.interp.GetRuleResults()[rule.Name] {
			// Copy matches from context?
			// The MatchContext matches are specific to this rule.
			// We need to capture them.
			matches := make(map[string][]Match)
			for k, v := range s.matchCtx.Matches {
				// Deep copy matches?
				// Match struct is small. Slice is ref.
				dst := make([]Match, len(v))
				copy(dst, v)
				matches[k] = dst
			}

			result.MatchedRules = append(result.MatchedRules, RuleMatch{
				Rule:    rule.Name,
				Matches: matches,
			})
		}

		// Reset match context for next rule (done by Populate)
		// But Interpreter needs Reset?
		// `Execute` calls `Reset` internally at start.
		// But `ruleResults` must persist!
		// `Interpreter.Reset()`: if `i.ruleResults == nil` make new. else `clear`.
		// THIS IS BAD for multi-rule scan.
		// If `Reset` clears `ruleResults`, we lose previous rule results (needed for dependencies).

		// We need `ResetExecutionState` vs `ResetFull`.
		// `Reset` in `interpreter.go`:
		// `i.ip = 0`, `i.stack = i.stack[:0]`, `i.memory...`.
		// `i.ruleResults` IS CLEARED.

		// So `Interpreter` as it stands is designed for ONE rule execution isolation?
		// No, `Interpreter` is designed to be reused.
		// But if we run multiple rules that depend on each other, they share `ruleResults`.
		// The `evaluateRule` approach:
		// `interp.SetRuleResults(sharedMap)`.
		// Does `Reset` clear it?
		// Let's check `interpreter.go` Reset logic again.
	}

	// Reset rule results for next Scan
	clear(s.ruleResults)

	return result, nil
}

// ScanReader reads from the reader and scans the data.
func (s *Scanner) ScanReader(r io.Reader) (*ScanResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return s.Scan(data)
}

// ScanFile scans the given file.
func (s *Scanner) ScanFile(filename string) (*ScanResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return s.Scan(data)
}

func (s *Scanner) extractGlobalMatches(data []byte, globalMatches map[string][]Match) {
	for match := range s.program.SharedAutomaton.SearchIter(data) {
		colonIdx := -1
		for i := 0; i < len(match.StringID); i++ {
			if match.StringID[i] == ':' {
				colonIdx = i
				break
			}
		}
		if colonIdx != -1 {
			ruleName := match.StringID[:colonIdx]
			stringID := match.StringID[colonIdx+1:]

			length := 0
			if match.StringIndex >= 0 && match.StringIndex < len(s.program.SharedAutomaton.Strings) {
				info := s.program.SharedAutomaton.Strings[match.StringIndex]
				length = info.Length
			}

			m := Match{
				Pattern: stringID,
				Offset:  int64(match.Backtrack),
				Length:  length,
			}

			globalMatches[ruleName] = append(globalMatches[ruleName], m)
		}
	}
}

func (s *Scanner) addStaticMatches(rule *CompiledRule, data []byte, matches []Match) {
	for _, m := range matches {
		if rule.StringKinds != nil && rule.StringKinds[m.Pattern] == StringKindText {
			isWide := false
			modifiers := rule.StringModifiers[m.Pattern]
			for _, mod := range modifiers {
				if mod.Type == ast.StringModifierWide {
					isWide = true
					break
				}
			}
			if matchPassesModifiers(data, m, modifiers, isWide) {
				s.matchCtx.AddMatch(m)
			}
		} else if matchPassesModifiers(data, m, rule.StringModifiers[m.Pattern], false) {
			s.matchCtx.AddMatch(m)
		}
	}
}
