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
	Matches map[string][]Match // pattern -> matches (string-keyed for public API)
}

// NewScanner creates a new Scanner for the given compiled program.
func NewScanner(program *CompiledProgram) *Scanner {
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
		s.interp.Release()
		s.interp = nil
	}
	if s.matchCtx != nil {
		s.matchCtx.Release()
		s.matchCtx = nil
	}
}

// globalMatchEntry is a match routed by integer indices from the shared automaton.
type globalMatchEntry struct {
	strID string // string identifier (e.g. "$a")
	m     Match  // the match itself
}

// Scan scans the provided byte slice against the compiled rules.
func (s *Scanner) Scan(data []byte) (*ScanResult, error) {
	result := &ScanResult{
		MatchedRules: make([]RuleMatch, 0),
	}

	// 1. One-pass scan over all static strings using the SharedAutomaton.
	// Route matches by rule index using the SharedLookup table (O(1) integer routing,
	// no colon parsing or string allocation).
	globalByRule := make(map[int][]globalMatchEntry)

	if s.program.SharedAutomaton != nil {
		s.extractGlobalMatchesInt(data, globalByRule)
	}

	// Reset rule results for next Scan
	clear(s.ruleResults)

	for _, rule := range s.program.Rules {
		// Populate context specific to this rule
		s.matchCtx.Reset(data)

		// 2. Add static matches found in the fast global pass
		s.addStaticMatchesInt(rule, data, globalByRule[rule.Index])

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

		// If matched, deep copy matches for the result.
		if s.interp.GetRuleResults()[rule.Name] {
			matches := make(map[string][]Match, len(s.matchCtx.Matches))
			for k, v := range s.matchCtx.Matches {
				dst := make([]Match, len(v))
				copy(dst, v)
				matches[k] = dst
			}

			result.MatchedRules = append(result.MatchedRules, RuleMatch{
				Rule:    rule.Name,
				Matches: matches,
			})
		}
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

// extractGlobalMatchesInt uses the SharedLookup table for O(1) integer routing
// instead of parsing colon-delimited string IDs.
func (s *Scanner) extractGlobalMatchesInt(data []byte, globalByRule map[int][]globalMatchEntry) {
	lookup := s.program.SharedLookup
	rules := s.program.Rules
	for match := range s.program.SharedAutomaton.SearchIter(data) {
		if match.StringIndex < 0 || match.StringIndex >= len(lookup) {
			continue
		}

		entry := lookup[match.StringIndex]
		length := 0
		if match.StringIndex >= 0 && match.StringIndex < len(s.program.SharedAutomaton.Strings) {
			info := s.program.SharedAutomaton.Strings[match.StringIndex]
			length = info.Length
		}

		var strID string
		if entry.RuleIndex >= 0 && entry.RuleIndex < len(rules) {
			rule := rules[entry.RuleIndex]
			if entry.StringIdx >= 0 && entry.StringIdx < len(rule.IndexToStringID) {
				strID = rule.IndexToStringID[entry.StringIdx]
			}
		}

		globalByRule[entry.RuleIndex] = append(globalByRule[entry.RuleIndex], globalMatchEntry{
			strID: strID,
			m: Match{
				Pattern: strID,
				Offset:  int64(match.Backtrack),
				Length:  length,
			},
		})
	}
}

// addStaticMatchesInt adds matches routed by integer indices to the match context.
func (s *Scanner) addStaticMatchesInt(rule *CompiledRule, data []byte, entries []globalMatchEntry) {
	for _, e := range entries {
		m := e.m
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
