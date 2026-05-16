package compiler

import (
	"io"
	"os"

	"github.com/cawalch/go-yara/regex"
)

// Scanner provides a reusable, allocation-efficient YARA scanning engine.
//
// A Scanner is safe to reuse across multiple Scan calls but is NOT safe for
// concurrent use. Use one Scanner per goroutine.
type Scanner struct {
	program     *CompiledProgram
	interp      *Interpreter    // reused across calls
	matchCtx    *MatchContext   // reused across calls
	ruleResults map[string]bool // reused across calls
}

// ScanResult represents the result of scanning data against compiled rules.
type ScanResult struct {
	MatchedRules []RuleMatch

	// RuleResults contains the boolean condition result for every evaluated rule.
	RuleResults map[string]bool

	// Matches contains per-rule pattern matches, keyed by rule name and string identifier.
	// Entries are deep-copied so callers may keep the result after Scanner reuse.
	Matches map[string]map[string][]Match
}

// RuleMatch represents a single rule match with details.
type RuleMatch struct {
	Rule    string
	Matches map[string][]Match // pattern -> matches (string-keyed for public API)
}

// NewScanner creates a new Scanner for the given compiled program.
func NewScanner(program *CompiledProgram) *Scanner {
	interp := acquireScannerInterpreter()
	if program != nil {
		interp.SetCompiledRules(program.Rules)
	}

	ctx := matchContextPool.Get().(*MatchContext)

	return &Scanner{
		program:     program,
		interp:      interp,
		matchCtx:    ctx,
		ruleResults: make(map[string]bool),
	}
}

func acquireScannerInterpreter() *Interpreter {
	interp := interpreterPool.Get().(*Interpreter)
	interp.bytecode = nil
	interp.ip = 0
	interp.stack = interp.stack[:0]
	for idx := range interp.memory {
		interp.memory[idx] = Value{}
	}
	interp.iterators = interp.iterators[:0]
	interp.stopped = false
	interp.result = nil
	interp.matchContext = nil
	interp.ruleResults = nil
	interp.currentRule = ""
	interp.currentCompiledRule = nil
	interp.compiledRules = nil
	interp.stringLiterals = nil
	interp.stringSets = nil
	interp.allStrings = nil
	interp.anonymousStrings = nil
	interp.stringArena = interp.stringArena[:0]
	if interp.regexCache == nil {
		interp.regexCache = make(map[string]compiledRegex)
	}
	interp.PreserveRuleResults = true
	return interp
}

// Close releases resources held by the Scanner.
func (s *Scanner) Close() {
	if s.interp != nil {
		s.interp.PreserveRuleResults = false
		s.interp.Release()
		s.interp = nil
	}
	if s.matchCtx != nil {
		s.matchCtx.Release()
		s.matchCtx = nil
	}
}

// NewScanner creates a Scanner for this compiled program.
func (cp *CompiledProgram) NewScanner() *Scanner {
	return NewScanner(cp)
}

// Scan evaluates all rules in this compiled program against data.
func (cp *CompiledProgram) Scan(data []byte) (*ScanResult, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.Scan(data)
}

// ScanReader reads from r and evaluates all rules in this compiled program.
func (cp *CompiledProgram) ScanReader(r io.Reader) (*ScanResult, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.ScanReader(r)
}

// ScanFile reads filename and evaluates all rules in this compiled program.
func (cp *CompiledProgram) ScanFile(filename string) (*ScanResult, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.ScanFile(filename)
}

// globalMatchEntry is a match routed by integer indices from the shared automaton.
type globalMatchEntry struct {
	strID  string // string identifier (e.g. "$a")
	m      Match  // the match itself
	isWide bool   // whether this concrete automaton pattern is wide-encoded
}

// Scan scans the provided byte slice against the compiled rules.
func (s *Scanner) Scan(data []byte) (*ScanResult, error) {
	result := &ScanResult{
		MatchedRules: make([]RuleMatch, 0),
		RuleResults:  make(map[string]bool),
		Matches:      make(map[string]map[string][]Match),
	}
	if s == nil || s.program == nil {
		return result, nil
	}

	globalByRule := make(map[int][]globalMatchEntry)
	useSharedAutomaton := s.program.SharedAutomaton != nil && len(s.program.SharedLookup) > 0
	if useSharedAutomaton {
		s.extractGlobalMatchesInt(data, globalByRule)
	}

	clear(s.ruleResults)

	for _, rule := range s.program.Rules {
		s.matchCtx.Reset(data)
		if useSharedAutomaton {
			// Add text matches from the one-pass shared automaton, then scan dynamic
			// regex/hex patterns locally because they require different engines.
			s.addStaticMatchesInt(rule, data, globalByRule[rule.Index])
			s.addLocalNonTextMatches(rule, data)
		} else {
			// Fallback for programs constructed manually without CompileSource.
			PopulateMatchContext(s.matchCtx, rule, data)
		}

		s.prepareInterpreter(rule)
		if err := s.interp.Execute(); err != nil {
			return nil, err
		}

		ruleMatches := cloneMatches(s.matchCtx.Matches)
		result.Matches[rule.Name] = ruleMatches

		matched := s.interp.GetRuleResults()[rule.Name]
		result.RuleResults[rule.Name] = matched
		if matched {
			result.MatchedRules = append(result.MatchedRules, RuleMatch{
				Rule:    rule.Name,
				Matches: ruleMatches,
			})
		}
	}

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
	data, err := os.ReadFile(filename) // #nosec G304 - caller intentionally scans this path
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
		if entry.RuleIndex < 0 || entry.RuleIndex >= len(rules) {
			continue
		}

		rule := rules[entry.RuleIndex]
		if entry.StringIdx < 0 || entry.StringIdx >= len(rule.IndexToStringID) {
			continue
		}

		info := s.program.SharedAutomaton.Strings[match.StringIndex]
		strID := rule.IndexToStringID[entry.StringIdx]
		globalByRule[entry.RuleIndex] = append(globalByRule[entry.RuleIndex], globalMatchEntry{
			strID: strID,
			m: Match{
				Pattern: strID,
				Offset:  int64(match.Backtrack),
				Length:  info.Length,
			},
			isWide: (info.Flags & regex.FlagsWide) != 0,
		})
	}
}

// addStaticMatchesInt adds matches routed by integer indices to the match context.
func (s *Scanner) addStaticMatchesInt(rule *CompiledRule, data []byte, entries []globalMatchEntry) {
	for _, e := range entries {
		m := e.m
		modifiers := rule.StringModifiers[m.Pattern]
		if matchPassesModifiers(data, m, modifiers, e.isWide) {
			s.matchCtx.AddMatch(m)
		}
	}
}

func (s *Scanner) addLocalNonTextMatches(rule *CompiledRule, data []byte) {
	if rule == nil {
		return
	}
	for id, regexInfo := range rule.RegexPatterns {
		modifiers := rule.StringModifiers[id]
		addRegexMatchesWithModifiers(s.matchCtx, id, regexInfo, data, modifiers)
	}
	for id, pattern := range rule.HexPatterns {
		for _, m := range FindHexMatches(pattern, data) {
			m.Pattern = id
			if matchPassesModifiers(data, m, rule.StringModifiers[id], false) {
				s.matchCtx.AddMatch(m)
			}
		}
	}
}

func (s *Scanner) prepareInterpreter(rule *CompiledRule) {
	for idx := range s.interp.memory {
		s.interp.memory[idx] = Value{Type: ValueTypeUndefined}
	}
	s.interp.stringArena = s.interp.stringArena[:0]

	s.interp.SetCurrentRule(rule.Name)
	s.interp.SetMatchContext(s.matchCtx)
	s.interp.SetRuleResults(s.ruleResults)

	if rule.Automaton == nil {
		return
	}
	for idx, str := range rule.Automaton.Strings {
		s.interp.SetMemoryString(idx, str.Identifier)
	}
}

func cloneMatches(src map[string][]Match) map[string][]Match {
	matches := make(map[string][]Match, len(src))
	for k, v := range src {
		dst := make([]Match, len(v))
		copy(dst, v)
		matches[k] = dst
	}
	return matches
}
