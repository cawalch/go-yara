package compiler

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"slices"

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
	tagsFilter  map[string]bool // non-empty means: only scan rules with these tags
	itersmax    int             // max for-loop iterations (0 = unlimited)

	matchDataMax        int
	matchContextBefore  int
	matchContextAfter   int
	matchContextEnabled bool

	externalValues map[string]externalValue
	externalErr    error
}

// ScanResult represents the result of scanning data against compiled rules.
type ScanResult struct {
	MatchedRules []RuleMatch

	// RuleResults contains the boolean condition result for every evaluated rule.
	RuleResults map[string]bool

	// Matches contains per-rule pattern matches, keyed by rule name and string identifier.
	Matches map[string]map[string][]Match
}

// RuleMatch represents a single rule match with details.
type RuleMatch struct {
	Rule    string
	Tags    []string           // Rule tags
	Meta    map[string]any     // Rule metadata
	Matches map[string][]Match // pattern -> matches (string-keyed for public API)
}

// ScannerOption configures a Scanner.
type ScannerOption func(*Scanner)

// WithTagsFilter restricts scanning to rules that have at least one of the given tags.
// Global rules are always evaluated regardless of tags.
func WithTagsFilter(tags []string) ScannerOption {
	filter := make(map[string]bool, len(tags))
	for _, t := range tags {
		filter[t] = true
	}
	return func(s *Scanner) {
		s.tagsFilter = filter
	}
}

// WithItersmax sets a limit on the total number of for-loop iterations.
// A value of 0 means unlimited. Corresponds to YARA's ITERSMAX compile-time constant.
func WithItersmax(limit int) ScannerOption {
	return func(scanner *Scanner) {
		scanner.itersmax = limit
	}
}

// WithMatchData includes up to maxBytes of matched data in each reported match.
// Non-positive values disable matched data evidence.
func WithMatchData(maxBytes int) ScannerOption {
	if maxBytes < 0 {
		maxBytes = 0
	}
	return func(scanner *Scanner) {
		scanner.matchDataMax = maxBytes
	}
}

// WithMatchContext includes byte context before and after each reported match.
// Negative values are treated as zero.
func WithMatchContext(beforeBytes, afterBytes int) ScannerOption {
	if beforeBytes < 0 {
		beforeBytes = 0
	}
	if afterBytes < 0 {
		afterBytes = 0
	}
	return func(scanner *Scanner) {
		scanner.matchContextBefore = beforeBytes
		scanner.matchContextAfter = afterBytes
		scanner.matchContextEnabled = true
	}
}

// WithExternalVariables provides runtime values for declared external variables.
//
// Invalid variable names or unsupported values are reported by Scan.
func WithExternalVariables(vars map[string]any) ScannerOption {
	return func(scanner *Scanner) {
		if err := scanner.SetExternalVariables(vars); err != nil {
			scanner.externalErr = err
		}
	}
}

// NewScanner creates a new Scanner for the given compiled program.
func NewScanner(program *CompiledProgram, opts ...ScannerOption) *Scanner {
	interp := acquireScannerInterpreter()
	if program != nil {
		interp.SetCompiledRules(program.Rules)
	}

	ctx := matchContextPool.Get().(*MatchContext)

	s := &Scanner{
		program:     program,
		interp:      interp,
		matchCtx:    ctx,
		ruleResults: make(map[string]bool),
	}
	if program != nil {
		s.externalValues = cloneExternalValues(program.externalValues)
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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
func (cp *CompiledProgram) NewScanner(opts ...ScannerOption) *Scanner {
	return NewScanner(cp, opts...)
}

// Scan evaluates all rules in this compiled program against data.
func (cp *CompiledProgram) Scan(data []byte) (*ScanResult, error) {
	return cp.ScanWithContext(context.Background(), data)
}

// ScanWithContext evaluates all rules in this compiled program against data.
func (cp *CompiledProgram) ScanWithContext(ctx context.Context, data []byte) (*ScanResult, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.ScanWithContext(ctx, data)
}

// ScanReader reads from r and evaluates all rules in this compiled program.
func (cp *CompiledProgram) ScanReader(r io.Reader) (*ScanResult, error) {
	return cp.ScanReaderWithContext(context.Background(), r)
}

// ScanReaderWithContext reads from r and evaluates all rules in this compiled program.
func (cp *CompiledProgram) ScanReaderWithContext(ctx context.Context, r io.Reader) (*ScanResult, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.ScanReaderWithContext(ctx, r)
}

// ScanFile reads filename and evaluates all rules in this compiled program.
func (cp *CompiledProgram) ScanFile(filename string) (*ScanResult, error) {
	return cp.ScanFileWithContext(context.Background(), filename)
}

// ScanFileWithContext reads filename and evaluates all rules in this compiled program.
func (cp *CompiledProgram) ScanFileWithContext(ctx context.Context, filename string) (*ScanResult, error) {
	scanner := NewScanner(cp)
	defer scanner.Close()
	return scanner.ScanFileWithContext(ctx, filename)
}

// globalMatchEntry is a match routed by integer indices from the shared automaton.
type globalMatchEntry struct {
	strID    string // string identifier (e.g. "$a")
	m        Match  // the match itself
	isWide   bool   // whether this concrete automaton pattern is wide-encoded
	isNocase bool   // whether the originating string is nocase
	pattern  []byte // stored automaton pattern bytes for re-verification
}

type nonTextMatchCache struct {
	regex map[string][]Match
	hex   map[string][]Match
}

// hasMatchingTag returns true if the rule has at least one tag in the filter.
func (s *Scanner) hasMatchingTag(rule *CompiledRule) bool {
	if len(s.tagsFilter) == 0 {
		return true
	}
	for _, tag := range rule.Tags {
		if s.tagsFilter[tag] {
			return true
		}
	}
	return false
}

// Scan scans the provided byte slice against the compiled rules.
func (s *Scanner) Scan(data []byte) (*ScanResult, error) {
	return s.ScanWithContext(context.Background(), data)
}

// ScanWithContext scans the provided byte slice against the compiled rules.
func (s *Scanner) ScanWithContext(ctx context.Context, data []byte) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result := &ScanResult{
		MatchedRules: make([]RuleMatch, 0),
		RuleResults:  make(map[string]bool),
		Matches:      make(map[string]map[string][]Match),
	}
	if s == nil || s.program == nil {
		return result, nil
	}
	if s.externalErr != nil {
		return nil, s.externalErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	globalByRule := make(map[int][]globalMatchEntry)
	nonTextCache := nonTextMatchCache{}
	useSharedAutomaton := s.program.SharedAutomaton != nil && len(s.program.SharedLookup) > 0
	if useSharedAutomaton {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.extractGlobalMatchesInt(data, globalByRule)
	}

	clear(s.ruleResults)

	// YARA spec: global rules are evaluated first and ALL must match
	// before non-global rules are evaluated.
	// Private rules are never reported in MatchedRules.
	// Tag filtering: only evaluate rules with matching tags (global rules always evaluated).
	//
	// Two-pass approach:
	// 1. Evaluate all rules to populate match context and rule results.
	// 2. Build MatchedRules, skipping non-global rules if any global rule failed.

	// Pass 1: evaluate every rule
	s.interp.ResetIterationCount()
	for _, rule := range s.program.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Global rules are always evaluated; others only if they match the tag filter.
		if !rule.IsGlobal && !s.hasMatchingTag(rule) {
			continue
		}
		s.matchCtx.Reset(data)
		if useSharedAutomaton {
			s.addStaticMatchesInt(rule, data, globalByRule[rule.Index])
		} else {
			s.addLocalTextMatches(rule, data)
		}
		s.addLocalNonTextMatches(rule, data, &nonTextCache)

		s.prepareInterpreter(rule)
		s.interp.SetItersmax(s.itersmax)
		if err := s.interp.Execute(); err != nil {
			return nil, err
		}

		// Only clone when there are matches — avoids allocating map + slices for empty results.
		if len(s.matchCtx.Matches) > 0 {
			ruleMatches := cloneMatches(s.matchCtx.Matches)
			ruleMatches = filterPrivateStrings(rule, ruleMatches)
			if err := s.populateMatchEvidence(ctx, data, ruleMatches); err != nil {
				return nil, err
			}
			result.Matches[rule.Name] = ruleMatches
		}
		result.RuleResults[rule.Name] = s.interp.GetRuleResults()[rule.Name]
	}

	// Check if all global rules matched
	allGlobalMatched := true
	for _, rule := range s.program.Rules {
		if rule.IsGlobal && !result.RuleResults[rule.Name] {
			allGlobalMatched = false
			break
		}
	}

	// Pass 2: build MatchedRules
	for _, rule := range s.program.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Skip non-global rules if not all global rules matched
		if !rule.IsGlobal && !allGlobalMatched {
			continue
		}
		// Skip rules not matching the tag filter
		if !s.hasMatchingTag(rule) {
			continue
		}
		// Private rules are not reported in results
		if rule.IsPrivate {
			continue
		}
		if result.RuleResults[rule.Name] {
			matches := result.Matches[rule.Name]
			// Filter out private strings from the report
			publicMatches := filterPrivateStrings(rule, matches)
			result.Matches[rule.Name] = publicMatches
			result.MatchedRules = append(result.MatchedRules, RuleMatch{
				Rule:    rule.Name,
				Tags:    rule.Tags,
				Meta:    rule.Meta,
				Matches: publicMatches,
			})
		}
	}

	clear(s.ruleResults)
	return result, nil
}

// ScanReader reads from the reader and scans the data.
func (s *Scanner) ScanReader(r io.Reader) (*ScanResult, error) {
	return s.ScanReaderWithContext(context.Background(), r)
}

// ScanReaderWithContext reads from the reader and scans the data.
func (s *Scanner) ScanReaderWithContext(ctx context.Context, r io.Reader) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.ScanWithContext(ctx, data)
}

// ScanFile scans the given file.
func (s *Scanner) ScanFile(filename string) (*ScanResult, error) {
	return s.ScanFileWithContext(context.Background(), filename)
}

// ScanFileWithContext scans the given file.
func (s *Scanner) ScanFileWithContext(ctx context.Context, filename string) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filename) // #nosec G304 - caller intentionally scans this path
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.ScanWithContext(ctx, data)
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
			isWide:   (info.Flags & regex.FlagsWide) != 0,
			isNocase: (info.Flags & regex.FlagsNoCase) != 0,
			pattern:  info.Data,
		})
	}
}

// addStaticMatchesInt adds matches routed by integer indices to the match context.
func (s *Scanner) addStaticMatchesInt(rule *CompiledRule, data []byte, entries []globalMatchEntry) {
	for _, e := range entries {
		m := e.m
		// Re-verify the candidate bytes against the stored pattern. The shared
		// automaton registers both ASCII cases for nocase strings, so a
		// case-sensitive string whose output state lies on a nocase path could
		// fire on the wrong case; reject those false candidates here.
		if !verifyTextMatch(data, m, e.pattern, e.isNocase) {
			continue
		}
		modifiers := rule.StringModifiers[m.Pattern]
		if matchPassesModifiers(data, m, modifiers, e.isWide) {
			s.matchCtx.AddMatch(m)
		}
	}
}

func (s *Scanner) addLocalTextMatches(rule *CompiledRule, data []byte) {
	if rule == nil || rule.Automaton == nil || len(data) == 0 {
		return
	}
	for match := range rule.Automaton.SearchIter(data) {
		acceptAutomatonMatch(s.matchCtx, rule, data, match)
	}
}

func (s *Scanner) addLocalNonTextMatches(rule *CompiledRule, data []byte, cache *nonTextMatchCache) {
	if rule == nil {
		return
	}
	for id, regexInfo := range rule.RegexPatterns {
		if regexInfo.cacheKey != "" && cache.regex != nil {
			if matches, ok := cache.regex[regexInfo.cacheKey]; ok {
				addCachedMatches(s.matchCtx, id, matches)
				continue
			}
		}
		modifiers := rule.StringModifiers[id]
		addRegexMatchesWithModifiers(s.matchCtx, id, regexInfo, data, modifiers)
		if regexInfo.cacheKey != "" {
			if cache.regex == nil {
				cache.regex = make(map[string][]Match)
			}
			cache.regex[regexInfo.cacheKey] = slices.Clone(s.matchCtx.Matches[id])
		}
	}
	for id, pattern := range rule.HexPatterns {
		if pattern != nil && pattern.cacheKey != "" && cache.hex != nil {
			if matches, ok := cache.hex[pattern.cacheKey]; ok {
				addCachedMatches(s.matchCtx, id, matches)
				continue
			}
		}
		for _, m := range FindHexMatches(pattern, data) {
			m.Pattern = id
			if matchPassesModifiers(data, m, rule.StringModifiers[id], false) {
				s.matchCtx.AddMatch(m)
			}
		}
		if pattern != nil && pattern.cacheKey != "" {
			if cache.hex == nil {
				cache.hex = make(map[string][]Match)
			}
			cache.hex[pattern.cacheKey] = slices.Clone(s.matchCtx.Matches[id])
		}
	}
}

func addCachedMatches(ctx *MatchContext, id string, matches []Match) {
	for _, match := range matches {
		match.Pattern = id
		ctx.AddMatch(match)
	}
}

func (s *Scanner) prepareInterpreter(rule *CompiledRule) {
	s.interp.stringArena = s.interp.stringArena[:0]

	s.interp.SetCurrentRule(rule.Name)
	s.interp.SetMatchContext(s.matchCtx)
	s.interp.SetRuleResults(s.ruleResults)

	if rule.Automaton != nil {
		for idx, str := range rule.Automaton.Strings {
			s.interp.SetMemoryString(idx, str.Identifier)
		}
	}
	s.setExternalVariables(rule)
	s.setGlobalVariables(rule)
}

func (s *Scanner) setExternalVariables(rule *CompiledRule) {
	for name, slot := range rule.ExternalSlots {
		value, ok := s.externalValues[name]
		if !ok {
			s.interp.memory[slot] = Value{Type: ValueTypeUndefined}
			continue
		}
		s.interp.memory[slot] = value.toInterpreterValue(s.interp)
	}
}

func (s *Scanner) setGlobalVariables(rule *CompiledRule) {
	for name, slot := range rule.GlobalSlots {
		value, ok := rule.GlobalValues[name]
		if !ok {
			s.interp.memory[slot] = Value{Type: ValueTypeUndefined}
			continue
		}
		s.interp.memory[slot] = value.toInterpreterValue(s.interp)
	}
}

func (v compiledGlobalValue) toInterpreterValue(interp *Interpreter) Value {
	switch v.valueType {
	case ValueTypeInt:
		return Value{Type: ValueTypeInt, IntVal: v.intVal}
	case ValueTypeDouble:
		return Value{Type: ValueTypeDouble, DoubleVal: v.doubleVal}
	case ValueTypeString:
		idx := len(interp.stringArena)
		interp.stringArena = append(interp.stringArena, v.stringVal)
		return Value{Type: ValueTypeString, StringRef: int64(idx)}
	default:
		return Value{Type: ValueTypeUndefined}
	}
}

// SetExternalVariables replaces runtime values for declared external variables.
func (s *Scanner) SetExternalVariables(vars map[string]any) error {
	values, err := normalizeExternalVariables(s.program, vars)
	if err != nil {
		return err
	}
	s.externalValues = values
	s.externalErr = nil
	return nil
}

type externalValue struct {
	valueType ValueType
	intVal    int64
	doubleVal float64
	stringVal string
}

func (v externalValue) toInterpreterValue(interp *Interpreter) Value {
	switch v.valueType {
	case ValueTypeInt:
		return Value{Type: ValueTypeInt, IntVal: v.intVal}
	case ValueTypeDouble:
		return Value{Type: ValueTypeDouble, DoubleVal: v.doubleVal}
	case ValueTypeString:
		idx := len(interp.stringArena)
		interp.stringArena = append(interp.stringArena, v.stringVal)
		return Value{Type: ValueTypeString, StringRef: int64(idx)}
	default:
		return Value{Type: ValueTypeUndefined}
	}
}

func normalizeExternalVariables(program *CompiledProgram, vars map[string]any) (map[string]externalValue, error) {
	if len(vars) == 0 {
		return nil, nil
	}

	declared := declaredExternalVariables(program)
	values := make(map[string]externalValue, len(vars))
	for name, raw := range vars {
		if !declared[name] {
			return nil, fmt.Errorf("external variable %q is not declared", name)
		}
		value, err := normalizeExternalValue(raw)
		if err != nil {
			return nil, fmt.Errorf("external variable %q: %w", name, err)
		}
		values[name] = value
	}
	return values, nil
}

func declaredExternalVariables(program *CompiledProgram) map[string]bool {
	declared := make(map[string]bool)
	if program == nil {
		return declared
	}
	for _, rule := range program.Rules {
		for name := range rule.ExternalSlots {
			declared[name] = true
		}
	}
	return declared
}

func normalizeExternalValue(value any) (externalValue, error) {
	switch v := value.(type) {
	case bool:
		if v {
			return externalValue{valueType: ValueTypeInt, intVal: 1}, nil
		}
		return externalValue{valueType: ValueTypeInt, intVal: 0}, nil
	case int:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int8:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int16:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int32:
		return externalValue{valueType: ValueTypeInt, intVal: int64(v)}, nil
	case int64:
		return externalValue{valueType: ValueTypeInt, intVal: v}, nil
	case uint:
		return normalizeExternalUint(uint64(v))
	case uint8:
		return normalizeExternalUint(uint64(v))
	case uint16:
		return normalizeExternalUint(uint64(v))
	case uint32:
		return normalizeExternalUint(uint64(v))
	case uint64:
		return normalizeExternalUint(v)
	case float32:
		return externalValue{valueType: ValueTypeDouble, doubleVal: float64(v)}, nil
	case float64:
		return externalValue{valueType: ValueTypeDouble, doubleVal: v}, nil
	case string:
		return externalValue{valueType: ValueTypeString, stringVal: v}, nil
	default:
		return externalValue{}, fmt.Errorf("unsupported value type %T", value)
	}
}

func normalizeExternalUint(value uint64) (externalValue, error) {
	if value > math.MaxInt64 {
		return externalValue{}, fmt.Errorf("unsigned integer %d exceeds int64 range", value)
	}
	return externalValue{valueType: ValueTypeInt, intVal: int64(value)}, nil
}

func cloneExternalValues(values map[string]externalValue) map[string]externalValue {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]externalValue, len(values))
	for name, value := range values {
		cloned[name] = value
	}
	return cloned
}

func (s *Scanner) populateMatchEvidence(ctx context.Context, data []byte, matches map[string][]Match) error {
	if s.matchDataMax <= 0 && !s.matchContextEnabled {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for id, perStringMatches := range matches {
		if err := ctx.Err(); err != nil {
			return err
		}
		for i := range perStringMatches {
			if err := ctx.Err(); err != nil {
				return err
			}
			s.populateSingleMatchEvidence(data, &perStringMatches[i])
		}
		matches[id] = perStringMatches
	}
	return nil
}

func (s *Scanner) populateSingleMatchEvidence(data []byte, match *Match) {
	if match.Offset < 0 || match.Length < 0 || match.Offset > int64(len(data)) {
		return
	}
	endOffset := match.Offset + int64(match.Length)
	if endOffset < match.Offset || endOffset > int64(len(data)) {
		return
	}

	start := int(match.Offset)
	end := int(endOffset)
	if s.matchDataMax > 0 {
		copyLength := match.Length
		if copyLength > s.matchDataMax {
			copyLength = s.matchDataMax
			match.MatchedDataTruncated = true
		}
		match.MatchedData = copyBytes(data[start : start+copyLength])
	}
	if s.matchContextEnabled {
		beforeStart := start - s.matchContextBefore
		if beforeStart < 0 {
			beforeStart = 0
		}
		afterEnd := end + s.matchContextAfter
		if afterEnd > len(data) {
			afterEnd = len(data)
		}
		match.ContextBefore = copyBytes(data[beforeStart:start])
		match.ContextAfter = copyBytes(data[end:afterEnd])
	}
}

func copyBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
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

// filterPrivateStrings removes private strings from the matches map.
func filterPrivateStrings(rule *CompiledRule, matches map[string][]Match) map[string][]Match {
	for id := range matches {
		if rule.IsPrivateString(id) {
			delete(matches, id)
		}
	}
	return matches
}
